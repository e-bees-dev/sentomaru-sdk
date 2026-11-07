using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;

namespace Sentomaru.Gateway.Verifier;

/// <summary>The outcome of a key lookup.</summary>
public enum JwkLookup
{
    /// <summary>One key with the token's <c>kid</c> fits the token's <c>alg</c>.</summary>
    Found,
    /// <summary>No key with that <c>kid</c> (after the refresh allowed, if any).</summary>
    KidUnknown,
    /// <summary>Review R N7: more than one key with that <c>kid</c> fits the <c>alg</c>: refused, never a refresh.</summary>
    KidAmbiguous,
    /// <summary>Keys with that <c>kid</c> exist, but none fits the token's <c>alg</c>: never a refresh.</summary>
    AlgMismatch,
    /// <summary>No usable key set (never fetched, every fetch failed, or the last one is older than <see cref="JwksSource.MaxStale"/>).</summary>
    Unavailable,
}

/// <summary>
/// D-17c2 (I6): the fixed JWKS of the jwt caller. Keys come only from the configured https URL (or the inline keys),
/// never from <c>iss</c>, <c>jku</c>, <c>x5u</c>, <c>jwk</c> or <c>x5c</c> of a token. The set is cached; a fetch is never
/// started by a request beyond these limits:
/// <list type="bullet">
/// <item>an unknown <c>kid</c> triggers at most one fetch per <see cref="JwtCallerSettings.UnknownKidRefresh"/> (minimum
/// 60 s), counting every fetch, and the request that cannot fetch is refused;</item>
/// <item>a set older than <see cref="CacheLifetime"/> is refreshed in the background, at most once per the smaller of
/// <see cref="CacheLifetime"/> and that interval, while the cached set keeps serving;</item>
/// <item>without any usable set, at most one fetch per <see cref="RetryWithoutKeys"/>; meanwhile the answer is
/// <see cref="JwkLookup.Unavailable"/> (fail closed);</item>
/// <item>a failed fetch keeps the previous set until it is <see cref="MaxStale"/> old, then the set is dropped.</item>
/// </list>
/// At most one fetch is in flight; requests that arrive during it wait for it. No redirect is followed, the answer is
/// read up to <see cref="MaxBytes"/> in at most <see cref="FetchTimeout"/> (<see cref="FirstFetchTimeout"/> for the fetch
/// started with the host, review R M-2), and nothing of it goes to a log.
/// </summary>
public sealed class JwksSource
{
    public const string ClientName = "sentomaru-jwks";
    public static readonly TimeSpan CacheLifetime = TimeSpan.FromMinutes(5);
    public static readonly TimeSpan MaxStale = TimeSpan.FromHours(1);
    public static readonly TimeSpan RetryWithoutKeys = TimeSpan.FromSeconds(5);
    public static readonly TimeSpan FetchTimeout = TimeSpan.FromSeconds(1);
    public static readonly TimeSpan FirstFetchTimeout = TimeSpan.FromSeconds(3);
    public const int MaxBytes = 65536;
    public const int MaxKeys = 64;

    private readonly JwtCallerSettings settings;
    private readonly IHttpClientFactory? clients;
    private readonly TimeProvider time;
    private readonly ILogger logger;
    private readonly Lock gate = new();
    private (IReadOnlyList<Jwk> Keys, DateTimeOffset FetchedAt)? current;
    private DateTimeOffset? lastAttempt;
    private Task? inflight;
    private long fetches;

    public JwksSource(JwtCallerSettings settings, IHttpClientFactory? clients, TimeProvider time, ILogger logger)
    {
        this.settings = settings;
        this.clients = clients;
        this.time = time;
        this.logger = logger;
        if (settings.JwksUrl is null) current = (settings.InlineKeys, DateTimeOffset.MaxValue);
    }

    /// <summary>When the cached set was fetched (null without one; <see cref="DateTimeOffset.MaxValue"/> for inline keys).</summary>
    public DateTimeOffset? FetchedAt
    {
        get
        {
            lock (gate) return current?.FetchedAt;
        }
    }

    /// <summary>
    /// Review R M-2: whether a usable set is cached (always true with inline keys). <c>/health</c> answers ready only then;
    /// without a set it also starts a fetch (at most one per <see cref="RetryWithoutKeys"/>, never waited for), so an
    /// instance with no traffic still recovers.
    /// </summary>
    public bool Ready()
    {
        if (Usable() is not null) return true;
        if (settings.JwksUrl is not null) _ = Start(RetryWithoutKeys, FetchTimeout);
        return false;
    }

    /// <summary>Review R M-2: the first fetch, started with the host and never waited for (deadline <see cref="FirstFetchTimeout"/>).</summary>
    public void Warm()
    {
        if (settings.JwksUrl is not null) _ = Start(TimeSpan.Zero, FirstFetchTimeout);
    }

    /// <summary>Fetches started so far (tests and the refresh limit proofs).</summary>
    public long Fetches => Interlocked.Read(ref fetches);

    /// <summary>The key for a token header (<paramref name="alg"/> is already allowlisted).</summary>
    public async Task<(JwkLookup Result, Jwk? Key)> FindAsync(string kid, string alg, CancellationToken cancellationToken)
    {
        if (settings.JwksUrl is null) return Lookup(settings.InlineKeys, kid, alg);

        var set = Usable();
        if (set is null)
        {
            if (Start(RetryWithoutKeys, FetchTimeout) is { } fetch) await fetch.WaitAsync(cancellationToken);
            set = Usable();
            return set is null ? (JwkLookup.Unavailable, null) : Lookup(set.Value.Keys, kid, alg);
        }

        if (time.GetUtcNow() - set.Value.FetchedAt >= CacheLifetime)
        {
            // Background refresh, at most once per the smaller of the cache lifetime and the configured interval, so a
            // long interval never lets the set reach MaxStale while the endpoint is up.
            _ = Start(CacheLifetime < settings.UnknownKidRefresh ? CacheLifetime : settings.UnknownKidRefresh, FetchTimeout);
        }

        var found = Lookup(set.Value.Keys, kid, alg);
        if (found.Result != JwkLookup.KidUnknown) return found;
        // I6: an unknown kid refreshes at most once per interval; otherwise it is refused now.
        if (Start(settings.UnknownKidRefresh, FetchTimeout) is not { } refresh) return found;
        await refresh.WaitAsync(cancellationToken);
        set = Usable();
        return set is null ? (JwkLookup.Unavailable, null) : Lookup(set.Value.Keys, kid, alg);
    }

    private (IReadOnlyList<Jwk> Keys, DateTimeOffset FetchedAt)? Usable()
    {
        lock (gate)
        {
            if (current is { } set && time.GetUtcNow() - set.FetchedAt >= MaxStale)
            {
                logger.LogError("Sentomaru verifier: the cached JWKS is older than {MaxStale} and was dropped; JWT callers are refused until a fetch succeeds.",
                    MaxStale);
                current = null;
            }
            return current;
        }
    }

    /// <summary>The fetch in flight, a new one when the last attempt is at least <paramref name="interval"/> old, or null.</summary>
    private Task? Start(TimeSpan interval, TimeSpan deadline)
    {
        lock (gate)
        {
            if (inflight is { IsCompleted: false }) return inflight;
            var now = time.GetUtcNow();
            if (lastAttempt is { } last && now - last < interval) return null;
            lastAttempt = now;
            Interlocked.Increment(ref fetches);
            inflight = Task.Run(() => FetchAsync(deadline));
            return inflight;
        }
    }

    private async Task FetchAsync(TimeSpan deadline)
    {
        string failure;
        try
        {
            using var timeout = new CancellationTokenSource(deadline);
            var client = clients!.CreateClient(ClientName);
            using var request = new HttpRequestMessage(HttpMethod.Get, settings.JwksUrl);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/jwk-set+json"));
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
            if (response.StatusCode != HttpStatusCode.OK)
            {
                failure = "status " + (int)response.StatusCode;
            }
            else if (response.Content.Headers.ContentLength is > MaxBytes)
            {
                failure = "too large";
            }
            else
            {
                var body = await ReadAsync(response.Content, timeout.Token);
                var keys = body is null ? null : Parse(body);
                if (body is null) failure = "too large";
                else if (keys is null) failure = "not a JWK set";
                else if (keys.Count == 0) failure = "no usable key";
                else
                {
                    lock (gate) current = (keys, time.GetUtcNow());
                    return;
                }
            }
        }
        catch (OperationCanceledException)
        {
            failure = "timeout";
        }
        catch (HttpRequestException)
        {
            failure = "network";
        }
        catch (Exception)
        {
            // Anything else (I/O, a handler bug) is a failed fetch too: never an exception for the request.
            failure = "transport";
        }
        // The configured URL is public; the answer is never logged.
        logger.LogError("Sentomaru verifier: the JWKS fetch failed ({Failure}); the cached keys, if any, keep serving up to {MaxStale}.",
            failure, MaxStale);
    }

    private static async Task<byte[]?> ReadAsync(HttpContent content, CancellationToken cancellationToken)
    {
        await using var stream = await content.ReadAsStreamAsync(cancellationToken);
        var buffer = new byte[MaxBytes + 1];
        var total = 0;
        int read;
        while (total < buffer.Length && (read = await stream.ReadAsync(buffer.AsMemory(total), cancellationToken)) > 0) total += read;
        return total > MaxBytes ? null : buffer[..total];
    }

    /// <summary>The usable keys of a JWK set (keys that are not usable are skipped), or null when it is not a JWK set.</summary>
    public static IReadOnlyList<Jwk>? Parse(byte[] body)
    {
        try
        {
            using var document = JsonDocument.Parse(body, new JsonDocumentOptions { AllowDuplicateProperties = false, MaxDepth = 16 });
            if (document.RootElement.ValueKind != JsonValueKind.Object ||
                !document.RootElement.TryGetProperty("keys", out var keys) || keys.ValueKind != JsonValueKind.Array ||
                keys.GetArrayLength() > MaxKeys)
            {
                return null;
            }
            var usable = new List<Jwk>();
            foreach (var element in keys.EnumerateArray())
            {
                if (Jwk.TryParse(element, out var key, out _)) usable.Add(key!);
            }
            return usable;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static (JwkLookup Result, Jwk? Key) Lookup(IReadOnlyList<Jwk> keys, string kid, string alg)
    {
        var named = keys.Where(k => string.Equals(k.Kid, kid, StringComparison.Ordinal)).ToList();
        if (named.Count == 0) return (JwkLookup.KidUnknown, null);
        var fitting = named.Where(k => k.Fits(alg)).ToList();
        return fitting.Count switch
        {
            0 => (JwkLookup.AlgMismatch, null),
            1 => (JwkLookup.Found, fitting[0]),
            // Two keys with the same kid that both fit: ambiguous, refused (never "try each", never a refresh).
            _ => (JwkLookup.KidAmbiguous, null),
        };
    }
}
