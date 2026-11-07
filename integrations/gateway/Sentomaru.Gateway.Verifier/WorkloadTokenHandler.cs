using System.Net.Http.Headers;

namespace Sentomaru.Gateway.Verifier;

/// <summary>
/// Puts the verifier's workload bearer (credential <c>kind</c> <c>gateway-verifier</c>, D-17x5) on every call to Sentomaru, read
/// from <see cref="SentomaruConfig.WorkloadTokenFile"/>, the file the customer's vault agent renders. The file is read
/// again when its identity changes (review R I-2: the final target of a symbolic link, its write time and its size, so a
/// Kubernetes/CSI secret that swaps the <c>..data</c> link, or a write still in progress, is seen) and in any case at
/// most <see cref="DefaultRefresh"/> after the last read. The token is never logged; a missing, empty or malformed file at
/// runtime fails the call as an outage (503 <c>store-unavailable</c>, fail closed), never as an anonymous call.
/// </summary>
public sealed class WorkloadTokenHandler : DelegatingHandler
{
    /// <summary>Longest time a token read from the file is used without reading the file again.</summary>
    public static readonly TimeSpan DefaultRefresh = TimeSpan.FromSeconds(30);

    private readonly string path;
    private readonly TimeSpan refresh;
    private readonly TimeProvider clock;
    private readonly Lock gate = new();
    private (string Target, DateTime Written, long Length)? key;
    private DateTimeOffset readAt = DateTimeOffset.MinValue;
    private string? token;

    public WorkloadTokenHandler(string path, TimeSpan? refresh = null, TimeProvider? clock = null)
    {
        this.path = path;
        this.refresh = refresh ?? DefaultRefresh;
        this.clock = clock ?? TimeProvider.System;
    }

    /// <summary>The token in the file (trimmed), or null when the file is missing, unreadable, empty or not one token of
    /// visible ASCII.</summary>
    internal static string? ReadToken(string path)
    {
        try
        {
            var value = File.ReadAllText(path).Trim();
            return value.Length == 0 || value.Any(c => c is < '!' or > '~') ? null : value;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return null;
        }
    }

    /// <summary>The real file (every link in the path followed, directories included), its write time and size; null when
    /// it cannot be read.</summary>
    private (string, DateTime, long)? Identity()
    {
        try
        {
            var target = new FileInfo(RealPath(path));
            return target.Exists ? (target.FullName, target.LastWriteTimeUtc, target.Length) : null;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return null;
        }
    }

    /// <summary>
    /// The path with every symbolic link resolved, component by component (a Kubernetes secret is
    /// <c>token -&gt; ..data/token</c> with <c>..data -&gt; ..2026_10_28_…</c>; only the directory link changes).
    /// </summary>
    internal static string RealPath(string path, int depth = 0)
    {
        // A link target may itself go through links (the file link points into the directory link): resolved again,
        // up to a bound (a loop is an unreadable file).
        if (depth > 32) throw new IOException("too many levels of symbolic links");
        var full = Path.GetFullPath(path);
        var root = Path.GetPathRoot(full) ?? "/";
        var current = root;
        foreach (var part in full[root.Length..].Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries))
        {
            var next = Path.Combine(current, part);
            FileSystemInfo info = Directory.Exists(next) ? new DirectoryInfo(next) : new FileInfo(next);
            current = info.LinkTarget is null ? next : RealPath(info.ResolveLinkTarget(returnFinalTarget: false)!.FullName, depth + 1);
        }
        return current;
    }

    internal string? Current()
    {
        var identity = Identity();
        var now = clock.GetUtcNow();
        lock (gate)
        {
            if (token is null || identity is null || identity != key || now - readAt >= refresh)
            {
                token = identity is null ? null : ReadToken(identity.Value.Item1);
                key = identity;
                readAt = now;
            }
            return token;
        }
    }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        // HttpRequestException is what SentomaruClient treats as an outage (503 store-unavailable); the message names
        // no secret.
        var bearer = Current() ?? throw new HttpRequestException("the workload token file is missing, unreadable or empty");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        return base.SendAsync(request, cancellationToken);
    }
}
