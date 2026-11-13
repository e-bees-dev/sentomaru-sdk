namespace Sentomaru.Hybrid;

/// <summary>
/// D-22, revisor A rodada 2 (médio A): contracts/sdk/hybrid-bridge-v1.json's "Security rule" note - `allowedHosts`,
/// `enrollmentUrl` and `renewalUrl` come from the channel, i.e. from the app's own JavaScript/XAML/Blazor code
/// calling `initialize`, which on a WebView-hosted page is not guaranteed to be the app's own content. The Kotlin
/// (<c>InitializeSecurityLock</c>, sdk/hybrid-core) and Swift (<c>HybridBridge.securityRefusal</c>,
/// sdk/ios-hybrid-core) dispatchers already enforce this; this class is the same rule for whoever writes the .NET
/// MAUI/Xamarin platform adapter (binding/JNI, "a separate, untested-here layer" per Sentomaru.Hybrid.csproj - this
/// project stays platform-neutral, so the rule lives here as something that adapter calls, not as a dispatcher it
/// would have to reimplement). <see cref="LockingNativeSentomaru"/> is the ready-to-use wrapper around it.
///
/// The first accepted `initialize` locks the three fields for the life of this instance. A later `initialize` may
/// only narrow `allowedHosts` (never grow it) and must repeat `enrollmentUrl`/`renewalUrl` unchanged (including
/// staying absent, for `renewalUrl`); anything else throws `ConfigurationError`, the same stable code a malformed
/// argument already uses.
/// </summary>
public sealed class InitializeSecurityLock
{
    private readonly HashSet<string> _allowedHosts;
    private readonly string _enrollmentUrl;
    private readonly string? _renewalUrl;

    private InitializeSecurityLock(HashSet<string> allowedHosts, string enrollmentUrl, string? renewalUrl)
    {
        _allowedHosts = allowedHosts;
        _enrollmentUrl = enrollmentUrl;
        _renewalUrl = renewalUrl;
    }

    /// <summary>
    /// Reads the three fields off one `initialize` call's arguments, exactly as <see cref="SentomaruSdk.InitializeAsync"/>
    /// already typed them before building the args map (`allowedHosts` an <c>IReadOnlyList&lt;string&gt;</c>,
    /// `enrollmentUrl` a non-blank <c>string</c>, `renewalUrl` a <c>string?</c>). A caller going straight through
    /// <see cref="INativeSentomaru"/> with a differently-shaped `args` map gets `ConfigurationError` here too - the
    /// adapter's own job to catch earlier, but never a silent pass-through.
    /// </summary>
    private static (HashSet<string> Hosts, string EnrollmentUrl, string? RenewalUrl) Read(IReadOnlyDictionary<string, object?> args)
    {
        if (!args.TryGetValue("allowedHosts", out var rawHosts) || rawHosts is not IReadOnlyList<string> hosts || hosts.Count == 0)
            throw new SentomaruException("ConfigurationError", "initialize: allowedHosts");
        if (!args.TryGetValue("enrollmentUrl", out var rawUrl) || rawUrl is not string enrollmentUrl || string.IsNullOrWhiteSpace(enrollmentUrl))
            throw new SentomaruException("ConfigurationError", "initialize: enrollmentUrl");
        var renewalUrl = args.TryGetValue("renewalUrl", out var rawRenewal) ? rawRenewal as string : null;
        return (new HashSet<string>(hosts), enrollmentUrl, renewalUrl);
    }

    /// <summary>Validates `args`' shape alone (see <see cref="Read"/>) without locking anything: for a first
    /// `initialize`, before anything is locked, so a malformed first call is still refused before it ever reaches
    /// the real adapter, same as a second one refused by <see cref="CheckSubsequentCall"/>.</summary>
    public static void Validate(IReadOnlyDictionary<string, object?> args) => Read(args);

    /// <summary>The lock of the first accepted `initialize`: call once, after that call's own native build succeeds
    /// (a config that fails to build, rather than one refused for being malformed, must not permanently lock the
    /// adapter to it - same reasoning as the Swift side's `lockSecurityAfterSuccess`).</summary>
    public static InitializeSecurityLock FromFirstCall(IReadOnlyDictionary<string, object?> args)
    {
        var (hosts, enrollmentUrl, renewalUrl) = Read(args);
        return new InitializeSecurityLock(hosts, enrollmentUrl, renewalUrl);
    }

    /// <summary>Throws `ConfigurationError` when `args` (a later `initialize`) would widen `allowedHosts` or change
    /// `enrollmentUrl`/`renewalUrl` from what the first accepted call locked in; otherwise returns.</summary>
    public void CheckSubsequentCall(IReadOnlyDictionary<string, object?> args)
    {
        var (hosts, enrollmentUrl, renewalUrl) = Read(args);
        if (!hosts.IsSubsetOf(_allowedHosts) || enrollmentUrl != _enrollmentUrl || renewalUrl != _renewalUrl)
            throw new SentomaruException("ConfigurationError", "initialize: allowedHosts/enrollmentUrl/renewalUrl changed after the first call");
    }
}

/// <summary>
/// Wraps any real <see cref="INativeSentomaru"/> adapter and enforces <see cref="InitializeSecurityLock"/> before
/// forwarding `initialize`, so the .NET side is never the one layer that trusts whatever page content calls it a
/// second time - the attacker-chosen configuration never reaches the wrapped adapter, let alone spends anything
/// there. Every other method passes straight through, unchanged.
/// </summary>
public sealed class LockingNativeSentomaru : INativeSentomaru
{
    private readonly INativeSentomaru _inner;
    private readonly object _gate = new();
    private InitializeSecurityLock? _lock;

    public LockingNativeSentomaru(INativeSentomaru inner) => _inner = inner ?? throw new ArgumentNullException(nameof(inner));

    public async Task<object?> CallAsync(string method, IReadOnlyDictionary<string, object?> args, CancellationToken cancellationToken = default)
    {
        if (method != "initialize") return await _inner.CallAsync(method, args, cancellationToken).ConfigureAwait(false);

        InitializeSecurityLock? current;
        lock (_gate) { current = _lock; }
        // Either branch throws ConfigurationError before `_inner` is ever called.
        if (current is null) InitializeSecurityLock.Validate(args);
        else current.CheckSubsequentCall(args);

        var result = await _inner.CallAsync(method, args, cancellationToken).ConfigureAwait(false);
        if (current is null)
        {
            lock (_gate) { _lock ??= InitializeSecurityLock.FromFirstCall(args); }
        }
        return result;
    }
}
