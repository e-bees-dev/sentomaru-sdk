namespace Sentomaru.Hybrid;

/// <summary>
/// The single native entry of the layer (D-22a/b/c): a method name of contracts/sdk/hybrid-bridge-v1.json and its arguments by the
/// contract's names. A platform adapter (.NET for Android binding, Unity JNI) implements it; it answers the value of the call or throws
/// <see cref="SentomaruException"/> with the stable code. Byte arrays cross as <c>byte[]</c> (the adapter converts if its channel is text).
/// </summary>
public interface INativeSentomaru
{
    Task<object?> CallAsync(string method, IReadOnlyDictionary<string, object?> args, CancellationToken cancellationToken = default);
}

/// <summary>An error of the SDK or of the bridge, with the stable <see cref="Code"/> of hybrid-bridge-v1.</summary>
public sealed class SentomaruException : Exception
{
    public string Code { get; }
    public SentomaruException(string code, string? message = null, Exception? inner = null) : base(message ?? code, inner) => Code = code;
}

/// <summary>
/// One method per method of hybrid-bridge-v1 (name + "Async"), parameters named exactly as the contract's arguments, in its order. It adds
/// no method, no default value and no retry: an omitted option goes as null. A native failure with a stable code keeps it; anything else is
/// a <c>ChannelError</c>. ContractTests drives this class from the contract JSON.
/// </summary>
public sealed class SentomaruSdk
{
    private readonly INativeSentomaru _native;
    public SentomaruSdk(INativeSentomaru native) => _native = native ?? throw new ArgumentNullException(nameof(native));

    private async Task<object?> Call(string method, CancellationToken ct, params (string Name, object? Value)[] args)
    {
        var map = new Dictionary<string, object?>(args.Length);
        foreach (var (name, value) in args) map[name] = value;
        try { return await _native.CallAsync(method, map, ct).ConfigureAwait(false); }
        catch (SentomaruException) { throw; }
        catch (OperationCanceledException) { throw; }
        catch (Exception e) { throw new SentomaruException("ChannelError", e.Message, e); }
    }

    private static T As<T>(object? value, string method) =>
        value is T typed ? typed : throw new SentomaruException("ChannelError", $"{method}: unexpected native reply");
    private static string? AsStringOrNull(object? value, string method) =>
        value is null ? null : value as string ?? throw new SentomaruException("ChannelError", $"{method}: unexpected native reply");

    public async Task InitializeAsync(string organization, string app, string environment, string enrollmentUrl, IReadOnlyList<string> allowedHosts,
        int? rotationGracePeriodDays = null, long? playIntegrityCloudProjectNumber = null, string? renewalUrl = null, string? reattestationChallengeUrl = null,
        string? reattestationSubmitUrl = null, int? reattestationMinIntervalSeconds = null, CancellationToken cancellationToken = default)
        => await Call("initialize", cancellationToken, (nameof(organization), organization), (nameof(app), app), (nameof(environment), environment),
            (nameof(enrollmentUrl), enrollmentUrl), (nameof(allowedHosts), allowedHosts), (nameof(rotationGracePeriodDays), rotationGracePeriodDays),
            (nameof(playIntegrityCloudProjectNumber), playIntegrityCloudProjectNumber), (nameof(renewalUrl), renewalUrl),
            (nameof(reattestationChallengeUrl), reattestationChallengeUrl), (nameof(reattestationSubmitUrl), reattestationSubmitUrl),
            (nameof(reattestationMinIntervalSeconds), reattestationMinIntervalSeconds)).ConfigureAwait(false);

    public async Task<string> StateAsync(CancellationToken cancellationToken = default) => As<string>(await Call("state", cancellationToken).ConfigureAwait(false), "state");
    public async Task<string?> ReenrollmentReasonAsync(CancellationToken cancellationToken = default) => AsStringOrNull(await Call("reenrollmentReason", cancellationToken).ConfigureAwait(false), "reenrollmentReason");

    public async Task<IReadOnlyDictionary<string, object?>> EnrollAsync(string challenge, bool? strongBox = null, bool? requiresHardware = null, CancellationToken cancellationToken = default)
        => As<IReadOnlyDictionary<string, object?>>(await Call("enroll", cancellationToken, (nameof(challenge), challenge), (nameof(strongBox), strongBox), (nameof(requiresHardware), requiresHardware)).ConfigureAwait(false), "enroll");

    public async Task<IReadOnlyDictionary<string, object?>> RotateAsync(string challenge, bool? strongBox = null, bool? requiresHardware = null, CancellationToken cancellationToken = default)
        => As<IReadOnlyDictionary<string, object?>>(await Call("rotate", cancellationToken, (nameof(challenge), challenge), (nameof(strongBox), strongBox), (nameof(requiresHardware), requiresHardware)).ConfigureAwait(false), "rotate");

    public async Task<IReadOnlyDictionary<string, object?>> SignAsync(string method, string targetUri, string operation, byte[]? body = null,
        IReadOnlyDictionary<string, string>? optional = null, CancellationToken cancellationToken = default)
        => As<IReadOnlyDictionary<string, object?>>(await Call("sign", cancellationToken, (nameof(method), method), (nameof(targetUri), targetUri),
            (nameof(operation), operation), (nameof(body), body), (nameof(optional), optional)).ConfigureAwait(false), "sign");

    public async Task ResetAsync(CancellationToken cancellationToken = default) => await Call("reset", cancellationToken).ConfigureAwait(false);
    public async Task<IReadOnlyList<object?>> CollectSignalsAsync(CancellationToken cancellationToken = default) => As<IReadOnlyList<object?>>(await Call("collectSignals", cancellationToken).ConfigureAwait(false), "collectSignals");

    public async Task<IReadOnlyDictionary<string, object?>> CollectSignalsSnapshotAsync(bool? rasp = null, IReadOnlyList<string>? expectedSignerDigests = null, CancellationToken cancellationToken = default)
        => As<IReadOnlyDictionary<string, object?>>(await Call("collectSignalsSnapshot", cancellationToken, (nameof(rasp), rasp), (nameof(expectedSignerDigests), expectedSignerDigests)).ConfigureAwait(false), "collectSignalsSnapshot");

    public async Task<string?> SessionIdAsync(CancellationToken cancellationToken = default) => AsStringOrNull(await Call("sessionId", cancellationToken).ConfigureAwait(false), "sessionId");
    public async Task<string> RenewSessionAsync(CancellationToken cancellationToken = default) => As<string>(await Call("renewSession", cancellationToken).ConfigureAwait(false), "renewSession");
    public async Task<bool> ReattestationDueAsync(CancellationToken cancellationToken = default) => As<bool>(await Call("reattestationDue", cancellationToken).ConfigureAwait(false), "reattestationDue");

    public async Task<IReadOnlyDictionary<string, object?>> ReattestIfDueAsync(bool? strongBox = null, CancellationToken cancellationToken = default)
        => As<IReadOnlyDictionary<string, object?>>(await Call("reattestIfDue", cancellationToken, (nameof(strongBox), strongBox)).ConfigureAwait(false), "reattestIfDue");

    public async Task<IReadOnlyDictionary<string, object?>> ReattestAsync(bool? strongBox = null, CancellationToken cancellationToken = default)
        => As<IReadOnlyDictionary<string, object?>>(await Call("reattest", cancellationToken, (nameof(strongBox), strongBox)).ConfigureAwait(false), "reattest");

    public async Task SealedConfigureAsync(bool? allowPlainFallback = null, string? plainStringsKey = null, CancellationToken cancellationToken = default)
        => await Call("sealedConfigure", cancellationToken, (nameof(allowPlainFallback), allowPlainFallback), (nameof(plainStringsKey), plainStringsKey)).ConfigureAwait(false);

    public async Task<byte[]> SealedLoadAsync(string key, CancellationToken cancellationToken = default) => As<byte[]>(await Call("sealedLoad", cancellationToken, (nameof(key), key)).ConfigureAwait(false), "sealedLoad");
    public async Task<string> SealedStringAsync(string key, CancellationToken cancellationToken = default) => As<string>(await Call("sealedString", cancellationToken, (nameof(key), key)).ConfigureAwait(false), "sealedString");
}
