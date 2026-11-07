namespace Sentomaru.Hybrid;

/// <summary>
/// What every text-channel adapter (Unity JNI, .NET for Android binding) does around the one native entry, written once so it is tested here
/// and the adapter stays thin: bytes become Base64 on the way in (<c>sign.body</c>) and the Base64 of <c>sealedLoad</c> becomes bytes on the
/// way out, a reply is <c>{value}</c> or an error <c>{code, message}</c>, and an error without a stable code is a <c>ChannelError</c>
/// (contracts/sdk/hybrid-bridge-v1.json, "notes"). No method, no default, no retry.
/// </summary>
public static class BridgeEnvelope
{
    /// <summary>The arguments for a text channel: a <c>byte[]</c> goes as Base64 text; everything else is untouched.</summary>
    public static IReadOnlyDictionary<string, object?> EncodeArguments(IReadOnlyDictionary<string, object?> args)
    {
        var map = new Dictionary<string, object?>(args.Count);
        foreach (var (name, value) in args) map[name] = value is byte[] bytes ? Convert.ToBase64String(bytes) : value;
        return map;
    }

    /// <summary>Unwraps the reply of <paramref name="method"/>: the value (bytes for <c>sealedLoad</c>), or throws the SDK's error.</summary>
    public static object? Decode(string method, IReadOnlyDictionary<string, object?>? reply)
    {
        if (reply is null) throw new SentomaruException("ChannelError", $"{method}: empty native reply");
        // Both keys is neither a value nor an error: reading it as the value would swallow the error code (a native side that serializes
        // `{value: null, code: "X"}`), reading it as the error would drop a value. Never defaulted.
        if (reply.ContainsKey("code") && reply.ContainsKey("value")) throw new SentomaruException("ChannelError", $"{method}: native reply has both value and code");
        if (reply.TryGetValue("code", out var code))
        {
            var text = code as string;
            var message = reply.TryGetValue("message", out var m) ? m as string : null;
            throw new SentomaruException(string.IsNullOrEmpty(text) ? "ChannelError" : text, message);
        }
        if (!reply.TryGetValue("value", out var value)) throw new SentomaruException("ChannelError", $"{method}: native reply has neither value nor code");
        if (method != "sealedLoad") return value;
        if (value is byte[]) return value;
        return CanonicalBase64(value as string) ?? throw new SentomaruException("ChannelError", "sealedLoad: reply is not canonical Base64 bytes");
    }

    /// <summary>
    /// The bytes of RFC 4648 section 4 Base64 text, or null. Canonical only, the one text a writer produces for those bytes: standard
    /// alphabet, padding present, no whitespace anywhere, no non-zero trailing bits. <c>Convert.FromBase64String</c> alone ignores
    /// whitespace; the iOS side is already canonical-only.
    /// </summary>
    public static byte[]? CanonicalBase64(string? text)
    {
        if (text is null) return null;
        try
        {
            var bytes = Convert.FromBase64String(text);
            return Convert.ToBase64String(bytes) == text ? bytes : null;
        }
        catch (FormatException) { return null; }
    }
}
