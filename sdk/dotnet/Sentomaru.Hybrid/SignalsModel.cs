namespace Sentomaru.Hybrid;

/// <summary>
/// D-20 scope of the screen-capture callback (<c>ScreenShield</c> on Android): <see cref="Marked"/> (the approved default) watches only
/// the screens the app lists; <see cref="All"/> (opt-in, needs the privacy review of the scope-all ficha) also counts a capture with an
/// unmarked screen in front, apart, in <c>captures_other</c>. It changes what is observed, never what is protected.
/// </summary>
public enum CaptureScope { Marked, All }

/// <summary>
/// What a host app gives the native side to install the screen shield (Android; Application.onCreate on the native side, once). The
/// native entry is <c>br.com.ebees.sentomaru.signals.ScreenShieldHost.install(Application, String[], String)</c>: plain types, so
/// Unity's AndroidJavaClass and a .NET for Android binding reach it. The scope travels as its lower-case name.
/// </summary>
public sealed record ScreenShieldOptions(IReadOnlyList<string> MarkedActivities, CaptureScope Scope = CaptureScope.Marked)
{
    public const string NativeClass = "br.com.ebees.sentomaru.signals.ScreenShieldHost";
    public const string NativeMethod = "install";

    public string ScopeName => Scope switch
    {
        CaptureScope.Marked => "marked",
        CaptureScope.All => "all",
        _ => throw new ArgumentOutOfRangeException(nameof(Scope)),
    };

    /// <summary>Arguments after the Application: the marked Activity class names (fully qualified, no blank) and the scope name.</summary>
    public (string[] MarkedActivities, string Scope) ToNativeArguments()
    {
        if (MarkedActivities is null) throw new ArgumentException("MarkedActivities is required", nameof(MarkedActivities));
        foreach (var name in MarkedActivities)
            if (string.IsNullOrWhiteSpace(name)) throw new ArgumentException("an Activity class name is blank", nameof(MarkedActivities));
        return (MarkedActivities.ToArray(), ScopeName);
    }
}

/// <summary>The signals catalog this binding was written against (contracts/sdk/signals-catalog-v1.json); a test keeps these equal to it.</summary>
public static class SignalsCatalogInfo
{
    public const string Version = "1.15.0";
    public const string ScreenCaptureVersion = "1.1.0";
}

public enum SignalState { Detected, NotDetected, Unknown, Unsupported, Error }

/// <summary>One observation as <c>collectSignalsSnapshot</c> replies (hybrid-bridge-v1): <c>data</c> is the detail, fixed codes only.</summary>
public sealed record SignalObservation(string CapabilityId, string Version, SignalState State, string Source, string ObservedAt,
    IReadOnlyDictionary<string, string> Data);

public sealed record SignalsSnapshot(string CollectedAt, long DurationMs, IReadOnlyList<SignalObservation> Observations)
{
    public SignalObservation? Find(string capabilityId) => Observations.FirstOrDefault(o => o.CapabilityId == capabilityId);
}

/// <summary><c>screen_capture</c> 1.1.0 detail. <see cref="CapturesOther"/> is null unless the app installed the shield with scope <c>all</c>.</summary>
public sealed record ScreenCaptureDetail(string Result, int Captures, int? CapturesOther)
{
    public const int MaxReported = 9;
}

public static class SignalsReader
{
    /// <summary>Reads the map <c>collectSignalsSnapshot</c> returns. Strict: a missing field, an unknown state or a non-text detail is a ChannelError, never a default.</summary>
    public static SignalsSnapshot ReadSnapshot(IReadOnlyDictionary<string, object?> reply)
    {
        var observations = new List<SignalObservation>();
        foreach (var raw in Get<IEnumerable<object?>>(reply, "observations"))
        {
            var o = raw as IReadOnlyDictionary<string, object?> ?? throw Bad("observation is not a map");
            var data = new Dictionary<string, string>();
            if (o.TryGetValue("data", out var detail) && detail is not null)
            {
                var map = detail as IReadOnlyDictionary<string, object?> ?? throw Bad("data is not a map");
                foreach (var (key, value) in map) data[key] = value as string ?? throw Bad($"data.{key} is not text");
            }
            observations.Add(new SignalObservation(Get<string>(o, "capabilityId"), Get<string>(o, "version"), State(Get<string>(o, "state")),
                Get<string>(o, "source"), Get<string>(o, "observedAt"), data));
        }
        return new SignalsSnapshot(Get<string>(reply, "collectedAt"), Duration(Get<object>(reply, "durationMs")), observations);
    }

    /// <summary>The typed detail of a <c>screen_capture</c> observation, or null when the state carries none (unknown/unsupported/error without result).</summary>
    public static ScreenCaptureDetail? ReadScreenCapture(SignalObservation observation)
    {
        if (observation.CapabilityId != "screen_capture") throw Bad("not a screen_capture observation");
        if (!observation.Data.TryGetValue("result", out var result)) return null;
        if (result is not ("captured" or "none" or "no_screens" or "timeout")) throw Bad($"unknown screen_capture result '{result}'");
        return new ScreenCaptureDetail(result, Count(observation.Data, "captures") ?? 0, Count(observation.Data, "captures_other"));
    }

    private static int? Count(IReadOnlyDictionary<string, string> data, string key)
    {
        if (!data.TryGetValue(key, out var text)) return null;
        if (!int.TryParse(text, out var n) || n < 0 || n > ScreenCaptureDetail.MaxReported || text != n.ToString()) throw Bad($"{key} is not a count 0..{ScreenCaptureDetail.MaxReported}");
        return n;
    }

    /// <summary>A whole, non-negative number as a JSON reader may hand it over (integer types, or a double with no fraction); text, bool or anything else is a ChannelError.</summary>
    private static long Duration(object value)
    {
        long n = value switch
        {
            byte or sbyte or short or ushort or int or uint or long => Convert.ToInt64(value),
            double d when d == Math.Floor(d) && d >= 0 && d < 9e15 => (long)d,
            _ => throw Bad("durationMs is not a whole number"),
        };
        return n >= 0 ? n : throw Bad("durationMs is negative");
    }

    private static SignalState State(string text) => text switch
    {
        "detected" => SignalState.Detected, "not_detected" => SignalState.NotDetected, "unknown" => SignalState.Unknown,
        "unsupported" => SignalState.Unsupported, "error" => SignalState.Error,
        _ => throw Bad($"unknown state '{text}'"),
    };

    private static T Get<T>(IReadOnlyDictionary<string, object?> map, string key) =>
        map.TryGetValue(key, out var value) && value is T typed ? typed : throw Bad($"missing or wrong type: {key}");

    private static SentomaruException Bad(string message) => new("ChannelError", "signals: " + message);
}
