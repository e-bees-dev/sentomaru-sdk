using System.Text.Json.Serialization;

namespace Sentomaru.AspNetCore;

/// <summary>
/// 4.16.0 (WS-F, contracts/web/web-evaluation-v1.md): the closed catalog of web signal ids the route accepts. The server refuses an id outside it.
/// </summary>
public static class SentomaruWebSignals
{
    public const string SessionKeyMissing = "WEB_SESSION_KEY_MISSING";
    public const string SessionKeyNewForAccount = "WEB_SESSION_KEY_NEW_FOR_ACCOUNT";
    public const string CookieReplayNoProof = "WEB_COOKIE_REPLAY_NO_PROOF";
    public const string ClientHintMismatch = "WEB_CLIENT_HINT_MISMATCH";
    public const string ChallengeResult = "WEB_CHALLENGE_RESULT";

    public static IReadOnlyList<string> Closed { get; } =
        [SessionKeyMissing, SessionKeyNewForAccount, CookieReplayNoProof, ClientHintMismatch, ChallengeResult];
}

/// <summary>4.16.0: the three states a backend can declare for a web signal. A signal the body does not carry is read as UNKNOWN, never as clean.</summary>
public static class SentomaruWebSignalStates
{
    public const string Detected = "DETECTED";
    public const string NotDetected = "NOT_DETECTED";
    public const string Unknown = "UNKNOWN";
}

/// <summary>4.16.0: one declared web signal. A DECLARATION by the consumer's backend: it can be forged or suppressed, and Sentomaru never takes it as proof.</summary>
public sealed record WebSignalDto
{
    [JsonPropertyName("signalId")]
    public required string SignalId { get; init; }

    [JsonPropertyName("state")]
    public required string State { get; init; }
}

/// <summary>
/// 4.16.0: body of <c>POST /v1/{org}/{app}/{env}/web/evaluations</c>. The server reads it strictly (all or nothing): <see cref="Operation"/> matches
/// <c>[a-z0-9._-]{1,64}</c>, at most 16 signals, no other member, no free text. Nothing about the user, the session, the cookie, the IP or the
/// User-Agent can be carried, so none of it is sent.
/// </summary>
public sealed record WebEvaluationRequestDto
{
    [JsonPropertyName("operation")]
    public required string Operation { get; init; }

    [JsonPropertyName("signals")]
    public required IReadOnlyList<WebSignalDto> Signals { get; init; }
}

/// <summary>
/// 4.16.0: the advisory answer of the scope's active <c>channel: web</c> policy. <see cref="Advisory"/> is always true and <see cref="Mode"/> always
/// "shadow". <see cref="Recommendation"/> is never "challenge" nor "deny": read <see cref="EvaluatedAction"/> for what the rules would say, and decide
/// yourself. A scope with no web policy answers <c>policyId</c> null, "defer" and the reason code WEB_POLICY_NONE.
/// </summary>
public sealed record WebEvaluationResponseDto
{
    [JsonPropertyName("advisory")]
    public bool Advisory { get; init; }

    [JsonPropertyName("policyId")]
    public string? PolicyId { get; init; }

    [JsonPropertyName("policyVersion")]
    public string? PolicyVersion { get; init; }

    [JsonPropertyName("policyDigest")]
    public string? PolicyDigest { get; init; }

    [JsonPropertyName("mode")]
    public string? Mode { get; init; }

    [JsonPropertyName("recommendation")]
    public string? Recommendation { get; init; }

    [JsonPropertyName("evaluatedAction")]
    public string? EvaluatedAction { get; init; }

    [JsonPropertyName("rulesMatched")]
    public IReadOnlyList<string> RulesMatched { get; init; } = [];

    [JsonPropertyName("reasonCodes")]
    public IReadOnlyList<string> ReasonCodes { get; init; } = [];

    [JsonPropertyName("observedRules")]
    public IReadOnlyList<string> ObservedRules { get; init; } = [];
}

/// <summary>4.16.0: builds the request in the form the server accepts, so a consumer cannot send a body the route refuses for format.</summary>
public static class SentomaruWeb
{
    private const int MaxSignals = 16;

    /// <summary>
    /// Builds a request from <paramref name="operation"/> and the signals the backend observed. Returns null when the operation is not
    /// <c>[a-z0-9._-]{1,64}</c>, a signal id is outside the closed catalog, a state is not one of the three, or a signal repeats: the server would answer
    /// 400 web-evaluation-format for the whole body, so nothing is sent. A signal not listed is read by the server as UNKNOWN (never as clean).
    /// </summary>
    public static WebEvaluationRequestDto? TryBuild(string operation, IEnumerable<(string SignalId, string State)> signals)
    {
        ArgumentNullException.ThrowIfNull(signals);
        if (!ValidOperation(operation)) return null;
        var list = new List<WebSignalDto>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var (id, state) in signals)
        {
            if (list.Count == MaxSignals) return null;
            if (!SentomaruWebSignals.Closed.Contains(id) || !ValidState(state) || !seen.Add(id)) return null;
            list.Add(new WebSignalDto { SignalId = id, State = state });
        }
        return new WebEvaluationRequestDto { Operation = operation, Signals = list };
    }

    private static bool ValidState(string? state) =>
        state is SentomaruWebSignalStates.Detected or SentomaruWebSignalStates.NotDetected or SentomaruWebSignalStates.Unknown;

    private static bool ValidOperation(string? operation)
    {
        if (string.IsNullOrEmpty(operation) || operation.Length > 64) return false;
        foreach (var c in operation)
            if (!(c is >= 'a' and <= 'z' || c is >= '0' and <= '9' || c is '.' or '_' or '-')) return false;
        return true;
    }
}
