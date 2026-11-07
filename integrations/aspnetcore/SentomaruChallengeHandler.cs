using Microsoft.AspNetCore.Http;

namespace Sentomaru.AspNetCore;

/// <summary>
/// 4.5.0 (D-06b): the kind of a <c>challenge</c> verdict (contract v1.9, <c>challengeKind</c>) as the adapter knows it.
/// <see cref="Unknown"/> is a kind this adapter version does not know (4.6.0 knows <c>reattest</c>, D-06h): the raw value stays
/// readable (<see cref="EvaluationResponseDto.ChallengeKind"/>, the 401 body, <see cref="SentomaruObservation.ChallengeKind"/>),
/// and it never calls the step-up hook.
/// </summary>
public enum SentomaruChallengeKind
{
    /// <summary>No kind: the challenging rule declares none, another verdict, or a Sentomaru older than v1.9.</summary>
    None,
    FreshSignals,
    StepUp,

    /// <summary>A kind newer than this adapter: answered as 4.4.0 (401 <c>challenge-required</c>) with the raw kind.</summary>
    Unknown,

    /// <summary>4.6.0 (D-06h): the policy asks for a recent passed reattestation. Sentomaru checks it on the next
    /// evaluation, after the app reattests; the step-up hook never runs for it. Declared after <see cref="Unknown"/> so
    /// the 4.5.0 values keep their numbers.</summary>
    Reattest
}

/// <summary>
/// 4.5.0 (D-06b): the kinds of a <c>challenge</c> verdict known to this adapter. A kind outside them is not dropped: it
/// is read as <see cref="SentomaruChallengeKind.Unknown"/> and passed through raw, so a consumer sees a new kind
/// without a new adapter version.
/// </summary>
public static class SentomaruChallengeKinds
{
    /// <summary>The finding goes away with a new signed snapshot; Sentomaru checks it on the next request.</summary>
    public const string FreshSignals = "fresh_signals";

    /// <summary>The consumer asks the user for a reauthentication or confirmation. Sentomaru does not verify it.</summary>
    public const string StepUp = "step_up";

    /// <summary>4.6.0 (D-06h): the app runs <c>reattest()</c> (the D-12b reattestation) and repeats the operation once with
    /// a new nonce; Sentomaru checks the result on that next evaluation. Not the consumer's to verify: the
    /// <see cref="ISentomaruChallengeHandler"/> is never called for it.</summary>
    public const string Reattest = "reattest";

    /// <summary>4.6.0 (D-06h): the closed set of kinds this adapter knows, in contract order (v1.10).</summary>
    public static readonly IReadOnlyList<string> Closed = Array.AsReadOnly([FreshSignals, StepUp, Reattest]);

    /// <summary>The known kind of a value as the server sent it: <see cref="SentomaruChallengeKind.None"/> for null or
    /// empty, the known kind for <see cref="FreshSignals"/>, <see cref="StepUp"/> and <see cref="Reattest"/> (exact), and
    /// <see cref="SentomaruChallengeKind.Unknown"/> for anything else, a malformed value included (it is a kind, just
    /// not one this adapter knows; only <see cref="Raw"/> decides what goes into a response).</summary>
    public static SentomaruChallengeKind Parse(string? value) => value switch
    {
        null or "" => SentomaruChallengeKind.None,
        FreshSignals => SentomaruChallengeKind.FreshSignals,
        StepUp => SentomaruChallengeKind.StepUp,
        Reattest => SentomaruChallengeKind.Reattest,
        _ => SentomaruChallengeKind.Unknown
    };

    /// <summary>
    /// The raw kind as the adapter passes it on (401 body, observation): the server's value when it is a kind token
    /// (lowercase letter, then up to 31 lowercase letters, digits or <c>_</c>, as the policy's closed sets), otherwise
    /// null. The guard keeps a malformed or oversized value out of the app's response; it never drops a well-formed
    /// kind, known or not.
    /// </summary>
    public static string? Raw(string? value) => value is { Length: >= 1 and <= 32 } && IsToken(value) ? value : null;

    private static bool IsToken(string value)
    {
        if (value[0] is < 'a' or > 'z') return false;
        foreach (var c in value)
            if (c is not ((>= 'a' and <= 'z') or (>= '0' and <= '9') or '_')) return false;
        return true;
    }
}

/// <summary>4.5.0 (D-06b): what an <see cref="ISentomaruChallengeHandler"/> answers.</summary>
public enum SentomaruChallengeDecision
{
    /// <summary>Default, as in 4.4.0: 401 <c>challenge-required</c>.</summary>
    Refuse,

    /// <summary>The consumer already did the step-up in its own session: the action runs.</summary>
    Proceed
}

/// <summary>
/// 4.5.0 (D-06b): what the filter passes to the hook. <see cref="ReasonCodes"/> are the policy's codes of the verdict. A
/// request with a signed operation id never reaches the hook.
/// </summary>
public sealed record SentomaruChallengeContext(
    string Operation,
    string ChallengeKind,
    IReadOnlyList<string> ReasonCodes,
    HttpContext HttpContext);

/// <summary>
/// 4.5.0 (D-06b): optional consumer hook for a <c>challenge</c> verdict of kind <c>step_up</c> (never for
/// <c>reattest</c>, which Sentomaru checks itself, nor for a kind this adapter does not know). Register it in DI; without
/// it the filter behaves as 4.4.0 (401 <c>challenge-required</c>, now with <c>challengeKind</c> in the body).
/// <para>Called only in <see cref="DeviceAssuranceLevel.ZeroTrust"/>, only for <c>challenge</c> with
/// <c>challengeKind: step_up</c>; never for <c>deny</c>, <c>fresh_signals</c>, <c>reattest</c>, an unknown kind, a challenge without a kind, nor in
/// <see cref="DeviceAssuranceLevel.Observe"/>. Sentomaru does not verify the step-up and keeps no step-up state: the
/// hook is where the consumer checks its own session ("reauthenticated in the last N minutes"), otherwise the next request
/// is challenged again. Returning <see cref="SentomaruChallengeDecision.Refuse"/>, throwing, or a request with a signed
/// operation id (the hook is not called: Sentomaru records only an allow, so a challenge that proceeded would have no
/// single effect) all answer 401 <c>challenge-required</c>. After a Proceed, the observation in
/// <see cref="SentomaruIntegrityAttribute.ObservationItem"/> still says <c>challenge</c> and
/// <see cref="SentomaruIntegrityAttribute.StepUpProceededItem"/> is true.</para>
/// </summary>
public interface ISentomaruChallengeHandler
{
    ValueTask<SentomaruChallengeDecision> HandleAsync(SentomaruChallengeContext challenge, CancellationToken cancellationToken);
}
