using System.Text.Json;
using System.Text.Json.Serialization;

namespace Sentomaru.AspNetCore;

/// <summary>
/// HTTP message forwarded to Sentomaru for RFC 9421 cryptographic proof verification.
/// </summary>
public sealed record ForwardedMessageDto
{
    [JsonPropertyName("method")]
    public required string Method { get; init; }

    [JsonPropertyName("uri")]
    public required string Uri { get; init; }

    [JsonPropertyName("headers")]
    public required Dictionary<string, string[]> Headers { get; init; }

    [JsonPropertyName("body")]
    public required string Body { get; init; }
}

/// <summary>
/// Authenticated caller context derived by the consumer workload.
/// </summary>
public sealed record CallerContextDto
{
    [JsonPropertyName("subject")]
    public required string Subject { get; init; }

    [JsonPropertyName("tenant")]
    public required string Tenant { get; init; }

    /// <summary>
    /// 4.0.0 (C-09, #142): a usable caller context names one caller: both values non-empty and neither one of the
    /// placeholders a resolver falls back to (<c>anonymous</c>, <c>default</c>), which the API refuses with 400
    /// <c>caller-context-reserved</c>. An unusable context is refused by the adapter (403 <c>caller-context-missing</c>)
    /// before Sentomaru is called.
    /// </summary>
    public static bool IsUsable(string? subject, string? tenant) =>
        !string.IsNullOrWhiteSpace(subject) && !string.IsNullOrWhiteSpace(tenant) && !Reserved(subject) && !Reserved(tenant);

    [JsonIgnore]
    public bool Usable => IsUsable(Subject, Tenant);

    /// <summary>Same comparison as the Sentomaru API: after Trim and Unicode compatibility folding (NFKC), any case.</summary>
    internal static bool Reserved(string value)
    {
        var folded = value.Trim().Normalize(System.Text.NormalizationForm.FormKC);
        return folded.Equals("anonymous", StringComparison.OrdinalIgnoreCase) ||
               folded.Equals("default", StringComparison.OrdinalIgnoreCase);
    }
}

/// <summary>
/// Hardware, integrity and behavioral signals snapshot forwarded from the client.
/// </summary>
public sealed record SignalsDto
{
    [JsonPropertyName("captured_at")]
    public string? CapturedAt { get; init; }

    [JsonPropertyName("device_fingerprint")]
    public string? DeviceFingerprint { get; init; }

    [JsonPropertyName("integrity_verdict")]
    public string? IntegrityVerdict { get; init; }

    [JsonPropertyName("risk_score")]
    public double? RiskScore { get; init; }

    [JsonPropertyName("extra_signals")]
    public Dictionary<string, object?>? ExtraSignals { get; init; }
}

/// <summary>
/// Request payload sent to POST /v1/evaluations.
/// </summary>
public sealed record EvaluationRequestDto
{
    [JsonPropertyName("operation")]
    public required string Operation { get; init; }

    [JsonPropertyName("request")]
    public required ForwardedMessageDto Request { get; init; }

    [JsonPropertyName("context")]
    public required CallerContextDto Context { get; init; }

    [JsonPropertyName("signals")]
    public JsonElement? Signals { get; init; }

    /// <summary>
    /// E-06: hex SHA-256 of <c>orgId:appId:idpIssuer:sub:tokenIdentifier</c> of the IdP token of THIS request, computed by
    /// <see cref="SentomaruTokenBinding"/> from the claims of the already authenticated principal. The token never goes to
    /// Sentomaru. Omitted when the binding is not configured or the principal has no usable claims.
    /// </summary>
    [JsonPropertyName("externalTokenBindingHash")]
    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? ExternalTokenBindingHash { get; init; }
}

/// <summary>E-06: registers the binding between a live grant and the hash of the user's IdP token (POST session-bindings).</summary>
public sealed record SessionBindingRequestDto
{
    [JsonPropertyName("installationId")] public required Guid InstallationId { get; init; }
    [JsonPropertyName("grantSessionId")] public required Guid GrantSessionId { get; init; }
    [JsonPropertyName("subjectRef")] public required string SubjectRef { get; init; }
    [JsonPropertyName("externalTokenBindingHash")] public required string ExternalTokenBindingHash { get; init; }
    [JsonPropertyName("idpIssuerSlug")] public required string IdpIssuerSlug { get; init; }
    [JsonPropertyName("maxConcurrentInstallationsPerSubject")]
    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public int? MaxConcurrentInstallationsPerSubject { get; init; }
}

/// <summary>E-06 (IDP-02): the IdP refresh issued another token; the hash changes, no attestation is repeated.</summary>
public sealed record SessionBindingRotationRequestDto
{
    [JsonPropertyName("installationId")] public required Guid InstallationId { get; init; }
    [JsonPropertyName("grantSessionId")] public required Guid GrantSessionId { get; init; }
    [JsonPropertyName("previousHash")] public required string PreviousHash { get; init; }
    [JsonPropertyName("externalTokenBindingHash")] public required string ExternalTokenBindingHash { get; init; }
}

public sealed record SessionBindingResponseDto
{
    [JsonPropertyName("status")] public string? Status { get; init; }
}

/// <summary>
/// How <see cref="SentomaruIntegrityAttribute"/> treats an operation.
/// </summary>
public enum DeviceAssuranceLevel
{
    /// <summary>
    /// Default. The action runs only with a valid proof and an allow/shadow verdict; a missing proof is 401.
    /// </summary>
    ZeroTrust,

    /// <summary>
    /// Telemetry only: PROVIDES NO PROTECTION. The action always runs; when a proof is present it is evaluated
    /// and the verdict is logged, otherwise the request is logged as unprotected. An attacker simply omits the
    /// headers. Never a default; declare it explicitly per operation that is knowingly unprotected.
    /// (Replaces the former RuntimeTrust, which silently let unsigned requests through.)
    /// </summary>
    Observe
}

/// <summary>
/// Decision verdicts returned by the Sentomaru policy engine.
/// </summary>
public enum EvaluationVerdict
{
    Allow,
    Deny,
    Challenge,
    Shadow
}

/// <summary>
/// Full evaluation response from POST /v1/evaluations.
/// </summary>
public sealed record EvaluationResponseDto
{
    [JsonPropertyName("proofStatus")]
    public required string ProofStatus { get; init; }

    [JsonPropertyName("policyStatus")]
    public required string PolicyStatus { get; init; }

    [JsonPropertyName("recommendedAction")]
    public required string RecommendedAction { get; init; }

    [JsonPropertyName("installationId")]
    public Guid InstallationId { get; init; }

    [JsonPropertyName("sessionId")]
    public Guid SessionId { get; init; }

    [JsonPropertyName("subject")]
    public required string Subject { get; init; }

    [JsonPropertyName("tenant")]
    public required string Tenant { get; init; }

    [JsonPropertyName("policyId")]
    public string? PolicyId { get; init; }

    [JsonPropertyName("policyVersion")]
    public string? PolicyVersion { get; init; }

    [JsonPropertyName("policyDigest")]
    public string? PolicyDigest { get; init; }

    /// <summary>
    /// C-09 (#142): <c>published</c> (a policy published for the scope) or <c>default</c> (the built-in fallback of a
    /// scope without an active policy). Null from a Sentomaru older than this field.
    /// </summary>
    [JsonPropertyName("policySource")]
    public string? PolicySource { get; init; }

    [JsonPropertyName("rulesMatched")]
    public IReadOnlyList<string>? RulesMatched { get; init; }

    [JsonPropertyName("reasonCodes")]
    public IReadOnlyList<string>? ReasonCodes { get; init; }

    [JsonPropertyName("shadowMode")]
    public bool? ShadowMode { get; init; }

    [JsonPropertyName("evaluatedAction")]
    public string? EvaluatedAction { get; init; }

    /// <summary>3.1.0 (J-01f): the signed operation id of the request, when the app sent one.</summary>
    [JsonPropertyName("operationId")]
    public string? OperationId { get; init; }

    /// <summary>3.1.0 (J-01f): false when this operation id was already admitted (a retry): the verdict is the first
    /// one and the effect must not be applied again. Null when no operation id was signed.</summary>
    [JsonPropertyName("firstAdmission")]
    public bool? FirstAdmission { get; init; }

    /// <summary>4.5.0 (contract v1.9, D-06a): ids of the matched rules in <c>stage: observe</c> (counted, never in the
    /// recommendation). Null when none, or from a Sentomaru older than this field.</summary>
    [JsonPropertyName("observedRules")]
    public IReadOnlyList<string>? ObservedRules { get; init; }

    /// <summary>4.5.0 (contract v1.9, D-06a): the kind of a <c>challenge</c> recommendation (<c>fresh_signals</c> or
    /// <c>step_up</c>, or a newer kind such as <c>reattest</c>), raw, as sent. Null when the challenging rule declares
    /// none, or on another verdict. Not sanitized: the filter passes on only <see cref="SentomaruChallengeKinds.Raw"/>
    /// of it. <see cref="KnownChallengeKind"/> is how this adapter reads it.</summary>
    [JsonPropertyName("challengeKind")]
    public string? ChallengeKind { get; init; }

    /// <summary>4.5.0 (D-06b): <see cref="ChallengeKind"/> as this adapter knows it; a newer (or malformed) kind is
    /// <see cref="SentomaruChallengeKind.Unknown"/> and keeps its raw value in <see cref="ChallengeKind"/>.</summary>
    [JsonIgnore]
    public SentomaruChallengeKind KnownChallengeKind => SentomaruChallengeKinds.Parse(ChallengeKind);

    public EvaluationVerdict Verdict => RecommendedAction switch
    {
        "allow" => EvaluationVerdict.Allow,
        "deny" => EvaluationVerdict.Deny,
        "challenge" => EvaluationVerdict.Challenge,
        "shadow" => EvaluationVerdict.Shadow,
        _ => EvaluationVerdict.Deny
    };
}

/// <summary>
/// 4.4.0: what the <see cref="SentomaruIntegrityAttribute"/> learned from its evaluation of the current request, in
/// <c>HttpContext.Items[SentomaruIntegrityAttribute.ObservationItem]</c>. <see cref="Status"/> is the HTTP status of the
/// evaluation (200 on a verdict); <see cref="Code"/> the error code of a refusal (<c>installation-suspended</c>,
/// <c>session-unavailable</c>, ...); <see cref="Action"/> the recommended action of a verdict; <see cref="InstallationId"/>
/// the installation whose key verified the proof (empty when refused); <see cref="ProofStatus"/> the proof status
/// Sentomaru reported with the verdict (<c>valid</c> when the signature verified; null when refused or not evaluated).
/// A request whose evaluation failed (exception or timeout in the client) is recorded as 503
/// <c>integrity-unavailable</c>; a body above <see cref="SentomaruExtractor.MaxBodyBytes"/> as 413 <c>body-limit</c>.
/// </summary>
public sealed record SentomaruObservation(int Status, string? Code, string? Action, Guid InstallationId, string? ProofStatus = null)
{
    /// <summary>4.5.0 (D-06b): the raw kind of a <c>challenge</c> verdict (<see cref="SentomaruChallengeKinds.Raw"/>),
    /// known to this adapter or not; null on any other verdict, without a kind, or when the value is not a kind token. Outside the positional members, so 4.4.0 deconstruction still
    /// compiles.</summary>
    public string? ChallengeKind { get; init; }
}

/// <summary>
/// 4.4.0: installation state from GET installations/{id}. <see cref="State"/> is <c>active</c>, <c>suspended</c> (until
/// <see cref="SuspendedUntil"/>) or <c>revoked</c>; null from a Sentomaru older than this field (treat as unknown).
/// Contract v1.6 (D-04d): an installation re-enrolled with a proof of its key stays <c>revoked</c> (this id no longer
/// signs) with <see cref="SupersededAt"/> set and <see cref="SuccessorInstallationId"/> naming the installation that now
/// signs (same installation code). Treat every state other than <c>active</c> as not signing.
/// </summary>
public sealed record InstallationStatusDto
{
    [JsonPropertyName("installationId")]
    public Guid InstallationId { get; init; }

    [JsonPropertyName("state")]
    public string? State { get; init; }

    [JsonPropertyName("suspendedUntil")]
    public DateTimeOffset? SuspendedUntil { get; init; }

    [JsonPropertyName("revokedAt")]
    public DateTimeOffset? RevokedAt { get; init; }

    /// <summary>Contract v1.6: when a proven re-enrollment replaced this installation (state <c>revoked</c>); null otherwise.</summary>
    [JsonPropertyName("supersededAt")]
    public DateTimeOffset? SupersededAt { get; init; }

    /// <summary>Contract v1.6: the installation that re-enrolled this one; null otherwise.</summary>
    [JsonPropertyName("successorInstallationId")]
    public Guid? SuccessorInstallationId { get; init; }
}

/// <summary>
/// Payload to request an enrollment challenge via POST /v1/challenges.
/// </summary>
public sealed record ChallengeRequestDto
{
    [JsonPropertyName("subject")]
    public required string Subject { get; init; }

    [JsonPropertyName("tenant")]
    public required string Tenant { get; init; }

    [JsonPropertyName("publicKeyPem")]
    public string? PublicKeyPem { get; init; }
}

/// <summary>
/// Challenge issued by Sentomaru.
/// </summary>
public sealed record ChallengeResponseDto
{
    [JsonPropertyName("challengeId")]
    public Guid ChallengeId { get; init; }

    [JsonPropertyName("challenge")]
    public required string Challenge { get; init; }

    [JsonPropertyName("attestationChallenge")]
    public required string AttestationChallenge { get; init; }

    [JsonPropertyName("expiresAt")]
    public DateTimeOffset ExpiresAt { get; init; }
}

/// <summary>
/// Envelope forwarded to complete enrollment via POST /v1/enrollments.
/// </summary>
public sealed record EnrollmentEnvelopeDto
{
    [JsonPropertyName("request")]
    public required ForwardedMessageDto Request { get; init; }
}

/// <summary>
/// 4.1.0 (J-04r): envelope of a signed grant renewal, forwarded to POST /v1/{org}/{app}/{env}/sessions. <c>Context</c>
/// is optional: the installation key authorizes the renewal; when given it must be the installation's caller.
/// </summary>
public sealed record SessionRenewalEnvelopeDto
{
    [JsonPropertyName("request")]
    public required ForwardedMessageDto Request { get; init; }

    [JsonPropertyName("context")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public CallerContextDto? Context { get; init; }
}

/// <summary>4.1.0 (J-04r): the new grant (pass it to the app as received; the SDK schedules the next renewal).</summary>
public sealed record SessionRenewalResponseDto
{
    [JsonPropertyName("installationId")]
    public Guid InstallationId { get; init; }

    [JsonPropertyName("keyId")]
    public Guid KeyId { get; init; }

    [JsonPropertyName("sessionId")]
    public Guid SessionId { get; init; }

    [JsonPropertyName("expiresAt")]
    public DateTimeOffset ExpiresAt { get; init; }

    /// <summary>Remaining lifetime of the grant handed out (a retry gets the same, part-used grant).</summary>
    [JsonPropertyName("ttlSeconds")]
    public int TtlSeconds { get; init; }

    /// <summary>When the renewal chain ends (the app enrolls again).</summary>
    [JsonPropertyName("chainExpiresAt")]
    public DateTimeOffset ChainExpiresAt { get; init; }
}

/// <summary>
/// Enrollment completion response.
/// </summary>
public sealed record EnrollmentResponseDto
{
    [JsonPropertyName("installationId")]
    public Guid InstallationId { get; init; }

    [JsonPropertyName("sessionId")]
    public Guid SessionId { get; init; }

    [JsonPropertyName("keyId")]
    public Guid? KeyId { get; init; }

    [JsonPropertyName("subject")]
    public string? Subject { get; init; }

    [JsonPropertyName("tenant")]
    public string? Tenant { get; init; }

    [JsonPropertyName("hardwareStatus")]
    public string? HardwareStatus { get; init; }

    [JsonPropertyName("attestationStatus")]
    public string? AttestationStatus { get; init; }

    [JsonPropertyName("attestationReason")]
    public string? AttestationReason { get; init; }

    [JsonPropertyName("hardwareLevel")]
    public string? HardwareLevel { get; init; }
}

/// <summary>
/// Error format returned by Sentomaru API.
/// </summary>
public sealed record SentomaruApiError
{
    [JsonPropertyName("code")]
    public string Code { get; init; } = "";

    [JsonPropertyName("attestationReason")]
    public string? AttestationReason { get; init; }

    /// <summary>4.5.0 (D-06b): on 401 <c>challenge-required</c>, the raw kind of the challenge (<c>fresh_signals</c>,
    /// <c>step_up</c>, or a kind newer than the adapter) when the policy declared one (<see cref="SentomaruChallengeKinds.Raw"/>).
    /// Omitted otherwise, so a body without a kind is the 4.4.0 body.</summary>
    [JsonPropertyName("challengeKind")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ChallengeKind { get; init; }
}

/// <summary>
/// Result container for client invocations.
/// </summary>
public sealed record SentomaruClientResult<T>
{
    public bool Succeeded { get; private init; }
    public T? Value { get; private init; }
    public int StatusCode { get; private init; }
    public string? ErrorCode { get; private init; }
    public string? AttestationReason { get; private init; }
    public bool IsDegraded { get; private init; }
    public string? ErrorMessage { get; private init; }

    public static SentomaruClientResult<T> Success(T value, int statusCode = 200, bool isDegraded = false) =>
        new()
        {
            Succeeded = true,
            Value = value,
            StatusCode = statusCode,
            IsDegraded = isDegraded
        };

    public static SentomaruClientResult<T> Failure(int statusCode, string errorCode, string? attestationReason = null, string? message = null) =>
        new()
        {
            Succeeded = false,
            StatusCode = statusCode,
            ErrorCode = errorCode,
            AttestationReason = attestationReason,
            ErrorMessage = message
        };
}

/// <summary>
/// 4.9.0 (D-12b): envelope of a signed reattestation step, forwarded to POST /v1/{org}/{app}/{env}/reattestations/challenges
/// (step 1, the app's body is <c>{}</c>) and POST …/reattestations (step 2). <c>Context</c> is optional: the installation
/// key authorizes the step; when given it must be the installation's caller.
/// </summary>
public sealed record ReattestationEnvelopeDto
{
    [JsonPropertyName("request")]
    public required ForwardedMessageDto Request { get; init; }

    [JsonPropertyName("context")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public CallerContextDto? Context { get; init; }
}

/// <summary>4.9.0 (D-12b): the single-use challenge the app puts in the attestation of its ephemeral key (pass it to the app as received).</summary>
public sealed record ReattestationChallengeResponseDto
{
    [JsonPropertyName("challengeId")]
    public Guid ChallengeId { get; init; }

    /// <summary>Standard base64 of the 32 bytes the app puts in the ephemeral key's attestation challenge.</summary>
    [JsonPropertyName("attestationChallenge")]
    public string AttestationChallenge { get; init; } = "";

    [JsonPropertyName("expiresAt")]
    public DateTimeOffset ExpiresAt { get; init; }
}

/// <summary>4.9.0 (D-12b): the recorded reattestation (pass it to the app as received; it is advisory, never an authorization).</summary>
public sealed record ReattestationResponseDto
{
    [JsonPropertyName("installationId")]
    public Guid InstallationId { get; init; }

    [JsonPropertyName("challengeId")]
    public Guid ChallengeId { get; init; }

    [JsonPropertyName("reattestedAt")]
    public DateTimeOffset ReattestedAt { get; init; }

    [JsonPropertyName("hardwareStatus")]
    public string HardwareStatus { get; init; } = "";

    [JsonPropertyName("attestationStatus")]
    public string AttestationStatus { get; init; } = "";

    [JsonPropertyName("attestationReason")]
    public string? AttestationReason { get; init; }

    [JsonPropertyName("buildMatchState")]
    public string BuildMatchState { get; init; } = "";

    [JsonPropertyName("buildMatchReason")]
    public string? BuildMatchReason { get; init; }

    [JsonPropertyName("appIdentityState")]
    public string AppIdentityState { get; init; } = "";

    [JsonPropertyName("appIdentityReason")]
    public string? AppIdentityReason { get; init; }

    [JsonPropertyName("replayed")]
    public bool Replayed { get; init; }
}
