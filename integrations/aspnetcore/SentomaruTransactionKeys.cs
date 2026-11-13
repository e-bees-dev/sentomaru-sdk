using System.Text.Json.Serialization;

namespace Sentomaru.AspNetCore;

/// <summary>
/// 4.19.0 (D-25, contracts/api/transaction-keys-v1.md): envelope of a signed transaction key step, forwarded to
/// POST /v1/{org}/{app}/{env}/transaction-keys/challenges, …/transaction-keys, …/transaction-keys/status and
/// …/transaction-keys/revocations. The app signs its request with the installation key, <c>x-sentomaru-session</c> = a live grant
/// and <c>x-sentomaru-operation</c> = <c>tx_key_challenge</c>, <c>tx_key_enroll</c>, <c>tx_key_status</c> or <c>tx_key_revoke</c>.
/// <c>Context</c> is optional: the installation key authorizes the step; when given it must be the installation's caller.
/// </summary>
public sealed record TransactionKeyEnvelopeDto
{
    [JsonPropertyName("request")]
    public required ForwardedMessageDto Request { get; init; }

    [JsonPropertyName("context")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public CallerContextDto? Context { get; init; }
}

/// <summary>4.19.0: the enrollment challenge (201 new, 200 the live one already issued). Pass it to the app as received.</summary>
public sealed record TransactionKeyChallengeResponseDto
{
    [JsonPropertyName("challengeId")]
    public Guid ChallengeId { get; init; }

    /// <summary>The challenge id as text: the app puts it in the <c>challenge</c> member of the enrollment body.</summary>
    [JsonPropertyName("token")]
    public string Token { get; init; } = "";

    /// <summary>Standard base64 of the 32 bytes the app puts in the transaction key's attestation challenge.</summary>
    [JsonPropertyName("attestationChallenge")]
    public string AttestationChallenge { get; init; } = "";

    [JsonPropertyName("expiresAt")]
    public DateTimeOffset ExpiresAt { get; init; }
}

/// <summary>4.19.0: the enrolled transaction key (201). <see cref="UserAuthentication"/> is <c>biometric-strong</c>,
/// <c>biometric-or-credential</c> or <c>advisory-ios</c> (never a proof of presence).</summary>
public sealed record TransactionKeyEnrollmentResponseDto
{
    [JsonPropertyName("txKeyId")]
    public Guid TxKeyId { get; init; }

    [JsonPropertyName("userAuthentication")]
    public string UserAuthentication { get; init; } = "";

    [JsonPropertyName("attestationStatus")]
    public string AttestationStatus { get; init; } = "";

    [JsonPropertyName("enrolledAt")]
    public DateTimeOffset EnrolledAt { get; init; }
}

/// <summary>4.19.0: whether the installation has a live transaction key. <see cref="SignatureVersions"/> absent = a server that
/// only accepts v1 of <c>x-sentomaru-tx-signature</c>.</summary>
public sealed record TransactionKeyStatusResponseDto
{
    [JsonPropertyName("enrolled")]
    public bool Enrolled { get; init; }

    [JsonPropertyName("txKeyId")]
    public Guid? TxKeyId { get; init; }

    [JsonPropertyName("userAuthentication")]
    public string? UserAuthentication { get; init; }

    [JsonPropertyName("enrolledAt")]
    public DateTimeOffset? EnrolledAt { get; init; }

    [JsonPropertyName("signatureVersions")]
    public IReadOnlyList<string>? SignatureVersions { get; init; }
}
