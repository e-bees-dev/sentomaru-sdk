using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Http;

namespace Sentomaru.AspNetCore;

/// <summary>
/// 4.12.0 (Fraud F-10): <c>deviceSignals</c> of <c>POST /v1/{org}/{app}/{env}/fraud/evaluate</c>. Only the member the
/// reattestation measurement needs; the server refuses members it does not know, so nothing else is sent from here.
/// </summary>
public sealed record FraudDeviceSignalsDto
{
    /// <summary>
    /// The <c>installationId</c> Sentomaru returned for the verified installation, a canonical 36-character UUID. A
    /// DECLARATION by the consumer: Sentomaru uses it only to read the server's own attestation history (rule
    /// <c>DEVICE_BOOT_STATE_CHANGED</c>), never stores the link, and ignores an id that does not match the scope. Take it
    /// from a Sentomaru evaluation your own pipeline verified (<see cref="SentomaruFraud.WithInstallation"/>), never from
    /// a value the app or the user typed.
    /// </summary>
    [JsonPropertyName("installationId")]
    public string? InstallationId { get; init; }
}

/// <summary>4.12.0 (Fraud F-10): <c>sessionSignals</c>, the member that dates a credential change (0 to 2592000 seconds).</summary>
public sealed record FraudSessionSignalsDto
{
    [JsonPropertyName("credentialChangedSecondsAgo")]
    public int? CredentialChangedSecondsAgo { get; init; }
}

/// <summary>
/// 4.14.0 (Fraud F-03c, migration 0122): <c>context</c> of the evaluation request, the closed-format labels the calibration report segments by.
/// DECLARED by the consumer, never scored, never a decision input. A member that does not match the server's format is not sent (the server
/// answers 400 for the whole evaluation otherwise): <see cref="SentomaruFraud.WithContext"/> drops it. Needs a Sentomaru with migration 0122; an older
/// one refuses the member it does not know.
/// </summary>
public sealed record FraudSegmentContextDto
{
    [JsonPropertyName("platform"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Platform { get; init; }

    [JsonPropertyName("sdkVersion"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? SdkVersion { get; init; }

    [JsonPropertyName("attestationLevel"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? AttestationLevel { get; init; }

    [JsonPropertyName("operation"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Operation { get; init; }
}

/// <summary>
/// 4.12.0 (Fraud F-10): the subset of the fraud evaluation request an integrating backend sends to give Sentomaru the
/// installation behind a transaction. <see cref="DeviceId"/> is the consumer's own device handle (1 to 128 characters).
/// Not a full model of the fraud request: other signals stay out until a consumer needs them.
/// </summary>
public sealed record FraudEvaluationRequestDto
{
    [JsonPropertyName("deviceId")]
    public required string DeviceId { get; init; }

    [JsonPropertyName("subjectId")]
    public string? SubjectId { get; init; }

    [JsonPropertyName("transactionId")]
    public string? TransactionId { get; init; }

    [JsonPropertyName("deviceSignals")]
    public FraudDeviceSignalsDto? DeviceSignals { get; init; }

    [JsonPropertyName("sessionSignals")]
    public FraudSessionSignalsDto? SessionSignals { get; init; }

    /// <summary>4.14.0: omitted from the body while null, so a consumer that never sets it sends what 4.13.0 sent.</summary>
    [JsonPropertyName("context"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public FraudSegmentContextDto? Context { get; init; }
}

/// <summary>4.12.0 (Fraud F-10): the evaluation as Sentomaru recorded it. <see cref="Decision"/> is Allow, Monitor, StepUp or Block; advisory.</summary>
public sealed record FraudEvaluationResponseDto
{
    [JsonPropertyName("evaluationId")]
    public Guid EvaluationId { get; init; }

    [JsonPropertyName("riskScore")]
    public int RiskScore { get; init; }

    [JsonPropertyName("decision")]
    public string? Decision { get; init; }

    [JsonPropertyName("modelVersion")]
    public string? ModelVersion { get; init; }

    [JsonPropertyName("configRevision")]
    public string? ConfigRevision { get; init; }
}

/// <summary>
/// 4.12.0 (Fraud F-10): hands the installation of a request your Sentomaru filter already verified to the fraud
/// evaluation, so the evaluation can read the server's boot history of that installation.
/// </summary>
public static class SentomaruFraud
{
    /// <summary>
    /// Returns a copy that declares the installation of the Sentomaru evaluation recorded in <c>HttpContext.Items</c> by
    /// <see cref="SentomaruIntegrityAttribute"/> or <see cref="SentomaruEvaluationPipeline"/>. Unchanged when there is none
    /// (no evaluation ran on this request, it was refused, or the installation id is empty): the field is optional and
    /// an absent id is never an error.
    /// </summary>
    public static FraudEvaluationRequestDto WithInstallation(this FraudEvaluationRequestDto request, HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(context);
        return SentomaruIntegrityAttribute.Observation(context) is { Code: null, InstallationId: var id } && id != Guid.Empty
            ? request.WithInstallation(id) : request;
    }

    /// <summary>Declares <paramref name="installationId"/> (canonical lower-case UUID); an empty id leaves the request unchanged.</summary>
    public static FraudEvaluationRequestDto WithInstallation(this FraudEvaluationRequestDto request, Guid installationId)
    {
        ArgumentNullException.ThrowIfNull(request);
        return installationId == Guid.Empty ? request
            : request with { DeviceSignals = (request.DeviceSignals ?? new FraudDeviceSignalsDto()) with { InstallationId = installationId.ToString("D") } };
    }

    private static readonly string[] Platforms = ["android", "ios", "web"];
    private static readonly string[] AssuranceLevels =
        ["key-not-proven", "hardware-key", "hardware-key-app-match", "hardware-key-app-match-recent", "not-covered"];

    private const int MaxDigitRun = 5;

    // Same rules as the server (FraudRequestInput), repeated because this package does not reference the server.
    private static bool SdkVersionOk(string? value)
    {
        if (value is null || value.Length is < 3 or > 32) return false;
        var suffix = value.IndexOfAny(['-', '+']);
        var parts = (suffix < 0 ? value : value[..suffix]).Split('.');
        if (parts.Length is < 2 or > 4 || parts.Any(p => p.Length is 0 or > 9 || !p.All(char.IsAsciiDigit))) return false;
        if (suffix < 0) return true;
        var tail = value[(suffix + 1)..];
        return tail.Length is >= 1 and <= 16 && tail.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '+' or '-');
    }

    private static bool OperationOk(string? value)
    {
        if (value is null || value.Length is < 1 or > 48 || !char.IsAsciiLetter(value[0])) return false;
        var run = 0;
        foreach (var c in value)
        {
            if (!(char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '-')) return false;
            run = char.IsAsciiDigit(c) ? run + 1 : 0;
            if (run >= MaxDigitRun) return false;
        }
        return true;
    }

    /// <summary>
    /// 4.14.0: declares the segment labels. Each member is optional; one that does not match the closed format of the server
    /// (<c>platform</c> android|ios|web, <c>sdkVersion</c> a dotted version of 2 to 4 numeric parts with an optional suffix, at most 32,
    /// <c>attestationLevel</c> a step of <c>assurance-levels-v1</c> or <c>not-covered</c>, <c>operation</c> 1 to 48 of <c>[0-9A-Za-z._-]</c>, starting with a
    /// letter, no run of 5 digits) is dropped, never sent, so a label
    /// can never turn the evaluation into a 400. Members already on the request are kept when the argument is null.
    /// </summary>
    public static FraudEvaluationRequestDto WithContext(this FraudEvaluationRequestDto request, string? platform = null,
        string? sdkVersion = null, string? attestationLevel = null, string? operation = null)
    {
        ArgumentNullException.ThrowIfNull(request);
        var current = request.Context ?? new FraudSegmentContextDto();
        var next = current with
        {
            Platform = platform is not null && Platforms.Contains(platform) ? platform : current.Platform,
            SdkVersion = SdkVersionOk(sdkVersion) ? sdkVersion : current.SdkVersion,
            AttestationLevel = attestationLevel is not null && AssuranceLevels.Contains(attestationLevel) ? attestationLevel : current.AttestationLevel,
            Operation = OperationOk(operation) ? operation : current.Operation,
        };
        return next == new FraudSegmentContextDto() ? request : request with { Context = next };
    }

    /// <summary>
    /// 4.14.0: declares the operation name the Sentomaru filter of this request protected (the route's own name from
    /// <see cref="SentomaruIntegrityAttribute"/> or <see cref="SentomaruEvaluationOptions"/>, never read from the client). Unchanged when no filter ran
    /// on this request or the name does not match the format. This is the only label the adapter knows by itself: the evaluation answer carries
    /// neither the platform nor the SDK version nor an assurance level, so those come from <see cref="WithContext"/> if the consumer has them.
    /// </summary>
    public static FraudEvaluationRequestDto WithOperation(this FraudEvaluationRequestDto request, HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(context);
        return context.Items.TryGetValue(SentomaruIntegrityAttribute.OperationItem, out var value) && value is string name
            ? request.WithContext(operation: name) : request;
    }
}
