namespace Sentomaru.AspNetCore;

/// <summary>
/// Client contract for evaluating device and request integrity against Sentomaru.
/// </summary>
public interface ISentomaruClient
{
    /// <summary>
    /// Issues an enrollment challenge for a new installation/device.
    /// </summary>
    Task<SentomaruClientResult<ChallengeResponseDto>> IssueChallengeAsync(
        ChallengeRequestDto request,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Forwards and completes an enrollment proof from the client.
    /// </summary>
    Task<SentomaruClientResult<EnrollmentResponseDto>> CompleteEnrollmentAsync(
        EnrollmentEnvelopeDto envelope,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Evaluates the cryptographic proof and policy integrity of a forwarded client request.
    /// </summary>
    Task<SentomaruClientResult<EvaluationResponseDto>> EvaluateAsync(
        EvaluationRequestDto request,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// 3.1.0 (J-01f): releases an admitted operation id whose effect this consumer could not apply, so the app's retry
    /// is a first admission again. The filter calls it when a protected action fails. Default: not supported.
    /// </summary>
    Task<SentomaruClientResult<bool>> ReleaseOperationAsync(Guid installationId, string operationId,
        CancellationToken cancellationToken = default) =>
        Task.FromResult(SentomaruClientResult<bool>.Failure(501, "not-implemented"));

    /// <summary>
    /// 4.1.0 (J-04r): forwards the app's signed grant renewal (the grant lives 10 minutes; renewal needs no new
    /// attestation). Default: not supported, so implementations written before 4.1.0 keep compiling.
    /// </summary>
    Task<SentomaruClientResult<SessionRenewalResponseDto>> RenewSessionAsync(SessionRenewalEnvelopeDto envelope,
        CancellationToken cancellationToken = default) =>
        Task.FromResult(SentomaruClientResult<SessionRenewalResponseDto>.Failure(501, "not-implemented"));

    /// <summary>
    /// 4.9.0 (D-12b): forwards step 1 of the app's signed reattestation (POST reattestations/challenges): the server
    /// answers the single-use challenge for the app's ephemeral key. Default: not supported.
    /// </summary>
    Task<SentomaruClientResult<ReattestationChallengeResponseDto>> IssueReattestationChallengeAsync(
        ReattestationEnvelopeDto envelope, CancellationToken cancellationToken = default) =>
        Task.FromResult(SentomaruClientResult<ReattestationChallengeResponseDto>.Failure(501, "not-implemented"));

    /// <summary>
    /// 4.9.0 (D-12b): forwards step 2 (POST reattestations): the ephemeral key, its Key Attestation chain and the
    /// challenge id. The result is advisory: the next evaluation reads it. Default: not supported.
    /// </summary>
    Task<SentomaruClientResult<ReattestationResponseDto>> ReattestAsync(
        ReattestationEnvelopeDto envelope, CancellationToken cancellationToken = default) =>
        Task.FromResult(SentomaruClientResult<ReattestationResponseDto>.Failure(501, "not-implemented"));

    /// <summary>
    /// 4.4.0 (resposta por instalação): the state of an installation of the configured scope (GET installations/{id}):
    /// <c>active</c>, <c>suspended</c> or <c>revoked</c>. For a consumer that enforces the state of an installation it
    /// already verified (a session bound to it) on a request it cannot evaluate, such as a multipart upload the app does
    /// not sign. It is not a proof: it says nothing about who sent the request. Default: not supported.
    /// </summary>
    Task<SentomaruClientResult<InstallationStatusDto>> GetInstallationAsync(Guid installationId,
        CancellationToken cancellationToken = default) =>
        Task.FromResult(SentomaruClientResult<InstallationStatusDto>.Failure(501, "not-implemented"));

    /// <summary>
    /// 4.12.0 (Fraud F-10): <c>POST fraud/evaluate</c> with the scoped workload credential. Send the installation the request was verified
    /// as with <see cref="SentomaruFraud.WithInstallation(FraudEvaluationRequestDto, Microsoft.AspNetCore.Http.HttpContext)"/>, so
    /// the evaluation can read the boot history; without it the rule has no input. 400 fraud-evaluation-format for a malformed field.
    /// Default: not supported.
    /// </summary>
    Task<SentomaruClientResult<FraudEvaluationResponseDto>> EvaluateFraudAsync(FraudEvaluationRequestDto request,
        CancellationToken cancellationToken = default) =>
        Task.FromResult(SentomaruClientResult<FraudEvaluationResponseDto>.Failure(501, "not-implemented"));

    /// <summary>
    /// 4.16.0 (WS-F): <c>POST web/evaluations</c> with the scoped workload credential: the backend declares the state of web signals it observed and the
    /// scope's active <c>channel: web</c> policy answers, ALWAYS advisory (shadow). Build the body with <see cref="SentomaruWeb.TryBuild"/>. 400
    /// web-evaluation-format, 413 web-evaluation-too-large, 503 store-unavailable. Needs a Sentomaru with migration 0126. Default: not supported.
    /// </summary>
    Task<SentomaruClientResult<WebEvaluationResponseDto>> EvaluateWebAsync(WebEvaluationRequestDto request,
        CancellationToken cancellationToken = default) =>
        Task.FromResult(SentomaruClientResult<WebEvaluationResponseDto>.Failure(501, "not-implemented"));

    /// <summary>
    /// 4.13.0 (fase E): <c>POST consumer/heartbeat</c> with the scoped workload credential: what the consumer says it turned on. Informational; the 204 carries
    /// no body. 400 heartbeat-format, 404 scope-unknown, 429 heartbeat-instance-limit. Default: not supported.
    /// </summary>
    Task<SentomaruClientResult<bool>> SendHeartbeatAsync(ConsumerHeartbeatDto heartbeat, CancellationToken cancellationToken = default) =>
        Task.FromResult(SentomaruClientResult<bool>.Failure(501, "not-implemented"));

    /// <summary>E-06: binds the hash of the user's IdP token to a live grant (the Sentomaru session bindings contract). Default: not supported.</summary>
    Task<SentomaruClientResult<SessionBindingResponseDto>> BindSessionAsync(SessionBindingRequestDto request,
        CancellationToken cancellationToken = default) =>
        Task.FromResult(SentomaruClientResult<SessionBindingResponseDto>.Failure(501, "not-implemented"));

    /// <summary>E-06 (IDP-02): replaces the bound hash after an IdP refresh, without a new attestation. Default: not supported.</summary>
    Task<SentomaruClientResult<SessionBindingResponseDto>> RotateSessionBindingAsync(SessionBindingRotationRequestDto request,
        CancellationToken cancellationToken = default) =>
        Task.FromResult(SentomaruClientResult<SessionBindingResponseDto>.Failure(501, "not-implemented"));

    /// <summary>E-06: erases the binding of the grant's installation (data subject request). Default: not supported.</summary>
    Task<SentomaruClientResult<bool>> ClearSessionBindingAsync(Guid grantSessionId,
        CancellationToken cancellationToken = default) =>
        Task.FromResult(SentomaruClientResult<bool>.Failure(501, "not-implemented"));

    /// <summary>
    /// Revokes an active session in Sentomaru.
    /// </summary>
    Task<SentomaruClientResult<bool>> RevokeSessionAsync(
        Guid sessionId,
        string reason = "consumer-revocation",
        CancellationToken cancellationToken = default);
}
