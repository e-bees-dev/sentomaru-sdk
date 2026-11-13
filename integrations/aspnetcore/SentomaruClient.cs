using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Sentomaru.AspNetCore;

/// <summary>
/// HTTP client implementation for interacting with Sentomaru private integrity service.
/// </summary>
public sealed class SentomaruClient : ISentomaruClient
{
    private readonly HttpClient _httpClient;
    private readonly SentomaruClientOptions _options;
    private readonly ILogger<SentomaruClient> _logger;

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = true
    };

    public SentomaruClient(
        HttpClient httpClient,
        IOptions<SentomaruClientOptions> options,
        ILogger<SentomaruClient> logger)
    {
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));

        if (_options.BaseAddress is not null && _httpClient.BaseAddress is null)
        {
            _httpClient.BaseAddress = _options.BaseAddress;
        }

        if (!string.IsNullOrWhiteSpace(_options.WorkloadToken) &&
            _httpClient.DefaultRequestHeaders.Authorization is null)
        {
            _httpClient.DefaultRequestHeaders.Authorization =
                new AuthenticationHeaderValue("Bearer", _options.WorkloadToken);
        }

        if (_options.ClientTimeout > TimeSpan.Zero)
        {
            _httpClient.Timeout = _options.ClientTimeout;
        }
    }

    public async Task<SentomaruClientResult<ChallengeResponseDto>> IssueChallengeAsync(
        ChallengeRequestDto request,
        CancellationToken cancellationToken = default)
    {
        var path = _options.BuildScopedPath("challenges");
        // 4.0.0 (C-09, #142): a challenge is bound to the caller of the consumer's own authenticated session. Without
        // one (empty value or a resolver placeholder) nothing is sent: 403 caller-context-missing.
        if (!CallerContextDto.IsUsable(request.Subject, request.Tenant))
        {
            _logger.LogError("Sentomaru challenge refused: no subject/tenant from the authenticated session (caller-context-missing).");
            return SentomaruClientResult<ChallengeResponseDto>.Failure(403, "caller-context-missing");
        }
        try
        {
            using var response = await PostJsonStrictAsync(path, request, cancellationToken);
            return await HandleResponseAsync<ChallengeResponseDto>(response, cancellationToken);
        }
        catch (Exception ex) when (IsTransientException(ex))
        {
            _logger.LogWarning(ex, "Transient error issuing challenge to Sentomaru at {Path}", path);
            return SentomaruClientResult<ChallengeResponseDto>.Failure(503, "store-unavailable", message: ex.Message);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error calling Sentomaru challenge endpoint {Path}", path);
            return SentomaruClientResult<ChallengeResponseDto>.Failure(500, "internal-error", message: ex.Message);
        }
    }

    public async Task<SentomaruClientResult<EnrollmentResponseDto>> CompleteEnrollmentAsync(
        EnrollmentEnvelopeDto envelope,
        CancellationToken cancellationToken = default)
    {
        var path = _options.BuildScopedPath("installations");
        try
        {
            using var response = await PostJsonStrictAsync(path, envelope, cancellationToken, _options.EnrollmentDeadline);
            if (response.IsSuccessStatusCode)
            {
                var value = await response.Content.ReadFromJsonAsync<EnrollmentResponseDto>(JsonOptions, cancellationToken);
                if (value is null)
                {
                    return SentomaruClientResult<EnrollmentResponseDto>.Failure(502, "invalid-response", message: "Empty response body");
                }

                if (value.InstallationId == Guid.Empty ||
                    value.SessionId == Guid.Empty ||
                    value.KeyId is null ||
                    value.KeyId.Value == Guid.Empty ||
                    string.IsNullOrWhiteSpace(value.HardwareStatus) ||
                    string.IsNullOrWhiteSpace(value.AttestationStatus) ||
                    value.AttestationStatus is not ("notEvaluated" or "verified" or "untrusted"))
                {
                    return SentomaruClientResult<EnrollmentResponseDto>.Failure(502, "invalid-response", message: "Upstream enrollment response missing or invalid required contract fields");
                }

                return SentomaruClientResult<EnrollmentResponseDto>.Success(value, (int)response.StatusCode);
            }

            var (code, reason) = await ParseErrorAsync(response, cancellationToken);
            return SentomaruClientResult<EnrollmentResponseDto>.Failure((int)response.StatusCode, code, reason);
        }
        catch (Exception ex) when (IsTransientException(ex))
        {
            _logger.LogWarning(ex, "Transient error completing enrollment with Sentomaru at {Path}", path);
            return SentomaruClientResult<EnrollmentResponseDto>.Failure(503, "store-unavailable", message: ex.Message);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error calling Sentomaru enrollment endpoint {Path}", path);
            return SentomaruClientResult<EnrollmentResponseDto>.Failure(500, "internal-error", message: ex.Message);
        }
    }

    public async Task<SentomaruClientResult<SessionRenewalResponseDto>> RenewSessionAsync(SessionRenewalEnvelopeDto envelope,
        CancellationToken cancellationToken = default)
    {
        var path = _options.BuildScopedPath("sessions");
        try
        {
            using var response = await PostJsonStrictAsync(path, envelope, cancellationToken);
            if (response.IsSuccessStatusCode)
            {
                var value = await response.Content.ReadFromJsonAsync<SessionRenewalResponseDto>(JsonOptions, cancellationToken);
                if (value is null || value.InstallationId == Guid.Empty || value.KeyId == Guid.Empty ||
                    value.SessionId == Guid.Empty || value.TtlSeconds is < 1 or > 86_400)
                    return SentomaruClientResult<SessionRenewalResponseDto>.Failure(502, "invalid-response",
                        message: "Upstream renewal response missing or invalid required contract fields");
                return SentomaruClientResult<SessionRenewalResponseDto>.Success(value, (int)response.StatusCode);
            }

            var (code, reason) = await ParseErrorAsync(response, cancellationToken);
            return SentomaruClientResult<SessionRenewalResponseDto>.Failure((int)response.StatusCode, code, reason);
        }
        catch (Exception ex) when (IsTransientException(ex))
        {
            _logger.LogWarning(ex, "Transient error renewing a session with Sentomaru at {Path}", path);
            return SentomaruClientResult<SessionRenewalResponseDto>.Failure(503, "store-unavailable", message: ex.Message);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error calling Sentomaru sessions endpoint {Path}", path);
            return SentomaruClientResult<SessionRenewalResponseDto>.Failure(500, "internal-error", message: ex.Message);
        }
    }

    public Task<SentomaruClientResult<ReattestationChallengeResponseDto>> IssueReattestationChallengeAsync(
        ReattestationEnvelopeDto envelope, CancellationToken cancellationToken = default) =>
        PostReattestationAsync<ReattestationChallengeResponseDto>("reattestations/challenges", envelope,
            v => v.ChallengeId != Guid.Empty && v.AttestationChallenge.Length > 0, cancellationToken);

    public Task<SentomaruClientResult<ReattestationResponseDto>> ReattestAsync(
        ReattestationEnvelopeDto envelope, CancellationToken cancellationToken = default) =>
        PostReattestationAsync<ReattestationResponseDto>("reattestations", envelope,
            v => v.InstallationId != Guid.Empty && v.ChallengeId != Guid.Empty, cancellationToken);

    private async Task<SentomaruClientResult<T>> PostReattestationAsync<T>(string endpoint, ReattestationEnvelopeDto envelope,
        Func<T, bool> valid, CancellationToken cancellationToken) where T : class
    {
        var path = _options.BuildScopedPath(endpoint);
        try
        {
            using var response = await PostJsonStrictAsync(path, envelope, cancellationToken);
            if (response.IsSuccessStatusCode)
            {
                var value = await response.Content.ReadFromJsonAsync<T>(JsonOptions, cancellationToken);
                if (value is null || !valid(value))
                    return SentomaruClientResult<T>.Failure(502, "invalid-response",
                        message: "Upstream reattestation response missing or invalid required contract fields");
                return SentomaruClientResult<T>.Success(value, (int)response.StatusCode);
            }

            var (code, reason) = await ParseErrorAsync(response, cancellationToken);
            return SentomaruClientResult<T>.Failure((int)response.StatusCode, code, reason);
        }
        catch (Exception ex) when (IsTransientException(ex))
        {
            _logger.LogWarning(ex, "Transient error calling Sentomaru reattestation endpoint {Path}", path);
            return SentomaruClientResult<T>.Failure(503, "store-unavailable", message: ex.Message);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error calling Sentomaru reattestation endpoint {Path}", path);
            return SentomaruClientResult<T>.Failure(500, "internal-error", message: ex.Message);
        }
    }

    public Task<SentomaruClientResult<TransactionKeyChallengeResponseDto>> CreateTransactionKeyChallengeAsync(
        TransactionKeyEnvelopeDto envelope, CancellationToken cancellationToken = default) =>
        PostTransactionKeyAsync("transaction-keys/challenges", envelope, Body<TransactionKeyChallengeResponseDto>(
            v => v.ChallengeId != Guid.Empty && v.Token.Length > 0 && v.AttestationChallenge.Length > 0, cancellationToken), cancellationToken);

    public Task<SentomaruClientResult<TransactionKeyEnrollmentResponseDto>> EnrollTransactionKeyAsync(
        TransactionKeyEnvelopeDto envelope, CancellationToken cancellationToken = default) =>
        PostTransactionKeyAsync("transaction-keys", envelope, Body<TransactionKeyEnrollmentResponseDto>(
            v => v.TxKeyId != Guid.Empty && v.UserAuthentication.Length > 0, cancellationToken), cancellationToken);

    public Task<SentomaruClientResult<TransactionKeyStatusResponseDto>> GetTransactionKeyStatusAsync(
        TransactionKeyEnvelopeDto envelope, CancellationToken cancellationToken = default) =>
        PostTransactionKeyAsync("transaction-keys/status", envelope, Body<TransactionKeyStatusResponseDto>(
            v => !v.Enrolled || v.TxKeyId is { } id && id != Guid.Empty, cancellationToken), cancellationToken);

    public Task<SentomaruClientResult<bool>> RevokeTransactionKeyAsync(
        TransactionKeyEnvelopeDto envelope, CancellationToken cancellationToken = default) =>
        PostTransactionKeyAsync("transaction-keys/revocations", envelope,
            response => Task.FromResult(SentomaruClientResult<bool>.Success(true, (int)response.StatusCode)), cancellationToken);

    /// <summary>4.19.0: a 2xx body checked like the reattestation's (missing or incomplete = 502 <c>invalid-response</c>).</summary>
    private static Func<HttpResponseMessage, Task<SentomaruClientResult<T>>> Body<T>(Func<T, bool> valid,
        CancellationToken cancellationToken) where T : class => async response =>
    {
        var value = await response.Content.ReadFromJsonAsync<T>(JsonOptions, cancellationToken);
        return value is null || !valid(value)
            ? SentomaruClientResult<T>.Failure(502, "invalid-response",
                message: "Upstream transaction key response missing or invalid required contract fields")
            : SentomaruClientResult<T>.Success(value, (int)response.StatusCode);
    };

    /// <summary>4.19.0 (D-25): same strict JSON, credential and error mapping as the reattestation; a refusal also keeps its
    /// <c>Retry-After</c> (<see cref="SentomaruClientResult{T}.RetryAfterSeconds"/>).</summary>
    private async Task<SentomaruClientResult<T>> PostTransactionKeyAsync<T>(string endpoint, TransactionKeyEnvelopeDto envelope,
        Func<HttpResponseMessage, Task<SentomaruClientResult<T>>> success, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        var path = _options.BuildScopedPath(endpoint);
        try
        {
            using var response = await PostJsonStrictAsync(path, envelope, cancellationToken);
            if (response.IsSuccessStatusCode) return await success(response);
            var (code, reason) = await ParseErrorAsync(response, cancellationToken);
            return SentomaruClientResult<T>.Failure((int)response.StatusCode, code, reason) with { RetryAfterSeconds = RetryAfter(response) };
        }
        catch (Exception ex) when (IsTransientException(ex))
        {
            _logger.LogWarning(ex, "Transient error calling Sentomaru transaction key endpoint {Path}", path);
            return SentomaruClientResult<T>.Failure(503, "store-unavailable", message: ex.Message);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error calling Sentomaru transaction key endpoint {Path}", path);
            return SentomaruClientResult<T>.Failure(500, "internal-error", message: ex.Message);
        }
    }

    /// <summary>4.19.0: <c>Retry-After</c> as seconds (delta or HTTP date), 1..86400 (the largest wait Sentomaru sends is 24 h); null
    /// when absent or in the past.</summary>
    internal static int? RetryAfter(HttpResponseMessage response)
    {
        var header = response.Headers.RetryAfter;
        var wait = header?.Delta ?? (header?.Date is { } at ? at - DateTimeOffset.UtcNow : null);
        if (wait is not { } w || w < TimeSpan.Zero) return null;
        return (int)Math.Clamp(Math.Ceiling(w.TotalSeconds), 1, 86_400);
    }

    public async Task<SentomaruClientResult<FraudEvaluationResponseDto>> EvaluateFraudAsync(FraudEvaluationRequestDto request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var path = _options.BuildScopedPath("fraud/evaluate");
        try
        {
            using var response = await PostJsonStrictAsync(path, request, cancellationToken);
            if (response.IsSuccessStatusCode)
            {
                var value = await response.Content.ReadFromJsonAsync<FraudEvaluationResponseDto>(JsonOptions, cancellationToken);
                return value is null || value.EvaluationId == Guid.Empty
                    ? SentomaruClientResult<FraudEvaluationResponseDto>.Failure(502, "invalid-response",
                        message: "Upstream fraud evaluation missing required contract fields")
                    : SentomaruClientResult<FraudEvaluationResponseDto>.Success(value, (int)response.StatusCode);
            }

            var (code, reason) = await ParseErrorAsync(response, cancellationToken);
            return SentomaruClientResult<FraudEvaluationResponseDto>.Failure((int)response.StatusCode, code, reason);
        }
        catch (Exception ex) when (IsTransientException(ex) && !cancellationToken.IsCancellationRequested)
        {
            _logger.LogWarning(ex, "Sentomaru unavailable during fraud evaluation at {Path}", path);
            return SentomaruClientResult<FraudEvaluationResponseDto>.Failure(503, "store-unavailable", message: ex.Message);
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
        {
            _logger.LogError(ex, "Unexpected error calling Sentomaru fraud evaluation {Path}", path);
            return SentomaruClientResult<FraudEvaluationResponseDto>.Failure(500, "internal-error", message: ex.Message);
        }
    }

    public async Task<SentomaruClientResult<WebEvaluationResponseDto>> EvaluateWebAsync(WebEvaluationRequestDto request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var path = _options.BuildScopedPath("web/evaluations");
        try
        {
            using var response = await PostJsonStrictAsync(path, request, cancellationToken);
            if (response.IsSuccessStatusCode)
            {
                var value = await response.Content.ReadFromJsonAsync<WebEvaluationResponseDto>(JsonOptions, cancellationToken);
                // The route is always advisory and shadow: an answer that says otherwise is not this contract and is never handed on.
                return value is null || !value.Advisory || value.Mode != "shadow" || string.IsNullOrEmpty(value.Recommendation)
                    ? SentomaruClientResult<WebEvaluationResponseDto>.Failure(502, "invalid-response",
                        message: "Upstream web evaluation missing required contract fields")
                    : SentomaruClientResult<WebEvaluationResponseDto>.Success(value, (int)response.StatusCode);
            }

            var (code, reason) = await ParseErrorAsync(response, cancellationToken);
            return SentomaruClientResult<WebEvaluationResponseDto>.Failure((int)response.StatusCode, code, reason);
        }
        catch (Exception ex) when (IsTransientException(ex) && !cancellationToken.IsCancellationRequested)
        {
            _logger.LogWarning(ex, "Sentomaru unavailable during web evaluation at {Path}", path);
            return SentomaruClientResult<WebEvaluationResponseDto>.Failure(503, "store-unavailable", message: ex.Message);
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
        {
            _logger.LogError(ex, "Unexpected error calling Sentomaru web evaluation {Path}", path);
            return SentomaruClientResult<WebEvaluationResponseDto>.Failure(500, "internal-error", message: ex.Message);
        }
    }

    public async Task<SentomaruClientResult<bool>> SendHeartbeatAsync(ConsumerHeartbeatDto heartbeat, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(heartbeat);
        var path = _options.BuildScopedPath("consumer/heartbeat");
        try
        {
            using var response = await PostJsonStrictAsync(path, heartbeat, cancellationToken);
            if (response.IsSuccessStatusCode) return SentomaruClientResult<bool>.Success(true, (int)response.StatusCode);
            var (code, reason) = await ParseErrorAsync(response, cancellationToken);
            return SentomaruClientResult<bool>.Failure((int)response.StatusCode, code, reason);
        }
        catch (Exception ex) when (IsTransientException(ex) && !cancellationToken.IsCancellationRequested)
        {
            _logger.LogInformation(ex, "Sentomaru unavailable for the consumer heartbeat at {Path}", path);
            return SentomaruClientResult<bool>.Failure(503, "store-unavailable", message: ex.Message);
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
        {
            _logger.LogError(ex, "Unexpected error sending the consumer heartbeat {Path}", path);
            return SentomaruClientResult<bool>.Failure(500, "internal-error", message: ex.Message);
        }
    }

    public async Task<SentomaruClientResult<EvaluationResponseDto>> EvaluateAsync(
        EvaluationRequestDto request,
        CancellationToken cancellationToken = default)
    {
        var path = _options.BuildScopedPath("evaluations");
        try
        {
            using var response = await PostJsonStrictAsync(path, request, cancellationToken);
            if (response.IsSuccessStatusCode)
            {
                var result = await response.Content.ReadFromJsonAsync<EvaluationResponseDto>(JsonOptions, cancellationToken);
                if (result is null)
                {
                    return SentomaruClientResult<EvaluationResponseDto>.Failure(500, "internal-error", message: "Empty response body");
                }
                return SentomaruClientResult<EvaluationResponseDto>.Success(result, (int)response.StatusCode);
            }

            // The client never fabricates an allow: outages are reported as failures and only the filter may apply
            // FailOpen (Development only, after a proof was presented).
            var (code, reason) = await ParseErrorAsync(response, cancellationToken);
            return SentomaruClientResult<EvaluationResponseDto>.Failure((int)response.StatusCode, code, reason);
        }
        catch (Exception ex) when (IsTransientException(ex))
        {
            _logger.LogWarning(ex, "Sentomaru unavailable during evaluation call to {Path}", path);
            return SentomaruClientResult<EvaluationResponseDto>.Failure(503, "store-unavailable", message: ex.Message);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error evaluating integrity with Sentomaru at {Path}", path);
            return SentomaruClientResult<EvaluationResponseDto>.Failure(500, "internal-error", message: ex.Message);
        }
    }

    public async Task<SentomaruClientResult<SessionBindingResponseDto>> BindSessionAsync(SessionBindingRequestDto request,
        CancellationToken cancellationToken = default) =>
        await PostBindingAsync("session-bindings", request, cancellationToken);

    public async Task<SentomaruClientResult<SessionBindingResponseDto>> RotateSessionBindingAsync(
        SessionBindingRotationRequestDto request, CancellationToken cancellationToken = default) =>
        await PostBindingAsync("session-bindings/rotate", request, cancellationToken);

    private async Task<SentomaruClientResult<SessionBindingResponseDto>> PostBindingAsync<T>(string route, T body,
        CancellationToken cancellationToken)
    {
        var path = _options.BuildScopedPath(route);
        try
        {
            using var response = await PostJsonStrictAsync(path, body, cancellationToken);
            return await HandleResponseAsync<SessionBindingResponseDto>(response, cancellationToken);
        }
        catch (Exception ex) when (IsTransientException(ex) && !cancellationToken.IsCancellationRequested)
        {
            _logger.LogWarning(ex, "Transient error calling Sentomaru session-binding endpoint {Path}", path);
            return SentomaruClientResult<SessionBindingResponseDto>.Failure(503, "store-unavailable", message: ex.Message);
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
        {
            _logger.LogError(ex, "Unexpected error calling Sentomaru session-binding endpoint {Path}", path);
            return SentomaruClientResult<SessionBindingResponseDto>.Failure(500, "internal-error", message: ex.Message);
        }
    }

    public async Task<SentomaruClientResult<bool>> ClearSessionBindingAsync(Guid grantSessionId,
        CancellationToken cancellationToken = default)
    {
        var path = _options.BuildScopedPath($"session-bindings/{grantSessionId:D}");
        try
        {
            using var response = await SendAsync(HttpMethod.Delete, path, null, _options.Timeout, cancellationToken);
            if (response.IsSuccessStatusCode) return SentomaruClientResult<bool>.Success(true, (int)response.StatusCode);
            var (code, reason) = await ParseErrorAsync(response, cancellationToken);
            return SentomaruClientResult<bool>.Failure((int)response.StatusCode, code, reason);
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
        {
            _logger.LogError(ex, "Unexpected error clearing a session binding at {Path}", path);
            return SentomaruClientResult<bool>.Failure(500, "internal-error", message: ex.Message);
        }
    }

    public async Task<SentomaruClientResult<bool>> ReleaseOperationAsync(Guid installationId, string operationId,
        CancellationToken cancellationToken = default)
    {
        var path = _options.BuildScopedPath($"installations/{installationId}/operations/{Uri.EscapeDataString(operationId)}/release");
        try
        {
            using var response = await SendAsync(HttpMethod.Post, path, null, _options.Timeout, cancellationToken);
            if (response.IsSuccessStatusCode) return SentomaruClientResult<bool>.Success(true, (int)response.StatusCode);
            var (code, attestationReason) = await ParseErrorAsync(response, cancellationToken);
            return SentomaruClientResult<bool>.Failure((int)response.StatusCode, code, attestationReason);
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
        {
            _logger.LogError(ex, "Unexpected error releasing operation id at {Path}", path);
            return SentomaruClientResult<bool>.Failure(500, "internal-error", message: ex.Message);
        }
    }

    public async Task<SentomaruClientResult<InstallationStatusDto>> GetInstallationAsync(Guid installationId,
        CancellationToken cancellationToken = default)
    {
        var path = _options.BuildScopedPath($"installations/{installationId}");
        try
        {
            using var response = await SendAsync(HttpMethod.Get, path, null, _options.Timeout, cancellationToken);
            return await HandleResponseAsync<InstallationStatusDto>(response, cancellationToken);
        }
        catch (Exception ex) when (IsTransientException(ex) && !cancellationToken.IsCancellationRequested)
        {
            _logger.LogWarning(ex, "Sentomaru unavailable during installation lookup at {Path}", path);
            return SentomaruClientResult<InstallationStatusDto>.Failure(503, "store-unavailable", message: ex.Message);
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
        {
            _logger.LogError(ex, "Unexpected error looking up installation at {Path}", path);
            return SentomaruClientResult<InstallationStatusDto>.Failure(500, "internal-error", message: ex.Message);
        }
    }

    public async Task<SentomaruClientResult<bool>> RevokeSessionAsync(
        Guid sessionId,
        string reason = "consumer-revocation",
        CancellationToken cancellationToken = default)
    {
        var path = _options.BuildScopedPath($"grants/{sessionId}/revoke");
        try
        {
            using var response = await SendAsync(HttpMethod.Post, path, null, _options.Timeout, cancellationToken);
            if (response.IsSuccessStatusCode)
            {
                return SentomaruClientResult<bool>.Success(true, (int)response.StatusCode);
            }

            var (code, attestationReason) = await ParseErrorAsync(response, cancellationToken);
            return SentomaruClientResult<bool>.Failure((int)response.StatusCode, code, attestationReason);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error revoking session {SessionId} at {Path}", sessionId, path);
            return SentomaruClientResult<bool>.Failure(500, "internal-error", message: ex.Message);
        }
    }

    private static async Task<SentomaruClientResult<T>> HandleResponseAsync<T>(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        if (response.IsSuccessStatusCode)
        {
            var value = await response.Content.ReadFromJsonAsync<T>(JsonOptions, cancellationToken);
            if (value is null)
            {
                return SentomaruClientResult<T>.Failure(500, "internal-error", message: "Empty response body");
            }
            return SentomaruClientResult<T>.Success(value, (int)response.StatusCode);
        }

        var (code, reason) = await ParseErrorAsync(response, cancellationToken);
        return SentomaruClientResult<T>.Failure((int)response.StatusCode, code, reason);
    }

    private static async Task<(string Code, string? Reason)> ParseErrorAsync(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        try
        {
            var error = await response.Content.ReadFromJsonAsync<SentomaruApiError>(JsonOptions, cancellationToken);
            if (error is not null && !string.IsNullOrWhiteSpace(error.Code))
            {
                return (error.Code, error.AttestationReason);
            }
        }
        catch
        {
            // Ignore JSON parse errors for non-standard error responses
        }

        return (response.StatusCode switch
        {
            System.Net.HttpStatusCode.BadRequest => "request-format",
            System.Net.HttpStatusCode.Unauthorized => "workload-required",
            System.Net.HttpStatusCode.Forbidden => "workload-scope",
            System.Net.HttpStatusCode.NotFound => "route-format",
            System.Net.HttpStatusCode.Conflict => "replay",
            System.Net.HttpStatusCode.UnprocessableEntity => "hardware-not-proven",
            System.Net.HttpStatusCode.TooManyRequests => "rate-limited",
            System.Net.HttpStatusCode.ServiceUnavailable => "store-unavailable",
            _ => "internal-error"
        }, null);
    }

    private async Task<HttpResponseMessage> PostJsonStrictAsync<T>(
        string path,
        T value,
        CancellationToken cancellationToken,
        TimeSpan? timeout = null)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(value, JsonOptions);
        var content = new ByteArrayContent(bytes);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        return await SendAsync(HttpMethod.Post, path, content, timeout ?? _options.Timeout, cancellationToken);
    }

    // 4.8.0: HttpClient.Timeout is the longest deadline plus 1 s (ClientTimeout); each call cancels at its own first. The response is
    // buffered (ResponseContentRead) inside the deadline. A deadline that fires is a TimeoutException (transient), as
    // the HttpClient's own timeout was; the caller's cancellation still propagates as cancellation.
    private async Task<HttpResponseMessage> SendAsync(HttpMethod method, string path, HttpContent? content, TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(method, path) { Content = content };
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        if (SentomaruClientOptions.Bounded(timeout)) deadline.CancelAfter(timeout);
        try
        {
            return await _httpClient.SendAsync(request, deadline.Token);
        }
        catch (OperationCanceledException e) when (!cancellationToken.IsCancellationRequested && deadline.IsCancellationRequested)
        {
            throw new TimeoutException($"Sentomaru did not answer within {timeout.TotalMilliseconds:0} ms", e);
        }
    }

    private static bool IsTransientException(Exception ex) =>
        ex is HttpRequestException or TaskCanceledException or TimeoutException;
}
