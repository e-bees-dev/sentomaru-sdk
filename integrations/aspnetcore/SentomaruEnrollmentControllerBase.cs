using System.Net.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Sentomaru.AspNetCore;

/// <summary>
/// 4.2.0: the three routes the app calls on the consumer's backend, as protected helpers. The consumer keeps its own
/// controller (routes, attributes, authentication, aliases: <c>gen-endpoints</c>-style tools still see them) and each
/// action is one line that calls a helper here. What lives here instead of in every consumer: the kill switch (503
/// <c>sentomaru-disabled</c> without calling Sentomaru), the scope check (404 <c>sentomaru-env-unknown</c>), the
/// envelope (<see cref="SentomaruExtractor"/> honouring <see cref="SentomaruClientOptions.PublicBaseUrl"/> and
/// <see cref="SentomaruClientOptions.KnownProxies"/>, never raw <c>X-Forwarded-*</c>), the exact
/// <c>application/json</c> the Sentomaru guard demands (the client posts it), and the answer the app can act on.
/// <para>Answers: 2xx with the typed value, <b>re-serialized by the host's JSON formatter</b> (a field Sentomaru adds that
/// the DTO does not have is dropped; the DTOs use <c>[JsonPropertyName]</c>, which Newtonsoft ignores, so with Newtonsoft
/// the names match only through camelCase); 400, 409, 413, 422 and 429 with their code (the app's request is the
/// problem); 401 only for <c>proof-invalid</c> or <c>challenge-invalid</c> (the app asks for a new challenge) and 403
/// only for <c>session-unavailable</c>, <c>session-expired</c>, <c>installation-suspended</c> (4.3.0),
/// <c>operation-context</c> or <c>enrollment-context</c>
/// (the signed URI or scope headers do not map to the route: the app's request, or this backend's
/// <c>PublicBaseUrl</c> being wrong); any other 401/403 is this backend's own credential, scope or entitlement (502
/// <c>sentomaru-integration-error</c>, logged as Error: it must never reach the app, whose HTTP stack may read a 401 as
/// "log the user out"); 5xx or Sentomaru down is 503 <c>sentomaru-unavailable</c>. The logs carry the status and the
/// Sentomaru code, never a token, a body or an identifier.</para>
/// </summary>
public abstract class SentomaruEnrollmentControllerBase(
    ISentomaruClient sentomaru, IOptions<SentomaruClientOptions> options, ILogger logger) : ControllerBase
{
    /// <summary>
    /// Decision of the challenge for the caller resolved from the session (your <see cref="ISentomaruContextResolver"/>):
    /// return a result to refuse (for example a tenant the user does not belong to) or null to go on. <b>Abstract on
    /// purpose</b>: whether the resolved tenant belongs to the user is the consumer's rule, and a base that allowed by
    /// default would let a migrated consumer that forgot it hand out challenges for a tenant the user is not in. Say
    /// <c>=&gt; Task.FromResult&lt;IActionResult?&gt;(null)</c> when the resolver already guarantees it.
    /// </summary>
    protected abstract Task<IActionResult?> AuthorizeCallerAsync(CallerContextDto caller, CancellationToken cancellationToken);

    /// <summary>The challenge for the authenticated caller. 401 without a session, 403 <c>caller-context-missing</c> without a usable caller.</summary>
    protected async Task<IActionResult> IssueChallengeAsync(SentomaruChallengeInput? input, string? env, CancellationToken cancellationToken)
    {
        if (Gate(env) is { } refused) return refused;
        if (User.Identity?.IsAuthenticated != true)
            return StatusCode(StatusCodes.Status401Unauthorized, new SentomaruApiError { Code = "authentication-required" });
        var resolver = HttpContext.RequestServices.GetService(typeof(ISentomaruContextResolver)) as ISentomaruContextResolver
                       ?? new DefaultSentomaruContextResolver();
        var caller = resolver.ResolveContext(HttpContext);
        if (!caller.Usable)
        {
            if ((HttpContext.RequestServices.GetService(typeof(SentomaruNotices)) as SentomaruNotices)?.MissingCallerLogDue() ?? true)
                logger.LogError("Sentomaru: no subject/tenant from the authenticated session for the challenge (caller-context-missing; " +
                    "logged at most once a minute). Register an ISentomaruContextResolver that reads your claims.");
            return StatusCode(StatusCodes.Status403Forbidden, new SentomaruApiError { Code = "caller-context-missing" });
        }
        if (await AuthorizeCallerAsync(caller, cancellationToken) is { } denied) return denied;
        var result = await sentomaru.IssueChallengeAsync(new ChallengeRequestDto
        {
            Subject = caller.Subject, Tenant = caller.Tenant, PublicKeyPem = input?.PublicKeyPem,
        }, cancellationToken);
        return Answer(result, "challenge", StatusCodes.Status201Created);
    }

    /// <summary>Forwards the app-signed enrollment as received.</summary>
    protected async Task<IActionResult> CompleteEnrollmentAsync(string? env, CancellationToken cancellationToken)
    {
        if (Gate(env) is { } refused) return refused;
        var (message, failure) = await ExtractAsync(cancellationToken);
        if (failure is not null) return failure;
        var result = await sentomaru.CompleteEnrollmentAsync(new EnrollmentEnvelopeDto { Request = message! }, cancellationToken);
        return Answer(result, "enrollment", StatusCodes.Status201Created);
    }

    /// <summary>Forwards the app-signed grant renewal as received (4.1.0 <see cref="ISentomaruClient.RenewSessionAsync"/>).</summary>
    protected async Task<IActionResult> RenewSessionAsync(string? env, CancellationToken cancellationToken)
    {
        if (Gate(env) is { } refused) return refused;
        var (message, failure) = await ExtractAsync(cancellationToken);
        if (failure is not null) return failure;
        var result = await sentomaru.RenewSessionAsync(new SessionRenewalEnvelopeDto { Request = message! }, cancellationToken);
        return Answer(result, "session renewal", StatusCodes.Status200OK);
    }

    /// <summary>Forwards step 1 of the app-signed reattestation (4.9.0 <see cref="ISentomaruClient.IssueReattestationChallengeAsync"/>).</summary>
    protected async Task<IActionResult> IssueReattestationChallengeAsync(string? env, CancellationToken cancellationToken)
    {
        if (Gate(env) is { } refused) return refused;
        var (message, failure) = await ExtractAsync(cancellationToken);
        if (failure is not null) return failure;
        var result = await sentomaru.IssueReattestationChallengeAsync(new ReattestationEnvelopeDto { Request = message! }, cancellationToken);
        return Answer(result, "reattestation challenge", StatusCodes.Status201Created);
    }

    /// <summary>Forwards step 2 of the app-signed reattestation (4.9.0 <see cref="ISentomaruClient.ReattestAsync"/>).</summary>
    protected async Task<IActionResult> ReattestAsync(string? env, CancellationToken cancellationToken)
    {
        if (Gate(env) is { } refused) return refused;
        var (message, failure) = await ExtractAsync(cancellationToken);
        if (failure is not null) return failure;
        var result = await sentomaru.ReattestAsync(new ReattestationEnvelopeDto { Request = message! }, cancellationToken);
        return Answer(result, "reattestation", StatusCodes.Status200OK);
    }

    /// <summary>4.19.0 (D-25): forwards the app's signed <c>tx_key_challenge</c> (<see cref="ISentomaruClient.CreateTransactionKeyChallengeAsync"/>);
    /// 201 a new challenge, 200 the live one.</summary>
    protected Task<IActionResult> CreateTransactionKeyChallengeAsync(string? env, CancellationToken cancellationToken) =>
        ForwardTransactionKeyAsync(env, (envelope, ct) => sentomaru.CreateTransactionKeyChallengeAsync(envelope, ct),
            "transaction key challenge", StatusCodes.Status201Created, cancellationToken);

    /// <summary>4.19.0 (D-25): forwards the app's signed <c>tx_key_enroll</c> (<see cref="ISentomaruClient.EnrollTransactionKeyAsync"/>);
    /// a 422 <c>user-auth-not-proven</c> reaches the app with its <c>attestationReason</c>.</summary>
    protected Task<IActionResult> EnrollTransactionKeyAsync(string? env, CancellationToken cancellationToken) =>
        ForwardTransactionKeyAsync(env, (envelope, ct) => sentomaru.EnrollTransactionKeyAsync(envelope, ct),
            "transaction key enrollment", StatusCodes.Status201Created, cancellationToken);

    /// <summary>4.19.0 (D-25): forwards the app's signed <c>tx_key_status</c> (<see cref="ISentomaruClient.GetTransactionKeyStatusAsync"/>).</summary>
    protected Task<IActionResult> GetTransactionKeyStatusAsync(string? env, CancellationToken cancellationToken) =>
        ForwardTransactionKeyAsync(env, (envelope, ct) => sentomaru.GetTransactionKeyStatusAsync(envelope, ct),
            "transaction key status", StatusCodes.Status200OK, cancellationToken);

    /// <summary>4.19.0 (D-25): forwards the app's signed <c>tx_key_revoke</c> (<see cref="ISentomaruClient.RevokeTransactionKeyAsync"/>);
    /// 204 without a body, also when there was no key.</summary>
    protected async Task<IActionResult> RevokeTransactionKeyAsync(string? env, CancellationToken cancellationToken)
    {
        var answer = await ForwardTransactionKeyAsync(env, (envelope, ct) => sentomaru.RevokeTransactionKeyAsync(envelope, ct),
            "transaction key revocation", StatusCodes.Status204NoContent, cancellationToken);
        return answer is ObjectResult { Value: true, StatusCode: >= 200 and < 300 } ? NoContent() : answer;
    }

    private async Task<IActionResult> ForwardTransactionKeyAsync<T>(string? env,
        Func<TransactionKeyEnvelopeDto, CancellationToken, Task<SentomaruClientResult<T>>> call, string what, int successStatus,
        CancellationToken cancellationToken)
    {
        if (Gate(env) is { } refused) return refused;
        var (message, failure) = await ExtractAsync(cancellationToken);
        if (failure is not null) return failure;
        var result = await call(new TransactionKeyEnvelopeDto { Request = message! }, cancellationToken);
        return Answer(result, what, successStatus);
    }

    private IActionResult? Gate(string? env)
    {
        var current = options.Value;
        if (!current.Enabled)
            return StatusCode(StatusCodes.Status503ServiceUnavailable, new SentomaruApiError { Code = "sentomaru-disabled" });
        if (env is not null && !string.Equals(env, current.Env, StringComparison.Ordinal))
            return NotFound(new SentomaruApiError { Code = "sentomaru-env-unknown" });
        return null;
    }

    private async Task<(ForwardedMessageDto? Message, IActionResult? Failure)> ExtractAsync(CancellationToken cancellationToken)
    {
        try
        {
            return (await SentomaruExtractor.ExtractAsync(Request, null, options.Value, cancellationToken), null);
        }
        catch (SentomaruBodyTooLargeException)
        {
            return (null, StatusCode(StatusCodes.Status413PayloadTooLarge, new SentomaruApiError { Code = "body-limit" }));
        }
        catch (Exception exception) when (exception is FormatException or ArgumentException or InvalidOperationException or UriFormatException)
        {
            // A client abort (IOException, cancellation) is not a malformed request: it propagates.
            logger.LogWarning(exception, "Sentomaru: the app's request could not be forwarded (malformed)");
            return (null, BadRequest(new SentomaruApiError { Code = "forward-format" }));
        }
    }

    private static readonly HashSet<string> SessionRefusals = new(StringComparer.Ordinal)
    {
        "session-unavailable", "session-expired", "operation-context", "enrollment-context",
        "reattestation-disabled", "reattestation-unsupported", // 4.9.0: the scope has it off / an App Attest installation
        "installation-suspended", // 4.3.0: temporary suspension (installation response); the app waits, never re-enrolls
    };

    private static readonly System.Text.RegularExpressions.Regex CodeShape = new(@"^[a-z0-9][a-z0-9_-]{0,63}\z",
        System.Text.RegularExpressions.RegexOptions.Compiled | System.Text.RegularExpressions.RegexOptions.CultureInvariant);

    private IActionResult Answer<T>(SentomaruClientResult<T> result, string what, int successStatus)
    {
        if (result.Succeeded) return StatusCode(result.StatusCode is >= 200 and < 300 ? result.StatusCode : successStatus, result.Value);
        var status = result.StatusCode;
        var code = result.ErrorCode is { } c && CodeShape.IsMatch(c) ? c : "integrity-error"; // never echo an unbounded string
        var forApp = status switch
        {
            400 or 409 or 413 or 422 or 429 => true,
            401 => code is "proof-invalid" or "challenge-invalid",
            403 => SessionRefusals.Contains(code),
            503 => code is "verifier-unavailable", // 4.9.0: reattestation only; the challenge was not consumed, the app may retry once
            _ => false,
        };
        if (forApp)
        {
            // 4.8.0: the attestation reason (a short slug such as aaguid_mismatch, only with 422 hardware-not-proven) is
            // logged too, so the consumer can tell why without the app's body; anything else is logged as "-".
            var reason = result.AttestationReason is { } r && CodeShape.IsMatch(r) ? r : "-";
            logger.LogWarning("Sentomaru refused the {What}: Status={Status}, Code={Code}, AttestationReason={AttestationReason}",
                what, status, code, reason);
            // 4.19.0: Sentomaru's wait (429) reaches the app, so the SDK waits that long instead of a fixed "not now".
            if (result.RetryAfterSeconds is { } wait)
                Response.Headers.RetryAfter = wait.ToString(System.Globalization.CultureInfo.InvariantCulture);
            return StatusCode(status, new SentomaruApiError { Code = code, AttestationReason = result.AttestationReason });
        }
        if (status is >= 400 and < 500)
        {
            logger.LogError("Sentomaru refused this backend on the {What} (credential, scope or entitlement): Status={Status}, Code={Code}",
                what, status, code);
            return StatusCode(StatusCodes.Status502BadGateway, new SentomaruApiError { Code = "sentomaru-integration-error" });
        }
        logger.LogWarning("Sentomaru unavailable on the {What}: Status={Status}, Code={Code}", what, status, code);
        return StatusCode(StatusCodes.Status503ServiceUnavailable, new SentomaruApiError { Code = "sentomaru-unavailable" });
    }
}
