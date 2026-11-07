using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Sentomaru.AspNetCore;

namespace ThirdPartyApi;

/// <summary>
/// The public enrollment routes the app calls (challenge, enrollment, renewal, reattestation). The challenge is issued by this backend (it holds the workload
/// token) for the caller it authenticated; the enrollment itself is signed by the app and forwarded as received.
/// </summary>
[ApiController]
[Route("integrity")]
public sealed class EnrollmentController(ISentomaruClient sentomaru, IOptions<SentomaruClientOptions> options,
    ISentomaruContextResolver callers) : ControllerBase
{
    public sealed record ChallengeInput(string? PublicKeyPem);

    // guide:begin challenge
    [HttpPost("challenges")]
    public async Task<IActionResult> Challenge([FromBody] ChallengeInput? input, CancellationToken ct)
    {
        // Your authentication sets HttpContext.User; subject and tenant come from it, never from the app's body.
        if (User.Identity?.IsAuthenticated != true) return Unauthorized();
        var caller = callers.ResolveContext(HttpContext);
        if (string.IsNullOrEmpty(caller.Subject) || string.IsNullOrEmpty(caller.Tenant))
            return StatusCode(StatusCodes.Status403Forbidden, new SentomaruApiError { Code = "caller-context-missing" });
        var result = await sentomaru.IssueChallengeAsync(new ChallengeRequestDto
        {
            Subject = caller.Subject, Tenant = caller.Tenant, PublicKeyPem = input?.PublicKeyPem,
        }, ct);
        return result.Succeeded
            ? StatusCode(StatusCodes.Status201Created, result.Value)
            : StatusCode(result.StatusCode, new SentomaruApiError { Code = result.ErrorCode ?? "integrity-error" });
    }
    // guide:end challenge

    // guide:begin enrollment
    // The app signs this exact public URL: <PublicBaseUrl>/integrity/v1/{org}/{app}/{env}/installations.
    [HttpPost("v1/{org}/{app}/{env}/installations")]
    public async Task<IActionResult> Enroll(CancellationToken ct)
    {
        ForwardedMessageDto message;
        try
        {
            message = await SentomaruExtractor.ExtractAsync(Request, null, options.Value, ct);
        }
        catch (SentomaruBodyTooLargeException)
        {
            return StatusCode(StatusCodes.Status413PayloadTooLarge, new SentomaruApiError { Code = "body-limit" });
        }
        var result = await sentomaru.CompleteEnrollmentAsync(new EnrollmentEnvelopeDto { Request = message }, ct);
        return result.Succeeded
            ? StatusCode(result.StatusCode, result.Value)
            : StatusCode(result.StatusCode, new SentomaruApiError { Code = result.ErrorCode ?? "integrity-error" });
    }
    // guide:end enrollment

    // J-04r grant renewal (the SDK's renew(), `renewalUrl` in its config): the app signs
    // <PublicBaseUrl>/integrity/v1/{org}/{app}/{env}/sessions, forwarded as received. Without this route the example's
    // apps cannot renew (their profiles leave `renewalUrl` out); the iOS example (D-10 Phase 5) sets it.
    [HttpPost("v1/{org}/{app}/{env}/sessions")]
    public async Task<IActionResult> Renew(CancellationToken ct)
    {
        var message = await SentomaruExtractor.ExtractAsync(Request, null, options.Value, ct);
        var result = await sentomaru.RenewSessionAsync(new SessionRenewalEnvelopeDto { Request = message }, ct);
        return result.Succeeded
            ? StatusCode(result.StatusCode, result.Value)
            : StatusCode(result.StatusCode, new SentomaruApiError { Code = result.ErrorCode ?? "integrity-error" });
    }

    // D-12b (adapter 4.9.0): the two reattestation routes the app's reattest() calls, forwarded as received. The scope
    // must have the reattestation on (otherwise 403 reattestation-disabled, which the app shows as a refusal).
    [HttpPost("v1/{org}/{app}/{env}/reattestations/challenges")]
    public async Task<IActionResult> ReattestChallenge(CancellationToken ct)
    {
        var message = await SentomaruExtractor.ExtractAsync(Request, null, options.Value, ct);
        var result = await sentomaru.IssueReattestationChallengeAsync(new ReattestationEnvelopeDto { Request = message }, ct);
        return result.Succeeded
            ? StatusCode(result.StatusCode, result.Value)
            : StatusCode(result.StatusCode, new SentomaruApiError { Code = result.ErrorCode ?? "integrity-error" });
    }

    [HttpPost("v1/{org}/{app}/{env}/reattestations")]
    public async Task<IActionResult> Reattest(CancellationToken ct)
    {
        var message = await SentomaruExtractor.ExtractAsync(Request, null, options.Value, ct);
        var result = await sentomaru.ReattestAsync(new ReattestationEnvelopeDto { Request = message }, ct);
        return result.Succeeded
            ? StatusCode(result.StatusCode, result.Value)
            : StatusCode(result.StatusCode, new SentomaruApiError { Code = result.ErrorCode ?? "integrity-error" });
    }
}
