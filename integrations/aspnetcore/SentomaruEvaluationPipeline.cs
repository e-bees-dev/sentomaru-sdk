using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Sentomaru.AspNetCore;

/// <summary>4.7.0 (D-17a): what <see cref="SentomaruEvaluationPipeline"/> decided for one request.</summary>
public enum SentomaruDecisionKind
{
    /// <summary>The protected operation may run once (see <see cref="SentomaruDecision.Reason"/>).</summary>
    Proceed,

    /// <summary>The protected operation must not run; answer <see cref="SentomaruDecision.StatusCode"/> with
    /// <see cref="SentomaruDecision.Error"/> as the body.</summary>
    Refuse
}

/// <summary>4.7.0 (D-17a): why a <see cref="SentomaruDecisionKind.Proceed"/> decision lets the operation run.</summary>
public enum SentomaruProceedReason
{
    /// <summary>Not a proceed decision.</summary>
    None,

    /// <summary>Sentomaru answered <c>allow</c> or <c>shadow</c> (and the operation id, if any, is a first admission or
    /// the route allows a replay).</summary>
    Verified,

    /// <summary><see cref="DeviceAssuranceLevel.Observe"/>: the operation always runs; the evaluation, if one was made, is
    /// in <see cref="SentomaruDecision.Evaluation"/> and <see cref="SentomaruIntegrityAttribute.ObservationItem"/>.</summary>
    Observe,

    /// <summary><see cref="SentomaruClientOptions.Enabled"/> is false (Development, or the acknowledged kill switch).</summary>
    Disabled,

    /// <summary>Development only: Sentomaru unavailable with <see cref="SentomaruClientOptions.FailOpen"/>.</summary>
    FailOpen,

    /// <summary>A <c>step_up</c> challenge whose <see cref="ISentomaruChallengeHandler"/> answered Proceed.</summary>
    StepUpProceeded
}

/// <summary>
/// 4.7.0 (D-17a): options of one decision, the members of <see cref="SentomaruIntegrityAttribute"/> without MVC.
/// </summary>
/// <param name="Operation">The operation of the route (never taken from the client; 4.19.0: the default when
/// <see cref="OperationRules"/> picks one of the configured operations from the body).</param>
public sealed record SentomaruEvaluationOptions(string Operation)
{
    /// <summary>Same as <see cref="SentomaruIntegrityAttribute.AssuranceLevel"/>.</summary>
    public DeviceAssuranceLevel AssuranceLevel { get; init; } = DeviceAssuranceLevel.ZeroTrust;

    /// <summary>Same as <see cref="SentomaruIntegrityAttribute.AllowOperationReplay"/>.</summary>
    public bool AllowOperationReplay { get; init; }

    /// <summary>Same as <see cref="SentomaruIntegrityAttribute.PublicBaseUrlOverride"/>.</summary>
    public string? PublicBaseUrlOverride { get; init; }

    /// <summary>
    /// True (the attribute) asks a registered <see cref="ISentomaruChallengeHandler"/> on a <c>step_up</c> challenge.
    /// False (a gateway verifier, which has no session to step up) answers every challenge with 401
    /// <c>challenge-required</c>, as the attribute does without a hook.
    /// </summary>
    public bool UseChallengeHandler { get; init; } = true;

    /// <summary>
    /// 4.19.0: the name of a set in <see cref="SentomaruClientOptions.OperationRules"/>. With it, <see cref="Operation"/> is the
    /// default and the first rule whose value matches the JSON body replaces it for this request (a body that cannot be
    /// read or parsed picks the first rule's operation). Null (default) keeps <see cref="Operation"/>.
    /// </summary>
    public string? OperationRules { get; init; }
}

/// <summary>
/// 4.7.0 (D-17a): the decision of <see cref="SentomaruEvaluationPipeline.DecideAsync"/>. On
/// <see cref="SentomaruDecisionKind.Refuse"/>, <see cref="StatusCode"/> and <see cref="Error"/> are the response the
/// attribute writes (the same JSON body). On <see cref="SentomaruDecisionKind.Proceed"/>, the caller runs the operation
/// exactly once.
/// </summary>
public sealed record SentomaruDecision
{
    public SentomaruDecisionKind Kind { get; init; }

    public SentomaruProceedReason Reason { get; init; }

    /// <summary>The refusal status; 200 on proceed.</summary>
    public int StatusCode { get; init; }

    /// <summary>The refusal body; null on proceed.</summary>
    public SentomaruApiError? Error { get; init; }

    /// <summary>The verdict Sentomaru returned, when an evaluation succeeded (also on a refusal by verdict).</summary>
    public EvaluationResponseDto? Evaluation { get; init; }

    public static SentomaruDecision Proceed(SentomaruProceedReason reason, EvaluationResponseDto? evaluation = null) =>
        new() { Kind = SentomaruDecisionKind.Proceed, Reason = reason, StatusCode = StatusCodes.Status200OK, Evaluation = evaluation };

    public static SentomaruDecision Refuse(int statusCode, SentomaruApiError error, EvaluationResponseDto? evaluation = null) =>
        new() { Kind = SentomaruDecisionKind.Refuse, StatusCode = statusCode, Error = error, Evaluation = evaluation };
}

/// <summary>
/// 4.7.0 (D-17a, spec D-17 item 6): the decision of <see cref="SentomaruIntegrityAttribute"/> without MVC, so a gateway
/// verifier answers what the attribute would answer for the same request. One call evaluates at most once (one nonce);
/// it records <see cref="SentomaruIntegrityAttribute.ObservationItem"/>, <see cref="SentomaruIntegrityAttribute.OperationIdItem"/>,
/// <see cref="SentomaruIntegrityAttribute.FirstAdmissionItem"/> and <see cref="SentomaruIntegrityAttribute.StepUpProceededItem"/>
/// as the attribute does. What happens after the operation ran (the release of an operation id after a 5xx) stays with
/// the caller. Services are read from <see cref="HttpContext.RequestServices"/>, as in the attribute.
/// </summary>
public static class SentomaruEvaluationPipeline
{
    // Manual registrations without AddSentomaruClient still warn once per process.
    private static readonly SentomaruNotices FallbackNotices = new();

    public static async Task<SentomaruDecision> DecideAsync(HttpContext httpContext, SentomaruEvaluationOptions request,
        ILogger? logger = null)
    {
        var decision = await DecideCoreAsync(httpContext, request, logger);
        if (decision.Kind != SentomaruDecisionKind.Refuse || decision.Error is not { Message: null } error) return decision;
        // sdk-user-message-v1: only the presentable text is added; code, status and the rest of the body are unchanged.
        var situation = SentomaruUserMessage.SituationForRefusal(error.Code, decision.StatusCode);
        if (situation is null) return decision;
        var configured = httpContext.RequestServices.GetService<IOptions<SentomaruClientOptions>>()?.Value;
        if (configured is not { IncludeUserMessage: true }) return decision;
        var message = SentomaruUserMessage.Resolve(situation, SentomaruUserMessage.FromAcceptLanguage(httpContext.Request.Headers.AcceptLanguage.ToString()), configured.UserMessages);
        return decision with { Error = error with { Message = message } };
    }

    private static async Task<SentomaruDecision> DecideCoreAsync(HttpContext httpContext, SentomaruEvaluationOptions request,
        ILogger? logger)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        ArgumentNullException.ThrowIfNull(request);
        var services = httpContext.RequestServices;
        var client = services.GetService<ISentomaruClient>();
        var options = services.GetService<IOptions<SentomaruClientOptions>>()?.Value ?? new SentomaruClientOptions();
        if (request.OperationRules is { } setName)
        {
            // 4.19.0: the operation chosen from the body replaces the route's default for everything below (evaluation,
            // OperationItem, logs, the step-up hook). An unknown or invalid set (startup validation bypassed) is a
            // misconfiguration: never fails open.
            if (SentomaruOperationRules.FindSet(options, setName) is not { Count: > 0 } rules ||
                SentomaruOperationRules.Validate(new Dictionary<string, List<SentomaruOperationRule>> { [setName] = rules }).Count > 0)
            {
                httpContext.Items[SentomaruIntegrityAttribute.OperationItem] = request.Operation;
                logger?.LogError("Sentomaru:OperationRules has no valid set {Set} (route {Operation}); refusing.", setName, request.Operation);
                return Error(StatusCodes.Status503ServiceUnavailable, "integrity-unavailable");
            }
            request = request with { Operation = await SelectOperationAsync(httpContext, rules, request.Operation) };
        }
        var operation = request.Operation;
        httpContext.Items[SentomaruIntegrityAttribute.OperationItem] = operation;
        var isDevelopment = services.GetService<IHostEnvironment>()?.IsDevelopment() == true;

        if (!options.Enabled)
        {
            if (isDevelopment)
            {
                logger?.LogWarning("Sentomaru disabled (Development); {Operation} is unprotected.", operation);
                return SentomaruDecision.Proceed(SentomaruProceedReason.Disabled);
            }
            if (!options.DisabledAcknowledged)
            {
                // Not acknowledged (startup validation bypassed, e.g. manual registration): fail closed.
                logger?.LogError("Sentomaru:Enabled=false without DisabledAcknowledged outside Development; refusing {Operation}.", operation);
                return Error(StatusCodes.Status503ServiceUnavailable, "integrity-unavailable");
            }
            logger?.LogError("Sentomaru DISABLED (acknowledged kill switch): {Operation} runs without verification.", operation);
            return SentomaruDecision.Proceed(SentomaruProceedReason.Disabled);
        }

        var hasProof = HasHeader(httpContext.Request, "Signature-Input") && HasHeader(httpContext.Request, "Signature");

        if (request.AssuranceLevel == DeviceAssuranceLevel.Observe)
        {
            var observed = await ObserveAsync(httpContext, request, client, options, isDevelopment, logger, hasProof);
            return SentomaruDecision.Proceed(SentomaruProceedReason.Observe, observed);
        }

        if (client is null)
        {
            // Misconfiguration never fails open.
            logger?.LogError("ISentomaruClient is not registered; refusing protected operation {Operation}.", operation);
            return Error(StatusCodes.Status503ServiceUnavailable, "integrity-unavailable");
        }

        // Absent signature headers are always 401: FailOpen covers Sentomaru outages, never an absent proof.
        // "hasProof" means both headers are present and non-empty; validity is decided by Sentomaru only.
        if (!hasProof)
        {
            return Error(StatusCodes.Status401Unauthorized, "proof-required");
        }

        var caller = ResolveCaller(httpContext, operation, options, isDevelopment, logger);
        if (caller is null)
        {
            return Error(StatusCodes.Status403Forbidden, "caller-context-missing");
        }

        var evalResult = await EvaluateGuardedAsync(httpContext, request, client, caller, logger);
        Record(httpContext, evalResult);
        if (evalResult is null)
        {
            return Error(StatusCodes.Status413PayloadTooLarge, "body-limit");
        }

        if (!evalResult.Succeeded)
        {
            // FailOpen is honoured only in Development, and only for an outage when signature headers were present
            // (unverified: in Development a forged proof passes during an outage).
            if (evalResult.StatusCode == StatusCodes.Status503ServiceUnavailable && options.FailOpen)
            {
                if (isDevelopment)
                {
                    logger?.LogWarning("Sentomaru unavailable; FailOpen (Development) lets {Operation} run unverified.", operation);
                    return SentomaruDecision.Proceed(SentomaruProceedReason.FailOpen);
                }
                logger?.LogError("Sentomaru:FailOpen is ignored outside Development; refusing {Operation}.", operation);
            }

            return SentomaruDecision.Refuse(
                evalResult.StatusCode > 0 ? evalResult.StatusCode : StatusCodes.Status403Forbidden,
                new SentomaruApiError
                {
                    Code = evalResult.ErrorCode ?? "integrity-error",
                    AttestationReason = evalResult.AttestationReason
                });
        }

        var evaluation = evalResult.Value!;
        WarnDefaultPolicyOnce(services, evaluation, logger);
        var verdict = evaluation.Verdict;
        if (evaluation.OperationId is { } operationId)
        {
            httpContext.Items[SentomaruIntegrityAttribute.OperationIdItem] = operationId;
            httpContext.Items[SentomaruIntegrityAttribute.FirstAdmissionItem] = evaluation.FirstAdmission;
        }

        switch (verdict)
        {
            case EvaluationVerdict.Allow when evaluation.FirstAdmission == false && !request.AllowOperationReplay:
            case EvaluationVerdict.Shadow when evaluation.FirstAdmission == false && !request.AllowOperationReplay:
                logger?.LogInformation("Sentomaru: {Operation} retried an operation id already admitted; not run again.", operation);
                return SentomaruDecision.Refuse(StatusCodes.Status409Conflict,
                    new SentomaruApiError { Code = "operation-replayed" }, evaluation);

            case EvaluationVerdict.Allow:
            case EvaluationVerdict.Shadow:
                if (verdict == EvaluationVerdict.Shadow)
                {
                    logger?.LogInformation("Sentomaru shadow evaluation for {Operation}: {PolicyStatus}", operation, evaluation.PolicyStatus);
                }
                return SentomaruDecision.Proceed(SentomaruProceedReason.Verified, evaluation);

            case EvaluationVerdict.Challenge:
                // Review of D-06h: a kind this adapter does not know is passed on raw and never reaches the hook.
                var kind = SentomaruChallengeKinds.Raw(evaluation.ChallengeKind);
                if (request.UseChallengeHandler && evaluation.KnownChallengeKind == SentomaruChallengeKind.StepUp &&
                    await StepUpProceedsAsync(httpContext, operation, evaluation, logger))
                {
                    logger?.LogInformation("Sentomaru step_up challenge for {Operation}: the consumer's hook proceeded.", operation);
                    httpContext.Items[SentomaruIntegrityAttribute.StepUpProceededItem] = true;
                    return SentomaruDecision.Proceed(SentomaruProceedReason.StepUpProceeded, evaluation);
                }
                logger?.LogWarning("Sentomaru challenge required for {Operation} (kind {ChallengeKind}).", operation, kind ?? "none");
                return SentomaruDecision.Refuse(StatusCodes.Status401Unauthorized,
                    new SentomaruApiError { Code = "challenge-required", ChallengeKind = kind }, evaluation);

            case EvaluationVerdict.Deny:
            default:
                logger?.LogWarning("Sentomaru integrity policy denied request for {Operation}. Reason: {ReasonCodes}",
                    operation, string.Join(",", evaluation.ReasonCodes ?? []));
                return SentomaruDecision.Refuse(StatusCodes.Status403Forbidden,
                    new SentomaruApiError { Code = evaluation.ReasonCodes?.FirstOrDefault() ?? "policy-denied" }, evaluation);
        }
    }

    /// <summary>
    /// 4.5.0 (D-06b): true only when an <see cref="ISentomaruChallengeHandler"/> is registered and answers
    /// <see cref="SentomaruChallengeDecision.Proceed"/>. A request with a signed operation id never asks the hook (review
    /// R C-1: Sentomaru does not admit a challenge, so FirstAdmission is null and nothing would keep the operation
    /// single-effect, not even an action with <see cref="SentomaruIntegrityAttribute.AllowOperationReplay"/>). A hook that
    /// throws refuses, unless the request itself was cancelled (the cancellation propagates, as everywhere in the filter).
    /// </summary>
    private static async Task<bool> StepUpProceedsAsync(HttpContext httpContext, string operation, EvaluationResponseDto verdict,
        ILogger? logger)
    {
        var handler = httpContext.RequestServices.GetService<ISentomaruChallengeHandler>();
        if (handler is null) return false;
        if (verdict.OperationId is not null)
        {
            logger?.LogWarning("Sentomaru step_up for {Operation} carries a signed operation id; the hook is not called.", operation);
            return false;
        }
        try
        {
            var decision = await handler.HandleAsync(new SentomaruChallengeContext(operation, SentomaruChallengeKinds.StepUp,
                verdict.ReasonCodes ?? [], httpContext), httpContext.RequestAborted);
            return decision == SentomaruChallengeDecision.Proceed;
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !httpContext.RequestAborted.IsCancellationRequested)
        {
            logger?.LogWarning("Sentomaru step_up hook failed for {Operation}: {Type}; refusing.", operation, ex.GetType().Name);
            return false;
        }
    }

    /// <summary>
    /// The caller of the consumer's session, or null (logged at Error) when it has none: an empty value or a resolver
    /// placeholder. In Development with <see cref="SentomaruClientOptions.AllowAnonymousContext"/> the development
    /// placeholders are used instead.
    /// </summary>
    private static CallerContextDto? ResolveCaller(HttpContext httpContext, string operation, SentomaruClientOptions options,
        bool isDevelopment, ILogger? logger)
    {
        var resolver = httpContext.RequestServices.GetService<ISentomaruContextResolver>() ?? new DefaultSentomaruContextResolver();
        var caller = resolver.ResolveContext(httpContext);
        if (caller.Usable) return caller;
        if (isDevelopment && options.AllowAnonymousContext)
        {
            logger?.LogWarning("Sentomaru: no caller context for {Operation}; AllowAnonymousContext (Development) uses placeholders.", operation);
            return new CallerContextDto
            {
                Subject = string.IsNullOrWhiteSpace(caller.Subject) ? "development-anonymous" : caller.Subject,
                Tenant = string.IsNullOrWhiteSpace(caller.Tenant) ? "development-default" : caller.Tenant
            };
        }
        if ((httpContext.RequestServices.GetService<SentomaruNotices>() ?? FallbackNotices).MissingCallerLogDue())
        {
            logger?.LogError("Sentomaru: no subject/tenant from the authenticated session for {Operation} (caller-context-missing; " +
                "logged at most once a minute). Authenticate the route or register an ISentomaruContextResolver that reads your claims.", operation);
        }
        return null;
    }

    private static void WarnDefaultPolicyOnce(IServiceProvider services, EvaluationResponseDto response, ILogger? logger)
    {
        var notices = services.GetService<SentomaruNotices>() ?? FallbackNotices;
        if (response.PolicySource == "default" && notices.FirstDefaultPolicy())
        {
            logger?.LogWarning("Sentomaru: no policy is published for this scope; the built-in default {PolicyId} {PolicyVersion} " +
                "is in force (logged once per process).", response.PolicyId, response.PolicyVersion);
        }
    }

    private static async Task<SentomaruClientResult<EvaluationResponseDto>?> EvaluateAsync(HttpContext httpContext,
        SentomaruEvaluationOptions request, ISentomaruClient client, CallerContextDto caller)
    {
        ForwardedMessageDto forwardedMessage;
        try
        {
            var opts = httpContext.RequestServices.GetService<IOptions<SentomaruClientOptions>>()?.Value;
            forwardedMessage = await SentomaruExtractor.ExtractAsync(httpContext.Request, request.PublicBaseUrlOverride, opts, httpContext.RequestAborted);
        }
        catch (SentomaruBodyTooLargeException)
        {
            return null;
        }
        catch (UriFormatException)
        {
            // 4.7.0 (D-17b review R I-1): no @target-uri under publicBaseUrl (a network-path reference such as "//host/x").
            // The request is malformed, not Sentomaru unavailable: 400 forward-format, as SentomaruEnrollmentControllerBase
            // answers it; Sentomaru is not called.
            return SentomaruClientResult<EvaluationResponseDto>.Failure(StatusCodes.Status400BadRequest, "forward-format");
        }

        var bindingOptions = httpContext.RequestServices.GetService<IOptions<SentomaruClientOptions>>()?.Value;
        return await client.EvaluateAsync(new EvaluationRequestDto
        {
            Operation = request.Operation,
            Request = forwardedMessage,
            Context = caller,
            ExternalTokenBindingHash = SentomaruTokenBinding.ForPrincipal(bindingOptions, httpContext.User),
        }, httpContext.RequestAborted);
    }

    /// <summary>
    /// <see cref="EvaluateAsync"/> with an evaluation failure (any exception except cancellation) turned into a 503
    /// <c>integrity-unavailable</c> result, so it is recorded for the consumer (4.4.0) and the ZeroTrust path answers
    /// it like an outage (FailOpen still honoured only in Development) instead of letting the exception escape.
    /// </summary>
    private static async Task<SentomaruClientResult<EvaluationResponseDto>?> EvaluateGuardedAsync(HttpContext httpContext,
        SentomaruEvaluationOptions request, ISentomaruClient client, CallerContextDto caller, ILogger? logger)
    {
        try
        {
            return await EvaluateAsync(httpContext, request, client, caller);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger?.LogWarning("Sentomaru evaluation failed for {Operation}: {Type}.", request.Operation, ex.GetType().Name);
            return SentomaruClientResult<EvaluationResponseDto>.Failure(StatusCodes.Status503ServiceUnavailable, "integrity-unavailable");
        }
    }

    /// <summary>Observe never blocks; returns the verdict when one was obtained.</summary>
    private static async Task<EvaluationResponseDto?> ObserveAsync(HttpContext httpContext, SentomaruEvaluationOptions request,
        ISentomaruClient? client, SentomaruClientOptions options, bool isDevelopment, ILogger? logger, bool hasProof)
    {
        if (!hasProof || client is null)
        {
            logger?.LogWarning("Sentomaru Observe (no protection): {Operation} ran without a verifiable proof.", request.Operation);
            return null;
        }
        var caller = ResolveCaller(httpContext, request.Operation, options, isDevelopment, logger);
        if (caller is null)
        {
            // Observe never blocks: the action runs, the missing session context is logged (Error) and nothing is sent.
            return null;
        }
        var result = await EvaluateGuardedAsync(httpContext, request, client, caller, logger);
        Record(httpContext, result);
        if (result?.Value is { } observed) WarnDefaultPolicyOnce(httpContext.RequestServices, observed, logger);
        logger?.LogInformation("Sentomaru Observe (no protection): {Operation} verdict {Verdict} status {Status}.",
            request.Operation, result?.Value?.RecommendedAction ?? result?.ErrorCode ?? "body-limit", result?.StatusCode);
        return result?.Value;
    }

    private static void Record(HttpContext context, SentomaruClientResult<EvaluationResponseDto>? result) =>
        context.Items[SentomaruIntegrityAttribute.ObservationItem] = result is null
            ? new SentomaruObservation(StatusCodes.Status413PayloadTooLarge, "body-limit", null, Guid.Empty)
            : result.Succeeded && result.Value is { } value
                ? new SentomaruObservation(result.StatusCode, null, value.RecommendedAction, value.InstallationId, value.ProofStatus)
                {
                    ChallengeKind = value.Verdict == EvaluationVerdict.Challenge ? SentomaruChallengeKinds.Raw(value.ChallengeKind) : null
                }
                : new SentomaruObservation(result.StatusCode, result.ErrorCode, null, Guid.Empty);

    /// <summary>4.19.0: the body is read through the extractor's buffer (once per request, same 64 KiB limit); over the
    /// limit it is "unreadable", which picks the first rule's operation.</summary>
    private static async Task<string> SelectOperationAsync(HttpContext httpContext, List<SentomaruOperationRule> rules, string defaultOperation)
    {
        ReadOnlyMemory<byte>? body;
        try
        {
            body = await SentomaruExtractor.ReadBodyAsync(httpContext.Request, httpContext.RequestAborted);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Over the limit, or a read failure (the evaluation below meets it again and answers as before).
            body = null;
        }
        return SentomaruOperationRules.Select(rules, body, defaultOperation);
    }

    private static bool HasHeader(HttpRequest request, string name) =>
        request.Headers.TryGetValue(name, out var values) && values.Any(v => !string.IsNullOrWhiteSpace(v));

    private static SentomaruDecision Error(int status, string code) =>
        SentomaruDecision.Refuse(status, new SentomaruApiError { Code = code });
}
