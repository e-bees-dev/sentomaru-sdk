using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Sentomaru.AspNetCore;

/// <summary>
/// Strategy to extract the authenticated caller identity (subject and tenant) from the current request context.
/// Default implementation reads from ClaimsPrincipal claims ("sub" or NameIdentifier, and "tenant" or "IdVarejista").
/// </summary>
public interface ISentomaruContextResolver
{
    CallerContextDto ResolveContext(HttpContext context);
}

/// <summary>
/// Default claims-based caller context resolver. 4.0.0 (C-09, #142): a missing claim is no longer filled with
/// <c>anonymous</c>/<c>default</c> (which merged every caller without a claim into one bucket): it stays empty, and the
/// filter refuses with 403 <c>caller-context-missing</c> and an Error log. Claims read, in order: subject from
/// NameIdentifier, <c>sub</c>, <c>id_usuario</c>, the identity name; tenant from <c>tenant</c>, <c>tenant_id</c>,
/// <c>id_varejista</c>, <c>IdVarejista</c>. Register your own <see cref="ISentomaruContextResolver"/> when your session
/// names them differently.
/// </summary>
public sealed class DefaultSentomaruContextResolver : ISentomaruContextResolver
{
    public CallerContextDto ResolveContext(HttpContext context)
    {
        var user = context.User;
        var subject = user.FindFirstValue(ClaimTypes.NameIdentifier) ??
                      user.FindFirstValue("sub") ??
                      user.FindFirstValue("id_usuario") ??
                      user.Identity?.Name ??
                      "";

        var tenant = user.FindFirstValue("tenant") ??
                     user.FindFirstValue("tenant_id") ??
                     user.FindFirstValue("id_varejista") ??
                     user.FindFirstValue("IdVarejista") ??
                     "";

        return new CallerContextDto
        {
            Subject = subject,
            Tenant = tenant
        };
    }
}

/// <summary>
/// 4.0.0 (C-09): process-wide log state, a DI singleton (registered by <c>AddSentomaruClient</c>). The Warning that
/// the built-in default policy is in force is written once per process; the Error for a request without a session
/// caller at most once per minute (the 403 itself is answered every time).
/// </summary>
public sealed class SentomaruNotices
{
    private int defaultPolicyWarned;
    private long missingCallerLoggedAt = long.MinValue;

    /// <summary>True the first time only (thread-safe).</summary>
    public bool FirstDefaultPolicy() => Interlocked.Exchange(ref defaultPolicyWarned, 1) == 0;

    /// <summary>True when the missing-caller Error was not logged in the last minute (thread-safe).</summary>
    public bool MissingCallerLogDue()
    {
        var now = Environment.TickCount64;
        var last = Interlocked.Read(ref missingCallerLoggedAt);
        return (last == long.MinValue || now - last >= 60_000) &&
               Interlocked.CompareExchange(ref missingCallerLoggedAt, now, last) == last;
    }
}

/// <summary>
/// Decorator attribute that enforces Sentomaru hardware and cryptographic integrity on an endpoint/action.
/// </summary>
[AttributeUsage(AttributeTargets.Method | AttributeTargets.Class, AllowMultiple = false, Inherited = true)]
public sealed class SentomaruIntegrityAttribute : Attribute, IAsyncActionFilter
{
    public string Operation { get; }
    public string? PublicBaseUrlOverride { get; set; }
    public DeviceAssuranceLevel AssuranceLevel { get; set; } = DeviceAssuranceLevel.ZeroTrust;

    /// <summary>
    /// 3.1.0 (J-01f, RETRY-01): when the app retries an operation id Sentomaru already admitted (firstAdmission=false),
    /// the action does NOT run again: 409 <c>operation-replayed</c>. Set true only where the action itself returns the
    /// result it stored for that id (read it from <see cref="OperationIdItem"/> / <see cref="FirstAdmissionItem"/>).
    /// </summary>
    public bool AllowOperationReplay { get; set; }

    /// <summary>HttpContext.Items keys set on an allowed evaluation that carried a signed operation id.</summary>
    public const string OperationIdItem = "sentomaru-operation-id";
    public const string FirstAdmissionItem = "sentomaru-first-admission";

    /// <summary>4.14.0: HttpContext.Items key with the operation name of the route this filter protected (a string from the route's own declaration, never from the request).</summary>
    public const string OperationItem = "sentomaru-operation";

    /// <summary>
    /// 4.4.0 (resposta por instalação, tarefa 6): HttpContext.Items key with the <see cref="SentomaruObservation"/> of
    /// the evaluation this filter made (Observe and ZeroTrust). A consumer filter that runs after this attribute reads it
    /// to enforce explicit installation states (suspended, revoked) for its own sessions without evaluating the same
    /// proof twice (the nonce is single use: a second evaluation would be a replay). Absent when nothing was evaluated
    /// (no proof, no caller, Sentomaru disabled).
    /// </summary>
    public const string ObservationItem = "sentomaru-observation";

    /// <summary>
    /// 4.5.0 (D-06b review R I-2): HttpContext.Items key set to true when a <c>step_up</c> challenge ran the action because
    /// the consumer's <see cref="ISentomaruChallengeHandler"/> answered Proceed. The <see cref="ObservationItem"/> still
    /// says <c>challenge</c> (what Sentomaru recommended); a consumer filter reading it checks this key too.
    /// </summary>
    public const string StepUpProceededItem = "sentomaru-step-up-proceeded";

    /// <summary>The observation stored by this filter on the request, or null.</summary>
    public static SentomaruObservation? Observation(HttpContext context) =>
        context.Items.TryGetValue(ObservationItem, out var value) ? value as SentomaruObservation : null;

    public SentomaruIntegrityAttribute(string operation)
    {
        Operation = operation ?? throw new ArgumentNullException(nameof(operation));
    }

    public SentomaruIntegrityAttribute(string operation, DeviceAssuranceLevel assuranceLevel)
    {
        Operation = operation ?? throw new ArgumentNullException(nameof(operation));
        AssuranceLevel = assuranceLevel;
    }

    /// <summary>
    /// 4.7.0 (D-17a): the decision is <see cref="SentomaruEvaluationPipeline.DecideAsync"/>, shared with the gateway
    /// verifier; this filter runs the action once on a proceed and, after it, releases the first admission of an
    /// operation id whose action failed. Behaviour and logs are those of 4.6.0.
    /// </summary>
    public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
    {
        var httpContext = context.HttpContext;
        var logger = httpContext.RequestServices.GetService<ILogger<SentomaruIntegrityAttribute>>();
        var decision = await SentomaruEvaluationPipeline.DecideAsync(httpContext, new SentomaruEvaluationOptions(Operation)
        {
            AssuranceLevel = AssuranceLevel,
            AllowOperationReplay = AllowOperationReplay,
            PublicBaseUrlOverride = PublicBaseUrlOverride
        }, logger);

        if (decision.Kind == SentomaruDecisionKind.Refuse)
        {
            context.Result = new ObjectResult(decision.Error) { StatusCode = decision.StatusCode };
            return;
        }

        var executed = await next();
        if (decision.Reason != SentomaruProceedReason.Verified || decision.Evaluation is not { } evaluation) return;

        // J-01f review F1: the first admission of an operation id whose action failed (unhandled exception or a
        // 5xx result) is released, so the app's retry is not refused for 24 h. Best effort: a failed release is
        // logged; the retry then gets 409 operation-replayed until the id expires.
        if (evaluation.FirstAdmission == true && evaluation.OperationId is { } admittedId &&
            executed is not null && (executed.Exception is not null && !executed.ExceptionHandled ||
                executed.Result is Microsoft.AspNetCore.Mvc.Infrastructure.IStatusCodeActionResult { StatusCode: >= 500 }))
        {
            var client = httpContext.RequestServices.GetService<ISentomaruClient>();
            if (client is null) return;
            // Review G1: not the request's token (a client timeout aborts it, which is exactly when the release
            // matters); a short timeout of its own, and a release failure never replaces the action's result.
            try
            {
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                var released = await client.ReleaseOperationAsync(evaluation.InstallationId, admittedId, timeout.Token);
                if (!released.Succeeded)
                    logger?.LogWarning("Sentomaru: could not release operation id for {Operation} ({Code}).", Operation, released.ErrorCode);
            }
            catch (Exception releaseError)
            {
                logger?.LogWarning("Sentomaru: release of operation id for {Operation} failed: {Type}.", Operation, releaseError.GetType().Name);
            }
        }
    }
}
