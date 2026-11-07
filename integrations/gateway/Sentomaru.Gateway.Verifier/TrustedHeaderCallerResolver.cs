using Microsoft.AspNetCore.Http;
using Sentomaru.AspNetCore;

namespace Sentomaru.Gateway.Verifier;

/// <summary>
/// Caller mode <c>trusted-header</c> (spec D-17 item 3): the gateway authenticates the user, removes the client's
/// <c>sentomaru-caller-*</c> and injects its own. Exactly one non-empty value of each header names the caller; a
/// missing, empty or repeated one leaves it unusable, and the decision core answers 403 <c>caller-context-missing</c>
/// (placeholders such as <c>anonymous</c> are refused by <see cref="CallerContextDto.IsUsable"/>, as in the adapter).
/// <c>Authorization</c> is never read in this mode.
/// </summary>
public sealed class TrustedHeaderCallerResolver : ISentomaruContextResolver
{
    public const string SubjectHeader = "sentomaru-caller-subject";
    public const string TenantHeader = "sentomaru-caller-tenant";

    public CallerContextDto ResolveContext(HttpContext context) => new()
    {
        Subject = Single(context.Request, SubjectHeader),
        Tenant = Single(context.Request, TenantHeader),
    };

    private static string Single(HttpRequest request, string name) =>
        request.Headers.TryGetValue(name, out var values) && values.Count == 1 ? values[0] ?? "" : "";
}
