using System.Security.Claims;
using Sentomaru.AspNetCore;

namespace ThirdPartyApi;

// guide:begin resolver
/// <summary>
/// Subject and tenant from YOUR session only: the claims "sub" and "tenant". Missing claims stay empty, and the
/// adapter then refuses the request (403 caller-context-missing): it never sends a caller it does not have.
/// </summary>
public sealed class CallerContextResolver : ISentomaruContextResolver
{
    public CallerContextDto ResolveContext(HttpContext context) => new()
    {
        Subject = context.User.FindFirstValue("sub") ?? "",
        Tenant = context.User.FindFirstValue("tenant") ?? "",
    };
}
// guide:end resolver
