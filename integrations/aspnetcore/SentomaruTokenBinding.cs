using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Sentomaru.AspNetCore;

/// <summary>
/// E-06 (the Sentomaru session bindings contract): the hash that ties an IdP token to the app's hardware grant,
/// <c>hex(SHA-256("{org}:{app}:{idpIssuer}:{sub}:{tokenIdentifier}"))</c>. It is computed here, in the consumer, from the claims of the
/// principal that authentication already validated; the token, <c>sub</c> and the token identifier never reach Sentomaru.
/// </summary>
public static class SentomaruTokenBinding
{
    /// <summary>Hex hash, or null when any part is empty (an empty token identifier would make the hash stable per user).</summary>
    public static string? Compute(string org, string app, string idpIssuer, string? sub, string? tokenIdentifier)
    {
        if (string.IsNullOrWhiteSpace(org) || string.IsNullOrWhiteSpace(app) || string.IsNullOrWhiteSpace(idpIssuer) ||
            string.IsNullOrWhiteSpace(sub) || string.IsNullOrWhiteSpace(tokenIdentifier))
            return null;
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes($"{org}:{app}:{idpIssuer}:{sub}:{tokenIdentifier}"));
        return Convert.ToHexStringLower(digest);
    }

    /// <summary>
    /// The hash for the current request, or null when the binding is off (<see cref="SentomaruClientOptions.TokenBindingIdpIssuer"/> unset),
    /// the principal is not authenticated or it lacks <c>sub</c> / <c>sid</c> / <c>jti</c>. Null on a bound grant is refused by the server
    /// (fail closed), so a missing claim never opens a bypass.
    /// </summary>
    public static string? ForPrincipal(SentomaruClientOptions? options, ClaimsPrincipal? principal)
    {
        if (options is null || string.IsNullOrWhiteSpace(options.TokenBindingIdpIssuer) || principal?.Identity?.IsAuthenticated != true)
            return null;
        var sub = principal.FindFirst("sub")?.Value ?? principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var tokenId = principal.FindFirst("sid")?.Value ?? principal.FindFirst("jti")?.Value;
        return Compute(options.Org, options.App, options.TokenBindingIdpIssuer!, sub, tokenId);
    }
}
