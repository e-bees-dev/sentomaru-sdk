using System.Net;
using System.Net.Sockets;
using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace RaspLabHost;

/// <summary>
/// The laboratory login of the device round: one fixed user, and the test chooses how old its login is with the header
/// <see cref="AgeHeader"/> (seconds, 0 to 86400): the claim "auth_time" is then now minus that age, which is what the sample's
/// step-up hook reads (recent = at most 5 minutes). Without the header there is no "auth_time" and the hook refuses.
/// It trusts the network, not the caller: requests from outside loopback and private ranges are not authenticated, and the
/// host refuses to start outside the Development environment (Program.cs). Not a model of a real login.
/// </summary>
public sealed class LabSession(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder,
    TimeProvider clock) : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    public const string SchemeName = "Lab", AgeHeader = "X-Lab-Auth-Age-Seconds", Subject = "rasp-lab-user", Tenant = "rasp-lab";

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!IsLabNetwork(Context.Connection.RemoteIpAddress)) return Task.FromResult(AuthenticateResult.NoResult());
        var claims = new List<Claim> { new("sub", Subject), new("tenant", Tenant) };
        if (Request.Headers.TryGetValue(AgeHeader, out var age))
        {
            if (!int.TryParse(age.ToString(), System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture,
                    out var seconds) || seconds is < 0 or > 86400)
                return Task.FromResult(AuthenticateResult.Fail("lab-auth-age"));
            claims.Add(new Claim("auth_time", clock.GetUtcNow().AddSeconds(-seconds).ToUnixTimeSeconds()
                .ToString(System.Globalization.CultureInfo.InvariantCulture)));
        }
        var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, SchemeName));
        return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(principal, SchemeName)));
    }

    /// <summary>Loopback, RFC 1918 and the IPv6 unique-local and link-local ranges (a mapped IPv4 address counts as IPv4).</summary>
    public static bool IsLabNetwork(IPAddress? address)
    {
        if (address is null) return false;
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        if (IPAddress.IsLoopback(address)) return true;
        var b = address.GetAddressBytes();
        return address.AddressFamily switch
        {
            AddressFamily.InterNetwork => b[0] == 10 || (b[0] == 172 && b[1] is >= 16 and <= 31) || (b[0] == 192 && b[1] == 168),
            AddressFamily.InterNetworkV6 => (b[0] & 0xFE) == 0xFC || address.IsIPv6LinkLocal,
            _ => false,
        };
    }
}
