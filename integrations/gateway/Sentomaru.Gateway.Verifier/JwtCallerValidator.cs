using System.Buffers.Text;
using System.Globalization;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Primitives;
using Sentomaru.AspNetCore;

namespace Sentomaru.Gateway.Verifier;

/// <summary>
/// The outcome of the jwt caller: <see cref="Reason"/> is <c>valid</c> or one of <see cref="JwtCallerValidator.Reasons"/>
/// (a closed list, used in logs and metrics; never a claim, a header or the token). <see cref="Caller"/> is set only when
/// valid.
/// </summary>
public sealed record JwtOutcome(string Reason, CallerContextDto? Caller)
{
    public bool Valid => Caller is not null;
}

/// <summary>
/// D-17c2 (spec D-17 item 3, rules I6): validates the user's JWT from <c>Authorization: Bearer</c> and extracts the caller.
/// <list type="number">
/// <item>Exactly one <c>Authorization</c> line, scheme <c>Bearer</c>, a compact JWS of three base64url parts (no
/// padding), at most <see cref="MaxTokenLength"/> characters.</item>
/// <item>Header: JSON object without duplicate members; <c>alg</c> in the configured allowlist (asymmetric only:
/// <c>none</c> and <c>HS*</c> can never be in it); <c>kid</c> required; <c>crit</c> refused. <c>jku</c>, <c>x5u</c>,
/// <c>jwk</c> and <c>x5c</c> are ignored: the key comes only from the configured JWKS (<see cref="JwksSource"/>).</item>
/// <item>Signature verified with the one key of that <c>kid</c> that fits the <c>alg</c>, before any claim is read.</item>
/// <item>Claims: <c>iss</c> equal to the configured issuer; <c>aud</c> (string or array) containing the configured
/// audience; <c>exp</c> required and in the future; <c>nbf</c> and <c>iat</c>, when present, not in the future; all with
/// the configured clock skew (0 to 120 s).</item>
/// <item>Subject and tenant: for each configured claim list, the first claim present decides; a string or an integer is
/// the value, anything else leaves the caller unusable. The pipeline then refuses placeholders and empty values as for
/// <c>trusted-header</c> (403 <c>caller-context-missing</c>).</item>
/// </list>
/// </summary>
public sealed class JwtCallerValidator(JwtCallerSettings settings, JwksSource keys, TimeProvider time)
{
    public const int MaxTokenLength = 8192;

    /// <summary>Every reason a JWT caller is not valid (closed list, also the metric label).</summary>
    public static readonly IReadOnlySet<string> Reasons = new HashSet<string>(StringComparer.Ordinal)
    {
        "missing", "format", "alg", "typ", "kid-unknown", "kid-ambiguous", "signature", "issuer", "audience", "expired",
        "not-yet-valid", "claims", "caller", "jwks-unavailable",
    };

    /// <summary>
    /// Review R I-1: the reasons that say the token itself is not acceptable (absent, malformed, not signed by the
    /// configured keys, not for this issuer or audience, out of its time window). Answered 401
    /// <c>authentication-required</c> with <c>WWW-Authenticate: Bearer error="invalid_token"</c>, as an ASP.NET consumer
    /// with JwtBearer and the gateway's own <c>jwt_authn</c> answer, so the app renews its token. <c>caller</c> (a valid
    /// token without a usable subject/tenant) is 403 <c>caller-context-missing</c>; <c>jwks-unavailable</c> is 503.
    /// </summary>
    public static readonly IReadOnlySet<string> InvalidToken = new HashSet<string>(StringComparer.Ordinal)
    {
        "missing", "format", "alg", "typ", "kid-unknown", "kid-ambiguous", "signature", "issuer", "audience", "expired",
        "not-yet-valid", "claims",
    };

    /// <summary>Review R M-1: the longest subject or tenant taken from a token.</summary>
    public const int MaxCallerLength = 512;

    private static readonly JsonDocumentOptions Strict = new() { AllowDuplicateProperties = false, MaxDepth = 16 };

    public async Task<JwtOutcome> ValidateAsync(StringValues authorization, CancellationToken cancellationToken)
    {
        if (authorization.Count != 1 || authorization[0] is not { } line) return Refused("missing");
        const string scheme = "Bearer ";
        if (line.Length <= scheme.Length || !line.StartsWith(scheme, StringComparison.OrdinalIgnoreCase)) return Refused("missing");
        var token = line[scheme.Length..];
        if (token.Length > MaxTokenLength) return Refused("format");
        var parts = token.Split('.');
        // An empty signature is a format the parser accepts so that alg none is refused as such (by the allowlist).
        if (parts.Length != 3 || !IsBase64Url(parts[0]) || !IsBase64Url(parts[1]) || (parts[2].Length > 0 && !IsBase64Url(parts[2])))
        {
            return Refused("format");
        }

        using var header = Decode(parts[0]);
        if (header is null) return Refused("format");
        var h = header.RootElement;
        if (!h.TryGetProperty("alg", out var algElement) || algElement.ValueKind != JsonValueKind.String) return Refused("format");
        var alg = algElement.GetString()!;
        // none, HS256 and anything else outside the configured asymmetric allowlist.
        if (!settings.Algorithms.Contains(alg)) return Refused("alg");
        if (h.TryGetProperty("crit", out _)) return Refused("format");
        if (settings.RequiredTyp is { } requiredTyp &&
            (!h.TryGetProperty("typ", out var typ) || typ.ValueKind != JsonValueKind.String || !SameTyp(typ.GetString()!, requiredTyp)))
        {
            return Refused("typ");
        }
        if (!h.TryGetProperty("kid", out var kidElement) || kidElement.ValueKind != JsonValueKind.String ||
            kidElement.GetString() is not { Length: > 0 and <= 256 } kid)
        {
            return Refused("format");
        }

        var (lookup, key) = await keys.FindAsync(kid, alg, cancellationToken);
        switch (lookup)
        {
            case JwkLookup.Unavailable: return Refused("jwks-unavailable");
            case JwkLookup.KidUnknown: return Refused("kid-unknown");
            case JwkLookup.KidAmbiguous: return Refused("kid-ambiguous");
            case JwkLookup.AlgMismatch: return Refused("alg");
        }

        if (parts[2].Length == 0) return Refused("signature");
        byte[] signature;
        try
        {
            signature = Base64Url.DecodeFromChars(parts[2]);
        }
        catch (FormatException)
        {
            return Refused("format");
        }
        var signed = Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]);
        if (!key!.Verify(alg, signed, signature)) return Refused("signature");

        using var payload = Decode(parts[1]);
        if (payload is null) return Refused("format");
        var claims = payload.RootElement;

        if (!claims.TryGetProperty("iss", out var iss) || iss.ValueKind != JsonValueKind.String) return Refused("claims");
        if (!string.Equals(iss.GetString(), settings.Issuer, StringComparison.Ordinal)) return Refused("issuer");
        if (!claims.TryGetProperty("aud", out var aud)) return Refused("claims");
        if (aud.ValueKind == JsonValueKind.String)
        {
            if (!string.Equals(aud.GetString(), settings.Audience, StringComparison.Ordinal)) return Refused("audience");
        }
        else if (aud.ValueKind == JsonValueKind.Array && aud.GetArrayLength() > 0)
        {
            // Review R: a list with anything but strings ([1, "api"]) is not an audience list; refused as audience.
            if (!aud.EnumerateArray().All(a => a.ValueKind == JsonValueKind.String) ||
                !aud.EnumerateArray().Any(a => string.Equals(a.GetString(), settings.Audience, StringComparison.Ordinal)))
            {
                return Refused("audience");
            }
        }
        else
        {
            return Refused("claims");
        }

        var now = time.GetUtcNow().ToUnixTimeMilliseconds() / 1000.0;
        var skew = settings.ClockSkew.TotalSeconds;
        if (!NumericDate(claims, "exp", required: true, out var exp) ||
            !NumericDate(claims, "nbf", required: false, out var nbf) ||
            !NumericDate(claims, "iat", required: false, out var iat))
        {
            return Refused("claims");
        }
        if (now >= exp!.Value + skew) return Refused("expired");
        if ((nbf is { } notBefore && now + skew < notBefore) || (iat is { } issuedAt && now + skew < issuedAt)) return Refused("not-yet-valid");

        var subject = Claim(claims, settings.SubjectClaims);
        var tenant = Claim(claims, settings.TenantClaims);
        // Review R M-1: a value that cannot travel unchanged in a header (non-ASCII, CR/LF, edge spaces) or is too long is
        // refused here, before Sentomaru is called (the grant could hold the same value: the nonce would be spent and the
        // answer would still fail on the result headers).
        if (subject is null || tenant is null || !CallerValue(subject) || !CallerValue(tenant)) return Refused("caller");
        // Same shape trusted-header hands to the pipeline; IsUsable (placeholders, empty) is decided there.
        return new JwtOutcome("valid", new CallerContextDto { Subject = subject, Tenant = tenant });
    }

    private static JwtOutcome Refused(string reason) => new(reason, null);

    /// <summary>Empty passes here (the core refuses it as for trusted-header); otherwise header-safe and at most 512.</summary>
    private static bool CallerValue(string value) =>
        value.Length == 0 || (value.Length <= MaxCallerLength && VerifierApp.HeaderSafe(value));

    /// <summary>RFC 7515 section 4.1.9: case-insensitive, <c>application/</c> may be omitted.</summary>
    private static bool SameTyp(string value, string required)
    {
        static string Bare(string t) => t.StartsWith("application/", StringComparison.OrdinalIgnoreCase) ? t["application/".Length..] : t;
        return string.Equals(Bare(value), Bare(required), StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Base64url without padding: <c>[A-Za-z0-9_-]+</c> and a length that is not 1 modulo 4.</summary>
    public static bool IsBase64Url(string text) =>
        text.Length > 0 && text.Length % 4 != 1 && text.All(c => c is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-' or '_');

    private static JsonDocument? Decode(string part)
    {
        try
        {
            var document = JsonDocument.Parse(Base64Url.DecodeFromChars(part), Strict);
            if (document.RootElement.ValueKind == JsonValueKind.Object) return document;
            document.Dispose();
            return null;
        }
        catch (Exception e) when (e is FormatException or JsonException)
        {
            return null;
        }
    }

    /// <summary>A NumericDate (RFC 7519): a finite JSON number. False when present and not one, or required and absent.</summary>
    private static bool NumericDate(JsonElement claims, string name, bool required, out double? value)
    {
        value = null;
        if (!claims.TryGetProperty(name, out var member)) return !required;
        if (member.ValueKind != JsonValueKind.Number || !member.TryGetDouble(out var number) || !double.IsFinite(number)) return false;
        value = number;
        return true;
    }

    /// <summary>The first claim of the list that is present: its string or integer value; null otherwise.</summary>
    private static string? Claim(JsonElement claims, IReadOnlyList<string> names)
    {
        foreach (var name in names)
        {
            if (!claims.TryGetProperty(name, out var value)) continue;
            return value.ValueKind switch
            {
                JsonValueKind.String => value.GetString(),
                JsonValueKind.Number when value.TryGetInt64(out var number) => number.ToString(CultureInfo.InvariantCulture),
                _ => null,
            };
        }
        return null;
    }
}

/// <summary>
/// Caller mode <c>jwt</c>: the caller the verifier validated from the user's JWT for this request (stored by the
/// verifier before the decision core runs), or an empty one, which the core refuses with 403
/// <c>caller-context-missing</c>, as an absent trusted header is. <c>sentomaru-caller-*</c> are never read in this mode.
/// </summary>
public sealed class JwtCallerResolver : ISentomaruContextResolver
{
    public const string Item = "Sentomaru.Gateway.Verifier.JwtCaller";

    public CallerContextDto ResolveContext(HttpContext context) =>
        context.Items.TryGetValue(Item, out var value) && value is CallerContextDto caller
            ? caller
            : new CallerContextDto { Subject = "", Tenant = "" };
}
