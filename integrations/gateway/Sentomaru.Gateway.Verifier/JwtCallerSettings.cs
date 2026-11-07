using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Sentomaru.Gateway.Verifier;

/// <summary>
/// D-17c2: the validated settings of the <c>jwt</c> caller (schema <c>jwtCaller</c>, spec D-17 item 3, rules I6). Built
/// only from a configuration that passed <see cref="Validate"/>; the host does not start otherwise.
/// </summary>
public sealed record JwtCallerSettings
{
    /// <summary>The allowlist the configuration may choose from: asymmetric only. <c>none</c> and every <c>HS*</c> never.</summary>
    public static readonly IReadOnlySet<string> SupportedAlgorithms = new HashSet<string>(StringComparer.Ordinal)
    {
        "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384",
    };

    /// <summary>Defaults of <c>DefaultSentomaruContextResolver</c> (its NameIdentifier and identity name are the JWT <c>sub</c>).</summary>
    public static readonly IReadOnlyList<string> DefaultSubjectClaims = ["sub", "id_usuario"];
    public static readonly IReadOnlyList<string> DefaultTenantClaims = ["tenant", "tenant_id", "id_varejista", "IdVarejista"];

    private static readonly Regex JwksUrlPattern = new("^https://[^\\s/?#@]+(/[^\\s#]*)?$", RegexOptions.CultureInvariant);
    private static readonly Regex TypPattern = new("^[A-Za-z0-9][A-Za-z0-9.+/-]{0,63}$", RegexOptions.CultureInvariant);
    private static readonly Regex ClaimPattern = new("^[A-Za-z_][A-Za-z0-9_.:/-]{0,127}$", RegexOptions.CultureInvariant);

    public Uri? JwksUrl { get; private init; }
    public IReadOnlyList<Jwk> InlineKeys { get; private init; } = [];
    public required IReadOnlySet<string> Algorithms { get; init; }
    public required string Issuer { get; init; }
    public required string Audience { get; init; }
    public required TimeSpan ClockSkew { get; init; }
    public required TimeSpan UnknownKidRefresh { get; init; }
    public required IReadOnlyList<string> SubjectClaims { get; init; }
    public required IReadOnlyList<string> TenantClaims { get; init; }

    /// <summary>
    /// Review R N2 (optional): the header <c>typ</c> the token must carry (for example <c>at+jwt</c>, RFC 9068), compared
    /// without case and without the <c>application/</c> prefix. Null: <c>typ</c> and <c>azp</c> are not checked, so an ID
    /// token of the same issuer with the same audience passes (contract section 11).
    /// </summary>
    public string? RequiredTyp { get; init; }

    /// <summary>Every error of a jwt caller section (appended to <paramref name="errors"/>).</summary>
    public static void Validate(CallerConfig caller, List<string> errors)
    {
        if (caller.VerifierReachableOnlyFromGateway is not null || caller.Extra is { Count: > 0 })
        {
            var foreign = (caller.Extra?.Keys ?? Enumerable.Empty<string>()).ToList();
            if (caller.VerifierReachableOnlyFromGateway is not null) foreign.Add("verifierReachableOnlyFromGateway");
            errors.Add($"caller jwt does not have: {string.Join(", ", foreign.Order(StringComparer.Ordinal))}.");
        }

        if (caller.Jwks is null)
        {
            errors.Add("caller.jwks is required (a fixed https url or inline public keys; never taken from the token).");
        }
        else if (caller.Jwks.Url is not null == caller.Jwks.Keys is not null)
        {
            errors.Add("caller.jwks must have exactly one of url or keys.");
        }
        else if (caller.Jwks.Url is { } url)
        {
            if (url.Length > 2048 || !JwksUrlPattern.IsMatch(url) || !Uri.TryCreate(url, UriKind.Absolute, out var parsed) ||
                parsed.Scheme != Uri.UriSchemeHttps || !string.IsNullOrEmpty(parsed.UserInfo))
            {
                errors.Add("caller.jwks.url must be an https URL without user info or fragment.");
            }
        }
        else
        {
            var keys = caller.Jwks.Keys!;
            if (keys.Count is < 1 or > 16) errors.Add("caller.jwks.keys must have 1 to 16 keys.");
            var kids = new HashSet<string>(StringComparer.Ordinal);
            for (var i = 0; i < keys.Count; i++)
            {
                if (!Jwk.TryParse(keys[i], out var key, out var error))
                {
                    errors.Add($"caller.jwks.keys[{i}]: {error}");
                }
                else if (!kids.Add(key!.Kid))
                {
                    errors.Add($"caller.jwks.keys[{i}]: kid repeated.");
                }
                else if (key.Alg is { } alg && (!SupportedAlgorithms.Contains(alg) ||
                                                !(caller.Algorithms ?? []).Contains(alg, StringComparer.Ordinal)))
                {
                    errors.Add($"caller.jwks.keys[{i}]: alg is not one of caller.algorithms.");
                }
            }
        }

        if (caller.Algorithms is null || caller.Algorithms.Count == 0)
        {
            errors.Add("caller.algorithms must list at least one asymmetric algorithm.");
        }
        else
        {
            foreach (var alg in caller.Algorithms)
            {
                if (alg is null || !SupportedAlgorithms.Contains(alg))
                {
                    // Never echoes a value that is not in the closed list (it could be anything).
                    errors.Add("caller.algorithms must be among RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384 " +
                               "(none and HS* are never accepted).");
                    break;
                }
            }
            if (caller.Algorithms.Distinct(StringComparer.Ordinal).Count() != caller.Algorithms.Count)
            {
                errors.Add("caller.algorithms repeats an algorithm.");
            }
        }

        if (caller.Issuer is null || caller.Issuer.Length is < 1 or > 512) errors.Add("caller.issuer is required (1 to 512 characters).");
        if (caller.Audience is null || caller.Audience.Length is < 1 or > 512) errors.Add("caller.audience is required (1 to 512 characters).");
        if (caller.ClockSkewSeconds is < 0 or > 120) errors.Add("caller.clockSkewSeconds must be between 0 and 120.");
        if (caller.UnknownKidRefreshSeconds is < 60 or > 86400) errors.Add("caller.unknownKidRefreshSeconds must be between 60 and 86400.");
        if (caller.RequiredTyp is { } typ && !TypPattern.IsMatch(typ))
        {
            errors.Add("caller.requiredTyp must match ^[A-Za-z0-9][A-Za-z0-9.+/-]{0,63}$ (for example at+jwt).");
        }
        ValidateClaims("subjectClaims", caller.SubjectClaims, errors);
        ValidateClaims("tenantClaims", caller.TenantClaims, errors);
    }

    private static void ValidateClaims(string name, IReadOnlyList<string?>? claims, List<string> errors)
    {
        if (claims is null) return;
        if (claims.Count is < 1 or > 8 || claims.Any(c => c is null || !ClaimPattern.IsMatch(c)) ||
            claims.Distinct(StringComparer.Ordinal).Count() != claims.Count)
        {
            errors.Add($"caller.{name} must be 1 to 8 distinct claim names matching ^[A-Za-z_][A-Za-z0-9_.:/-]{{0,127}}$.");
        }
    }

    /// <summary>The settings of a configuration that passed validation.</summary>
    public static JwtCallerSettings From(CallerConfig caller) => new()
    {
        JwksUrl = caller.Jwks!.Url is { } url ? new Uri(url) : null,
        InlineKeys = caller.Jwks.Keys is { } keys ? keys.Select(k => Jwk.TryParse(k, out var key, out _) ? key! : throw new InvalidOperationException()).ToList() : [],
        Algorithms = new HashSet<string>(caller.Algorithms!.Select(a => a!), StringComparer.Ordinal),
        Issuer = caller.Issuer!,
        Audience = caller.Audience!,
        ClockSkew = TimeSpan.FromSeconds(caller.ClockSkewSeconds ?? 30),
        UnknownKidRefresh = TimeSpan.FromSeconds(caller.UnknownKidRefreshSeconds ?? 60),
        SubjectClaims = caller.SubjectClaims?.Select(c => c!).ToList() ?? DefaultSubjectClaims,
        TenantClaims = caller.TenantClaims?.Select(c => c!).ToList() ?? DefaultTenantClaims,
        RequiredTyp = caller.RequiredTyp,
    };
}

/// <summary>
/// One public verification key of the JWKS (RFC 7517). Only <c>kty</c> <c>RSA</c> (modulus of 2048 bits or more) and
/// <c>EC</c> P-256/P-384 are usable; <c>kid</c> is required; <c>use</c>, when present, must be <c>sig</c>; <c>key_ops</c>,
/// when present, must include <c>verify</c>; a key with any private member (<c>d</c>, <c>p</c>, <c>q</c>, <c>dp</c>,
/// <c>dq</c>, <c>qi</c>, <c>oth</c>, <c>k</c>) is never used. <c>x5c</c>, <c>x5u</c> and <c>jku</c> are ignored: nothing
/// is fetched or trusted from a key or a token.
/// </summary>
public sealed record Jwk
{
    private static readonly string[] PrivateMembers = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

    public required string Kid { get; init; }
    public required string Kty { get; init; }
    public string? Alg { get; init; }
    public RSAParameters? Rsa { get; init; }
    public ECParameters? Ec { get; init; }

    /// <summary>The key, or the reason it is not usable (the reason never carries key material).</summary>
    public static bool TryParse(JsonElement element, out Jwk? key, out string? error)
    {
        key = null;
        error = null;
        if (element.ValueKind != JsonValueKind.Object) return Fail("not an object", out error);
        if (PrivateMembers.Any(m => element.TryGetProperty(m, out _))) return Fail("private or symmetric key material is not allowed", out error);
        if (!String(element, "kid", out var kid) || kid.Length is < 1 or > 256) return Fail("kid is required", out error);
        if (!String(element, "kty", out var kty)) return Fail("kty is required", out error);
        if (element.TryGetProperty("use", out var use) && (use.ValueKind != JsonValueKind.String || use.GetString() != "sig"))
        {
            return Fail("use must be sig", out error);
        }
        if (element.TryGetProperty("key_ops", out var ops) &&
            (ops.ValueKind != JsonValueKind.Array || !ops.EnumerateArray().Any(o => o.ValueKind == JsonValueKind.String && o.GetString() == "verify")))
        {
            return Fail("key_ops must include verify", out error);
        }
        string? alg = null;
        if (element.TryGetProperty("alg", out var algElement))
        {
            if (algElement.ValueKind != JsonValueKind.String) return Fail("alg must be a string", out error);
            alg = algElement.GetString();
        }

        switch (kty)
        {
            case "RSA":
                if (!Bytes(element, "n", out var n) || !Bytes(element, "e", out var e)) return Fail("RSA key needs n and e", out error);
                n = n.SkipWhile(b => b == 0).ToArray();
                // Review R N1: the real bit length (the first byte may have leading zero bits), 2048 to 8192.
                var bits = n.Length == 0 ? 0 : (n.Length - 1) * 8 + (32 - System.Numerics.BitOperations.LeadingZeroCount((uint)n[0]));
                if (bits < 2048 || bits > 8192) return Fail("RSA modulus must have 2048 to 8192 bits", out error);
                // Review R M-3: an odd public exponent of at least 3 (e = 1 makes every signature verify trivially).
                e = e.SkipWhile(b => b == 0).ToArray();
                if (e.Length is < 1 or > 4) return Fail("RSA exponent must be odd and at least 3", out error);
                var exponent = e.Aggregate(0L, (acc, b) => (acc << 8) | b);
                if (exponent < 3 || exponent % 2 == 0) return Fail("RSA exponent must be odd and at least 3", out error);
                if (alg is not null && !alg.StartsWith("RS", StringComparison.Ordinal) && !alg.StartsWith("PS", StringComparison.Ordinal))
                {
                    return Fail("alg does not fit an RSA key", out error);
                }
                key = new Jwk { Kid = kid, Kty = kty, Alg = alg, Rsa = new RSAParameters { Modulus = n, Exponent = e } };
                break;
            case "EC":
                if (!String(element, "crv", out var crv)) return Fail("EC key needs crv", out error);
                var (curve, size, fit) = crv switch
                {
                    "P-256" => (ECCurve.NamedCurves.nistP256, 32, "ES256"),
                    "P-384" => (ECCurve.NamedCurves.nistP384, 48, "ES384"),
                    _ => (default(ECCurve), 0, ""),
                };
                if (size == 0) return Fail("EC curve must be P-256 or P-384", out error);
                if (!Bytes(element, "x", out var x) || !Bytes(element, "y", out var y) || x.Length != size || y.Length != size)
                {
                    return Fail("EC key needs x and y of the curve size", out error);
                }
                if (alg is not null && alg != fit) return Fail("alg does not fit the EC curve", out error);
                var parameters = new ECParameters { Curve = curve, Q = new ECPoint { X = x, Y = y } };
                try
                {
                    // Import checks the point is on the curve.
                    using var probe = ECDsa.Create(parameters);
                }
                catch (CryptographicException)
                {
                    return Fail("EC point is not on the curve", out error);
                }
                key = new Jwk { Kid = kid, Kty = kty, Alg = alg, Ec = parameters };
                break;
            default:
                return Fail("kty must be RSA or EC", out error);
        }
        return true;
    }

    /// <summary>Whether this key may verify a token signed with <paramref name="alg"/> (an allowlisted algorithm).</summary>
    public bool Fits(string alg)
    {
        if (Alg is not null && Alg != alg) return false;
        return alg switch
        {
            "RS256" or "RS384" or "RS512" or "PS256" or "PS384" or "PS512" => Rsa is not null,
            "ES256" => Ec is { } ec && ec.Q.X!.Length == 32,
            "ES384" => Ec is { } ec384 && ec384.Q.X!.Length == 48,
            _ => false,
        };
    }

    /// <summary>Verifies a JWS signature (RFC 7518 section 3) over <paramref name="data"/>.</summary>
    public bool Verify(string alg, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        if (!Fits(alg)) return false;
        var hash = alg[2..] switch
        {
            "256" => HashAlgorithmName.SHA256,
            "384" => HashAlgorithmName.SHA384,
            "512" => HashAlgorithmName.SHA512,
            _ => default,
        };
        try
        {
            if (Rsa is { } rsaParameters)
            {
                using var rsa = RSA.Create(rsaParameters);
                if (signature.Length != rsaParameters.Modulus!.Length) return false;
                var padding = alg[0] == 'P' ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1;
                return rsa.VerifyData(data, signature, hash, padding);
            }
            using var ecdsa = ECDsa.Create(Ec!.Value);
            // JWS uses the fixed-size R||S form only (64 bytes for ES256, 96 for ES384); DER is refused.
            if (signature.Length != 2 * Ec.Value.Q.X!.Length) return false;
            return ecdsa.VerifyData(data, signature, hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    private static bool Fail(string reason, out string? error)
    {
        error = reason + ".";
        return false;
    }

    private static bool String(JsonElement element, string name, out string value)
    {
        value = "";
        if (!element.TryGetProperty(name, out var member) || member.ValueKind != JsonValueKind.String) return false;
        value = member.GetString()!;
        return value.Length > 0;
    }

    private static bool Bytes(JsonElement element, string name, out byte[] value)
    {
        value = [];
        if (!String(element, name, out var text) || !JwtCallerValidator.IsBase64Url(text)) return false;
        try
        {
            value = Base64Url.DecodeFromChars(text);
        }
        catch (FormatException)
        {
            return false;
        }
        return value.Length > 0;
    }
}
