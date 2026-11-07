using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace Sentomaru.Gateway.Verifier;

/// <summary>
/// The verifier configuration, <c>contracts/api/gateway-verifier-config-v1.schema.json</c> (contract section 4). Read
/// strictly: unknown members (such as <c>knownProxies</c>), duplicate keys and members in another case are refused, so a
/// field the verifier does not have can never be believed to be in force. <see cref="Load"/> and <see cref="Validate"/>
/// are the startup validation: the host does not start with an invalid configuration.
/// </summary>
public sealed record VerifierConfig
{
    public string? SchemaVersion { get; init; }
    public string? PublicBaseUrl { get; init; }
    public ScopeConfig? Scope { get; init; }
    public SentomaruConfig? Sentomaru { get; init; }
    public bool Enabled { get; init; } = true;
    public bool DisabledAcknowledged { get; init; }
    public CallerConfig? Caller { get; init; }
    public IReadOnlyList<RouteConfig>? Routes { get; init; }
    public IReadOnlyList<ExemptConfig>? Exempt { get; init; }

    /// <summary>
    /// D-17c (additive to the schema): the port of the management listener, the only one where <c>GET /health</c> and
    /// <c>GET /metrics</c> answer. Without it the verifier serves neither. They never answer on the verification
    /// listener: there every path is a request the gateway is asking about, and a 200 there lets it reach the upstream.
    /// </summary>
    public int? ManagementPort { get; init; }

    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        AllowDuplicateProperties = false,
        ReadCommentHandling = JsonCommentHandling.Disallow,
        AllowTrailingCommas = false,
        NumberHandling = JsonNumberHandling.Strict,
    };

    /// <summary>Reads and validates the file; throws <see cref="VerifierConfigException"/> with every error found.</summary>
    public static VerifierConfig Load(string path)
    {
        VerifierConfig? config;
        try
        {
            config = JsonSerializer.Deserialize<VerifierConfig>(File.ReadAllBytes(path), Json);
        }
        catch (Exception e) when (e is JsonException or IOException or UnauthorizedAccessException or NotSupportedException)
        {
            // The configuration holds no secret (the token is in workloadTokenFile), so the parser's message may be shown.
            throw new VerifierConfigException([$"configuration {path}: {e.Message}"]);
        }
        if (config is null) throw new VerifierConfigException([$"configuration {path}: empty"]);
        var errors = config.Validate();
        if (errors.Count > 0) throw new VerifierConfigException(errors);
        return config;
    }

    /// <summary>Parses a configuration from JSON text (tests); same rules as <see cref="Load"/>.</summary>
    public static VerifierConfig Parse(string json)
    {
        VerifierConfig? config;
        try
        {
            config = JsonSerializer.Deserialize<VerifierConfig>(json, Json);
        }
        catch (JsonException e)
        {
            throw new VerifierConfigException([$"configuration: {e.Message}"]);
        }
        if (config is null) throw new VerifierConfigException(["configuration: empty"]);
        var errors = config.Validate();
        if (errors.Count > 0) throw new VerifierConfigException(errors);
        return config;
    }

    // Same patterns as the schema.
    private static readonly Regex PublicBaseUrlPattern = new(
        "^https://[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*" +
        "(:(?!443$)([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]))?$",
        RegexOptions.CultureInvariant);
    private static readonly Regex SlugPattern = new("^[a-z0-9][a-z0-9-]{0,62}$", RegexOptions.CultureInvariant);
    private static readonly Regex BaseAddressPattern = new("^https://[^\\s/?#@]+(/[^\\s?#]*)?$", RegexOptions.CultureInvariant);
    private static readonly Regex TokenFilePattern = new("^/[^\\s]+$", RegexOptions.CultureInvariant);
    internal static readonly Regex OperationPattern = new("^[a-z0-9_-]{2,32}$", RegexOptions.CultureInvariant);

    /// <summary>Methods of the route table (schema <c>method</c>): upper case only, compared ordinally.</summary>
    public static readonly IReadOnlySet<string> Methods = new HashSet<string>(StringComparer.Ordinal)
    {
        "GET", "POST", "PUT", "PATCH", "DELETE"
    };

    /// <summary>Every error of this configuration (empty when valid), including the reading of the token file.</summary>
    public IReadOnlyList<string> Validate()
    {
        var errors = new List<string>();
        if (SchemaVersion != "1") errors.Add("schemaVersion must be \"1\".");

        if (PublicBaseUrl is null)
        {
            errors.Add("publicBaseUrl is required (KnownProxies and X-Forwarded-* do not exist in the verifier).");
        }
        else if (PublicBaseUrl.Length > 262 || !PublicBaseUrlPattern.IsMatch(PublicBaseUrl) ||
                 !Uri.TryCreate(PublicBaseUrl, UriKind.Absolute, out var publicBase) || publicBase.Scheme != Uri.UriSchemeHttps ||
                 !string.IsNullOrEmpty(publicBase.UserInfo))
        {
            errors.Add("publicBaseUrl must be https, a lower-case host, a port only when not 443, and no user info, path, " +
                       "query or fragment.");
        }

        if (Scope is null)
        {
            errors.Add("scope is required.");
        }
        else
        {
            foreach (var (name, value) in new[] { ("org", Scope.Org), ("app", Scope.App), ("env", Scope.Env) })
            {
                if (value is null || !SlugPattern.IsMatch(value)) errors.Add($"scope.{name} must match ^[a-z0-9][a-z0-9-]{{0,62}}$.");
            }
        }

        if (Sentomaru is null)
        {
            errors.Add("sentomaru is required.");
        }
        else
        {
            if (Sentomaru.BaseAddress is null || Sentomaru.BaseAddress.Length > 2048 || !BaseAddressPattern.IsMatch(Sentomaru.BaseAddress) ||
                !Uri.TryCreate(Sentomaru.BaseAddress, UriKind.Absolute, out _))
            {
                errors.Add("sentomaru.baseAddress must be an https URL (the workload bearer travels in every call).");
            }
            if (Sentomaru.WorkloadTokenFile is null || Sentomaru.WorkloadTokenFile.Length > 1024 ||
                !TokenFilePattern.IsMatch(Sentomaru.WorkloadTokenFile))
            {
                errors.Add("sentomaru.workloadTokenFile must be an absolute path (the token is never in the configuration).");
            }
            else if (WorkloadTokenHandler.ReadToken(Sentomaru.WorkloadTokenFile) is null)
            {
                // The content is never shown.
                errors.Add($"sentomaru.workloadTokenFile {Sentomaru.WorkloadTokenFile} is missing, unreadable, empty or not one token of visible ASCII.");
            }
            if (Sentomaru.TimeoutMs is < 100 or > 10000) errors.Add("sentomaru.timeoutMs must be between 100 and 10000.");
        }

        if (!Enabled && !DisabledAcknowledged)
        {
            errors.Add("enabled=false requires disabledAcknowledged=true (the audited kill switch).");
        }

        if (Caller is null)
        {
            errors.Add("caller is required.");
        }
        else if (Caller.Mode == "jwt")
        {
            // D-17c2 (I6): every rule of the jwt caller is checked here, before the host starts.
            JwtCallerSettings.Validate(Caller, errors);
        }
        else if (Caller.Mode != "trusted-header")
        {
            errors.Add("caller.mode must be trusted-header or jwt.");
        }
        else
        {
            if (Caller.VerifierReachableOnlyFromGateway != true)
            {
                errors.Add("caller trusted-header requires verifierReachableOnlyFromGateway=true (loopback, private address or Unix socket; mTLS in a sidecar on loopback).");
            }
            var foreign = Caller.JwtMembers().Concat(Caller.Extra?.Keys ?? Enumerable.Empty<string>()).ToList();
            if (foreign.Count > 0)
            {
                errors.Add($"caller trusted-header does not have: {string.Join(", ", foreign.Order(StringComparer.Ordinal))}.");
            }
        }

        if (ManagementPort is < 1 or > 65535) errors.Add("managementPort must be between 1 and 65535.");

        RouteTable.Validate(Routes, Exempt, errors);
        return errors;
    }
}

public sealed record ScopeConfig
{
    public string? Org { get; init; }
    public string? App { get; init; }
    public string? Env { get; init; }
}

public sealed record SentomaruConfig
{
    public string? BaseAddress { get; init; }
    public string? WorkloadTokenFile { get; init; }
    public int TimeoutMs { get; init; } = 2000;
}

public sealed record CallerConfig
{
    public string? Mode { get; init; }
    public bool? VerifierReachableOnlyFromGateway { get; init; }

    // D-17c2: the members of the jwt caller (schema jwtCaller); refused, by name, in trusted-header.
    public JwksConfig? Jwks { get; init; }
    public IReadOnlyList<string?>? Algorithms { get; init; }
    public string? Issuer { get; init; }
    public string? Audience { get; init; }
    public int? ClockSkewSeconds { get; init; }
    public int? UnknownKidRefreshSeconds { get; init; }
    public IReadOnlyList<string?>? SubjectClaims { get; init; }
    public IReadOnlyList<string?>? TenantClaims { get; init; }
    public string? RequiredTyp { get; init; }

    /// <summary>Members no mode has: refused and reported by name.</summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement>? Extra { get; init; }

    /// <summary>The jwt members present (trusted-header has none of them).</summary>
    internal IEnumerable<string> JwtMembers()
    {
        if (Jwks is not null) yield return "jwks";
        if (Algorithms is not null) yield return "algorithms";
        if (Issuer is not null) yield return "issuer";
        if (Audience is not null) yield return "audience";
        if (ClockSkewSeconds is not null) yield return "clockSkewSeconds";
        if (UnknownKidRefreshSeconds is not null) yield return "unknownKidRefreshSeconds";
        if (SubjectClaims is not null) yield return "subjectClaims";
        if (TenantClaims is not null) yield return "tenantClaims";
        if (RequiredTyp is not null) yield return "requiredTyp";
    }
}

/// <summary>The fixed JWKS of the jwt caller: exactly one of an https <see cref="Url"/> or inline public <see cref="Keys"/>.</summary>
public sealed record JwksConfig
{
    public string? Url { get; init; }
    public IReadOnlyList<JsonElement>? Keys { get; init; }
}

public sealed record RouteConfig
{
    public string? Method { get; init; }
    public string? Path { get; init; }
    public string? Operation { get; init; }
    public string Mode { get; init; } = "enforce";
    public bool AllowOperationReplay { get; init; }
}

public sealed record ExemptConfig
{
    public string? Method { get; init; }
    public string? Path { get; init; }
}

/// <summary>The configuration is invalid; the host does not start. <see cref="Errors"/> never carries a secret.</summary>
public sealed class VerifierConfigException(IReadOnlyList<string> errors)
    : Exception("Invalid gateway verifier configuration: " + string.Join(" ", errors))
{
    public IReadOnlyList<string> Errors { get; } = errors;
}
