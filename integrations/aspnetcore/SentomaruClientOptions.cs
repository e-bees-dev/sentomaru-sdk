namespace Sentomaru.AspNetCore;

/// <summary>
/// Configuration options for connecting to Sentomaru integrity service.
/// </summary>
public sealed class SentomaruClientOptions
{
    public const string DefaultSectionName = "Sentomaru";

    /// <summary>
    /// Master toggle. false = every [SentomaruIntegrity] operation runs WITHOUT verification. Outside Development
    /// this is refused at startup unless <see cref="DisabledAcknowledged"/> is also true (an explicit, audited
    /// production kill switch); then it is logged at Error at startup and on every bypassed protected request.
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Required (outside Development) to run with <see cref="Enabled"/> = false. Set only as a deliberate,
    /// recorded incident decision; it disables protection for every protected operation.
    /// </summary>
    public bool DisabledAcknowledged { get; set; } = false;

    /// <summary>
    /// 4.17.0: adds the end-user <c>message</c> to the refusal body of a blocked operation (<see cref="SentomaruApiError.Message"/>). Off by default: the refusal body is
    /// a contract the apps already parse and pin, so it stays byte for byte as before until the host turns this on; the apps' SDKs show the same text from the code.
    /// </summary>
    public bool IncludeUserMessage { get; set; }

    /// <summary>
    /// 4.17.0: the host's own end-user text for a blocked operation, per language (<c>pt-BR</c>, <c>en</c>, <c>es</c>). A blank or missing entry keeps the SDK's
    /// default text (which already says that some critical operations are blocked until approval). Shown in the <c>message</c> member of the refusal body.
    /// </summary>
    public Dictionary<string, string> UserMessages { get; set; } = new(StringComparer.Ordinal);

    /// <summary>
    /// Public https base URL clients sign against (e.g. https://api.example.com). Used to rebuild @target-uri.
    /// Outside Development either this or <see cref="KnownProxies"/> is required.
    /// </summary>
    public Uri? PublicBaseUrl { get; set; }

    /// <summary>
    /// IP addresses of reverse proxies whose X-Forwarded-Proto / X-Forwarded-Host are trusted. X-Forwarded-* from
    /// any other peer is ignored.
    /// </summary>
    public IList<string> KnownProxies { get; set; } = new List<string>();

    /// <summary>
    /// Base address of the Sentomaru private integrity API. Must be https outside the Development environment
    /// (the workload bearer token travels in every call); http is accepted only in Development.
    /// </summary>
    public Uri? BaseAddress { get; set; }

    /// <summary>
    /// Organization identifier (e.g. "ebees").
    /// </summary>
    public string Org { get; set; } = "ebees";

    /// <summary>
    /// Application identifier (e.g. "exampleapp" or "examplebackend").
    /// </summary>
    public string App { get; set; } = "exampleapp";

    /// <summary>
    /// Environment identifier (e.g. "dev", "hml", "prod").
    /// </summary>
    public string Env { get; set; } = "prod";

    /// <summary>
    /// Workload authentication Bearer token issued to the consumer application.
    /// </summary>
    public string? WorkloadToken { get; set; }

    /// <summary>
    /// Strict HTTP timeout for every call but the enrollment (see <see cref="EnrollmentTimeout"/>). Defaults to 2 seconds.
    /// </summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(2);

    /// <summary>
    /// 4.8.0: HTTP timeout for the enrollment call (<see cref="ISentomaruClient.CompleteEnrollmentAsync"/>), which
    /// verifies the attestation (Android key chain or Apple App Attest) and takes longer than an evaluation: in the HML
    /// the server spent ~1.1 s verifying an App Attest enrollment and the ExampleBackend saw it pass the 2 s <see cref="Timeout"/>
    /// (503 <c>store-unavailable</c>). Defaults to 10 seconds. The enrollment waits the longer of the two, never less
    /// than <see cref="Timeout"/>; zero or less means <see cref="Timeout"/>. Every other call keeps <see cref="Timeout"/>.
    /// A <see cref="Timeout"/> of zero, less or infinite (no deadline of the adapter's own, the HttpClient's applies)
    /// stays so for the enrollment too.
    /// </summary>
    public TimeSpan EnrollmentTimeout { get; set; } = TimeSpan.FromSeconds(10);

    /// <summary>Upper bound of <see cref="Timeout"/> and <see cref="EnrollmentTimeout"/> (validated at startup).</summary>
    public static readonly TimeSpan MaxTimeout = TimeSpan.FromMinutes(5);

    internal static bool Bounded(TimeSpan t) => t > TimeSpan.Zero && t != System.Threading.Timeout.InfiniteTimeSpan;

    /// <summary>The enrollment's deadline: the longer of <see cref="Timeout"/> and <see cref="EnrollmentTimeout"/>, or
    /// none (as <see cref="Timeout"/>) when <see cref="Timeout"/> sets none.</summary>
    internal TimeSpan EnrollmentDeadline =>
        Bounded(Timeout) && Bounded(EnrollmentTimeout) && EnrollmentTimeout > Timeout ? EnrollmentTimeout : Timeout;

    /// <summary>What the underlying <c>HttpClient.Timeout</c> is set to: the longest deadline plus 1 s, so each call's
    /// own deadline always fires first (a TimeoutException); zero = leave the HttpClient's own timeout.</summary>
    internal TimeSpan ClientTimeout => Bounded(Timeout) ? EnrollmentDeadline + TimeSpan.FromSeconds(1) : TimeSpan.Zero;

    /// <summary>
    /// Development only. When true, and only when the request carries non-empty Signature and Signature-Input
    /// headers (present, NOT verified), a Sentomaru outage (timeout or 503) lets the action run, so in Development a
    /// forged, unverified proof passes during an outage. Absent signature headers are always 401
    /// <c>proof-required</c>, FailOpen or not. Refused at startup outside Development and ignored at runtime there.
    /// </summary>
    public bool FailOpen { get; set; } = false;

    /// <summary>
    /// Development only (4.0.0, C-09). When the caller has no subject/tenant claim, the default resolver uses the
    /// placeholders <c>development-anonymous</c>/<c>development-default</c> instead of refusing. Refused at startup
    /// outside Development: there a missing claim is always 403 <c>caller-context-missing</c>.
    /// </summary>
    public bool AllowAnonymousContext { get; set; } = false;

    /// <summary>
    /// E-06: the <c>iss</c> of the IdP whose tokens are bound to the app's grants. Null (default) = the binding is off and
    /// evaluations carry no <c>externalTokenBindingHash</c>. When set, the filter hashes the claims of the principal that
    /// ASP.NET authentication already validated (<c>sub</c> and <c>sid</c>, else <c>jti</c>); it never reads or sends the token.
    /// </summary>
    public string? TokenBindingIdpIssuer { get; set; }

    /// <summary>
    /// 4.13.0 (ativação de módulos, fase E): the consumer's name in the heartbeat (<c>[a-z][a-z0-9-]{0,39}</c>, such as <c>examplebackend</c>). While null the package
    /// declares nothing, so the Sentomaru Readiness shows the consumer modules as unknown. The declaration is informational and never changes a decision.
    /// </summary>
    public string? HeartbeatConsumer { get; set; }

    /// <summary>4.13.0: how often the declaration is sent after the one at start (one minute at least; shorter means one hour). Defaults to one hour.</summary>
    public TimeSpan HeartbeatInterval { get; set; } = TimeSpan.FromHours(1);

    /// <summary>
    /// 4.20.0: what the consumer declares by configuration (<c>Sentomaru:HeartbeatFeatures:MetricsExported=true</c>, <c>…:MobileGate</c>, <c>…:RequireBinding</c>,
    /// <c>…:Fraud</c>, <c>…:BindingTablePresent:{table}</c>), so a consumer declares without code. A member an <see cref="ISentomaruFeatureSource"/> fills wins over
    /// the one here; a member left out of both is not sent ("not declared", never false). <c>FailOpen</c> is not declared here: the package always sends
    /// <see cref="FailOpen"/>. Informational, like every heartbeat member: it never changes a decision.
    /// </summary>
    public ConsumerFeaturesDto HeartbeatFeatures { get; set; } = new();

    /// <summary>
    /// 4.19.0: named rule sets (<c>Sentomaru:OperationRules:{set}</c>) that pick the operation of a request from its JSON
    /// body, for a route that covers several business actions. A route opts in with
    /// <c>[SentomaruIntegrity("default_op", OperationRules = "set")]</c>; see <see cref="SentomaruOperationRules"/>. Set names
    /// ignore case. Validated at startup in every environment.
    /// </summary>
    public Dictionary<string, List<SentomaruOperationRule>> OperationRules { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Number of retries on 503 Store Unavailable or transient transport failures. Defaults to 2.
    /// </summary>
    public int RetryCount { get; set; } = 2;

    /// <summary>
    /// Returns the configuration errors for the given environment (empty when valid). Used by startup validation
    /// (<see cref="SentomaruClientOptionsValidator"/>) and re-checked by the filter at runtime.
    /// </summary>
    public IReadOnlyList<string> Validate(bool isDevelopment)
    {
        var errors = new List<string>();
        // 4.19.0: a broken rule set is refused in every environment and also with Enabled=false.
        errors.AddRange(SentomaruOperationRules.Validate(OperationRules));
        if (!Enabled)
        {
            if (!isDevelopment && !DisabledAcknowledged)
            {
                errors.Add("Sentomaru:Enabled=false outside Development requires Sentomaru:DisabledAcknowledged=true.");
            }
            return errors;
        }

        if (AllowAnonymousContext && !isDevelopment)
        {
            errors.Add("Sentomaru:AllowAnonymousContext=true is only allowed in the Development environment.");
        }
        if (FailOpen && !isDevelopment)
        {
            errors.Add("Sentomaru:FailOpen=true is only allowed in the Development environment.");
        }
        if (HeartbeatConsumer is not null && !System.Text.RegularExpressions.Regex.IsMatch(HeartbeatConsumer, @"\A[a-z][a-z0-9-]{0,39}\z"))
        {
            errors.Add("Sentomaru:HeartbeatConsumer must be lowercase letters, digits and hyphens, starting with a letter (40 characters at most).");
        }
        if (HeartbeatFeatures?.FailOpen is not null)
        {
            errors.Add("Sentomaru:HeartbeatFeatures:FailOpen is not declared by configuration: the heartbeat always sends Sentomaru:FailOpen.");
        }
        if (HeartbeatFeatures?.BindingTablePresent is { } tables &&
            (tables.Count > 8 || tables.Keys.Any(k => !System.Text.RegularExpressions.Regex.IsMatch(k, @"\A[a-z0-9_-]{1,32}\z"))))
        {
            errors.Add("Sentomaru:HeartbeatFeatures:BindingTablePresent takes at most 8 table names of lowercase letters, digits, '_' and '-' (32 characters at most).");
        }
        // 4.8.0: HttpClient.Timeout and CancelAfter throw above int.MaxValue ms; nothing here needs minutes.
        if (Timeout > MaxTimeout)
        {
            errors.Add("Sentomaru:Timeout must be at most 5 minutes.");
        }
        if (EnrollmentTimeout > MaxTimeout)
        {
            errors.Add("Sentomaru:EnrollmentTimeout must be at most 5 minutes.");
        }
        if (BaseAddress is not null && !isDevelopment &&
            !string.Equals(BaseAddress.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            errors.Add("Sentomaru:BaseAddress must use https outside the Development environment.");
        }
        if (!isDevelopment && PublicBaseUrl is null && KnownProxies.Count == 0)
        {
            errors.Add("Sentomaru:PublicBaseUrl or Sentomaru:KnownProxies is required outside Development.");
        }
        if (PublicBaseUrl is not null && !isDevelopment &&
            !string.Equals(PublicBaseUrl.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            errors.Add("Sentomaru:PublicBaseUrl must use https outside the Development environment.");
        }
        // 4.7.0 (D-17b review R M-4): user information would become part of every @target-uri; refused in every
        // environment.
        if (PublicBaseUrl is not null && PublicBaseUrl.IsAbsoluteUri && !string.IsNullOrEmpty(PublicBaseUrl.UserInfo))
        {
            errors.Add("Sentomaru:PublicBaseUrl must not carry user information.");
        }
        return errors;
    }

    /// <summary>
    /// Helper to build the scoped prefix /v1/{org}/{app}/{env}.
    /// </summary>
    public string BuildScopedPath(string endpoint)
    {
        var cleanEndpoint = endpoint.TrimStart('/');
        return $"/v1/{Org}/{App}/{Env}/{cleanEndpoint}";
    }
}
