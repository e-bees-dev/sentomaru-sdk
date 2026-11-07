using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Sentomaru.AspNetCore;

namespace Sentomaru.Gateway.Verifier;

/// <summary>
/// The gateway verifier host (D-17c, contract <c>contracts/api/gateway-verifier-v1.md</c>). One instance per scope
/// (D-17x9). For every request the gateway asks about: the route table gives the operation and mode (403
/// <c>operation-unmapped</c> outside it), the decision core of the adapter (<see cref="SentomaruEvaluationPipeline"/>,
/// with <see cref="SentomaruExtractor"/> and no <c>UsePathBase</c>, so the @target-uri is built as the attribute builds
/// it) evaluates once, and the answer is the attribute's: 200 with the <c>sentomaru-verified-*</c> headers, or its status
/// and JSON body. Divergences from the attribute are only those of the closed list (contract section 6): a refused
/// workload credential becomes 503 <c>integrity-unavailable</c>; a challenge is always 401 <c>challenge-required</c>
/// (no step-up hook, <see cref="SentomaruEvaluationOptions.UseChallengeHandler"/> false). Fail closed everywhere: no
/// FailOpen, no KnownProxies, no X-Forwarded-*, no retry.
/// </summary>
public static class VerifierApp
{
    public const string ResultPrefix = "sentomaru-verified-";
    public const string SubjectResult = ResultPrefix + "subject";
    public const string TenantResult = ResultPrefix + "tenant";
    public const string InstallationResult = ResultPrefix + "installation";
    public const string SessionResult = ResultPrefix + "session";
    public const string VerdictResult = ResultPrefix + "verdict";
    public const string PolicyStatusResult = ResultPrefix + "policy-status";
    public const string OperationIdResult = ResultPrefix + "operation-id";
    public const string FirstAdmissionResult = ResultPrefix + "first-admission";
    public const string ObservedResult = ResultPrefix + "observed";

    private const string LogCategory = "Sentomaru.Gateway.Verifier";

    /// <summary>
    /// API codes that refuse the verifier's own credential or its organization's entitlement (ApiContract: 401
    /// <c>workload-required</c>; 403 <c>workload-kind</c>, <c>workload-scope</c> and the <c>module-*</c> codes): 503
    /// <c>integrity-unavailable</c>. <c>workload-kind</c> since D-17x5: a credential of a kind the evaluation route does not
    /// take is a deployment error of the verifier, never an answer about the app.
    /// </summary>
    public static readonly IReadOnlySet<string> CredentialCodes = new HashSet<string>(StringComparer.Ordinal)
    {
        "workload-required", "workload-kind", "workload-scope", "module-not-entitled", "module-quota-exceeded", "module-trial-expired",
    };

    /// <summary>
    /// Builds the host from a configuration. Throws <see cref="VerifierConfigException"/> when the configuration, the
    /// derived adapter options or the environment is not allowed: the host never starts with them.
    /// <paramref name="overrides"/> lets the tests replace the transport to Sentomaru; <paramref name="beforeVerification"/>
    /// lets them observe a request before the verifier answers it (it must not change it).
    /// </summary>
    public static WebApplication Build(VerifierConfig config, string[]? args = null, Action<IServiceCollection>? overrides = null,
        Action<WebApplication>? beforeVerification = null)
    {
        ArgumentNullException.ThrowIfNull(config);
        var errors = config.Validate();
        if (errors.Count > 0) throw new VerifierConfigException(errors);

        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            Args = args ?? [], ApplicationName = typeof(VerifierApp).Assembly.GetName().Name,
            // Review R M-3: always Production, whatever ASPNETCORE_ENVIRONMENT or --environment say: no developer
            // exception page, and no Development branch in the decision core (FailOpen, placeholders, unacknowledged
            // kill switch).
            EnvironmentName = Environments.Production,
        });
        if (!builder.Environment.IsProduction())
        {
            throw new VerifierConfigException(["the verifier runs only in the Production environment."]);
        }
        // ASPNETCORE_FORWARDEDHEADERS_ENABLED would add the forwarded-headers middleware (X-Forwarded-*, trusting every
        // peer); the verifier has none (contract section 1).
        if (string.Equals(builder.Configuration["FORWARDEDHEADERS_ENABLED"], "true", StringComparison.OrdinalIgnoreCase))
        {
            throw new VerifierConfigException(["ASPNETCORE_FORWARDEDHEADERS_ENABLED is not allowed: the verifier reads no X-Forwarded-* header."]);
        }
        // No reload of Kestrel:Endpoints: a listener opened after the start would escape ListenerCheck (R of 30/10, M-4).
        builder.WebHost.ConfigureKestrel((context, kestrel) =>
        {
            kestrel.AddServerHeader = false;
            kestrel.Configure(context.Configuration.GetSection("Kestrel"), reloadOnChange: false);
        });
        // No request line in the log (it carries the path and the host); the verifier writes its own line, with the
        // route's operation and never the path, a token, a body or an identifier.
        builder.Logging.AddFilter("Microsoft.AspNetCore", LogLevel.Warning);
        builder.Logging.AddFilter("System.Net.Http.HttpClient", LogLevel.Warning);

        var table = RouteTable.Compile(config.Routes!);
        var tokenFile = config.Sentomaru!.WorkloadTokenFile!;
        builder.Services.AddSingleton(config);
        builder.Services.AddSingleton(table);
        builder.Services.AddSingleton<VerifierMetrics>();
        if (config.Caller!.Mode == "jwt")
        {
            // D-17c2: the user's JWT is validated here against the fixed JWKS; the caller reaches the decision core in the
            // same shape trusted-header gives it.
            var jwtSettings = JwtCallerSettings.From(config.Caller);
            builder.Services.AddSingleton(jwtSettings);
            builder.Services.TryAddSingleton(TimeProvider.System);
            builder.Services.AddHttpClient(JwksSource.ClientName)
                // Review R N5: no proxy either (HTTPS_PROXY/ALL_PROXY would put a third party between the verifier and the IdP).
                .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler { AllowAutoRedirect = false, UseCookies = false, UseProxy = false });
            builder.Services.AddSingleton(sp => new JwksSource(jwtSettings, sp.GetService<IHttpClientFactory>(),
                sp.GetRequiredService<TimeProvider>(), sp.GetRequiredService<ILoggerFactory>().CreateLogger(LogCategory)));
            builder.Services.AddSingleton<JwtCallerValidator>();
            builder.Services.AddSingleton<ISentomaruContextResolver, JwtCallerResolver>();
            // Review R M-2: the first fetch starts with the host (never waited for); /health is ready only with a usable set.
            if (config.Enabled) builder.Services.AddHostedService(sp => new JwksWarmup(sp.GetRequiredService<JwksSource>()));
        }
        else
        {
            builder.Services.AddSingleton<ISentomaruContextResolver, TrustedHeaderCallerResolver>();
        }
        builder.Services.AddSentomaruClient(options =>
        {
            options.Enabled = config.Enabled;
            options.DisabledAcknowledged = config.DisabledAcknowledged;
            options.PublicBaseUrl = new Uri(config.PublicBaseUrl!);
            options.BaseAddress = new Uri(config.Sentomaru.BaseAddress!);
            options.Org = config.Scope!.Org!;
            options.App = config.Scope.App!;
            options.Env = config.Scope.Env!;
            options.Timeout = TimeSpan.FromMilliseconds(config.Sentomaru.TimeoutMs);
        });
        builder.Services.AddHttpClient<ISentomaruClient, SentomaruClient>()
            .AddHttpMessageHandler(() => new WorkloadTokenHandler(tokenFile));
        var listeners = new ListenerCheck(config.ManagementPort, config.Caller.Mode == "trusted-header");
        builder.Services.AddSingleton(listeners);
        builder.Services.AddHostedService(sp => sp.GetRequiredService<ListenerCheck>().Bind(sp));
        overrides?.Invoke(builder.Services);
        // Whatever was registered: the verifier never trusts a proxy, never fails open, never invents a caller, and the
        // bearer comes only from the token file.
        builder.Services.PostConfigure<SentomaruClientOptions>(options =>
        {
            options.KnownProxies.Clear();
            options.FailOpen = false;
            options.AllowAnonymousContext = false;
            options.WorkloadToken = null;
        });

        var app = builder.Build();
        try
        {
            _ = app.Services.GetRequiredService<IOptions<SentomaruClientOptions>>().Value;
        }
        catch (OptionsValidationException e)
        {
            throw new VerifierConfigException([.. e.Failures]);
        }

        beforeVerification?.Invoke(app);
        var metrics = app.Services.GetRequiredService<VerifierMetrics>();
        var logger = app.Services.GetRequiredService<ILoggerFactory>().CreateLogger(LogCategory);
        var jwt = config.Enabled ? app.Services.GetService<JwtCallerValidator>() : null;
        var jwks = config.Enabled ? app.Services.GetService<JwksSource>() : null;
        var jwksNotice = new MinuteNotice();
        app.Run(context =>
        {
            if (!listeners.Ready)
            {
                // Before (or after a failed) check of the listeners nothing is answered as verified or healthy.
                context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
                return context.Response.WriteAsJsonAsync(new SentomaruApiError { Code = "integrity-unavailable" }, context.RequestAborted);
            }
            return config.ManagementPort is { } port && context.Connection.LocalPort == port
                ? ManageAsync(context, metrics, jwks)
                : VerifyAsync(context, table, metrics, logger, jwt, jwksNotice);
        });
        return app;
    }

    /// <summary>
    /// Review R I-1: the management port must not be a port the gateway can reach as the verification listener. After
    /// the server bound its addresses, the start fails (<see cref="VerifierConfigException"/>) unless at least one listener
    /// uses another port (the verification listener) and one uses <see cref="VerifierConfig.ManagementPort"/>. Every
    /// request is answered 503 until this check passed, so a refused start never answered 200.
    /// </summary>
    internal sealed class ListenerCheck(int? managementPort, bool trustedHeader) : IHostedLifecycleService
    {
        private IServiceProvider? services;
        private volatile bool ready;

        public bool Ready => ready;

        public ListenerCheck Bind(IServiceProvider provider)
        {
            services = provider;
            return this;
        }

        public Task StartedAsync(CancellationToken cancellationToken)
        {
            var addresses = services?.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()?.Addresses ?? [];
            if (trustedHeader)
            {
                var exposed = ExposedAddresses(addresses);
                if (exposed.Count > 0)
                {
                    throw new VerifierConfigException([$"caller trusted-header cannot listen on {string.Join(", ", exposed)}: anyone who " +
                        "reaches the listener chooses the caller. Bind a loopback or private address or a Unix socket; for mTLS, terminate it in a sidecar on loopback."]);
                }
            }
            var ports = addresses.Select(a => BindingAddress.Parse(a).Port).ToList();
            if (managementPort is { } port)
            {
                var errors = new List<string>();
                if (!ports.Contains(port)) errors.Add($"managementPort {port} is not one of the bound addresses.");
                if (!ports.Any(p => p != port))
                {
                    errors.Add($"managementPort {port} is the only bound port: the verification listener would answer /health and " +
                               "/metrics to the gateway. Bind the verification listener to another port.");
                }
                if (errors.Count > 0) throw new VerifierConfigException(errors);
            }
            ready = true;
            return Task.CompletedTask;
        }

        public Task StartingAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public Task StartAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public Task StoppingAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public Task StoppedAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    }

    /// <summary>
    /// The addresses that <c>trusted-header</c> refuses (contract section 5, item 6): a wildcard, a host name other than
    /// <c>localhost</c>, or any IP outside this list. Loopback, private and unique-local IPs and Unix sockets pass; that they are reachable only
    /// from the gateway stays the deployer's declaration (<c>verifierReachableOnlyFromGateway</c>).
    /// </summary>
    public static IReadOnlyList<string> ExposedAddresses(IEnumerable<string> addresses) =>
        [.. addresses.Where(address =>
        {
            var parsed = BindingAddress.Parse(address);
            if (parsed.IsUnixPipe || string.Equals(parsed.Host, "localhost", StringComparison.OrdinalIgnoreCase)) return false;
            return !System.Net.IPAddress.TryParse(parsed.Host, out var ip) || !IsLocalOrPrivate(ip);
        })];

    private static bool IsLocalOrPrivate(System.Net.IPAddress ip)
    {
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (ip.Equals(System.Net.IPAddress.Any) || ip.Equals(System.Net.IPAddress.IPv6Any)) return false;
        if (System.Net.IPAddress.IsLoopback(ip)) return true;
        var bytes = ip.GetAddressBytes();
        return bytes.Length == 4
            ? bytes[0] == 10 || (bytes[0] == 172 && bytes[1] is >= 16 and <= 31) || (bytes[0] == 192 && bytes[1] == 168)
            : (bytes[0] & 0xfe) == 0xfc;
    }

    /// <summary>The management listener: <c>GET /health</c> and <c>GET /metrics</c>, 404 for anything else.</summary>
    private static Task ManageAsync(HttpContext context, VerifierMetrics metrics, JwksSource? jwks)
    {
        if (context.Request.Method == HttpMethods.Get && context.Request.Path == "/health")
        {
            if (jwks is not null && !jwks.Ready())
            {
                // Review R M-2: in jwt mode the instance is not ready without a usable JWKS (every token would be refused).
                context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
                return context.Response.WriteAsJsonAsync(new { status = "jwks-unavailable" }, context.RequestAborted);
            }
            return context.Response.WriteAsJsonAsync(new { status = "ok" }, context.RequestAborted);
        }
        if (context.Request.Method == HttpMethods.Get && context.Request.Path == "/metrics")
        {
            context.Response.ContentType = "text/plain; version=0.0.4; charset=utf-8";
            return context.Response.WriteAsync(metrics.Render(), context.RequestAborted);
        }
        context.Response.StatusCode = StatusCodes.Status404NotFound;
        return Task.CompletedTask;
    }

    private static async Task VerifyAsync(HttpContext context, RouteTable table, VerifierMetrics metrics, ILogger logger,
        JwtCallerValidator? jwt, MinuteNotice jwksNotice)
    {
        // I4: the @target-uri is publicBaseUrl + PathBase + Path + QueryString; the verifier never has a PathBase.
        if (context.Request.PathBase.HasValue)
        {
            logger.LogError("Sentomaru verifier: a PathBase is set (UsePathBase or a prefix middleware); refusing.");
            await RefuseAsync(context, metrics, logger, null, StatusCodes.Status500InternalServerError, new SentomaruApiError { Code = "internal-error" });
            return;
        }

        // Review R M-2: Kestrel removes dot segments (also %2E-encoded) before Path; the table must not match a path the
        // upstream may see differently. A raw target with a dot, an encoded dot or an empty segment is outside the table.
        var raw = context.Features.Get<IHttpRequestFeature>()?.RawTarget;
        var route = RouteTable.RawTargetAllowed(raw) ? table.Match(context.Request.Method, context.Request.Path.Value) : null;
        if (route is null)
        {
            // C1: a request outside the table never passes. The path is not logged (it may carry an identifier).
            await RefuseAsync(context, metrics, logger, null, StatusCodes.Status403Forbidden, new SentomaruApiError { Code = "operation-unmapped" });
            return;
        }

        // D-17c2: the JWT is validated only where the decision core would ask for the caller (a proof is present: without
        // one the core answers 401 proof-required, or observes without a caller), so the order of the answers stays the
        // attribute's.
        if (jwt is not null && HasProof(context.Request))
        {
            JwtOutcome outcome;
            try
            {
                outcome = await jwt.ValidateAsync(context.Request.Headers.Authorization, context.RequestAborted);
            }
            catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested)
            {
                // Review R N6: the gateway went away while a JWKS fetch was awaited; nothing to answer, nothing to log.
                return;
            }
            if (outcome.Valid)
            {
                context.Items[JwtCallerResolver.Item] = outcome.Caller;
            }
            else
            {
                metrics.RecordJwt(outcome.Reason);
                // The reason only: never the token, a claim or a header value.
                logger.LogInformation("Sentomaru verifier: caller JWT refused ({Reason}) for {Operation}.", outcome.Reason, route.Operation);
                // Observe never refuses: the request passes without a caller (the core observes nothing), as in trusted-header.
                if (route.Mode == "enforce" && outcome.Reason == "jwks-unavailable")
                {
                    // Fail closed, and not as if the app's token were wrong: the verifier cannot check any token now.
                    if (jwksNotice.Due())
                    {
                        logger.LogError("Sentomaru verifier: no usable JWKS; refusing JWT callers with 503 (logged at most once a minute).");
                    }
                    await RefuseAsync(context, metrics, logger, route, StatusCodes.Status503ServiceUnavailable,
                        new SentomaruApiError { Code = "integrity-unavailable" });
                    return;
                }
                if (route.Mode == "enforce" && JwtCallerValidator.InvalidToken.Contains(outcome.Reason))
                {
                    // Review R I-1: as JwtBearer and jwt_authn answer, so the app renews its token.
                    context.Response.Headers.WWWAuthenticate = "Bearer error=\"invalid_token\"";
                    await RefuseAsync(context, metrics, logger, route, StatusCodes.Status401Unauthorized,
                        new SentomaruApiError { Code = "authentication-required" });
                    return;
                }
                // "caller": a valid token without a usable subject/tenant; the core answers 403 caller-context-missing.
            }
        }

        var decision = await SentomaruEvaluationPipeline.DecideAsync(context, new SentomaruEvaluationOptions(route.Operation)
        {
            AssuranceLevel = route.AssuranceLevel,
            AllowOperationReplay = route.AllowOperationReplay,
            UseChallengeHandler = false,
        }, logger);

        if (decision.Kind == SentomaruDecisionKind.Refuse)
        {
            var error = decision.Error ?? new SentomaruApiError { Code = "internal-error" };
            if (CredentialCodes.Contains(error.Code))
            {
                // The verifier's own credential (or its organization's module entitlement) was refused: never answered as
                // if it were the app's (contract section 2).
                logger.LogError("Sentomaru refused the verifier's workload credential ({Code}) for {Operation}; answering 503.",
                    error.Code, route.Operation);
                await RefuseAsync(context, metrics, logger, route, StatusCodes.Status503ServiceUnavailable,
                    new SentomaruApiError { Code = "integrity-unavailable" });
                return;
            }
            await RefuseAsync(context, metrics, logger, route, decision.StatusCode, error);
            return;
        }

        var evaluation = decision.Evaluation;
        string resultCode;
        switch (decision.Reason)
        {
            case SentomaruProceedReason.Verified when evaluation is not null:
                if (!TryAddResults(context.Response.Headers, evaluation, observed: false))
                {
                    logger.LogError("Sentomaru verifier: a result value for {Operation} cannot travel in a header; refusing.", route.Operation);
                    context.Response.Headers.Clear();
                    await RefuseAsync(context, metrics, logger, route, StatusCodes.Status500InternalServerError,
                        new SentomaruApiError { Code = "internal-error" });
                    return;
                }
                resultCode = "verified";
                break;
            case SentomaruProceedReason.Observe:
                // Observe always passes (contract section 2); unrepresentable values are left out, never invented.
                if (evaluation is not null && !TryAddResults(context.Response.Headers, evaluation, observed: true))
                {
                    context.Response.Headers.Clear();
                }
                context.Response.Headers[ObservedResult] = "true";
                resultCode = "observed";
                break;
            case SentomaruProceedReason.Disabled:
                // The acknowledged kill switch (the core logs Error on every request): only the verdict "disabled", no
                // subject or tenant; nothing was verified, the upstream decides (contract section 3).
                context.Response.Headers[VerdictResult] = "disabled";
                resultCode = "disabled";
                break;
            default:
                // FailOpen and the step-up hook do not exist here; anything else is a bug, and a bug refuses.
                logger.LogError("Sentomaru verifier: unexpected proceed reason {Reason} for {Operation}; refusing.", decision.Reason, route.Operation);
                await RefuseAsync(context, metrics, logger, route, StatusCodes.Status500InternalServerError,
                    new SentomaruApiError { Code = "internal-error" });
                return;
        }
        context.Response.StatusCode = StatusCodes.Status200OK;
        metrics.Record(StatusCodes.Status200OK, resultCode, route.Mode);
        logger.LogInformation("Sentomaru verifier: 200 {Code} {Mode} {Operation}.", resultCode, route.Mode, route.Operation);
    }

    private static async Task RefuseAsync(HttpContext context, VerifierMetrics metrics, ILogger logger, VerifierRoute? route, int status,
        SentomaruApiError error)
    {
        var mode = route?.Mode ?? "none";
        metrics.Record(status, error.Code, mode);
        logger.LogInformation("Sentomaru verifier: {Status} {Code} {Mode} {Operation}.", status,
            VerifierMetrics.Codes.Contains(error.Code) ? error.Code : "other", mode, route?.Operation ?? "-");
        context.Response.StatusCode = status;
        await context.Response.WriteAsJsonAsync(error, context.RequestAborted);
    }

    /// <summary>The result headers of contract section 3; false when a value cannot travel in a header.</summary>
    private static bool TryAddResults(IHeaderDictionary headers, EvaluationResponseDto evaluation, bool observed)
    {
        var values = new List<(string Name, string Value)>
        {
            (SubjectResult, evaluation.Subject),
            (TenantResult, evaluation.Tenant),
            (InstallationResult, evaluation.InstallationId.ToString("D")),
            (SessionResult, evaluation.SessionId.ToString("D")),
            (VerdictResult, evaluation.RecommendedAction),
            (PolicyStatusResult, evaluation.PolicyStatus),
        };
        if (evaluation.OperationId is { } operationId) values.Add((OperationIdResult, operationId));
        if (evaluation.FirstAdmission is { } first) values.Add((FirstAdmissionResult, first ? "true" : "false"));
        // Subject and tenant are required on a verified answer: the upstream checks its session against them (I5).
        if (!observed && (string.IsNullOrEmpty(evaluation.Subject) || string.IsNullOrEmpty(evaluation.Tenant))) return false;
        if (values.Any(v => v.Value is null || !HeaderSafe(v.Value))) return false;
        foreach (var (name, value) in values) headers[name] = value;
        return true;
    }

    /// <summary>Review R N4: the "no usable JWKS" Error at most once a minute per host (the 503 is answered every time).</summary>
    internal sealed class MinuteNotice
    {
        private long loggedAt = long.MinValue;

        public bool Due()
        {
            var now = Environment.TickCount64;
            var last = Interlocked.Read(ref loggedAt);
            return (last == long.MinValue || now - last >= 60_000) && Interlocked.CompareExchange(ref loggedAt, now, last) == last;
        }
    }

    /// <summary>Review R M-2: starts the first JWKS fetch with the host, without waiting for it.</summary>
    private sealed class JwksWarmup(JwksSource source) : IHostedService
    {
        public Task StartAsync(CancellationToken cancellationToken)
        {
            source.Warm();
            return Task.CompletedTask;
        }

        public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    }

    /// <summary>Same test as the decision core: both signature headers present with a non-blank value.</summary>
    private static bool HasProof(HttpRequest request) =>
        request.Headers.TryGetValue("Signature-Input", out var input) && input.Any(v => !string.IsNullOrWhiteSpace(v)) &&
        request.Headers.TryGetValue("Signature", out var signature) && signature.Any(v => !string.IsNullOrWhiteSpace(v));

    /// <summary>Visible ASCII and inner spaces only: what every gateway passes unchanged.</summary>
    internal static bool HeaderSafe(string value) =>
        value.Length > 0 && value[0] != ' ' && value[^1] != ' ' && value.All(c => c is >= ' ' and <= '~');
}
