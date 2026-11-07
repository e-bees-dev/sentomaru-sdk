using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Sentomaru.AspNetCore;

/// <summary>
/// 4.0.0 (C-09, issue #143): what the CONSUMER backend enforces, for the app to read before it marks operations.
/// Sentomaru cannot know the consumer's <see cref="SentomaruClientOptions.Enabled"/>, so the adapter answers it.
/// Minimal by design: whether verification is on and which operations it protects (and whether each one blocks).
/// No token, no Sentomaru address, no scope, no adapter version, no FailOpen value. What it does expose (the names of
/// the protected operations) is already in the app binary that signs them; mapping the route is opt-in.
/// </summary>
public sealed record SentomaruCapabilitiesDto
{
    [JsonPropertyName("schemaVersion")]
    public string SchemaVersion { get; init; } = "1";

    /// <summary>Sentomaru verification is on in this backend (false = kill switch or not configured).</summary>
    [JsonPropertyName("enabled")]
    public required bool Enabled { get; init; }

    /// <summary>Each protected operation: <c>enforced</c> true = a missing or invalid proof is refused (ZeroTrust);
    /// false = evaluated and logged only (Observe). Empty when <see cref="Enabled"/> is false.</summary>
    [JsonPropertyName("operations")]
    public required IReadOnlyList<SentomaruCapabilitiesOperation> Operations { get; init; }
}

public sealed record SentomaruCapabilitiesOperation(
    [property: JsonPropertyName("operation")] string Operation,
    [property: JsonPropertyName("enforced")] bool Enforced);

/// <summary>How the capabilities route is exposed (opt-in; the defaults answer anonymous callers).</summary>
public sealed class SentomaruCapabilitiesRouteOptions
{
    /// <summary>Require an authenticated caller (the app reads it after login). Default false.</summary>
    public bool RequireAuthorization { get; set; }

    /// <summary>A rate limiting policy registered with <c>AddRateLimiter</c> to apply to the route. Default none.</summary>
    public string? RateLimitingPolicy { get; set; }

    /// <summary>Cache-Control max-age of the answer. Default 300 s (it only changes with a deploy or restart).</summary>
    public TimeSpan MaxAge { get; set; } = TimeSpan.FromMinutes(5);
}

public static class SentomaruCapabilitiesExtensions
{
    /// <summary>Default path, next to the enrollment routes of the integration guide.</summary>
    public const string DefaultPattern = "/integrity/capabilities";

    /// <summary>
    /// Maps <c>GET <paramref name="pattern"/></c>: the consumer's Sentomaru capabilities, computed ONCE (first request)
    /// from the options and the <see cref="SentomaruIntegrityAttribute"/> of every endpoint.
    /// </summary>
    public static IEndpointConventionBuilder MapSentomaruCapabilities(this IEndpointRouteBuilder endpoints,
        string pattern = DefaultPattern, Action<SentomaruCapabilitiesRouteOptions>? configure = null)
    {
        var route = new SentomaruCapabilitiesRouteOptions();
        configure?.Invoke(route);
        // PublicationOnly: an exception while describing is not cached; the next request tries again.
        var answer = new Lazy<SentomaruCapabilitiesDto>(() => Describe(endpoints.ServiceProvider), LazyThreadSafetyMode.PublicationOnly);
        // Behind authorization the answer is per caller to a shared cache: private.
        var maxAge = $"{(route.RequireAuthorization ? "private" : "public")}, max-age={(int)route.MaxAge.TotalSeconds}";
        var builder = endpoints.MapGet(pattern, (HttpContext http) =>
        {
            http.Response.Headers.CacheControl = maxAge;
            return Results.Json(answer.Value);
        });
        if (route.RequireAuthorization) builder.RequireAuthorization();
        else builder.AllowAnonymous();
        if (route.RateLimitingPolicy is { } policy) builder.RequireRateLimiting(policy);
        return builder;
    }

    /// <summary>The capabilities this process answers (also usable by tests and health checks). When one operation
    /// name is declared on several endpoints with different levels, the weakest one wins (Observe).</summary>
    public static SentomaruCapabilitiesDto Describe(IServiceProvider services)
    {
        var options = services.GetService<IOptions<SentomaruClientOptions>>()?.Value ?? new SentomaruClientOptions();
        var operations = new SortedDictionary<string, bool>(StringComparer.Ordinal);
        if (options.Enabled)
        {
            foreach (var source in services.GetServices<EndpointDataSource>())
            {
                foreach (var endpoint in source.Endpoints)
                {
                    var attribute = endpoint.Metadata.GetMetadata<SentomaruIntegrityAttribute>() ??
                        (endpoint.Metadata.GetMetadata<ControllerActionDescriptor>()?.MethodInfo
                            .GetCustomAttributes(typeof(SentomaruIntegrityAttribute), true).FirstOrDefault() as SentomaruIntegrityAttribute);
                    if (attribute is null) continue;
                    var enforced = attribute.AssuranceLevel != DeviceAssuranceLevel.Observe;
                    operations[attribute.Operation] = operations.TryGetValue(attribute.Operation, out var before) ? before && enforced : enforced;
                }
            }
        }
        return new SentomaruCapabilitiesDto
        {
            Enabled = options.Enabled,
            Operations = operations.Select(o => new SentomaruCapabilitiesOperation(o.Key, o.Value)).ToList(),
        };
    }
}
