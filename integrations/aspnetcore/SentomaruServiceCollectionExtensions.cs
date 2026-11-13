using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Sentomaru.AspNetCore;

/// <summary>
/// Dependency injection extensions for registering Sentomaru integrity services.
/// </summary>
public static class SentomaruServiceCollectionExtensions
{
    /// <summary>
    /// Registers <see cref="ISentomaruClient"/> and typed <see cref="SentomaruClient"/> with optional configuration.
    /// </summary>
    public static IServiceCollection AddSentomaruClient(
        this IServiceCollection services,
        Action<SentomaruClientOptions>? configure = null)
    {
        var optionsBuilder = services.AddOptions<SentomaruClientOptions>();
        if (configure is not null)
        {
            optionsBuilder.Configure(configure);
        }
        // FailOpen / http BaseAddress outside Development stop the host at startup instead of silently degrading.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<SentomaruClientOptions>, SentomaruClientOptionsValidator>());
        // 4.19.0: every [SentomaruIntegrity(OperationRules = "...")] names a configured set (every environment).
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<SentomaruClientOptions>, SentomaruOperationRulesValidator>());
        optionsBuilder.ValidateOnStart();
        services.TryAddSingleton<SentomaruNotices>();

        services.AddHttpClient<ISentomaruClient, SentomaruClient>((sp, client) =>
        {
            var options = sp.GetRequiredService<IOptions<SentomaruClientOptions>>().Value;
            if (options.BaseAddress is not null)
            {
                client.BaseAddress = options.BaseAddress;
            }
            if (options.ClientTimeout > TimeSpan.Zero)
            {
                client.Timeout = options.ClientTimeout;
            }
        });

        services.AddHostedService<SentomaruHeartbeatService>();

        return services;
    }

    /// <summary>
    /// Registers <see cref="ISentomaruClient"/> configured from an <see cref="IConfiguration"/> section.
    /// </summary>
    public static IServiceCollection AddSentomaruClient(
        this IServiceCollection services,
        IConfiguration configuration,
        string sectionName = SentomaruClientOptions.DefaultSectionName)
    {
        services.Configure<SentomaruClientOptions>(configuration.GetSection(sectionName));
        return services.AddSentomaruClient();
    }

    /// <summary>
    /// 4.17.0: registers the web observation (needs <see cref="AddSentomaruClient(IServiceCollection, Action{SentomaruClientOptions}?)"/>): <see cref="ISentomaruWebObserver"/>,
    /// the outcome store (the file one when <see cref="SentomaruWebObservationOptions.OutcomeDirectory"/> is set, else in memory; register your own
    /// <see cref="ISentomaruWebOutcomeStore"/> to replace it), <see cref="SentomaruWebObservationMetrics"/> and the optional weekly export service. Everything is off
    /// until <see cref="SentomaruWebObservationOptions.Enabled"/> is true. The host then calls <see cref="ISentomaruWebObserver.ObserveChallenge"/> where it knows the challenge verdict.
    /// </summary>
    public static IServiceCollection AddSentomaruWebObservation(
        this IServiceCollection services,
        Action<SentomaruWebObservationOptions>? configure = null)
    {
        var optionsBuilder = services.AddOptions<SentomaruWebObservationOptions>();
        if (configure is not null) optionsBuilder.Configure(configure);
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<SentomaruWebObservationMetrics>();
        services.TryAddSingleton<ISentomaruWebOutcomeStore>(sp =>
            sp.GetRequiredService<IOptions<SentomaruWebObservationOptions>>().Value.OutcomeDirectory is { Length: > 0 } dir
                ? new SentomaruFileWebOutcomeStore(dir)
                : new SentomaruMemoryWebOutcomeStore());
        services.TryAddScoped<ISentomaruWebObserver, SentomaruWebObserver>();
        services.AddHostedService<SentomaruWebOutcomeExportService>();
        return services;
    }

    /// <summary>4.17.0: same as above, configured from an <see cref="IConfiguration"/> section (default <c>Sentomaru:Web</c>).</summary>
    public static IServiceCollection AddSentomaruWebObservation(
        this IServiceCollection services,
        IConfiguration configuration,
        string sectionName = "Sentomaru:Web")
    {
        services.Configure<SentomaruWebObservationOptions>(configuration.GetSection(sectionName));
        return services.AddSentomaruWebObservation();
    }
}
