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
}
