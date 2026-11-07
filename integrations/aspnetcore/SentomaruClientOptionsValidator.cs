using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Sentomaru.AspNetCore;

/// <summary>
/// Startup validation of <see cref="SentomaruClientOptions"/> (runs via ValidateOnStart). Outside Development it
/// refuses FailOpen, an http BaseAddress/PublicBaseUrl, a missing PublicBaseUrl/KnownProxies and an unacknowledged
/// Enabled=false. Without a registered <see cref="IHostEnvironment"/> the strict (non-Development) rules apply.
/// An acknowledged production kill switch is logged at Error.
/// </summary>
public sealed class SentomaruClientOptionsValidator(IHostEnvironment? environment = null, ILoggerFactory? loggerFactory = null)
    : IValidateOptions<SentomaruClientOptions>
{
    public ValidateOptionsResult Validate(string? name, SentomaruClientOptions options)
    {
        var isDevelopment = environment?.IsDevelopment() == true;
        var errors = options.Validate(isDevelopment);
        if (errors.Count == 0 && !options.Enabled && !isDevelopment)
        {
            loggerFactory?.CreateLogger<SentomaruClientOptionsValidator>().LogError(
                "Sentomaru is DISABLED outside Development (Sentomaru:DisabledAcknowledged=true): every protected operation runs without verification.");
        }
        return errors.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(errors);
    }
}
