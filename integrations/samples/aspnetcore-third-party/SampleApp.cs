using Sentomaru.AspNetCore;

namespace ThirdPartyApi;

/// <summary>Host of the sample. <paramref name="overrides"/> lets the tests swap the transport to Sentomaru.</summary>
public static class SampleApp
{
    public static WebApplication Build(string[] args, Action<IServiceCollection>? overrides = null)
    {
        // ApplicationName pins controller discovery to this assembly (the tests host it from theirs).
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            Args = args, ApplicationName = typeof(SampleApp).Assembly.GetName().Name,
        });
        // guide:begin registration
        // Section "Sentomaru" (appsettings or environment variables Sentomaru__*). The workload token comes from the
        // secret store as Sentomaru__WorkloadToken, never from a versioned file.
        builder.Services.AddSentomaruClient(builder.Configuration, "Sentomaru");
        builder.Services.AddSingleton<ISentomaruContextResolver, CallerContextResolver>();
        builder.Services.AddControllers();
        // guide:end registration
        builder.Services.AddSingleton<OrderStore>();
        // guide:begin step-up-registration
        // 4.5.0 (D-06b): optional step_up hook (a fake one in this sample). Without it, a step_up challenge is 401.
        builder.Services.AddSingleton(TimeProvider.System);
        builder.Services.AddSingleton<ISentomaruChallengeHandler, StepUpHandler>();
        // guide:end step-up-registration
        overrides?.Invoke(builder.Services);
        var app = builder.Build();
        app.MapControllers();
        // guide:begin capabilities
        // C-09 (#143): GET /integrity/capabilities, public, no token: what this backend enforces, read by the app at
        // bootstrap and by the release smoke test.
        app.MapSentomaruCapabilities();
        // guide:end capabilities
        return app;
    }
}
