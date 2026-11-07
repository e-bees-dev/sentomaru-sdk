using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Sentomaru.AspNetCore;
using ThirdPartyApi;

namespace RaspLabHost;

public static class Program
{
    /// <summary>Names the certificate carries: LabHosts (comma separated, the addresses the devices use) plus localhost.</summary>
    public static IReadOnlyList<string> CertificateNames(string? labHosts) =>
        ["localhost", "127.0.0.1", .. (labHosts ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)];

    /// <summary>The host, built but not started. <paramref name="overrides"/> lets the tests swap the transport to Sentomaru.</summary>
    public static WebApplication Build(string[] args, Action<IServiceCollection>? overrides = null)
    {
        var certificate = LabCertificate.Create(CertificateNames(Environment.GetEnvironmentVariable("Lab__Hosts")), TimeProvider.System);
        var app = SampleApp.Build(args, services =>
        {
            services.AddAuthentication(LabSession.SchemeName).AddScheme<AuthenticationSchemeOptions, LabSession>(LabSession.SchemeName, _ => { });
            services.Configure<KestrelServerOptions>(kestrel => kestrel.ConfigureHttpsDefaults(https => https.ServerCertificate = certificate));
            // Lab only: shows the round that the adapter marked the step-up as proceeded (HttpContext.Items), without touching the sample the guide quotes.
            services.AddTransient<IStartupFilter, StepUpProceededHeader>();
            overrides?.Invoke(services);
        });
        // The laboratory login trusts the network: it never runs as a production host.
        if (!app.Environment.IsDevelopment())
            throw new InvalidOperationException("The rasp-lab host runs only with ASPNETCORE_ENVIRONMENT=Development.");
        Console.WriteLine($"rasp-lab host certificate sha256: {LabCertificate.Sha256(certificate)}");
        return app;
    }

    public static void Main(string[] args) => Build(args).Run();

    private sealed class StepUpProceededHeader : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            app.Use(async (context, pipeline) =>
            {
                context.Response.OnStarting(() =>
                {
                    if (context.Items[SentomaruIntegrityAttribute.StepUpProceededItem] is true)
                        context.Response.Headers["X-Lab-StepUp-Proceeded"] = "true";
                    return Task.CompletedTask;
                });
                await pipeline();
            });
            next(app);
        };
    }
}
