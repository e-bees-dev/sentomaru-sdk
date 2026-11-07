namespace Sentomaru.Gateway.Verifier;

public static class Program
{
    public const string ConfigVariable = "SENTOMARU_VERIFIER_CONFIG";

    /// <summary>
    /// <c>Sentomaru.Gateway.Verifier --config /etc/sentomaru/verifier.json</c> (or <c>SENTOMARU_VERIFIER_CONFIG</c>).
    /// Listeners come from the usual ASP.NET Core settings (<c>--urls</c>, <c>ASPNETCORE_URLS</c>); bind the verification
    /// listener where only the gateway reaches it, and the management port, if any, where the probes reach it. An invalid
    /// configuration prints every error and exits with 2 without starting.
    /// </summary>
    public static int Main(string[] args)
    {
        var path = ConfigPath(args) ?? Environment.GetEnvironmentVariable(ConfigVariable);
        if (string.IsNullOrWhiteSpace(path))
        {
            Console.Error.WriteLine($"Sentomaru verifier: no configuration (--config <file> or {ConfigVariable}).");
            return 2;
        }
        WebApplication app;
        try
        {
            app = VerifierApp.Build(VerifierConfig.Load(path), args);
        }
        catch (VerifierConfigException e)
        {
            foreach (var error in e.Errors) Console.Error.WriteLine("Sentomaru verifier: " + error);
            return 2;
        }
        try
        {
            app.Run();
        }
        catch (Exception e) when (Refusal(e) is { } refused)
        {
            // The listeners were refused after binding (review R I-1); nothing was answered as verified.
            foreach (var error in refused.Errors) Console.Error.WriteLine("Sentomaru verifier: " + error);
            return 2;
        }
        return 0;
    }

    private static VerifierConfigException? Refusal(Exception e) => e switch
    {
        VerifierConfigException refused => refused,
        AggregateException all => all.Flatten().InnerExceptions.OfType<VerifierConfigException>().FirstOrDefault(),
        _ => null,
    };

    private static string? ConfigPath(string[] args)
    {
        for (var i = 0; i < args.Length - 1; i++)
        {
            if (args[i] == "--config") return args[i + 1];
        }
        return null;
    }
}
