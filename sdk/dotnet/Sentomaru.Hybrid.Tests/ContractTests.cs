using System.Reflection;
using System.Text.Json;
using Sentomaru.Hybrid;
using Xunit;

namespace Sentomaru.Hybrid.Tests;

/// <summary>D-22c: the C# facade against contracts/sdk/hybrid-bridge-v1.json, the same checks as the Capacitor/Cordova/React Native layers.</summary>
public class ContractTests
{
    private sealed record Method(string Name, string[] Args, string Reply);

    private static readonly Method[] Methods = LoadContract();

    private static Method[] LoadContract()
    {
        var dir = AppContext.BaseDirectory;
        while (dir is not null && !File.Exists(Path.Combine(dir, "contracts/sdk/hybrid-bridge-v1.json"))) dir = Path.GetDirectoryName(dir);
        using var doc = JsonDocument.Parse(File.ReadAllText(Path.Combine(dir!, "contracts/sdk/hybrid-bridge-v1.json")));
        return doc.RootElement.GetProperty("methods").EnumerateArray().Select(m => new Method(
            m.GetProperty("name").GetString()!, m.GetProperty("args").EnumerateArray().Select(a => a.GetString()!).ToArray(),
            m.GetProperty("reply").GetString()!)).ToArray();
    }

    private sealed class Fake : INativeSentomaru
    {
        public List<(string Method, IReadOnlyDictionary<string, object?> Args)> Calls { get; } = new();
        public Func<string, object?> Reply { get; set; } = _ => null;
        public Exception? Throw { get; set; }
        public Task<object?> CallAsync(string method, IReadOnlyDictionary<string, object?> args, CancellationToken ct = default)
        {
            Calls.Add((method, args));
            return Throw is null ? Task.FromResult(Reply(method)) : Task.FromException<object?>(Throw);
        }
    }

    // A value for every argument name, so each facade method is driven from the contract alone.
    private static readonly Dictionary<string, object?> Sample = new()
    {
        ["organization"] = "org", ["app"] = "app", ["environment"] = "hml", ["enrollmentUrl"] = "https://api.example.test/enroll",
        ["allowedHosts"] = new List<string> { "api.example.test" }, ["rotationGracePeriodDays"] = 3, ["playIntegrityCloudProjectNumber"] = 1L,
        ["renewalUrl"] = "https://api.example.test/renew", ["reattestationChallengeUrl"] = "https://api.example.test/c",
        ["reattestationSubmitUrl"] = "https://api.example.test/s", ["reattestationMinIntervalSeconds"] = 60, ["challenge"] = "ch",
        ["strongBox"] = true, ["requiresHardware"] = false, ["method"] = "POST", ["targetUri"] = "https://api.example.test/x", ["operation"] = "op",
        ["body"] = new byte[] { 1, 2, 3 }, ["optional"] = new Dictionary<string, string> { ["a"] = "b" }, ["rasp"] = true,
        ["expectedSignerDigests"] = new List<string> { new string('a', 64) }, ["allowPlainFallback"] = false, ["plainStringsKey"] = "k", ["key"] = "asset",
    };

    private static object? ReplyFor(string reply) => reply switch
    {
        "string" => "s", "string?" => null, "map" => new Dictionary<string, object?>(), "list" => new List<object?>(), "bool" => true,
        "bytes" => new byte[] { 1, 2, 3 }, _ => null,
    };

    private static MethodInfo FacadeMethod(string contractName)
    {
        var name = char.ToUpperInvariant(contractName[0]) + contractName[1..] + "Async";
        return typeof(SentomaruSdk).GetMethod(name) ?? throw new Xunit.Sdk.XunitException($"missing facade method {name}");
    }

    [Fact]
    public void TheFacadeHasExactlyTheMethodsOfTheContract()
    {
        var facade = typeof(SentomaruSdk).GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
            .Select(m => m.Name).OrderBy(n => n, StringComparer.Ordinal).ToArray();
        var contract = Methods.Select(m => char.ToUpperInvariant(m.Name[0]) + m.Name[1..] + "Async").OrderBy(n => n, StringComparer.Ordinal).ToArray();
        Assert.Equal(contract, facade);
    }

    [Fact]
    public void EachMethodTakesExactlyTheContractArgumentsInOrderAndNothingElseRequired()
    {
        foreach (var m in Methods)
        {
            var parameters = FacadeMethod(m.Name).GetParameters().Where(p => p.ParameterType != typeof(CancellationToken)).Select(p => p.Name!).ToArray();
            Assert.Equal(m.Args, parameters);
        }
    }

    [Fact]
    public async Task EachMethodCallsTheNativeEntryWithItsOwnNameAndExactlyTheContractArguments()
    {
        foreach (var m in Methods)
        {
            var fake = new Fake { Reply = _ => ReplyFor(m.Reply) };
            var sdk = new SentomaruSdk(fake);
            var info = FacadeMethod(m.Name);
            var values = info.GetParameters().Select(p => p.ParameterType == typeof(CancellationToken) ? (object?)CancellationToken.None : Sample[p.Name!]).ToArray();
            await (Task)info.Invoke(sdk, values)!;
            Assert.Single(fake.Calls);
            Assert.Equal(m.Name, fake.Calls[0].Method);
            Assert.Equal(m.Args.OrderBy(a => a, StringComparer.Ordinal), fake.Calls[0].Args.Keys.OrderBy(a => a, StringComparer.Ordinal));
        }
    }

    [Fact]
    public async Task BodyAndSealedLoadBytesPassThroughUnchanged()
    {
        var fake = new Fake { Reply = _ => new Dictionary<string, object?>() };
        await new SentomaruSdk(fake).SignAsync("GET", "https://api.example.test/x", "op", new byte[] { 0, 255, 16 });
        Assert.Equal(new byte[] { 0, 255, 16 }, (byte[])fake.Calls[0].Args["body"]!);
        var loaded = await new SentomaruSdk(new Fake { Reply = _ => new byte[] { 0, 255, 16 } }).SealedLoadAsync("k");
        Assert.Equal(new byte[] { 0, 255, 16 }, loaded);
    }

    [Fact]
    public async Task TheFacadeAddsNoDefaultAnOmittedOptionGoesAsNull()
    {
        var fake = new Fake { Reply = _ => new Dictionary<string, object?>() };
        await new SentomaruSdk(fake).EnrollAsync("c");
        Assert.Null(fake.Calls[0].Args["strongBox"]);
        Assert.Null(fake.Calls[0].Args["requiresHardware"]);
        Assert.True(fake.Calls[0].Args.ContainsKey("strongBox"));
    }

    [Fact]
    public async Task AStableCodeIsKeptAndAnyOtherFailureIsAChannelError()
    {
        var kept = await Assert.ThrowsAsync<SentomaruException>(() => new SentomaruSdk(new Fake { Throw = new SentomaruException("NotInitialized", "x") }).StateAsync());
        Assert.Equal("NotInitialized", kept.Code);
        var other = await Assert.ThrowsAsync<SentomaruException>(() => new SentomaruSdk(new Fake { Throw = new InvalidOperationException("boom") }).StateAsync());
        Assert.Equal("ChannelError", other.Code);
        var wrongShape = await Assert.ThrowsAsync<SentomaruException>(() => new SentomaruSdk(new Fake { Reply = _ => 42 }).StateAsync());
        Assert.Equal("ChannelError", wrongShape.Code);
    }

    [Fact]
    public async Task ACancellationIsNotTurnedIntoAChannelError()
    {
        using var cts = new CancellationTokenSource();
        var fake = new Fake { Throw = new OperationCanceledException() };
        await Assert.ThrowsAsync<OperationCanceledException>(() => new SentomaruSdk(fake).StateAsync(cts.Token));
    }

    [Fact]
    public void TheContractRepliesTheFacadeKnows()
    {
        Assert.All(Methods, m => Assert.Contains(m.Reply, new[] { "void", "string", "string?", "map", "list", "bool", "bytes" }));
    }
}
