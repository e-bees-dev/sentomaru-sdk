using System.Text.Json;
using Xunit;

namespace Sentomaru.Hybrid.Tests;

/// <summary>
/// D-22c: the C# end of the Kotlin to C# chain. contracts/sdk/hybrid-bridge-v1-vectors.json holds what the Kotlin side produces (the
/// signals module test drives the detector to the <c>observation</c>; the bridge core test turns it into the <c>reply</c>): here the
/// reader must make exactly the stated model out of that reply, and the envelope must do the stated Base64 rule.
/// </summary>
public class VectorsTests
{
    private static readonly JsonElement Vectors = Load();

    private static JsonElement Load()
    {
        var dir = AppContext.BaseDirectory;
        while (dir is not null && !File.Exists(Path.Combine(dir, "contracts/sdk/hybrid-bridge-v1-vectors.json"))) dir = Path.GetDirectoryName(dir);
        return JsonDocument.Parse(File.ReadAllText(Path.Combine(dir!, "contracts/sdk/hybrid-bridge-v1-vectors.json"))).RootElement.Clone();
    }

    // The shapes a bridge channel hands over: maps, lists, text, numbers (long), booleans.
    private static object? Plain(JsonElement e) => e.ValueKind switch
    {
        JsonValueKind.Object => e.EnumerateObject().ToDictionary(p => p.Name, p => Plain(p.Value)),
        JsonValueKind.Array => e.EnumerateArray().Select(Plain).ToList(),
        JsonValueKind.String => e.GetString(),
        JsonValueKind.Number => e.GetInt64(),
        JsonValueKind.True => true,
        JsonValueKind.False => false,
        _ => null,
    };

    private static IReadOnlyDictionary<string, object?> Reply(JsonElement e) => (IReadOnlyDictionary<string, object?>)Plain(e)!;

    private static IEnumerable<JsonElement> Items(string name) => Vectors.GetProperty(name).EnumerateArray();

    [Fact]
    public void TheVectorsAreWrittenForTheCatalogTheBindingKnows()
        => Assert.Equal(SignalsCatalogInfo.Version, Vectors.GetProperty("catalogVersion").GetString());

    [Fact]
    public void EveryKotlinScreenCaptureReplyReadsIntoTheStatedModel()
    {
        var count = 0;
        foreach (var vector in Items("screenCapture"))
        {
            count++;
            var name = vector.GetProperty("name").GetString()!;
            var snapshot = SignalsReader.ReadSnapshot(Reply(vector.GetProperty("reply")));
            var observation = Assert.Single(snapshot.Observations);
            var want = vector.GetProperty("observation");
            Assert.Equal(want.GetProperty("capabilityId").GetString(), observation.CapabilityId);
            Assert.Equal(want.GetProperty("version").GetString(), observation.Version);
            Assert.Equal(want.GetProperty("source").GetString(), observation.Source);
            Assert.Equal(want.GetProperty("observedAt").GetString(), observation.ObservedAt);
            Assert.Equal(want.GetProperty("detail").EnumerateObject().ToDictionary(p => p.Name, p => p.Value.GetString()!), observation.Data);
            Assert.Equal(SignalsCatalogInfo.ScreenCaptureVersion, observation.Version);

            var expect = vector.GetProperty("expect");
            Assert.Equal(Enum.Parse<SignalState>(expect.GetProperty("state").GetString()!), observation.State);
            var detail = SignalsReader.ReadScreenCapture(observation);
            if (expect.GetProperty("result").ValueKind == JsonValueKind.Null)
            {
                Assert.Null(detail);
                continue;
            }
            Assert.NotNull(detail);
            Assert.Equal(expect.GetProperty("result").GetString(), detail.Result);
            Assert.Equal(expect.GetProperty("captures").GetInt32(), detail.Captures);
            var other = expect.GetProperty("capturesOther");
            Assert.Equal(other.ValueKind == JsonValueKind.Null ? (int?)null : other.GetInt32(), detail.CapturesOther);
            _ = name;
        }
        Assert.True(count >= 8);
    }

    [Fact]
    public void EveryKotlinSnapshotReplyReadsIntoItsObservationsInOrder()
    {
        var count = 0;
        foreach (var vector in Items("snapshots"))
        {
            count++;
            var snapshot = SignalsReader.ReadSnapshot(Reply(vector.GetProperty("reply")));
            Assert.Equal(Vectors.GetProperty("collectedAt").GetString(), snapshot.CollectedAt);
            Assert.Equal(Vectors.GetProperty("durationMs").GetInt64(), snapshot.DurationMs);
            var want = vector.GetProperty("observations").EnumerateArray().ToArray();
            Assert.Equal(want.Length, snapshot.Observations.Count);
            for (var i = 0; i < want.Length; i++)
            {
                Assert.Equal(want[i].GetProperty("capabilityId").GetString(), snapshot.Observations[i].CapabilityId);
                Assert.Equal(want[i].GetProperty("state").GetString()!.Replace("_", ""), snapshot.Observations[i].State.ToString().ToUpperInvariant());
                Assert.Equal(want[i].GetProperty("detail").EnumerateObject().ToDictionary(p => p.Name, p => p.Value.GetString()!), snapshot.Observations[i].Data);
            }
        }
        Assert.True(count >= 4);
    }

    [Fact]
    public void TheEnvelopeDoesTheBase64RuleOfTheVectorsBothWays()
    {
        var count = 0;
        foreach (var vector in Items("bytes"))
        {
            count++;
            var bytes = Convert.FromHexString(vector.GetProperty("hex").GetString()!);
            var text = vector.GetProperty("base64").GetString();
            var sent = BridgeEnvelope.EncodeArguments(new Dictionary<string, object?> { ["body"] = bytes, ["operation"] = "op" });
            Assert.Equal(text, sent["body"]);
            Assert.Equal("op", sent["operation"]);
            var back = BridgeEnvelope.Decode("sealedLoad", new Dictionary<string, object?> { ["value"] = text });
            Assert.Equal(bytes, Assert.IsType<byte[]>(back));
        }
        Assert.True(count >= 5);
    }

    [Fact]
    public void TheEnvelopeRefusesEveryNonCanonicalBase64OfTheVectors()
    {
        var count = 0;
        foreach (var vector in Items("bytesRejected"))
        {
            count++;
            var name = vector.GetProperty("name").GetString()!;
            var text = vector.GetProperty("base64").GetString();
            var error = Assert.Throws<SentomaruException>(() =>
                BridgeEnvelope.Decode("sealedLoad", new Dictionary<string, object?> { ["value"] = text }));
            Assert.True(error.Code == "ChannelError", name);
            Assert.Null(BridgeEnvelope.CanonicalBase64(text));
        }
        Assert.True(count >= 10);
    }
}
