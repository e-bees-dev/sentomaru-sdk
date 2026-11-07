using System.Text.Json;
using Sentomaru.Hybrid;
using Xunit;

namespace Sentomaru.Hybrid.Tests;

/// <summary>D-22c / D-20: the typed signals model and the text-channel envelope against contracts/sdk/signals-catalog-v1.json and hybrid-bridge-v1.json.</summary>
public class SignalsAndEnvelopeTests
{
    private static JsonElement Load(string relative)
    {
        var dir = AppContext.BaseDirectory;
        while (dir is not null && !File.Exists(Path.Combine(dir, relative))) dir = Path.GetDirectoryName(dir);
        return JsonDocument.Parse(File.ReadAllText(Path.Combine(dir!, relative))).RootElement;
    }

    private static JsonElement ScreenCapture()
    {
        foreach (var c in Load("contracts/sdk/signals-catalog-v1.json").GetProperty("capabilities").EnumerateArray())
            if (c.GetProperty("capabilityId").GetString() == "screen_capture") return c;
        throw new Xunit.Sdk.XunitException("screen_capture not in the catalog");
    }

    private static IReadOnlyDictionary<string, object?> Snapshot(params (string Id, string Version, string State, Dictionary<string, object?>? Data)[] rows) =>
        new Dictionary<string, object?>
        {
            ["collectedAt"] = "2026-11-06T12:00:00Z", ["durationMs"] = 12,
            ["observations"] = rows.Select(r => (object?)new Dictionary<string, object?>
            {
                ["capabilityId"] = r.Id, ["version"] = r.Version, ["state"] = r.State, ["source"] = "client_observed",
                ["observedAt"] = "2026-11-06T12:00:00Z", ["data"] = r.Data ?? new Dictionary<string, object?>(),
            }).ToList(),
        };

    [Fact]
    public void TheBindingConstantsAreTheCatalogOnes()
    {
        Assert.Equal(SignalsCatalogInfo.Version, Load("contracts/sdk/signals-catalog-v1.json").GetProperty("version").GetString());
        Assert.Equal(SignalsCatalogInfo.ScreenCaptureVersion, ScreenCapture().GetProperty("version").GetString());
    }

    [Fact]
    public void TheCatalogFixtureOfScreenCaptureReadsAsTyped()
    {
        var fixture = ScreenCapture().GetProperty("fixture");
        var data = fixture.GetProperty("detail").EnumerateObject().ToDictionary(p => p.Name, p => (object?)p.Value.GetString());
        var state = fixture.GetProperty("state").GetString()!.ToLowerInvariant();
        var snapshot = SignalsReader.ReadSnapshot(Snapshot(("screen_capture", fixture.GetProperty("version").GetString()!, state, data)));
        var observation = snapshot.Find("screen_capture")!;
        Assert.Equal(SignalsCatalogInfo.ScreenCaptureVersion, observation.Version);
        Assert.Equal(SignalState.NotDetected, observation.State);
        Assert.Equal(new ScreenCaptureDetail("none", 0, null), SignalsReader.ReadScreenCapture(observation));
    }

    [Fact]
    public void CapturesOtherIsOnlyPresentInScopeAllAndIsACountApart()
    {
        var marked = new SignalObservation("screen_capture", "1.1.0", SignalState.Detected, "client_observed", "t",
            new Dictionary<string, string> { ["result"] = "captured", ["captures"] = "2" });
        Assert.Equal(new ScreenCaptureDetail("captured", 2, null), SignalsReader.ReadScreenCapture(marked));
        var all = marked with { Data = new Dictionary<string, string> { ["result"] = "captured", ["captures"] = "0", ["captures_other"] = "9" } };
        Assert.Equal(new ScreenCaptureDetail("captured", 0, 9), SignalsReader.ReadScreenCapture(all));
    }

    [Theory]
    [InlineData("captures_other", "10")]
    [InlineData("captures_other", "-1")]
    [InlineData("captures_other", "01")]
    [InlineData("captures", "x")]
    [InlineData("result", "everything")]
    public void ADetailOutsideTheCatalogVocabularyIsAChannelError(string key, string value)
    {
        var data = new Dictionary<string, string> { ["result"] = "captured", ["captures"] = "1", [key] = value };
        var e = Assert.Throws<SentomaruException>(() => SignalsReader.ReadScreenCapture(
            new SignalObservation("screen_capture", "1.1.0", SignalState.Detected, "client_observed", "t", data)));
        Assert.Equal("ChannelError", e.Code);
    }

    [Fact]
    public void NoScreensIsNotCleanAndAStateWithoutResultHasNoDetail()
    {
        var none = new SignalObservation("screen_capture", "1.1.0", SignalState.Unknown, "client_observed", "t",
            new Dictionary<string, string> { ["result"] = "no_screens" });
        Assert.Equal("no_screens", SignalsReader.ReadScreenCapture(none)!.Result);
        var unsupported = none with { State = SignalState.Unsupported, Data = new Dictionary<string, string>() };
        Assert.Null(SignalsReader.ReadScreenCapture(unsupported));
    }

    [Fact]
    public void ASnapshotWithAnUnknownStateOrAMissingFieldIsRefusedNotDefaulted()
    {
        Assert.Equal("ChannelError", Assert.Throws<SentomaruException>(() =>
            SignalsReader.ReadSnapshot(Snapshot(("screen_capture", "1.1.0", "maybe", null)))).Code);
        var broken = new Dictionary<string, object?> { ["collectedAt"] = "t", ["durationMs"] = 1 };
        Assert.Equal("ChannelError", Assert.Throws<SentomaruException>(() => SignalsReader.ReadSnapshot(broken)).Code);
    }

    [Fact]
    public void EveryStateTheBridgeCanSendIsReadable()
    {
        var states = new[] { "detected", "not_detected", "unknown", "unsupported", "error" };
        var snapshot = SignalsReader.ReadSnapshot(Snapshot(states.Select(s => ("os_version", "1.0.0", s, (Dictionary<string, object?>?)null)).ToArray()));
        Assert.Equal(new[] { SignalState.Detected, SignalState.NotDetected, SignalState.Unknown, SignalState.Unsupported, SignalState.Error },
            snapshot.Observations.Select(o => o.State));
    }

    [Fact]
    public void ShieldOptionsGivePlainTypesAndOnlyTheTwoScopeNames()
    {
        var (activities, scope) = new ScreenShieldOptions(new[] { "app.PayActivity" }).ToNativeArguments();
        Assert.Equal(new[] { "app.PayActivity" }, activities);
        Assert.Equal("marked", scope);
        Assert.Equal("all", new ScreenShieldOptions(new[] { "a.B" }, CaptureScope.All).ScopeName);
        Assert.Equal("br.com.ebees.sentomaru.signals.ScreenShieldHost", ScreenShieldOptions.NativeClass);
        Assert.Throws<ArgumentException>(() => new ScreenShieldOptions(new[] { "a.B", " " }).ToNativeArguments());
        Assert.Throws<ArgumentOutOfRangeException>(() => new ScreenShieldOptions(new[] { "a.B" }, (CaptureScope)7).ScopeName);
    }

    [Fact]
    public void TheNativeHostEntryAndScopeNamesAreTheKotlinOnes()
    {
        var dir = AppContext.BaseDirectory;
        while (dir is not null && !File.Exists(Path.Combine(dir, "sdk/android/signals/src/main/kotlin/br/com/ebees/sentomaru/signals/ScreenShieldHost.kt"))) dir = Path.GetDirectoryName(dir);
        var source = File.ReadAllText(Path.Combine(dir!, "sdk/android/signals/src/main/kotlin/br/com/ebees/sentomaru/signals/ScreenShieldHost.kt"));
        Assert.Contains("object ScreenShieldHost", source);
        Assert.Contains("fun install(application: Application, markedActivities: Array<String>, captureScope: String)", source);
        Assert.Contains("\"marked\" -> CaptureScope.MARKED", source);
        Assert.Contains("\"all\" -> CaptureScope.ALL", source);
        Assert.Contains("package br.com.ebees.sentomaru.signals", source);
    }

    [Fact]
    public void EnvelopeEncodesBytesAsBase64OnlyAndLeavesTheRest()
    {
        var encoded = BridgeEnvelope.EncodeArguments(new Dictionary<string, object?> { ["body"] = new byte[] { 0, 255, 16 }, ["method"] = "GET", ["n"] = 3, ["x"] = null });
        Assert.Equal("AP8Q", encoded["body"]);
        Assert.Equal(("GET", 3, (object?)null), ((string)encoded["method"]!, (int)encoded["n"]!, encoded["x"]));
    }

    [Fact]
    public void EnvelopeUnwrapsValueDecodesSealedLoadAndThrowsStableCodes()
    {
        Assert.Equal("ok", BridgeEnvelope.Decode("state", new Dictionary<string, object?> { ["value"] = "ok" }));
        Assert.Null(BridgeEnvelope.Decode("sessionId", new Dictionary<string, object?> { ["value"] = null }));
        Assert.Equal(new byte[] { 0, 255, 16 }, (byte[])BridgeEnvelope.Decode("sealedLoad", new Dictionary<string, object?> { ["value"] = "AP8Q" })!);
        Assert.Equal("AP8Q", BridgeEnvelope.Decode("sealedString", new Dictionary<string, object?> { ["value"] = "AP8Q" })); // only sealedLoad is bytes
        var stable = Assert.Throws<SentomaruException>(() => BridgeEnvelope.Decode("sign", new Dictionary<string, object?> { ["code"] = "NotInitialized", ["message"] = "m" }));
        Assert.Equal(("NotInitialized", "m"), (stable.Code, stable.Message));
        Assert.Equal("ChannelError", Assert.Throws<SentomaruException>(() => BridgeEnvelope.Decode("sign", new Dictionary<string, object?> { ["code"] = "" })).Code);
        Assert.Equal("ChannelError", Assert.Throws<SentomaruException>(() => BridgeEnvelope.Decode("sign", new Dictionary<string, object?>())).Code);
        Assert.Equal("ChannelError", Assert.Throws<SentomaruException>(() => BridgeEnvelope.Decode("sign", null)).Code);
        Assert.Equal("ChannelError", Assert.Throws<SentomaruException>(() => BridgeEnvelope.Decode("sealedLoad", new Dictionary<string, object?> { ["value"] = "***" })).Code);
    }

    [Fact]
    public void EnvelopeRefusesAReplyThatHasBothAValueAndACode()
    {
        foreach (var value in new object?[] { null, "ok" })
        {
            var e = Assert.Throws<SentomaruException>(() => BridgeEnvelope.Decode("sign", new Dictionary<string, object?> { ["value"] = value, ["code"] = "NotInitialized" }));
            Assert.Equal("ChannelError", e.Code);
        }
    }

    [Theory]
    [InlineData("12")]       // text
    [InlineData(true)]
    [InlineData(1.5)]
    [InlineData(-1)]
    [InlineData(double.NaN)]
    public void ADurationThatIsNotAWholeNonNegativeNumberIsAChannelErrorNotACastException(object duration)
    {
        var reply = new Dictionary<string, object?> { ["collectedAt"] = "t", ["durationMs"] = duration, ["observations"] = new List<object?>() };
        Assert.Equal("ChannelError", Assert.Throws<SentomaruException>(() => SignalsReader.ReadSnapshot(reply)).Code);
    }

    [Theory]
    [InlineData(12)]
    [InlineData(12L)]
    [InlineData(12.0)]
    public void AWholeDurationInAnyNumberTypeIsRead(object duration)
    {
        var reply = new Dictionary<string, object?> { ["collectedAt"] = "t", ["durationMs"] = duration, ["observations"] = new List<object?>() };
        Assert.Equal(12L, SignalsReader.ReadSnapshot(reply).DurationMs);
    }

    [Fact]
    public void EnvelopeKeepsAnySdkErrorCodeAsIs()
    {
        Assert.Equal("RenewalBackoff", Assert.Throws<SentomaruException>(() =>
            BridgeEnvelope.Decode("renewSession", new Dictionary<string, object?> { ["code"] = "RenewalBackoff", ["message"] = "wait" })).Code);
    }
}
