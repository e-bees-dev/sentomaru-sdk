using Sentomaru.Hybrid;
using Xunit;

namespace Sentomaru.Hybrid.Tests;

/// <summary>Revisor A, rodada 2 (médio A), applied to the .NET facade: <see cref="LockingNativeSentomaru"/> wraps
/// a fake <see cref="INativeSentomaru"/> so the lock is proven without any real platform adapter.</summary>
public class InitializeSecurityLockTests
{
    private sealed class Fake : INativeSentomaru
    {
        public int Calls;
        public Task<object?> CallAsync(string method, IReadOnlyDictionary<string, object?> args, CancellationToken cancellationToken = default)
        {
            Calls++;
            return Task.FromResult<object?>(null);
        }
    }

    private sealed class ThrowingOnceFake : INativeSentomaru
    {
        private bool _thrown;
        public Task<object?> CallAsync(string method, IReadOnlyDictionary<string, object?> args, CancellationToken cancellationToken = default)
        {
            if (!_thrown) { _thrown = true; throw new InvalidOperationException("native build failed"); }
            return Task.FromResult<object?>(null);
        }
    }

    private static Dictionary<string, object?> Args(IReadOnlyList<string> hosts, string enrollmentUrl = "https://api.example.test/enroll",
        string? renewalUrl = "https://api.example.test/renew") =>
        new() { ["allowedHosts"] = hosts, ["enrollmentUrl"] = enrollmentUrl, ["renewalUrl"] = renewalUrl };

    [Fact]
    public async Task ASecondInitializeIdenticalToTheFirstIsAllowed()
    {
        var fake = new Fake();
        var locking = new LockingNativeSentomaru(fake);
        await locking.CallAsync("initialize", Args(new[] { "api.example.test" }));
        await locking.CallAsync("initialize", Args(new[] { "api.example.test" }));
        Assert.Equal(2, fake.Calls);
    }

    [Fact]
    public async Task ASecondInitializeThatShrinksTheAllowlistIsAllowed()
    {
        var fake = new Fake();
        var locking = new LockingNativeSentomaru(fake);
        await locking.CallAsync("initialize", Args(new[] { "api.example.test", "other.example.test" }));
        await locking.CallAsync("initialize", Args(new[] { "api.example.test" }));
        Assert.Equal(2, fake.Calls);
    }

    [Fact]
    public async Task ASecondInitializeThatWidensTheAllowlistIsRefusedBeforeReachingTheInnerAdapter()
    {
        // the attack this closes: a WebView page calling `initialize` again to add a host it controls.
        var fake = new Fake();
        var locking = new LockingNativeSentomaru(fake);
        await locking.CallAsync("initialize", Args(new[] { "api.example.test" }));
        var error = await Assert.ThrowsAsync<SentomaruException>(() =>
            locking.CallAsync("initialize", Args(new[] { "api.example.test", "attacker.evil.test" })));
        Assert.Equal("ConfigurationError", error.Code);
        Assert.Equal(1, fake.Calls); // the second call never reached the inner adapter
    }

    [Fact]
    public async Task ASecondInitializeWithADifferentEnrollmentUrlIsRefused()
    {
        var locking = new LockingNativeSentomaru(new Fake());
        await locking.CallAsync("initialize", Args(new[] { "api.example.test" }));
        var error = await Assert.ThrowsAsync<SentomaruException>(() =>
            locking.CallAsync("initialize", Args(new[] { "api.example.test" }, enrollmentUrl: "https://api.example.test/enroll-2")));
        Assert.Equal("ConfigurationError", error.Code);
    }

    [Fact]
    public async Task ASecondInitializeThatDropsRenewalUrlIsRefused()
    {
        var locking = new LockingNativeSentomaru(new Fake());
        await locking.CallAsync("initialize", Args(new[] { "api.example.test" }));
        var error = await Assert.ThrowsAsync<SentomaruException>(() =>
            locking.CallAsync("initialize", Args(new[] { "api.example.test" }, renewalUrl: null)));
        Assert.Equal("ConfigurationError", error.Code);
    }

    [Fact]
    public async Task OtherMethodsPassThroughWithoutTouchingTheLock()
    {
        var fake = new Fake();
        var locking = new LockingNativeSentomaru(fake);
        await locking.CallAsync("state", new Dictionary<string, object?>());
        Assert.Equal(1, fake.Calls);
    }

    [Fact]
    public async Task AMalformedInitializeIsConfigurationErrorBeforeReachingTheInnerAdapter()
    {
        var fake = new Fake();
        var locking = new LockingNativeSentomaru(fake);
        var error = await Assert.ThrowsAsync<SentomaruException>(() =>
            locking.CallAsync("initialize", new Dictionary<string, object?> { ["enrollmentUrl"] = "https://api.example.test/enroll" }));
        Assert.Equal("ConfigurationError", error.Code);
        Assert.Equal(0, fake.Calls);
    }

    [Fact]
    public async Task AFailedFirstInitializeDoesNotPermanentlyLockTheAdapter()
    {
        // a transient native failure (not a malformed argument) must not brick the adapter against a corrected retry.
        var fake = new ThrowingOnceFake();
        var locking = new LockingNativeSentomaru(fake);
        await Assert.ThrowsAsync<InvalidOperationException>(() => locking.CallAsync("initialize", Args(new[] { "api.example.test" })));
        await locking.CallAsync("initialize", Args(new[] { "api.example.test" }, enrollmentUrl: "https://api.example.test/enroll-2"));
    }
}
