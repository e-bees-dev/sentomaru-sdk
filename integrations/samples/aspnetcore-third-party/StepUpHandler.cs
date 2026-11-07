using System.Globalization;
using System.Security.Claims;
using Sentomaru.AspNetCore;

namespace ThirdPartyApi;

// guide:begin step-up
/// <summary>
/// 4.5.0 (D-06b): a FAKE step-up for the sample. A real consumer checks its own reauthentication (a new login, a
/// confirmation it already has); Sentomaru never verifies it and keeps no step-up state. Here the session proves a recent
/// login with the claim "auth_time" (Unix seconds): within <see cref="Window"/> the operation proceeds, otherwise the
/// adapter answers 401 challenge-required with challengeKind step_up and the app asks the user to sign in again. The
/// window is what keeps the next request from being challenged again while the signal stays DETECTED.
/// </summary>
public sealed class StepUpHandler(TimeProvider clock) : ISentomaruChallengeHandler
{
    public static readonly TimeSpan Window = TimeSpan.FromMinutes(5);

    public ValueTask<SentomaruChallengeDecision> HandleAsync(SentomaruChallengeContext challenge, CancellationToken cancellationToken)
    {
        var claim = challenge.HttpContext.User.FindFirstValue("auth_time");
        var recent = long.TryParse(claim, NumberStyles.None, CultureInfo.InvariantCulture, out var seconds) &&
                     clock.GetUtcNow() - DateTimeOffset.FromUnixTimeSeconds(seconds) is var age &&
                     age >= TimeSpan.Zero && age <= Window;
        return ValueTask.FromResult(recent ? SentomaruChallengeDecision.Proceed : SentomaruChallengeDecision.Refuse);
    }
}
// guide:end step-up
