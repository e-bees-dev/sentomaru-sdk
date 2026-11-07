namespace Sentomaru.AspNetCore;

/// <summary>4.2.0: body of the consumer's challenge route. The caller (subject, tenant) never comes from here.</summary>
public sealed class SentomaruChallengeInput
{
    public string? PublicKeyPem { get; init; }
}
