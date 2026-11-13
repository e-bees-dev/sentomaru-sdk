namespace Sentomaru.AspNetCore;

/// <summary>
/// sdk-user-message-v1 (<c>contracts/sdk/user-message-v1.md</c>): the default end-user text when an operation is blocked (key
/// <see cref="Key"/>; pt-BR, en, es), the language resolution, the host override and the map from a refusal code to a situation. Fixed text: no code, reason or
/// detection detail. It changes no code and no status.
/// </summary>
public static class SentomaruUserMessage
{
    public const string Key = "critical_operations_blocked";

    public static IReadOnlyDictionary<string, string> Defaults { get; } = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["pt-BR"] = "Algumas operações críticas estão bloqueadas até a aprovação. Tente novamente mais tarde ou fale com o suporte.",
        ["en"] = "Some critical operations are blocked until approval. Please try again later or contact support.",
        ["es"] = "Algunas operaciones críticas están bloqueadas hasta su aprobación. Inténtelo de nuevo más tarde o póngase en contacto con el soporte.",
    };

    public static IReadOnlyList<string> Situations { get; } =
        ["attestation_failed", "verification_denied", "challenge", "defer", "unavailable", "enrollment_pending"];

    /// <summary><c>pt*</c> is <c>pt-BR</c>, <c>es*</c> is <c>es</c>, anything else (or empty/absent) is <c>en</c>.</summary>
    public static string ResolveLocale(string? tag)
    {
        var primary = (tag ?? string.Empty).Trim().Replace('_', '-').ToLowerInvariant().Split('-')[0];
        return primary == "pt" ? "pt-BR" : primary == "es" ? "es" : "en";
    }

    /// <summary>The text for a blocked <paramref name="situation"/> (null for a value outside <see cref="Situations"/>). <paramref name="overrides"/> maps a resolved language to the host's text, used when not blank.</summary>
    public static string? Resolve(string situation, string? locale, IReadOnlyDictionary<string, string>? overrides = null)
    {
        if (!Situations.Contains(situation)) return null;
        var resolved = ResolveLocale(locale);
        return overrides is not null && overrides.TryGetValue(resolved, out var own) && !string.IsNullOrWhiteSpace(own) ? own.Trim() : Defaults[resolved];
    }

    /// <summary>
    /// The situation a refusal presents, or null when it is not a block (<c>operation-replayed</c>, <c>caller-context-missing</c>, <c>body-limit</c>). An upstream
    /// code the table does not know is a verification refusal, or unavailable for 429 and 5xx.
    /// </summary>
    public static string? SituationForRefusal(string? code, int status) => code switch
    {
        "proof-required" or "policy-denied" => "verification_denied",
        "integrity-unavailable" => "unavailable",
        "challenge-required" => "challenge",
        "operation-replayed" or "caller-context-missing" or "body-limit" => null,
        _ => status == 429 || status >= 500 ? "unavailable" : "verification_denied",
    };

    /// <summary>The first language of an <c>Accept-Language</c> header (highest listed, order as sent), or null.</summary>
    public static string? FromAcceptLanguage(string? header)
    {
        if (string.IsNullOrWhiteSpace(header)) return null;
        var first = header.Split(',')[0].Split(';')[0].Trim();
        return first.Length == 0 || first == "*" ? null : first;
    }
}
