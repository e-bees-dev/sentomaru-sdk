using System.Text.Json;
using System.Text.RegularExpressions;

namespace Sentomaru.AspNetCore;

/// <summary>
/// 4.15.0 (D-26, contracts/sdk/offline-proof-chain-v1.md section 4): a pure reader of the answer to the offline reconciliation, for the consumer
/// backend that forwards the request and keeps the answer. Same rules as Android <c>OfflineReconcileOutcome.Verdict</c>, Dart
/// <c>SentomaruOfflineVerdict</c> and Swift <c>OfflineVerdict</c>: <see cref="Signals"/> only ever holds the three contract codes, and an answer that
/// disagrees with itself (accepted with signals, rejected without) is not a verdict.
/// <see cref="Advisories"/> (additive) is what the verdict could not check, today <c>offline_boot_unavailable</c>. It is not a signal and never changes
/// <see cref="Accepted"/>. Unknown codes are kept (a newer server may add one), repeats are dropped, at most <see cref="MaxAdvisories"/> are read,
/// and a missing or malformed list reads as empty: an advisory is never a reason to refuse the verdict. Nothing here calls Sentomaru.
/// </summary>
public sealed record SentomaruOfflineVerdict(string PermitId, bool Accepted, int ItemCount, IReadOnlyList<string> Signals, IReadOnlyList<string> Advisories)
{
    public const int MaxAdvisories = 8;
    private const int MaxAnswerChars = 16 * 1024;
    private static readonly string[] ContractSignals = ["offline_clock_tampered", "offline_chain_broken", "offline_chain_gap_detected"];
    private static readonly Regex Code = new(@"\A[a-z_]{1,64}\z", RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
    private static readonly Regex Uuid = new(@"\A[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\z",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);

    /// <summary><c>null</c> when the text is not a well-formed verdict.</summary>
    public static SentomaruOfflineVerdict? Parse(string? text)
    {
        if (text is null || text.Length > MaxAnswerChars) return null;
        try
        {
            using var doc = JsonDocument.Parse(text);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                !root.TryGetProperty("permitId", out var id) || id.ValueKind != JsonValueKind.String || !Uuid.IsMatch(id.GetString()!) ||
                !root.TryGetProperty("status", out var st) || st.ValueKind != JsonValueKind.String ||
                !root.TryGetProperty("itemCount", out var ic) || ic.ValueKind != JsonValueKind.Number || !ic.TryGetInt32(out var count) || count is < 0 or > 9999 ||
                !root.TryGetProperty("signals", out var sg) || sg.ValueKind != JsonValueKind.Array) return null;
            var status = st.GetString();
            if (status is not ("accepted" or "rejected")) return null;
            var signals = new List<string>();
            foreach (var s in sg.EnumerateArray())
            {
                if (s.ValueKind != JsonValueKind.String || !ContractSignals.Contains(s.GetString())) return null;
                signals.Add(s.GetString()!);
            }
            if ((status == "accepted") != (signals.Count == 0)) return null;
            return new SentomaruOfflineVerdict(id.GetString()!, status == "accepted", count, signals,
                root.TryGetProperty("advisories", out var adv) ? ReadAdvisories(adv) : []);
        }
        catch (JsonException) { return null; }
    }

    private static IReadOnlyList<string> ReadAdvisories(JsonElement raw)
    {
        if (raw.ValueKind != JsonValueKind.Array) return [];
        var all = new List<string>();
        foreach (var c in raw.EnumerateArray())
        {
            if (c.ValueKind != JsonValueKind.String || !Code.IsMatch(c.GetString()!)) return [];
            all.Add(c.GetString()!);
        }
        return all.Distinct().Take(MaxAdvisories).ToList();
    }
}
