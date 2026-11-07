using System.Collections.Concurrent;
using System.Globalization;
using System.Text;

namespace Sentomaru.Gateway.Verifier;

/// <summary>
/// Response counters with closed labels only (spec D-17, slice D-17c): <c>status</c>, <c>code</c> (a code of the contract
/// table, <c>verified</c>, <c>observed</c> or <c>disabled</c> on a 200, <c>other</c> for anything else) and <c>mode</c>
/// (<c>enforce</c>, <c>observe</c>, <c>none</c> when no route matched). No path, operation id, subject, tenant,
/// installation or session ever becomes a label. Served in the Prometheus text format at <c>GET /metrics</c> on the
/// management port only.
/// </summary>
public sealed class VerifierMetrics
{
    /// <summary>The codes of the contract (section 2) and of the 200 answers.</summary>
    public static readonly IReadOnlySet<string> Codes = new HashSet<string>(StringComparer.Ordinal)
    {
        "verified", "observed", "disabled",
        "proof-required", "authentication-required", "operation-unmapped", "caller-context-missing", "body-limit", "forward-format",
        "message-format", "evaluation-format", "signals-format", "proof-invalid", "session-unavailable", "session-expired",
        "installation-suspended", "operation-context", "route-format", "replay", "hardware-not-proven", "rate-limited",
        "internal-error", "store-unavailable", "integrity-unavailable", "operation-replayed", "challenge-required",
        "policy-denied",
    };

    private static readonly int[] Statuses = [200, 400, 401, 403, 404, 409, 413, 422, 429, 500, 502, 503];

    private readonly ConcurrentDictionary<(int Status, string Code, string Mode), long> counts = new();

    public void Record(int status, string code, string mode)
    {
        var key = (Array.IndexOf(Statuses, status) >= 0 ? status : 0, Codes.Contains(code) ? code : "other",
            mode is "enforce" or "observe" ? mode : "none");
        counts.AddOrUpdate(key, 1, (_, n) => n + 1);
    }

    private readonly ConcurrentDictionary<string, long> jwtRefusals = new(StringComparer.Ordinal);

    /// <summary>D-17c2: a refused caller JWT, by closed reason (<see cref="JwtCallerValidator.Reasons"/>).</summary>
    public void RecordJwt(string reason) =>
        jwtRefusals.AddOrUpdate(JwtCallerValidator.Reasons.Contains(reason) ? reason : "other", 1, (_, n) => n + 1);

    public long JwtCount(string reason) => jwtRefusals.TryGetValue(reason, out var n) ? n : 0;

    public long Count(int status, string code, string mode) => counts.TryGetValue((status, code, mode), out var n) ? n : 0;

    public string Render()
    {
        var text = new StringBuilder();
        text.Append("# HELP sentomaru_verifier_responses_total Answers of the gateway verifier.\n");
        text.Append("# TYPE sentomaru_verifier_responses_total counter\n");
        foreach (var ((status, code, mode), n) in counts.OrderBy(c => c.Key.Status).ThenBy(c => c.Key.Code, StringComparer.Ordinal)
                     .ThenBy(c => c.Key.Mode, StringComparer.Ordinal))
        {
            text.Append(CultureInfo.InvariantCulture,
                $"sentomaru_verifier_responses_total{{status=\"{status}\",code=\"{code}\",mode=\"{mode}\"}} {n}\n");
        }
        if (!jwtRefusals.IsEmpty)
        {
            text.Append("# HELP sentomaru_verifier_jwt_refusals_total Caller JWTs refused by the gateway verifier (D-17c2), by reason.\n");
            text.Append("# TYPE sentomaru_verifier_jwt_refusals_total counter\n");
            foreach (var (reason, n) in jwtRefusals.OrderBy(r => r.Key, StringComparer.Ordinal))
            {
                text.Append(CultureInfo.InvariantCulture, $"sentomaru_verifier_jwt_refusals_total{{reason=\"{reason}\"}} {n}\n");
            }
        }
        return text.ToString();
    }
}
