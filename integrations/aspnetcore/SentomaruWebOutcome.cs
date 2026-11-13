using System.Collections.Concurrent;
using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Sentomaru.AspNetCore;

/// <summary>4.17.0: the closed vocabulary of <c>contracts/web/web-outcome-table-v1.md</c>.</summary>
public static partial class SentomaruWebOutcomeVocabulary
{
    public static IReadOnlySet<string> Actions { get; } = new HashSet<string>(StringComparer.Ordinal) { "allow", "challenge", "defer" };

    [GeneratedRegex(@"^\d+\.\d+\.\d+\z")]
    internal static partial Regex PolicyVersionRegex();

    [GeneratedRegex(@"^[a-z0-9._-]{1,64}\z")]
    internal static partial Regex OperationRegex();

    public static bool ValidPolicyVersion(string? value) => value is not null && PolicyVersionRegex().IsMatch(value);
}

/// <summary>
/// 4.17.0: one cell of the outcome table: UTC day (no time), operation, the five states in the order of <see cref="SentomaruWebSignals.Closed"/>, the evaluated
/// action and the policy version. No account, session, device, IP or clock time.
/// </summary>
public sealed record SentomaruWebOutcomeCell(DateOnly Day, string Operation, IReadOnlyList<string> States, string Action, string PolicyVersion)
{
    public bool IsValid =>
        States is { Count: 5 } && States.All(s => s is SentomaruWebSignalStates.Detected or SentomaruWebSignalStates.NotDetected or SentomaruWebSignalStates.Unknown) &&
        SentomaruWebOutcomeVocabulary.Actions.Contains(Action ?? string.Empty) && SentomaruWebOutcomeVocabulary.ValidPolicyVersion(PolicyVersion) &&
        Operation is not null && SentomaruWebOutcomeVocabulary.OperationRegex().IsMatch(Operation);

    internal string Key => string.Join('|', [Day.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture), Operation, .. States, Action, PolicyVersion]);

    internal string StatesKey => string.Join('|', States);
}

/// <summary>A cell and how many evaluations fell in it.</summary>
public sealed record SentomaruWebOutcomeRow(SentomaruWebOutcomeCell Cell, long Count);

/// <summary>
/// 4.17.0: where the counters per cell live. The package ships <see cref="SentomaruMemoryWebOutcomeStore"/> and <see cref="SentomaruFileWebOutcomeStore"/>;
/// an OPTIONAL extension point: the default needs no database and no migration in the host. A host that wants its own storage registers it with
/// <c>services.AddSingleton&lt;ISentomaruWebOutcomeStore, ...&gt;()</c>. <see cref="RecordAsync"/> may throw: the observer counts <c>outcome-failed</c> and goes on.
/// </summary>
public interface ISentomaruWebOutcomeStore
{
    /// <summary>Adds one to the counter of the cell. A cell that is not <see cref="SentomaruWebOutcomeCell.IsValid"/> is ignored.</summary>
    Task RecordAsync(SentomaruWebOutcomeCell cell, CancellationToken cancellationToken);

    /// <summary>Rows with <c>from &lt;= Day &lt; to</c>.</summary>
    Task<IReadOnlyList<SentomaruWebOutcomeRow>> ReadAsync(DateOnly from, DateOnly to, CancellationToken cancellationToken);
}

/// <summary>4.17.0: in-memory counters (lost on restart). For tests and a first look; not for a multi-instance host.</summary>
public sealed class SentomaruMemoryWebOutcomeStore : ISentomaruWebOutcomeStore
{
    private readonly ConcurrentDictionary<string, (SentomaruWebOutcomeCell Cell, long Count)> _cells = new(StringComparer.Ordinal);

    public Task RecordAsync(SentomaruWebOutcomeCell cell, CancellationToken cancellationToken)
    {
        if (cell.IsValid) _cells.AddOrUpdate(cell.Key, _ => (cell, 1), static (_, old) => (old.Cell, old.Count + 1));
        return Task.CompletedTask;
    }

    public Task<IReadOnlyList<SentomaruWebOutcomeRow>> ReadAsync(DateOnly from, DateOnly to, CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyList<SentomaruWebOutcomeRow>>(_cells.Values.Where(v => v.Cell.Day >= from && v.Cell.Day < to)
            .Select(v => new SentomaruWebOutcomeRow(v.Cell, v.Count)).ToList());
}

/// <summary>
/// 4.17.0: counters in small JSON files in <paramref name="directory"/>, rotated by UTC day and written per store instance
/// (<c>web-outcome-cells-YYYY-MM-DD-{instance}.json</c>, temporary file then atomic move). Each process writes only its own file, so several processes (or
/// restarts) can share the directory without locks between them; a read merges every file of the day. No database, no migration. A file that cannot be read is
/// skipped. The files hold cells and counts, nothing else; <see cref="Prune"/> removes days older than a limit.
/// </summary>
public sealed class SentomaruFileWebOutcomeStore(string directory) : ISentomaruWebOutcomeStore
{
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly string _instance = Guid.NewGuid().ToString("N")[..12];
    private readonly Dictionary<DateOnly, List<FileCell>> _own = [];

    private sealed record FileCell(string Operation, string[] States, string Action, string PolicyVersion, long Count);

    private const string Prefix = "web-outcome-cells-";

    public async Task RecordAsync(SentomaruWebOutcomeCell cell, CancellationToken cancellationToken)
    {
        if (!cell.IsValid) return;
        await _gate.WaitAsync(cancellationToken);
        try
        {
            Directory.CreateDirectory(directory);
            if (!_own.TryGetValue(cell.Day, out var cells)) _own[cell.Day] = cells = [];
            var key = cell.Key;
            var i = cells.FindIndex(c => ToCell(cell.Day, c).Key == key);
            if (i >= 0) cells[i] = cells[i] with { Count = cells[i].Count + 1 };
            else cells.Add(new FileCell(cell.Operation, [.. cell.States], cell.Action, cell.PolicyVersion, 1));
            var path = Path.Combine(directory, $"{Prefix}{cell.Day:yyyy-MM-dd}-{_instance}.json");
            var temp = path + ".tmp";
            await File.WriteAllTextAsync(temp, JsonSerializer.Serialize(cells), cancellationToken);
            File.Move(temp, path, overwrite: true);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<IReadOnlyList<SentomaruWebOutcomeRow>> ReadAsync(DateOnly from, DateOnly to, CancellationToken cancellationToken)
    {
        var merged = new Dictionary<string, (SentomaruWebOutcomeCell Cell, long Count)>(StringComparer.Ordinal);
        if (!Directory.Exists(directory)) return [];
        for (var day = from; day < to; day = day.AddDays(1))
        {
            foreach (var path in Directory.EnumerateFiles(directory, $"{Prefix}{day:yyyy-MM-dd}-*.json"))
            {
                List<FileCell> cells;
                try { cells = await LoadAsync(path, cancellationToken); }
                catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException) { continue; }
                foreach (var c in cells)
                {
                    var cell = ToCell(day, c);
                    if (!cell.IsValid || c.Count < 0) continue;
                    merged[cell.Key] = merged.TryGetValue(cell.Key, out var old) ? (old.Cell, old.Count + c.Count) : (cell, c.Count);
                }
            }
        }
        return merged.Values.Select(v => new SentomaruWebOutcomeRow(v.Cell, v.Count)).ToList();
    }

    /// <summary>Deletes the cell files of days before <paramref name="before"/>. Never throws.</summary>
    public void Prune(DateOnly before)
    {
        try
        {
            if (!Directory.Exists(directory)) return;
            foreach (var path in Directory.EnumerateFiles(directory, Prefix + "*.json"))
            {
                var name = Path.GetFileName(path);
                if (name.Length > Prefix.Length + 10 && DateOnly.TryParseExact(name.AsSpan(Prefix.Length, 10), "yyyy-MM-dd", out var day) && day < before)
                    File.Delete(path);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }

    private static SentomaruWebOutcomeCell ToCell(DateOnly day, FileCell c) => new(day, c.Operation, c.States, c.Action, c.PolicyVersion);

    private static async Task<List<FileCell>> LoadAsync(string path, CancellationToken ct)
    {
        await using var stream = File.OpenRead(path);
        return await JsonSerializer.DeserializeAsync<List<FileCell>>(stream, cancellationToken: ct) ?? [];
    }
}

/// <summary>
/// 4.17.0: builds the weekly <c>web-outcome-table-v1</c> (<c>contracts/web/web-outcome-table-v1.md</c>): strict format, no identifier, a cell with fewer than 5
/// evaluations left out. With no label source yet every evaluation is <c>unlabeled</c> and <c>fraud</c>/<c>legit</c> are 0 (never counted as legitimate).
/// </summary>
public static class SentomaruWebOutcomeTable
{
    public const string Format = "web-outcome-table-v1";
    public const int LabelMaturityDays = 30;
    public const int MinCellTotal = 5;
    public const long MaxCount = 10_000_000;
    public const int MaxRows = 50_000;

    /// <summary>JSON of the window <c>[from, to)</c> for one policy version; null when no cell is left. Throws <see cref="ArgumentException"/> for a window over 31 days, an inverted one or a bad version.</summary>
    public static string? Build(DateOnly from, DateOnly to, string policyVersion, IEnumerable<SentomaruWebOutcomeRow> source)
    {
        ArgumentNullException.ThrowIfNull(source);
        if (to <= from || to.DayNumber - from.DayNumber > 31 || !SentomaruWebOutcomeVocabulary.ValidPolicyVersion(policyVersion))
            throw new ArgumentException("invalid window or policy version");

        var rows = source
            .Where(r => r.Cell.IsValid && r.Cell.PolicyVersion == policyVersion && r.Cell.Day >= from && r.Cell.Day < to)
            .GroupBy(r => (r.Cell.Operation, Key: r.Cell.StatesKey, r.Cell.Action))
            .Select(g => (g.First().Cell, Total: g.Sum(r => r.Count)))
            .Where(x => x.Total >= MinCellTotal)
            .OrderBy(x => x.Cell.Operation, StringComparer.Ordinal).ThenBy(x => x.Cell.StatesKey, StringComparer.Ordinal)
            .ThenBy(x => x.Cell.Action, StringComparer.Ordinal)
            .Take(MaxRows)
            .ToList();
        if (rows.Count == 0) return null;

        var table = new
        {
            format = Format,
            window = new { from = from.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture), to = to.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) },
            policyVersion,
            labelMaturityDays = LabelMaturityDays,
            rows = rows.Select(x => new
            {
                operation = x.Cell.Operation,
                signals = SentomaruWebSignals.Closed.Select((id, i) => (id, state: x.Cell.States[i])).ToDictionary(s => s.id, s => s.state),
                action = x.Cell.Action,
                fraud = 0,
                legit = 0,
                unlabeled = Math.Min(x.Total, MaxCount),
            }),
        };
        return JsonSerializer.Serialize(table);
    }

    /// <summary>The last closed week (Monday to Monday, UTC) before <paramref name="nowUtc"/>.</summary>
    public static (DateOnly From, DateOnly To) LastClosedWeek(DateTime nowUtc)
    {
        var today = DateOnly.FromDateTime(nowUtc);
        var monday = today.AddDays(-(((int)today.DayOfWeek + 6) % 7));
        return (monday.AddDays(-7), monday);
    }
}
