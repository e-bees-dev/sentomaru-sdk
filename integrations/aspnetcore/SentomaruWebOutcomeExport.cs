using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Sentomaru.AspNetCore;

/// <summary>
/// 4.17.0: writes the weekly <c>web-outcome-table-v1</c> as a FILE (no endpoint): one per closed week (Monday to Monday, UTC) and per policy version, in
/// <see cref="SentomaruWebObservationOptions.ExportDirectory"/> (default: <c>tables</c> inside the outcome directory), named <c>web-outcome-table-YYYY-MM-DD-YYYY-MM-DD-v{version}.json</c>. Off while the observation is disabled
/// (or <see cref="SentomaruWebObservationOptions.ExportEnabled"/> is false). An existing file is never rewritten; a failure is only logged. Several processes may run it: the file name is the same and the first move wins.
/// </summary>
public sealed class SentomaruWebOutcomeExportService(
    ISentomaruWebOutcomeStore store,
    IOptions<SentomaruWebObservationOptions> options,
    IOptions<SentomaruClientOptions> clientOptions,
    ILogger<SentomaruWebOutcomeExportService> logger,
    TimeProvider? time = null) : BackgroundService
{
    private readonly TimeProvider _time = time ?? TimeProvider.System;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var o = options.Value;
        if (!o.Enabled || !o.ExportEnabled || !clientOptions.Value.Enabled || o.EffectiveExportDirectory is null) return;
        try
        {
            await Task.Delay(o.ExportInitialDelay < TimeSpan.Zero ? TimeSpan.Zero : o.ExportInitialDelay, stoppingToken);
            var interval = o.ExportInterval < TimeSpan.FromMinutes(1) ? TimeSpan.FromHours(6) : o.ExportInterval;
            while (!stoppingToken.IsCancellationRequested)
            {
                try { await ExportOnceAsync(_time.GetUtcNow().UtcDateTime, stoppingToken); }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    logger.LogError(ex, "Sentomaru: web outcome table export failed; it will be retried at the next interval");
                }
                await Task.Delay(interval, stoppingToken);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
    }

    /// <summary>One pass for the last closed week at <paramref name="nowUtc"/>. Returns how many new files it wrote.</summary>
    public async Task<int> ExportOnceAsync(DateTime nowUtc, CancellationToken ct)
    {
        var o = options.Value;
        if (!o.Enabled || !o.ExportEnabled || o.EffectiveExportDirectory is not { } exportDirectory) return 0;
        if (o.OutcomeRetentionDays > 0 && store is SentomaruFileWebOutcomeStore files)
            files.Prune(DateOnly.FromDateTime(nowUtc).AddDays(-o.OutcomeRetentionDays));
        var (from, to) = SentomaruWebOutcomeTable.LastClosedWeek(nowUtc);
        var rows = await store.ReadAsync(from, to, ct);
        Directory.CreateDirectory(exportDirectory);
        var written = 0;
        foreach (var version in rows.Select(r => r.Cell.PolicyVersion).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal))
        {
            var file = Path.Combine(exportDirectory, $"web-outcome-table-{from:yyyy-MM-dd}-{to:yyyy-MM-dd}-v{version}.json");
            if (File.Exists(file)) continue;
            var json = SentomaruWebOutcomeTable.Build(from, to, version, rows);
            if (json is null) continue;
            var temp = file + ".tmp";
            await File.WriteAllTextAsync(temp, json, ct);
            try { File.Move(temp, file); }
            catch (IOException) { File.Delete(temp); continue; } // another instance won
            written++;
        }
        if (written > 0)
            logger.LogInformation("Sentomaru: web outcome table: {Total} file(s) for {From:yyyy-MM-dd} to {To:yyyy-MM-dd}", written, from, to);
        return written;
    }
}
