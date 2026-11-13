using System.Collections.Concurrent;
using System.Diagnostics.Metrics;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Sentomaru.AspNetCore;

/// <summary>4.17.0: what the host knows about the bot challenge of one web operation. Declared by the host backend; never proof of a human.</summary>
public enum SentomaruWebChallengeState
{
    /// <summary>No verdict: challenge absent, unavailable, skipped or the provider failed. Never read as clean.</summary>
    Unknown = 0,
    /// <summary>The challenge was presented and passed ("did not fail").</summary>
    Passed = 1,
    /// <summary>The challenge was presented and failed.</summary>
    Failed = 2,
}

/// <summary>
/// 4.17.0 (web observation): options of <c>AddSentomaruWebObservation</c>. Everything is off by default: with <see cref="Enabled"/> false nothing is sent and
/// nothing is recorded. It only takes effect while <see cref="SentomaruClientOptions.Enabled"/> is on.
/// </summary>
public sealed class SentomaruWebObservationOptions
{
    /// <summary>Sends the evaluation. Off by default.</summary>
    public bool Enabled { get; set; }

    /// <summary>
    /// Optional allow-list of operation names (written in code; never built from an account, order or session id). Empty = any name that matches
    /// <c>[a-z0-9._-]{1,64}</c> is accepted (the host passes constants). With a list, a name outside it is counted as <c>skipped</c> and not sent.
    /// </summary>
    public IList<string> Operations { get; set; } = [];

    /// <summary>Own short deadline of the evaluation call, separate from the client timeout. No retry.</summary>
    public TimeSpan Deadline { get; set; } = TimeSpan.FromSeconds(1);

    /// <summary>Records the answer as a counter per cell (day, operation, five states, evaluated action, policy version) in <see cref="ISentomaruWebOutcomeStore"/>. On by default while <see cref="Enabled"/>.</summary>
    public bool RecordOutcome { get; set; } = true;

    /// <summary>The one directory the package needs: cell counters (<see cref="SentomaruFileWebOutcomeStore"/>, rotated daily) and, in its <c>tables</c> subdirectory, the weekly files. Null = in-memory counters (lost on restart) and no export unless <see cref="ExportDirectory"/> is set.</summary>
    public string? OutcomeDirectory { get; set; }

    /// <summary>Writes the weekly <c>web-outcome-table-v1</c> file. On while <see cref="Enabled"/>; it needs <see cref="OutcomeDirectory"/> or <see cref="ExportDirectory"/>.</summary>
    public bool ExportEnabled { get; set; } = true;

    /// <summary>Where the weekly table files are written. Default: <c>tables</c> inside <see cref="OutcomeDirectory"/>.</summary>
    public string? ExportDirectory { get; set; }

    /// <summary>Days of cell files kept in <see cref="OutcomeDirectory"/>; older days are deleted by the export service. 0 = keep everything.</summary>
    public int OutcomeRetentionDays { get; set; } = 90;

    internal string? EffectiveExportDirectory => !string.IsNullOrWhiteSpace(ExportDirectory) ? ExportDirectory
        : !string.IsNullOrWhiteSpace(OutcomeDirectory) ? Path.Combine(OutcomeDirectory, "tables") : null;

    /// <summary>Delay before the first export check after start.</summary>
    public TimeSpan ExportInitialDelay { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>Interval between export checks. An existing file is never rewritten.</summary>
    public TimeSpan ExportInterval { get; set; } = TimeSpan.FromHours(6);
}

/// <summary>4.17.0: the host's only call: tell Sentomaru the challenge state of an operation. Observation only: the answer never changes what the user sees.</summary>
public interface ISentomaruWebObserver
{
    /// <summary>Fire and forget; never throws, never waits, no retry. Nothing about the user leaves: only the operation name and the five states.</summary>
    void ObserveChallenge(string operation, SentomaruWebChallengeState challenge);

    /// <summary>Same as <see cref="ObserveChallenge"/> but completes when the call and the outcome record are done (tests, graceful shutdown). Never throws.</summary>
    Task ObserveChallengeAsync(string operation, SentomaruWebChallengeState challenge, CancellationToken cancellationToken = default);
}

/// <summary>
/// 4.17.0: in-process counters of the web observation, by operation and result (<c>skipped</c>, <c>build-null</c>, <c>200</c>, a status code,
/// <c>exception</c>, <c>timeout</c>, <c>outcome-skipped</c>, <c>outcome-failed</c>, <c>outcome-recorded</c>). Also emitted as the
/// <c>sentomaru.web.observations</c> counter of the meter <c>Sentomaru.AspNetCore.Web</c> (export it with the host's OpenTelemetry or Prometheus bridge).
/// An operation outside the host's list is counted under <c>unlisted</c> so a caller cannot grow the label set.
/// </summary>
public sealed class SentomaruWebObservationMetrics
{
    public const string MeterName = "Sentomaru.AspNetCore.Web";
    private static readonly Meter Meter = new(MeterName);
    private static readonly Counter<long> Counter = Meter.CreateCounter<long>("sentomaru.web.observations", description: "Web observations by operation and result");
    private readonly ConcurrentDictionary<(string Operation, string Result), long> _counts = new();

    public void Count(string operation, string result)
    {
        _counts.AddOrUpdate((operation, result), 1, static (_, v) => v + 1);
        Counter.Add(1, new KeyValuePair<string, object?>("operation", operation), new KeyValuePair<string, object?>("result", result));
    }

    public long Get(string operation, string result) => _counts.TryGetValue((operation, result), out var v) ? v : 0;

    public IReadOnlyDictionary<(string Operation, string Result), long> Snapshot() => new Dictionary<(string, string), long>(_counts);
}

/// <summary>
/// 4.17.0: <see cref="ISentomaruWebObserver"/> over <see cref="ISentomaruClient.EvaluateWebAsync"/>. Only the challenge has a source; the other four web
/// signals go as UNKNOWN, never NOT_DETECTED. The answer is dropped: only the code reaches the counters, and the cell reaches the store.
/// </summary>
public sealed class SentomaruWebObserver(
    ISentomaruClient client,
    IOptions<SentomaruWebObservationOptions> web,
    IOptions<SentomaruClientOptions> clientOptions,
    ISentomaruWebOutcomeStore outcomes,
    SentomaruWebObservationMetrics metrics,
    ILogger<SentomaruWebObserver> logger,
    TimeProvider? time = null) : ISentomaruWebObserver
{
    private const string Unlisted = "unlisted";
    private readonly TimeProvider _time = time ?? TimeProvider.System;

    public void ObserveChallenge(string operation, SentomaruWebChallengeState challenge)
    {
        if (!Active) return;
        _ = Task.Run(() => ObserveChallengeAsync(operation, challenge));
    }

    public async Task ObserveChallengeAsync(string operation, SentomaruWebChallengeState challenge, CancellationToken cancellationToken = default)
    {
        try
        {
            await RunAsync(operation, challenge, cancellationToken);
        }
        catch (Exception ex)
        {
            metrics.Count(Label(operation), "exception");
            logger.LogWarning("Sentomaru: web observation failed ({Type}).", ex.GetType().Name);
        }
    }

    private bool Active => web.Value.Enabled && clientOptions.Value.Enabled;

    private bool Allowed(string operation) =>
        web.Value.Operations.Count > 0 ? web.Value.Operations.Contains(operation) : operation is not null && SentomaruWebOutcomeVocabulary.OperationRegex().IsMatch(operation);

    private string Label(string operation) => Allowed(operation) ? operation : Unlisted;

    private async Task RunAsync(string operation, SentomaruWebChallengeState challenge, CancellationToken ct)
    {
        if (!Active) return;
        if (!Allowed(operation))
        {
            metrics.Count(Unlisted, "skipped");
            return;
        }

        var states = new[]
        {
            SentomaruWebSignalStates.Unknown, SentomaruWebSignalStates.Unknown, SentomaruWebSignalStates.Unknown,
            SentomaruWebSignalStates.Unknown, StateOf(challenge),
        };
        // Order of SentomaruWebSignals.Closed; only the challenge has a source.
        var request = SentomaruWeb.TryBuild(operation, SentomaruWebSignals.Closed.Select((id, i) => (id, states[i])));
        if (request is null)
        {
            metrics.Count(operation, "build-null"); // a defect of the host configuration, not of the user
            return;
        }

        var deadline = web.Value.Deadline > TimeSpan.Zero ? web.Value.Deadline : TimeSpan.FromSeconds(1);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(deadline);
        SentomaruClientResult<WebEvaluationResponseDto> result;
        try
        {
            result = await client.EvaluateWebAsync(request, timeout.Token);
        }
        catch (OperationCanceledException) when (timeout.IsCancellationRequested)
        {
            metrics.Count(operation, "timeout");
            return;
        }

        metrics.Count(operation, result.Succeeded ? "200" : result.StatusCode.ToString());
        if (result.Succeeded && result.Value is { } answer && web.Value.RecordOutcome)
            await RecordOutcomeAsync(operation, states, answer);
    }

    /// <summary>Records the cell (no identifier) for the outcome table; an invalid answer or a store failure does not propagate.</summary>
    private async Task RecordOutcomeAsync(string operation, string[] states, WebEvaluationResponseDto answer)
    {
        var cell = new SentomaruWebOutcomeCell(DateOnly.FromDateTime(_time.GetUtcNow().UtcDateTime), operation, states,
            answer.EvaluatedAction ?? string.Empty, answer.PolicyVersion ?? string.Empty);
        if (!cell.IsValid)
        {
            metrics.Count(operation, "outcome-skipped"); // e.g. WEB_POLICY_NONE without a version
            return;
        }
        try
        {
            await outcomes.RecordAsync(cell, CancellationToken.None);
            metrics.Count(operation, "outcome-recorded");
        }
        catch (Exception ex)
        {
            metrics.Count(operation, "outcome-failed");
            logger.LogWarning("Sentomaru: recording the web outcome cell failed ({Type}).", ex.GetType().Name);
        }
    }

    private static string StateOf(SentomaruWebChallengeState state) => state switch
    {
        SentomaruWebChallengeState.Passed => SentomaruWebSignalStates.NotDetected,
        SentomaruWebChallengeState.Failed => SentomaruWebSignalStates.Detected,
        _ => SentomaruWebSignalStates.Unknown,
    };
}

/// <summary>4.17.0: shortcut for the host that has a plain pass/fail (<c>null</c> = no verdict).</summary>
public static class SentomaruWebObserverExtensions
{
    public static void ObserveChallenge(this ISentomaruWebObserver observer, string operation, bool? passed) =>
        observer.ObserveChallenge(operation, passed switch { true => SentomaruWebChallengeState.Passed, false => SentomaruWebChallengeState.Failed, _ => SentomaruWebChallengeState.Unknown });
}
