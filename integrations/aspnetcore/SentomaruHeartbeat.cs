using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Sentomaru.AspNetCore;

/// <summary>
/// 4.13.0 (ativação de módulos, fase E): what the consumer backend declares about itself. A DECLARATION: it feeds the Sentomaru Readiness and nothing else; it
/// never changes a decision. A member left null is "not declared" (the Readiness then says unknown), never false. The server refuses members it does not know.
/// </summary>
public sealed record ConsumerFeaturesDto
{
    [JsonPropertyName("mobileGate"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public bool? MobileGate { get; init; }
    [JsonPropertyName("requireBinding"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public bool? RequireBinding { get; init; }
    [JsonPropertyName("failOpen"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public bool? FailOpen { get; init; }
    [JsonPropertyName("fraud"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public bool? Fraud { get; init; }
    [JsonPropertyName("metricsExported"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public bool? MetricsExported { get; init; }
    /// <summary>Table name (<c>[a-z0-9_-]{1,32}</c>, at most 8) to whether it exists in the consumer database. Names only: no connection string, no row.</summary>
    [JsonPropertyName("bindingTablePresent"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public Dictionary<string, bool>? BindingTablePresent { get; init; }
}

/// <summary>Body of <c>POST /v1/{org}/{app}/{env}/consumer/heartbeat</c>.</summary>
public sealed record ConsumerHeartbeatDto
{
    [JsonPropertyName("package")] public string Package { get; init; } = SentomaruHeartbeat.PackageName;
    [JsonPropertyName("packageVersion")] public string PackageVersion { get; init; } = SentomaruHeartbeat.PackageVersion;
    [JsonPropertyName("consumer")] public string Consumer { get; init; } = "";
    /// <summary>Opaque instance id (lowercase hex, 8–32): never a host name.</summary>
    [JsonPropertyName("instance")] public string Instance { get; init; } = "";
    [JsonPropertyName("features")] public ConsumerFeaturesDto Features { get; init; } = new();
}

/// <summary>
/// The consumer implements this to say what it turned on (its own flags: the package cannot know the gate or the fraud client of the host application).
/// Register it as a singleton. The package fills <see cref="ConsumerFeaturesDto.FailOpen"/> from its own options when the source leaves it null.
/// </summary>
public interface ISentomaruFeatureSource
{
    ValueTask<ConsumerFeaturesDto> GetFeaturesAsync(CancellationToken cancellationToken);
}

internal static class SentomaruHeartbeat
{
    internal const string PackageName = "Sentomaru.AspNetCore";
    internal static readonly string PackageVersion = typeof(SentomaruHeartbeat).Assembly.GetName().Version is { } v ? $"{v.Major}.{v.Minor}.{Math.Max(v.Build, 0)}" : "0.0.0";

    /// <summary>A stable id per process host and scope, hashed so that no host name leaves the machine.</summary>
    internal static string InstanceId(SentomaruClientOptions options) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes($"{Environment.MachineName}|{options.Org}/{options.App}/{options.Env}"))).ToLowerInvariant()[..16];
}

/// <summary>
/// Sends the declaration at start and every <see cref="SentomaruClientOptions.HeartbeatInterval"/>. Off while <see cref="SentomaruClientOptions.HeartbeatConsumer"/>
/// is null or the client is disabled. A failure is only logged: the declaration must never take the host down or slow a request.
/// </summary>
public sealed class SentomaruHeartbeatService(ISentomaruClient client, IOptions<SentomaruClientOptions> options, ILogger<SentomaruHeartbeatService> logger,
    ISentomaruFeatureSource? source = null) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var o = options.Value;
        if (!o.Enabled || string.IsNullOrWhiteSpace(o.HeartbeatConsumer)) return;
        var interval = o.HeartbeatInterval < TimeSpan.FromMinutes(1) ? TimeSpan.FromHours(1) : o.HeartbeatInterval;
        using var timer = new PeriodicTimer(interval);
        do
        {
            await SendOnceAsync(o, stoppingToken);
        }
        while (await WaitAsync(timer, stoppingToken));
    }

    /// <summary>One declaration; never throws (a failure is logged).</summary>
    public async Task SendOnceAsync(SentomaruClientOptions o, CancellationToken ct)
    {
        try
        {
            var features = source is null ? new ConsumerFeaturesDto() : await source.GetFeaturesAsync(ct);
            features = features with { FailOpen = features.FailOpen ?? o.FailOpen };
            var result = await client.SendHeartbeatAsync(new ConsumerHeartbeatDto { Consumer = o.HeartbeatConsumer!, Instance = SentomaruHeartbeat.InstanceId(o), Features = features }, ct);
            if (!result.Succeeded) logger.LogInformation("Sentomaru consumer heartbeat refused: {Status} {Code}", result.StatusCode, result.ErrorCode);
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            logger.LogInformation(ex, "Sentomaru consumer heartbeat failed; it will be retried at the next interval");
        }
    }

    private static async Task<bool> WaitAsync(PeriodicTimer timer, CancellationToken ct)
    {
        try { return await timer.WaitForNextTickAsync(ct); }
        catch (OperationCanceledException) { return false; }
    }
}
