using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Sentomaru.AspNetCore;

/// <summary>
/// 4.19.0: one rule of a named set in <c>Sentomaru:OperationRules</c>. When the JSON value at <see cref="Pointer"/> in the
/// request body equals one of <see cref="Values"/>, the request is evaluated as <see cref="Operation"/> instead of the
/// attribute's own operation. Configuration only: the consumer writes no code nor table.
/// </summary>
public sealed class SentomaruOperationRule
{
    /// <summary>JSON pointer (RFC 6901) into the request body, such as <c>/etapaAtual</c> or <c>/demanda/status</c>.
    /// Property names match without regard to case, as ASP.NET model binding does.</summary>
    public string? Pointer { get; set; }

    /// <summary>The values that select <see cref="Operation"/>, compared as text: a JSON string after trimming, a JSON
    /// number by its invariant value (<c>6</c>, <c>6.0</c> and <c>"6"</c> all equal <c>"6"</c>), <c>true</c>/<c>false</c>.</summary>
    public List<string> Values { get; set; } = [];

    /// <summary>The operation evaluated when the rule matches (<c>^[a-z0-9_-]{2,32}$</c>, the policy's operation slug).</summary>
    public string? Operation { get; set; }
}

/// <summary>
/// 4.19.0: validation and evaluation of <see cref="SentomaruClientOptions.OperationRules"/>. The first rule (in order)
/// whose pointer finds a matching value picks the operation; none matching keeps the attribute's operation. A body that is
/// not JSON, cannot be parsed or is over <see cref="SentomaruExtractor.MaxBodyBytes"/> picks the operation of the FIRST rule
/// of the set (fail toward the protected operation), never the default.
/// </summary>
public static class SentomaruOperationRules
{
    /// <summary>The operation slug shape the server's policy and the gateway verifier's route table accept.</summary>
    public static readonly Regex OperationPattern = new("^[a-z0-9_-]{2,32}$", RegexOptions.CultureInvariant);

    private const int MaxPointerLength = 256;
    private const int MaxPointerSegments = 16;
    private const int MaxValueLength = 256;

    private static readonly JsonDocumentOptions ParseOptions = new()
    {
        // Lenient on purpose: a body ASP.NET would also accept must be read; anything unreadable picks the first rule.
        AllowTrailingCommas = true,
        CommentHandling = JsonCommentHandling.Skip,
        MaxDepth = 64
    };

    /// <summary>The set by name, ignoring case (the configuration binder may replace the dictionary's comparer).</summary>
    public static List<SentomaruOperationRule>? FindSet(SentomaruClientOptions options, string name)
    {
        if (options.OperationRules is not { } sets) return null;
        if (sets.TryGetValue(name, out var rules)) return rules;
        foreach (var (key, value) in sets)
        {
            if (string.Equals(key, name, StringComparison.OrdinalIgnoreCase)) return value;
        }
        return null;
    }

    /// <summary>Startup errors of the configured sets (empty when valid). Keys are reported as configuration paths.</summary>
    public static IReadOnlyList<string> Validate(IReadOnlyDictionary<string, List<SentomaruOperationRule>>? sets)
    {
        var errors = new List<string>();
        if (sets is null) return errors;
        foreach (var (name, rules) in sets)
        {
            var prefix = $"Sentomaru:OperationRules:{name}";
            if (string.IsNullOrWhiteSpace(name))
            {
                errors.Add("Sentomaru:OperationRules has a set without a name.");
                continue;
            }
            if (rules is null || rules.Count == 0)
            {
                errors.Add($"{prefix} must have at least one rule.");
                continue;
            }
            for (var i = 0; i < rules.Count; i++)
            {
                var rule = rules[i];
                var at = $"{prefix}:{i}";
                if (rule is null)
                {
                    errors.Add($"{at} is empty.");
                    continue;
                }
                if (!TryParsePointer(rule.Pointer, out _))
                    errors.Add($"{at}:Pointer must be a JSON pointer such as /etapaAtual (starts with '/', no empty segment, '~' only as ~0 or ~1, at most {MaxPointerSegments} segments and {MaxPointerLength} characters).");
                if (rule.Values is null || rule.Values.Count == 0)
                    errors.Add($"{at}:Values must list at least one value.");
                else if (rule.Values.Any(v => string.IsNullOrWhiteSpace(v) || v.Length > MaxValueLength))
                    errors.Add($"{at}:Values must not have a blank value nor one longer than {MaxValueLength} characters.");
                if (rule.Operation is null || !OperationPattern.IsMatch(rule.Operation))
                    errors.Add($"{at}:Operation must match ^[a-z0-9_-]{{2,32}}$ (lowercase letters, digits, '_' and '-').");
            }
        }
        return errors;
    }

    /// <summary>
    /// The operation for this body: the first matching rule's, else <paramref name="defaultOperation"/>. A null
    /// <paramref name="body"/> means it could not be read (over the limit); it and any body that is not parsable JSON pick
    /// the first rule's operation.
    /// </summary>
    public static string Select(IReadOnlyList<SentomaruOperationRule> rules, ReadOnlyMemory<byte>? body, string defaultOperation)
    {
        ArgumentNullException.ThrowIfNull(rules);
        if (rules.Count == 0) return defaultOperation;
        var protectedOperation = rules[0].Operation!;
        if (body is not { } bytes) return protectedOperation;
        var span = bytes;
        if (span.Span.StartsWith("﻿"u8)) span = span[3..];
        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(span, ParseOptions);
        }
        catch (JsonException)
        {
            return protectedOperation;
        }
        catch (ArgumentException)
        {
            return protectedOperation;
        }
        using (document)
        {
            foreach (var rule in rules)
            {
                if (!TryParsePointer(rule.Pointer, out var segments)) return protectedOperation; // validated at startup
                var wanted = rule.Values.Where(v => v is not null).SelectMany(Forms).ToHashSet(StringComparer.Ordinal);
                foreach (var found in Resolve(document.RootElement, segments, 0))
                {
                    if (FormsOf(found).Any(wanted.Contains)) return rule.Operation!;
                }
            }
        }
        return defaultOperation;
    }

    /// <summary>Every element the pointer reaches. An object segment matches every property of that name in any casing
    /// (duplicates included), so neither <c>EtapaAtual</c> nor a repeated key escapes a rule.</summary>
    private static IEnumerable<JsonElement> Resolve(JsonElement element, string[] segments, int index)
    {
        if (index == segments.Length)
        {
            yield return element;
            yield break;
        }
        var segment = segments[index];
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var property in element.EnumerateObject())
                {
                    if (!string.Equals(property.Name, segment, StringComparison.OrdinalIgnoreCase)) continue;
                    foreach (var found in Resolve(property.Value, segments, index + 1)) yield return found;
                }
                break;
            case JsonValueKind.Array:
                if (segment.Length > 0 && segment.All(char.IsAsciiDigit) && (segment == "0" || segment[0] != '0') &&
                    int.TryParse(segment, NumberStyles.None, CultureInfo.InvariantCulture, out var position) &&
                    position < element.GetArrayLength())
                {
                    foreach (var found in Resolve(element[position], segments, index + 1)) yield return found;
                }
                break;
        }
    }

    /// <summary>The text forms of a JSON value: a string trimmed (plus its number form when it reads as a number, since
    /// ASP.NET web defaults read numbers from strings), a number by its normalized invariant value, true/false.</summary>
    private static IEnumerable<string> FormsOf(JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.String:
                foreach (var form in Forms(element.GetString() ?? "")) yield return form;
                break;
            case JsonValueKind.Number:
                foreach (var form in Forms(element.GetRawText())) yield return form;
                break;
            case JsonValueKind.True:
                yield return "true";
                break;
            case JsonValueKind.False:
                yield return "false";
                break;
        }
    }

    private static IEnumerable<string> Forms(string text)
    {
        var trimmed = text.Trim();
        yield return trimmed;
        if (NormalizeNumber(trimmed) is { } number && number != trimmed) yield return number;
    }

    /// <summary>The invariant text of a number without trailing zeros (<c>6.0</c> and <c>6e0</c> are <c>6</c>), or null.</summary>
    internal static string? NormalizeNumber(string text)
    {
        if (text.Length == 0 || text.Length > MaxValueLength) return null;
        if (!decimal.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out var value)) return null;
        var normalized = (value / 1.000000000000000000000000000000000m).ToString(CultureInfo.InvariantCulture);
        return normalized == "-0" ? "0" : normalized;
    }

    internal static bool TryParsePointer(string? pointer, out string[] segments)
    {
        segments = [];
        if (pointer is null || pointer.Length < 2 || pointer.Length > MaxPointerLength || pointer[0] != '/') return false;
        var raw = pointer[1..].Split('/');
        if (raw.Length > MaxPointerSegments) return false;
        var parsed = new string[raw.Length];
        for (var i = 0; i < raw.Length; i++)
        {
            var part = raw[i];
            if (part.Length == 0) return false;
            for (var c = 0; c < part.Length; c++)
            {
                if (part[c] == '~' && (c + 1 >= part.Length || part[c + 1] is not ('0' or '1'))) return false;
            }
            parsed[i] = part.Replace("~1", "/", StringComparison.Ordinal).Replace("~0", "~", StringComparison.Ordinal);
        }
        segments = parsed;
        return true;
    }
}
