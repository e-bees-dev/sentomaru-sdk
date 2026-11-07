using Sentomaru.AspNetCore;

namespace Sentomaru.Gateway.Verifier;

/// <summary>One route of the table, compiled: the operation and mode come from here, never from the client.</summary>
public sealed record VerifierRoute(string Method, string Pattern, string Operation, DeviceAssuranceLevel AssuranceLevel,
    bool AllowOperationReplay)
{
    internal IReadOnlyList<string?> Segments { get; init; } = [];

    /// <summary>The mode label of the contract (<c>enforce</c> or <c>observe</c>).</summary>
    public string Mode => AssuranceLevel == DeviceAssuranceLevel.Observe ? "observe" : "enforce";
}

/// <summary>
/// The route table (contract section 4, C1): method + path pattern, exact and case-sensitive. The method is compared
/// ordinally, so <c>post</c> is not <c>POST</c> (D-17b review R I-2: the extractor upper-cases the method, the upstream
/// may not). A pattern is <c>/</c> or segments of RFC 3986 unreserved characters, where a whole segment may be
/// <c>{name}</c> (one non-empty segment of unreserved characters). No prefix, wildcard, trailing slash, <c>.</c> or
/// <c>..</c>. A request path (as Kestrel decoded it) with any other character (an escape Kestrel kept, <c>;</c>,
/// <c>\</c>) or an empty segment (<c>//</c>, trailing slash) matches nothing: 403 <c>operation-unmapped</c>. Kestrel
/// removes dot segments, also <c>%2E</c>-encoded ones, before <c>Path</c>; so the raw request-target is checked first
/// (<see cref="RawTargetAllowed"/>, review R M-2): a raw <c>.</c>, <c>..</c>, any <c>%2E</c> or an empty segment is
/// outside the table too.
/// </summary>
public sealed class RouteTable
{
    /// <summary>
    /// True when the raw request-target is origin-form (<c>/...</c>) and its path has no empty segment (except the root),
    /// no <c>.</c> or <c>..</c> segment and no <c>%2E</c> in any case. A gateway that normalizes (contract section 5)
    /// never sends one; anything else is refused before the table, so the operation is chosen on the path the upstream
    /// receives.
    /// </summary>
    public static bool RawTargetAllowed(string? rawTarget)
    {
        if (string.IsNullOrEmpty(rawTarget) || rawTarget[0] != '/') return false;
        var query = rawTarget.IndexOf('?', StringComparison.Ordinal);
        var path = query < 0 ? rawTarget : rawTarget[..query];
        if (path == "/") return true;
        foreach (var segment in path[1..].Split('/'))
        {
            if (segment.Length == 0 || segment is "." or ".." || segment.Contains("%2e", StringComparison.OrdinalIgnoreCase)) return false;
        }
        return true;
    }

    private readonly IReadOnlyList<VerifierRoute> routes;

    private RouteTable(IReadOnlyList<VerifierRoute> routes) => this.routes = routes;

    public IReadOnlyList<VerifierRoute> Routes => routes;

    /// <summary>Compiles a validated table (<see cref="Validate"/> found no error).</summary>
    public static RouteTable Compile(IReadOnlyList<RouteConfig> routes) =>
        new([.. routes.Select(r => new VerifierRoute(r.Method!, r.Path!, r.Operation!,
            r.Mode == "observe" ? DeviceAssuranceLevel.Observe : DeviceAssuranceLevel.ZeroTrust, r.AllowOperationReplay)
        {
            Segments = ParsePattern(r.Path!)!,
        })]);

    /// <summary>The route of this request, or null (403 <c>operation-unmapped</c>).</summary>
    public VerifierRoute? Match(string method, string? path)
    {
        var segments = SplitPath(path);
        if (segments is null) return null;
        foreach (var route in routes)
        {
            if (!string.Equals(route.Method, method, StringComparison.Ordinal) || route.Segments.Count != segments.Count) continue;
            var matches = true;
            for (var i = 0; i < segments.Count && matches; i++)
            {
                // A parameter matches any (already validated) segment; a literal only itself.
                matches = route.Segments[i] is not { } literal || string.Equals(literal, segments[i], StringComparison.Ordinal);
            }
            if (matches) return route;
        }
        return null;
    }

    /// <summary>
    /// The segments of a request path ("/" has none), or null when the path cannot match any pattern: not absolute, an
    /// empty or dot segment, or a character outside the unreserved set.
    /// </summary>
    internal static IReadOnlyList<string>? SplitPath(string? path)
    {
        if (string.IsNullOrEmpty(path) || path[0] != '/') return null;
        if (path == "/") return [];
        var segments = path[1..].Split('/');
        foreach (var segment in segments)
        {
            if (segment.Length == 0 || segment is "." or ".." || !segment.All(IsUnreserved)) return null;
        }
        return segments;
    }

    /// <summary>The segments of a pattern, null for a parameter; null when the pattern is invalid.</summary>
    internal static IReadOnlyList<string?>? ParsePattern(string? pattern)
    {
        if (pattern is null || pattern.Length > 512 || pattern.Length == 0 || pattern[0] != '/') return null;
        if (pattern == "/") return [];
        var result = new List<string?>();
        foreach (var segment in pattern[1..].Split('/'))
        {
            if (segment.Length > 2 && segment[0] == '{' && segment[^1] == '}')
            {
                var name = segment[1..^1];
                if (name.Length > 32 || name[0] is < 'a' or > 'z' || !name.All(char.IsAsciiLetterOrDigit)) return null;
                result.Add(null);
            }
            else if (segment.Length == 0 || segment is "." or ".." || !segment.All(IsUnreserved))
            {
                return null;
            }
            else
            {
                result.Add(segment);
            }
        }
        return result;
    }

    private static bool IsUnreserved(char c) => char.IsAsciiLetterOrDigit(c) || c is '-' or '.' or '_' or '~';

    /// <summary>
    /// The cross-entry rules the schema cannot hold (contract section 4): each route and exempt entry valid; no two
    /// routes of the same method that a path could match both (identical or overlapping patterns, so the operation of
    /// a request never depends on the order of the table); no route that an exempt entry covers; no repeated exempt
    /// entry.
    /// </summary>
    internal static void Validate(IReadOnlyList<RouteConfig>? routes, IReadOnlyList<ExemptConfig>? exempt, List<string> errors)
    {
        if (routes is null || routes.Count == 0)
        {
            errors.Add("routes must have at least one route.");
            return;
        }
        if (routes.Count > 1024) errors.Add("routes has more than 1024 entries.");
        var parsed = new List<(int Index, string Method, IReadOnlyList<string?> Segments)>();
        for (var i = 0; i < routes.Count; i++)
        {
            var route = routes[i];
            if (route is null)
            {
                errors.Add($"routes[{i}] is null.");
                continue;
            }
            var ok = true;
            if (route.Method is null || !VerifierConfig.Methods.Contains(route.Method))
            {
                errors.Add($"routes[{i}].method must be one of GET, POST, PUT, PATCH, DELETE (upper case).");
                ok = false;
            }
            var segments = ParsePattern(route.Path);
            if (segments is null)
            {
                errors.Add($"routes[{i}].path is not a valid pattern (exact, unreserved characters, whole-segment {{name}}).");
                ok = false;
            }
            if (route.Operation is null || !VerifierConfig.OperationPattern.IsMatch(route.Operation))
            {
                errors.Add($"routes[{i}].operation must match ^[a-z0-9_-]{{2,32}}$.");
            }
            if (route.Mode is not ("enforce" or "observe")) errors.Add($"routes[{i}].mode must be enforce or observe.");
            if (ok) parsed.Add((i, route.Method!, segments!));
        }
        for (var a = 0; a < parsed.Count; a++)
        {
            for (var b = a + 1; b < parsed.Count; b++)
            {
                if (parsed[a].Method == parsed[b].Method && Overlap(parsed[a].Segments, parsed[b].Segments))
                {
                    errors.Add($"routes[{parsed[a].Index}] and routes[{parsed[b].Index}] ({parsed[a].Method} {routes[parsed[a].Index].Path}, " +
                               $"{routes[parsed[b].Index].Path}) match the same path.");
                }
            }
        }

        if (exempt is null) return;
        if (exempt.Count > 64) errors.Add("exempt has more than 64 entries.");
        var seen = new List<(string Method, string Path)>();
        for (var i = 0; i < exempt.Count; i++)
        {
            var entry = exempt[i];
            if (entry is null)
            {
                errors.Add($"exempt[{i}] is null.");
                continue;
            }
            if (entry.Method is null || !VerifierConfig.Methods.Contains(entry.Method))
            {
                errors.Add($"exempt[{i}].method is required and must be one of GET, POST, PUT, PATCH, DELETE (upper case).");
                continue;
            }
            var segments = ParsePattern(entry.Path);
            if (segments is null || segments.Any(s => s is null))
            {
                errors.Add($"exempt[{i}].path must be an exact path (unreserved characters, no parameter).");
                continue;
            }
            if (seen.Any(s => s.Path == entry.Path && s.Method == entry.Method))
            {
                errors.Add($"exempt[{i}] repeats an exempt path ({entry.Path}).");
            }
            seen.Add((entry.Method, entry.Path!));
            foreach (var route in parsed)
            {
                if (entry.Method == route.Method && Overlap(route.Segments, segments))
                {
                    errors.Add($"routes[{route.Index}] ({route.Method} {routes[route.Index].Path}) is also exempt ({entry.Path}): " +
                               "an exempt path is never sent to the verifier.");
                }
            }
        }
    }

    /// <summary>True when one path matches both patterns (a parameter matches any segment).</summary>
    private static bool Overlap(IReadOnlyList<string?> a, IReadOnlyList<string?> b)
    {
        if (a.Count != b.Count) return false;
        for (var i = 0; i < a.Count; i++)
        {
            if (a[i] is { } x && b[i] is { } y && !string.Equals(x, y, StringComparison.Ordinal)) return false;
        }
        return true;
    }
}
