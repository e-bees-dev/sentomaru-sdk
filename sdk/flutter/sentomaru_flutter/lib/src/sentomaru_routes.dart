/// G-03c: the profile's `network-signing` section (contracts/devsecops/cli-v1.md) in the app.
///
/// A request with no declared operation whose host is in [hosts] and whose path matches a route is signed as that
/// route's operation, so the app protects its calls by installing the interceptor once
/// (`dio.addSentomaru(client, routes: ...)`) instead of tagging each request. A declared operation (header or
/// `extra`) always wins over the table. Same rules as the Android SDK and the CLI profile: hosts lowercase
/// `[a-z0-9.-]{1,253}`, unique, at least one; routes at least one, path starting with `/`, operation
/// `[a-z0-9_]{1,64}`. A segment `*` matches exactly one non-empty segment; other segments compare
/// case-insensitively; one trailing slash is ignored; no query or fragment in a route. Routes are tried **in order and
/// the first match wins** (put a literal route before a `*` route that would also match it); a repeated path is
/// refused. Paths are compared percent-decoded (`Uri.pathSegments`); the port is ignored; a request host with one
/// trailing dot (`api.example.`) is the same host, so it is covered and then refused by the allowlist check, never sent
/// unsigned. [hosts] must be within the client's allowed hosts: `dio.addSentomaru` refuses the installation otherwise
/// (checked at installation when the client is already initialized, and at each request otherwise).
class SentomaruRoutes {
  SentomaruRoutes._(this.hosts, this.routes);

  final Set<String> hosts;
  final List<SentomaruRoute> routes;

  static final RegExp _host = RegExp(r'^[a-z0-9.-]{1,253}$');
  static final RegExp _operation = RegExp(r'^[a-z0-9_]{1,64}$');

  /// Validates and builds the table; throws [ArgumentError] naming the first offending field.
  factory SentomaruRoutes({required List<String> hosts, required List<SentomaruRoute> routes}) {
    if (hosts.isEmpty || !hosts.every(_host.hasMatch) || hosts.toSet().length != hosts.length) {
      throw ArgumentError('network-signing.hosts');
    }
    if (routes.isEmpty) throw ArgumentError('network-signing.routes');
    for (final r in routes) {
      if (!_operation.hasMatch(r.operation)) throw ArgumentError('network-signing.routes.operation');
    }
    final keys = routes.map((r) => r._segments.map((s) => s.toLowerCase()).join('/')).toSet();
    if (keys.length != routes.length) throw ArgumentError('network-signing.routes: repeated path');
    return SentomaruRoutes._(hosts.toSet(), List.unmodifiable(routes));
  }

  /// The section as written in the profile (`{"version":"1","hosts":[...],"routes":[{"path":..,"operation":..}]}`).
  factory SentomaruRoutes.fromProfileSection(Map<String, dynamic> section) {
    if (section['version'] != '1') throw ArgumentError('network-signing.version');
    final hosts = section['hosts'];
    final routes = section['routes'];
    if (hosts is! List || routes is! List) throw ArgumentError('network-signing');
    return SentomaruRoutes(
      hosts: hosts.map((h) => h is String ? h : throw ArgumentError('network-signing.hosts')).toList(),
      routes: routes.map((r) {
        if (r is! Map || r['path'] is! String || r['operation'] is! String || r.length != 2) {
          throw ArgumentError('network-signing.routes');
        }
        return SentomaruRoute(r['path'] as String, r['operation'] as String);
      }).toList(),
    );
  }

  /// The operation for [uri] by this table, or null when its host or path is not covered.
  String? operationFor(Uri uri) {
    final host = uri.host.endsWith('.') ? uri.host.substring(0, uri.host.length - 1) : uri.host;
    if (!hosts.contains(host)) return null;
    var actual = uri.pathSegments;
    if (actual.length > 1 && actual.last.isEmpty) actual = actual.sublist(0, actual.length - 1);
    if (actual.isEmpty) actual = const [''];
    for (final route in routes) {
      if (_matches(route._segments, actual)) return route.operation;
    }
    return null;
  }

  static bool _matches(List<String> pattern, List<String> actual) {
    if (pattern.length != actual.length) return false;
    for (var i = 0; i < pattern.length; i++) {
      if (pattern[i] == '*') {
        if (actual[i].isEmpty) return false;
      } else if (pattern[i].toLowerCase() != actual[i].toLowerCase()) {
        return false;
      }
    }
    return true;
  }
}

/// One route of [SentomaruRoutes]: a path pattern and the operation it is signed as.
class SentomaruRoute {
  SentomaruRoute(this.path, this.operation) : _segments = _segmentsOf(path);

  final String path;
  final String operation;
  final List<String> _segments;

  static List<String> _segmentsOf(String path) {
    if (!path.startsWith('/') || path.contains('?') || path.contains('#') ||
        path.codeUnits.any((c) => c <= 0x20 || c == 0x7f)) {
      throw ArgumentError('network-signing.routes.path');
    }
    var parts = path.substring(1).split('/');
    if (parts.length > 1 && parts.last.isEmpty) parts = parts.sublist(0, parts.length - 1);
    if (!(parts.length == 1 && parts.single.isEmpty) && parts.any((p) => p.isEmpty)) {
      throw ArgumentError('network-signing.routes.path');
    }
    if (parts.any((p) => p.contains('*') && p != '*')) throw ArgumentError('network-signing.routes.path');
    return parts;
  }
}
