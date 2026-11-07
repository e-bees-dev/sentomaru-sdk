import 'dart:async';

import 'package:dio/dio.dart';

/// 0.6.0 (C-09, issue #143): what the consumer BACKEND enforces, read from its `GET /integrity/capabilities`
/// (mapped by `MapSentomaruCapabilities()` of Sentomaru.AspNetCore 4.x, opt-in). Sentomaru itself cannot know whether
/// the consumer turned verification on, so the app asks the backend before it marks operations.
///
/// The answer is advisory for the app's own behaviour (whether to mark operations); it never authorizes anything: the
/// backend decides every protected request.
class SentomaruCapabilities {
  const SentomaruCapabilities({required this.enabled, required this.operations});

  /// Sentomaru verification is on in the backend.
  final bool enabled;

  /// Protected operation → enforced (true = a missing or invalid proof is refused; false = Observe, logged only).
  final Map<String, bool> operations;

  /// Parses the backend answer; throws [FormatException] on anything else (unknown schema, missing members).
  factory SentomaruCapabilities.fromJson(Map<String, dynamic> json) {
    if (json['schemaVersion'] != '1') throw const FormatException('capabilities: unknown schemaVersion');
    final operations = json['operations'];
    if (json['enabled'] is! bool || operations is! List) throw const FormatException('capabilities: malformed');
    final ops = <String, bool>{};
    for (final o in operations) {
      if (o is! Map || o['operation'] is! String || o['enforced'] is! bool) {
        throw const FormatException('capabilities: malformed operation');
      }
      ops[o['operation'] as String] = o['enforced'] as bool;
    }
    return SentomaruCapabilities(enabled: json['enabled'] as bool, operations: Map.unmodifiable(ops));
  }

  /// Reads `GET <url>`; null when it cannot be read (offline, 404 from a backend without the route, bad answer). Only
  /// https URLs are accepted (http only for loopback in tests); redirects are not followed.
  static Future<SentomaruCapabilities?> fetch(Dio dio, Uri url, {Duration timeout = const Duration(seconds: 3)}) async {
    final loopback = url.host == '127.0.0.1' || url.host == 'localhost';
    if (url.scheme != 'https' && !(url.scheme == 'http' && loopback)) return null;
    try {
      final response = await dio.getUri<Map<String, dynamic>>(url,
          options: Options(responseType: ResponseType.json, receiveTimeout: timeout, sendTimeout: timeout,
              followRedirects: false, validateStatus: (s) => s == 200));
      final data = response.data;
      return data == null ? null : SentomaruCapabilities.fromJson(data);
    } on DioException {
      return null;
    } on FormatException {
      return null;
    } on TypeError {
      return null;
    }
  }
}

/// Why the app's configuration and the backend do not agree.
enum SentomaruCapabilityMismatch {
  /// Everything the app intends to mark is enforced by the backend.
  none,

  /// The backend could not be read (route not mapped, offline): unknown.
  unknown,

  /// The backend has Sentomaru turned off: marked operations would be refused or unverified.
  backendDisabled,

  /// An operation the app marks is not protected by the backend at all.
  operationNotProtected,
}

/// Not a mismatch: the marks are verified, but something the app team should know. Reported through
/// [SentomaruCapabilityGate.onWarning], never changes what is marked.
enum SentomaruCapabilityWarning {
  /// An operation the app marks is protected in Observe only (evaluated and logged, never refused).
  operationObserveOnly,
}

/// What the app does when [SentomaruCapabilityGate.mismatch] means its marks would not be verified.
enum SentomaruMismatchPolicy {
  /// Log and do not mark operations the backend does not verify (the request goes as a plain API call), so a
  /// misconfigured backend does not turn every marked operation into a 503. The default.
  degrade,

  /// Keep marking (a refused request surfaces the misconfiguration to the user).
  keep,
}

/// Decides, once at bootstrap, whether the app marks its protected operations.
class SentomaruCapabilityGate {
  SentomaruCapabilityGate({
    required this.appEnforces,
    required Iterable<String> operations,
    this.policy = SentomaruMismatchPolicy.degrade,
    this.onMismatch,
    this.onWarning,
  }) : operations = Set.unmodifiable(operations);

  /// The app was built to mark operations (for example its `SENTOMARU_ENFORCE`).
  final bool appEnforces;
  final Set<String> operations;
  final SentomaruMismatchPolicy policy;

  /// Called once with the mismatch found (log it; never show internals to the user).
  final void Function(SentomaruCapabilityMismatch mismatch)? onMismatch;

  /// Called once per warning found (log it at a lower level than a mismatch).
  final void Function(SentomaruCapabilityWarning warning)? onWarning;

  SentomaruCapabilityMismatch _mismatch = SentomaruCapabilityMismatch.unknown;
  SentomaruCapabilities? _capabilities;
  SentomaruCapabilityMismatch get mismatch => _mismatch;

  /// Compares the backend answer with what the app intends; null [capabilities] = could not be read.
  SentomaruCapabilityMismatch evaluate(SentomaruCapabilities? capabilities) {
    _capabilities = capabilities;
    _mismatch = compare(capabilities);
    if (_mismatch != SentomaruCapabilityMismatch.none) onMismatch?.call(_mismatch);
    warnings(capabilities).forEach((w) => onWarning?.call(w));
    return _mismatch;
  }

  /// Warnings for a backend answer that otherwise matches (empty when unreadable, disabled or mismatched).
  List<SentomaruCapabilityWarning> warnings(SentomaruCapabilities? c) {
    if (c == null || !c.enabled) return const [];
    final observeOnly = operations.any((o) => c.operations[o] == false);
    return observeOnly ? const [SentomaruCapabilityWarning.operationObserveOnly] : const [];
  }

  /// Pure comparison, usable by a release smoke test as well.
  SentomaruCapabilityMismatch compare(SentomaruCapabilities? c) {
    if (c == null) return SentomaruCapabilityMismatch.unknown;
    if (!c.enabled) return SentomaruCapabilityMismatch.backendDisabled;
    if (operations.any((o) => !c.operations.containsKey(o))) return SentomaruCapabilityMismatch.operationNotProtected;
    return SentomaruCapabilityMismatch.none;
  }

  /// Whether to mark [operation] (put `sentomaru_operation` in the request extra). Unknown (backend unreadable) keeps
  /// the app's own setting: absence of the route is not proof the backend is off.
  bool shouldMark(String operation) {
    if (!appEnforces || !operations.contains(operation)) return false;
    if (policy == SentomaruMismatchPolicy.keep || _mismatch == SentomaruCapabilityMismatch.unknown) return true;
    if (_mismatch == SentomaruCapabilityMismatch.backendDisabled) return false;
    // Mark what the backend protects (enforced or Observe); skip only operations it does not protect at all.
    return _capabilities?.operations.containsKey(operation) ?? false;
  }
}
