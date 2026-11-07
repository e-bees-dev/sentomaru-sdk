import 'dart:convert';

import 'models.dart';

/// D-15c: the family of a [SentomaruSignalEvent].
enum SentomaruSignalEventKind {
  /// A signal the app itself collected (D-15a, Android only).
  signal('signal'),

  /// A closed code a consumer answered to a SIGNED request (D-15b).
  serverResponse('server_response');

  final String wireName;
  const SentomaruSignalEventKind(this.wireName);
}

/// D-15c (0.14.0): an INFORMATIVE event, never a verdict. It says nothing about whether the app or the device is safe,
/// and a process the attacker controls can suppress or invent it; the server decides on every request. There is
/// deliberately no "is compromised", score or summary.
///
/// * [SentomaruSignalEventKind.signal]: a signal the app itself collected with
///   `SentomaruClient.collectSignalsSnapshot` (Android only; the D-05 and D-12c capabilities, never the six of
///   `collectSignals()`), on its first observation while the app listens and on each change of state. Fields: [type],
///   [capabilityId], [capabilityVersion], [state], [reasonCodes], [catalogVersion].
/// * [SentomaruSignalEventKind.serverResponse]: the closed code a consumer answered to a request the
///   `SentomaruDioInterceptor` signed (every platform). Fields: [code], [challengeKind], [httpStatus].
///
/// Every field comes from a closed vocabulary ([SentomaruSignalEventsCatalog], [SentomaruServerResponseCodes]); no
/// wall-clock time, detail text, installation, session or key id, package name, path, digest, URL or header.
/// [sequence] is the order in which the events reached this client's stream (one counter for both kinds).
class SentomaruSignalEvent {
  final SentomaruSignalEventKind kind;
  final int sequence;

  /// Signal events: the type of [SentomaruSignalEventsCatalog.eventTypes]; null for server responses.
  final String? type;
  final String? capabilityId;
  final String? capabilityVersion;
  final SignalState? state;

  /// Signal events: only codes of [SentomaruSignalEventsCatalog.eventReasonCodes] for [capabilityId]; empty otherwise.
  final List<String> reasonCodes;
  final String? catalogVersion;

  /// Server responses: `challenge-required`, `proof-required`, `installation-suspended`, `installation-revoked`,
  /// `session-unavailable`, `policy-denied`, or a policy reason code (`^[A-Z0-9_]{3,64}$`, 403 only).
  final String? code;

  /// Server responses with `challenge-required` only: one of [SentomaruServerResponseCodes.challengeKinds]
  /// (`fresh_signals`, `step_up`, `reattest`), or another token of `^[a-z][a-z0-9_]{0,31}$` from a newer server; null
  /// when the consumer sent none.
  final String? challengeKind;

  /// D-06h (0.15.0): a `challenge-required` of kind `reattest`: the app may call `SentomaruClient.reattest()` and repeat
  /// the operation once. Not a verdict; the plugin never reattests nor repeats by itself.
  bool get isReattestChallenge =>
      code == SentomaruServerResponseCodes.challengeRequired && challengeKind == SentomaruServerResponseCodes.reattest;

  /// Server responses: 401 or 403.
  final int? httpStatus;

  const SentomaruSignalEvent._({
    required this.kind,
    required this.sequence,
    this.type,
    this.capabilityId,
    this.capabilityVersion,
    this.state,
    this.reasonCodes = const [],
    this.catalogVersion,
  })  : code = null,
        challengeKind = null,
        httpStatus = null;

  /// The `server_response` event of one answer ([SentomaruServerResponseCodes.read]), or null when it carries no
  /// closed code. Only a checked code is ever built (review R I-1: no public constructor takes free values).
  static SentomaruSignalEvent? fromServerResponse(int? httpStatus, Object? data, int sequence) {
    final read = SentomaruServerResponseCodes.read(httpStatus, data);
    if (read == null) return null;
    return SentomaruSignalEvent._serverResponse(
        code: read.$1, challengeKind: read.$2, httpStatus: httpStatus!, sequence: sequence);
  }

  const SentomaruSignalEvent._serverResponse({
    required String this.code,
    required int this.httpStatus,
    this.challengeKind,
    required this.sequence,
  })  : kind = SentomaruSignalEventKind.serverResponse,
        type = null,
        capabilityId = null,
        capabilityVersion = null,
        state = null,
        reasonCodes = const [],
        catalogVersion = null;

  /// The event the EventChannel carried, renumbered with [sequence], or null when any field is outside the closed
  /// vocabulary (an unknown kind, type, capability, state or reason code, a version that is not `x.y.z`): such an event
  /// is dropped, never passed on partly.
  static SentomaruSignalEvent? fromPlatform(Object? raw, int sequence) {
    if (raw is! Map) return null;
    switch (raw['kind']) {
      case 'signal':
        final id = raw['capabilityId'];
        if (id is! String) return null;
        final type = SentomaruSignalEventsCatalog.eventTypes[id];
        final allowed = SentomaruSignalEventsCatalog.eventReasonCodes[id];
        if (type == null || allowed == null || raw['type'] != type) return null;
        final version = raw['capabilityVersion'];
        final catalogVersion = raw['catalogVersion'];
        if (version is! String || !_semver.hasMatch(version)) return null;
        if (catalogVersion is! String || !_semver.hasMatch(catalogVersion)) return null;
        final state = _states[raw['state']];
        final codes = raw['reasonCodes'];
        if (state == null || codes is! List) return null;
        if (codes.any((c) => c is! String || !allowed.contains(c))) return null;
        return SentomaruSignalEvent._(
          kind: SentomaruSignalEventKind.signal,
          sequence: sequence,
          type: type,
          capabilityId: id,
          capabilityVersion: version,
          state: state,
          reasonCodes: List.unmodifiable(codes.cast<String>()),
          catalogVersion: catalogVersion,
        );
      case 'server_response':
        final status = raw['httpStatus'];
        final code = raw['code'];
        final kind = raw['challengeKind'];
        if (status is! int || code is! String || (kind != null && kind is! String)) return null;
        final checked = SentomaruServerResponseCodes.check(status, code, kind as String?);
        if (checked == null) return null;
        return SentomaruSignalEvent._serverResponse(
            code: checked.$1, challengeKind: checked.$2, httpStatus: status, sequence: sequence);
      default:
        return null;
    }
  }

  static final _semver = RegExp(r'^\d{1,4}\.\d{1,4}\.\d{1,4}$');

  /// States a signal event can carry (never STALE: only the server sets it).
  static const _states = {
    'DETECTED': SignalState.detected,
    'NOT_DETECTED': SignalState.notDetected,
    'UNKNOWN': SignalState.unknown,
    'UNSUPPORTED': SignalState.unsupported,
    'ERROR': SignalState.error,
  };

  @override
  String toString() => kind == SentomaruSignalEventKind.signal
      ? 'SentomaruSignalEvent(signal #$sequence $type ${state?.wireName} $reasonCodes)'
      : 'SentomaruSignalEvent(server_response #$sequence $httpStatus $code${challengeKind == null ? '' : ' $challengeKind'})';
}

/// D-15c: the plugin's copy of the D-15a vocabulary of the Android `SignalsCatalog` (`EVENT_TYPES`,
/// `EVENT_REASON_CODES`). `signal_events_test.dart` compares it with `SignalsCatalog.kt`, so a change there fails
/// `flutter test` until this follows.
abstract final class SentomaruSignalEventsCatalog {
  static const eventTypes = <String, String>{
    'debugger_attached': 'debugger',
    'app_debuggable': 'debuggable_build',
    'dev_settings_enabled': 'developer_options',
    'root_artifacts': 'root_artifacts',
    'emulator_indicated': 'emulator',
    'hook_framework_java': 'hook_framework_java',
    'app_signer_mismatch': 'app_signer',
    'code_integrity': 'code_integrity',
    'installer_class': 'installer_class',
    'a11y_risk': 'accessibility_risk',
    'overlay': 'overlay',
    'ime_untrusted': 'ime_untrusted',
    'synthetic_input': 'synthetic_input',
    'known_malware': 'known_malware',
    'screen_capture': 'screen_capture',
    'screen_shared': 'screen_shared',
    'location_mock': 'location_mock',
    'call_active': 'call_active',
  };

  static const eventReasonCodes = <String, Set<String>>{
    'debugger_attached': {'jdwp_connected', 'jdwp_waiting', 'partial', 'timeout'},
    'app_debuggable': {'flag_debuggable', 'partial', 'timeout'},
    'dev_settings_enabled': {'adb_enabled', 'development_settings', 'partial', 'timeout'},
    'root_artifacts': {
      'su_path', 'manager_path', 'build_props', 'test_keys', 'build_type', 'root_package', 'mountinfo', 'partial',
      'timeout',
    },
    'emulator_indicated': {'build_props', 'qemu_device', 'sensor_missing', 'partial', 'timeout'},
    'hook_framework_java': {'xposed_class', 'hook_frame', 'partial', 'timeout'},
    'app_signer_mismatch': {'match', 'mismatch', 'no_reference', 'unreadable', 'timeout'},
    'installer_class': {
      'class_play', 'class_none', 'class_other', 'class_unknown',
      'initiator_play', 'initiator_none', 'initiator_other', 'initiator_unknown', 'timeout',
    },
    'code_integrity': {
      'not_compared', 'timeout', 'partial', 'main_thread', 'apk_list', 'executor', 'hash_failed', 'apk_unreadable',
      'duplicate_entry', 'entry_unreadable', 'no_code_files', 'too_large', 'too_many_files',
    },
    'a11y_risk': {'none', 'listed', 'unlisted_present', 'partial', 'timeout'},
    'overlay': {'obscured', 'clear', 'no_touches', 'timeout'},
    'ime_untrusted': {'known', 'unknown', 'no_reference', 'partial', 'timeout'},
    'synthetic_input': {'virtual_pointer', 'injected_touch', 'partial', 'timeout'},
    'known_malware': {'matched', 'clear', 'no_reference', 'partial', 'timeout'},
    'screen_capture': {'captured', 'none', 'no_screens', 'timeout'},
    'screen_shared': {'presentation_display', 'secondary_display', 'screen_recording', 'partial', 'timeout'},
    'location_mock': {'mock_flagged', 'clean', 'no_permission', 'no_fix', 'partial', 'timeout'},
    'call_active': {'cellular', 'communication', 'none', 'partial', 'timeout'},
  };
}

/// D-15c: the closed vocabulary of server response events (the Android `ServerResponseCodes` of D-15b) and the reader
/// of a response body as Dio hands it over (a decoded `Map`, a `String` or bytes). Only the top-level `code` member (and
/// `challengeKind` next to `challenge-required`) is read; any other member, free text, a `riskEvent` or a nested
/// `code` never becomes an event. A text or byte body longer than [maxBodyChars] is not read. The vocabulary is the
/// Kotlin one (`signal_events_test.dart` compares it with `SentomaruServerResponseEvent.kt`); the parser is not
/// (review R M-2): `jsonDecode` keeps the last of a repeated member where the Kotlin reader refuses the body, and a
/// `Map` Dio already decoded is read as is, without the size or depth bound.
abstract final class SentomaruServerResponseCodes {
  static const challengeRequired = 'challenge-required';
  static const maxBodyChars = 4096;

  /// Challenge kinds of the policy (contract v1.10). D-06h adds [reattest].
  static const freshSignals = 'fresh_signals';
  static const stepUp = 'step_up';
  static const reattest = 'reattest';

  /// The closed set of challenge kinds this plugin knows (the Kotlin `CHALLENGE_KINDS`). A well-formed kind outside it
  /// still passes raw in [SentomaruSignalEvent.challengeKind] (a newer server); a malformed one is null.
  static const challengeKinds = {freshSignals, stepUp, reattest};

  static const closed = {
    challengeRequired, 'proof-required', 'installation-suspended', 'installation-revoked', 'session-unavailable',
    'policy-denied',
  };
  static const _only401 = {challengeRequired, 'proof-required'};
  static final _policyReason = RegExp(r'^[A-Z0-9_]{3,64}$');
  static final _challengeKind = RegExp(r'^[a-z][a-z0-9_]{0,31}$');

  /// The (code, challengeKind) of a response body, or null when it carries no closed code.
  static (String, String?)? read(int? httpStatus, Object? data) {
    if (httpStatus != 401 && httpStatus != 403) return null;
    final members = _topLevel(data);
    if (members == null) return null;
    final code = members['code'];
    final kind = members['challengeKind'];
    if (code is! String) return null;
    return check(httpStatus!, code, kind is String ? kind : null);
  }

  /// The (code, challengeKind) when [code] is a closed code for [httpStatus]; [challengeKind] kept only with
  /// `challenge-required` and when it is a well-formed token.
  static (String, String?)? check(int httpStatus, String code, String? challengeKind) {
    if (httpStatus != 401 && httpStatus != 403) return null;
    final known = closed.contains(code) && (httpStatus == 401 || !_only401.contains(code));
    final policy = httpStatus == 403 && _policyReason.hasMatch(code);
    if (!known && !policy) return null;
    final kind = code == challengeRequired && challengeKind != null && _challengeKind.hasMatch(challengeKind)
        ? challengeKind
        : null;
    return (code, kind);
  }

  static Map? _topLevel(Object? data) {
    if (data is Map) return data;
    String? text;
    if (data is String) {
      text = data;
    } else if (data is List<int>) {
      if (data.length > maxBodyChars) return null;
      try {
        text = utf8.decode(data);
      } on FormatException {
        return null;
      }
    }
    if (text == null || text.length > maxBodyChars) return null;
    try {
      final decoded = jsonDecode(text);
      return decoded is Map ? decoded : null;
    } on FormatException {
      return null;
    }
  }
}
