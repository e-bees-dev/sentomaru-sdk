import 'dart:convert';

import 'exceptions.dart';
import 'models.dart';

/// One capability of the contract catalog `contracts/sdk/signals-catalog-v1.json`: id, version and provenance.
class SignalCapability {
  final String capabilityId;
  final String version;

  /// `client_observed` (collected by the SDK in the app process) or `server_verified` (set by the API only).
  final String source;

  const SignalCapability(this.capabilityId, this.version, this.source);

  bool get isServerVerified => source == 'server_verified';
}

/// D-05e: the plugin's copy of the contract catalog `contracts/sdk/signals-catalog-v1.json`, in the same order.
/// `signals_snapshot_test.dart` compares it with the JSON, so a catalog change fails `flutter test` until this follows.
abstract final class SentomaruSignalsCatalog {
  /// Catalog `version`; sent as the snapshot `catalogVersion`.
  static const version = '1.15.0';

  static const capabilities = <SignalCapability>[
    SignalCapability('debug_attached', '1.0.0', 'client_observed'),
    SignalCapability('emulator_detected', '1.0.0', 'client_observed'),
    SignalCapability('root_indicated', '1.0.0', 'client_observed'),
    SignalCapability('app_signing_digest', '1.0.0', 'client_observed'),
    SignalCapability('installer_source', '1.0.0', 'client_observed'),
    SignalCapability('os_version', '1.0.0', 'client_observed'),
    SignalCapability('play_integrity_failed', '1.0.0', 'server_verified'),
    SignalCapability('build_unregistered', '1.0.0', 'server_verified'),
    SignalCapability('debugger_attached', '1.0.0', 'client_observed'),
    SignalCapability('app_debuggable', '1.0.0', 'client_observed'),
    SignalCapability('dev_settings_enabled', '1.0.0', 'client_observed'),
    SignalCapability('root_artifacts', '1.0.0', 'client_observed'),
    SignalCapability('emulator_indicated', '1.0.0', 'client_observed'),
    SignalCapability('hook_framework_java', '1.0.0', 'client_observed'),
    SignalCapability('app_identity_mismatch', '1.0.0', 'server_verified'),
    SignalCapability('app_signer_mismatch', '1.0.0', 'client_observed'),
    SignalCapability('installer_class', '1.0.0', 'client_observed'),
    SignalCapability('code_integrity', '1.0.0', 'client_observed'),
    SignalCapability('a11y_risk', '1.0.0', 'client_observed'),
    SignalCapability('overlay', '1.0.0', 'client_observed'),
    SignalCapability('ime_untrusted', '1.0.0', 'client_observed'),
    SignalCapability('synthetic_input', '1.1.0', 'client_observed'),
    SignalCapability('known_malware', '1.0.0', 'client_observed'),
    SignalCapability('screen_capture', '1.1.0', 'client_observed'),
    SignalCapability('screen_shared', '1.0.0', 'client_observed'),
    SignalCapability('location_mock', '1.0.0', 'client_observed'),
    SignalCapability('call_active', '1.0.0', 'client_observed'),
  ];

  /// The six capabilities of `collectSignals()` (catalog 1.0.0), frozen until the J-04 report.
  static const defaultCapabilityIds = <String>[
    'debug_attached', 'emulator_detected', 'root_indicated', 'app_signing_digest', 'installer_source', 'os_version',
  ];

  /// The D-05 capabilities (catalog 1.3.0), collected only with `collectSignalsSnapshot(rasp: true)`.
  static const raspCapabilityIds = <String>[
    'debugger_attached', 'app_debuggable', 'dev_settings_enabled', 'root_artifacts', 'emulator_indicated',
    'hook_framework_java',
  ];

  /// The D-12c capabilities (catalog 1.5.0), collected only with `collectSignalsSnapshot(appIntegrity: …)` (D-12e,
  /// plugin 0.13.0; Android `SignalsCollector.appIntegrityDetectors`).
  static const appIntegrityCapabilityIds = <String>['app_signer_mismatch', 'installer_class', 'code_integrity'];

  /// The D-24 consultive capabilities (catalog 1.8.0; `known_malware` in 1.9.0): collected by the Android SDK by opt-in
  /// (`SignalsCollector.deviceThreatDetectors`); the plugin does not collect them yet.
  static const deviceThreatCapabilityIds = <String>['a11y_risk', 'overlay', 'ime_untrusted', 'synthetic_input', 'known_malware'];

  /// The D-20 consultive screen capabilities (catalog 1.10.0): collected by the Android SDK by opt-in
  /// (`SignalsCollector.screenDetectors`); the plugin does not collect them yet.
  static const screenCapabilityIds = <String>['screen_capture', 'screen_shared'];

  /// The F-07/F-08 consultive session capabilities (catalog 1.13.0): collected by the Android SDK by opt-in
  /// (`SignalsCollector.sessionDetectors`); the plugin does not collect them yet.
  static const sessionCapabilityIds = <String>['location_mock', 'call_active'];

  /// Ids only the server sets (`server_verified` in the catalog). Sent by the app, the server refuses the whole
  /// snapshot (`server_capability_reserved`), so [SignalsSnapshot.toMap] drops them.
  static Set<String> get serverVerifiedIds =>
      {for (final c in capabilities) if (c.isServerVerified) c.capabilityId};

  static SignalCapability? byId(String capabilityId) {
    final id = capabilityId.toLowerCase();
    for (final c in capabilities) {
      if (c.capabilityId == id) return c;
    }
    return null;
  }
}

/// D-12e (0.13.0): opt-in for the three app integrity capabilities of the catalog 1.5.0 in
/// `SentomaruClient.collectSignalsSnapshot(appIntegrity: …)`: `app_signer_mismatch`, `installer_class`,
/// `code_integrity`. Declared by the app and evadable; the server compares `code_integrity` (D-12c-2) and has the
/// stronger `app_identity_mismatch` for an enrolled app.
///
/// [expectedSignerDigests] is the app's own configuration: the SHA-256 of every signing certificate it accepts (the
/// whole rotation lineage; with Play App Signing, Google's certificate), 64 hex digits with or without `:` (keytool
/// form), any case. Empty = `UNKNOWN` `no_reference`. Anything else is refused before the native call
/// ([SentomaruErrorCode.configurationError]); no digest of the device ever goes in a `detail`.
class AppIntegritySignals {
  final List<String> expectedSignerDigests;

  AppIntegritySignals({required List<String> expectedSignerDigests})
      : expectedSignerDigests = List.unmodifiable(expectedSignerDigests);

  static final _sha256 = RegExp(r'^[0-9a-f]{64}$');

  /// Throws [SentomaruException] `configurationError` when a digest is not a SHA-256 (the SDK's normalization:
  /// `:` removed, lower case, 64 hex digits).
  void validate() {
    for (final d in expectedSignerDigests) {
      if (!_sha256.hasMatch(d.replaceAll(':', '').toLowerCase())) {
        throw const SentomaruException(
            SentomaruErrorCode.configurationError, 'expectedSignerDigests holds a value that is not a SHA-256');
      }
    }
  }
}

/// D-05e: a signals snapshot in the wire format the server validates (`signals-observation-schema-v1.json`), for the
/// `x-sentomaru-signals` header. The interceptor signs that header when it is present (H3).
///
/// Client-observed and evadable: an instrumented process can rewrite any value before it is signed. `NOT_DETECTED`
/// means "not detected in this collection", never a clean device. Never an authorization: the server decides.
class SignalsSnapshot {
  /// Always [SentomaruSignalsCatalog.version].
  final String catalogVersion;

  /// When the native collection started (UTC).
  final DateTime collectedAt;

  /// How long the native collection took, never negative: on Android from a monotonic clock; on iOS (D-10e) from the
  /// wall clock (no boot-time API), so a clock change during the collection can skew it.
  final int durationMs;

  /// The observations as the native side returned them (or the UNSUPPORTED ones on a platform without them).
  final List<SignalObservation> observations;

  SignalsSnapshot({
    required this.collectedAt,
    required int durationMs,
    required List<SignalObservation> observations,
  })  : catalogVersion = SentomaruSignalsCatalog.version,
        durationMs = durationMs < 0 ? 0 : durationMs,
        observations = List.unmodifiable(observations);

  /// The wire map: `server_verified` ids of the catalog dropped, state in the server's name (`NOT_DETECTED`),
  /// `source` `client_observed`, instants in UTC ISO-8601, `detail` as a string map without null values.
  Map<String, Object> toMap() {
    final reserved = SentomaruSignalsCatalog.serverVerifiedIds;
    return {
      'catalogVersion': catalogVersion,
      'collectedAt': collectedAt.toUtc().toIso8601String(),
      'durationMs': durationMs,
      'observations': [
        for (final o in observations)
          if (!reserved.contains(o.capabilityId.toLowerCase()))
            {
              'capabilityId': o.capabilityId,
              'version': o.version,
              'state': o.state.wireName,
              'source': 'client_observed',
              'observedAt': o.observedAt.toUtc().toIso8601String(),
              'detail': <String, String>{
                for (final e in o.data.entries)
                  if (e.value != null) e.key: '${e.value}',
              },
            },
      ],
    };
  }

  /// [toMap] as JSON. Pass it through `encodeSignalsHeader` (or let the interceptor do it) for the header value.
  String toJson() => jsonEncode(toMap());
}
