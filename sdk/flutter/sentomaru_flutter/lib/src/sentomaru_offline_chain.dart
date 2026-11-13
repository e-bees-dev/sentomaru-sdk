import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'sentomaru_flutter_platform_interface.dart';

/// D-26: why an operation could not be sealed, or why a call was refused. A seal is never produced in these cases.
enum SentomaruOfflineError {
  /// The permit text is not the `201` body of `offline-permits`.
  permitInvalid,

  /// The wall clock is past the permit's `validUntil`.
  permitExpired,

  /// `maxItems` seals were already made under this permit.
  chainFull,

  /// The operation digest is not a SHA-256 (32 bytes).
  invalidDigest,

  /// iOS: the boot session became unavailable (or available) in the middle of one permit.
  clockUnavailable,

  /// No enrolled installation: there is no installation key to sign with.
  notEnrolled,
  invalidRequest,
  notInitialized,
  storageUnavailable,

  /// This platform has no offline chain in the plugin (Android and iOS have one; any other platform answers this).
  unsupported,
  channelError,
}

class SentomaruOfflineException implements Exception {
  const SentomaruOfflineException(this.error);
  final SentomaruOfflineError error;

  @override
  String toString() => 'SentomaruOfflineException($error)';
}

/// The `201` of `POST .../offline-permits`. The text is kept as received: the native side parses it again on every call.
@immutable
class SentomaruOfflinePermit {
  const SentomaruOfflinePermit._(
    this.json, this.permitId, this.issuedAt, this.validUntil, this.maxItems, this.driftToleranceSeconds);

  /// The response body exactly as the consumer's backend returned it.
  final String json;
  final String permitId;
  final DateTime issuedAt;
  final DateTime validUntil;
  final int maxItems;
  final int driftToleranceSeconds;

  /// Parses the response body; anything else is [SentomaruOfflineError.permitInvalid].
  factory SentomaruOfflinePermit.parse(String json) {
    try {
      final map = jsonDecode(json);
      if (map is! Map) throw const FormatException('not an object');
      final id = map['permitId'];
      final issued = DateTime.tryParse('${map['issuedAt']}');
      final until = DateTime.tryParse('${map['validUntil']}');
      final max = map['maxItems'];
      final drift = map['driftToleranceSeconds'];
      if (id is! String || map['chainSeed'] is! String || issued == null || until == null || max is! int || drift is! int) {
        throw const FormatException('fields');
      }
      return SentomaruOfflinePermit._(json, id.toLowerCase(), issued, until, max, drift);
    } on FormatException {
      throw const SentomaruOfflineException(SentomaruOfflineError.permitInvalid);
    }
  }
}

/// One sealed operation, the item of the reconciliation body. Binary fields are base64url without padding.
@immutable
class SentomaruOfflineSeal {
  const SentomaruOfflineSeal(this.fields);

  /// `seq`, `bootCount`, `elapsedRealtimeNanos`, `wallClockMillis`, `operationDigest`, `prevHash`, `hash`, `signature`.
  final Map<String, Object> fields;

  int get seq => fields['seq'] as int;
  int get bootCount => fields['bootCount'] as int;
}

/// D-26 (iOS today): the offline proof chain of `contracts/sdk/offline-proof-chain-v1.md`. The same calls as the Android
/// `SentomaruOfflineChain` (`sealOfflineOperation`, `reconcileBody`); the permit request and the reconciliation request are
/// signed with [SentomaruClient.sign] (operations [permitOperation] and [reconcileOperation]) and forwarded by the consumer's
/// backend, which gets the verdict, never the app.
///
/// The chain proves order and the absence of removal made by the intact SDK. It does not prove the content is true, it does not
/// protect the tail (seals never sent) and it does not confirm the real time of an item. Sealing needs the installation key and
/// no grant, and makes no network call.
///
/// Clocks. Android: `SystemClock.elapsedRealtimeNanos` and `Settings.Global.BOOT_COUNT`. iOS has no public BOOT_COUNT: the
/// native SDK reads `CLOCK_MONOTONIC` (counts sleep, restarts at boot, NTP-slewed) and turns the `kern.bootsessionuuid` sysctl
/// (a new UUID on every boot) into a counter it keeps itself, which counts only the boots the SDK saw. Without the sysctl every
/// seal carries `bootCount` 4294967295 (unavailable) and, since contract v1.19 (D-26), the server refuses the chain (offline_chain_broken). Not measured on a device yet.
class SentomaruOfflineChain {
  const SentomaruOfflineChain();

  static const permitOperation = 'offline_permit';
  static const reconcileOperation = 'offline_reconcile';

  static const _codes = <String, SentomaruOfflineError>{
    'Offline:PERMIT_INVALID': SentomaruOfflineError.permitInvalid,
    'Offline:PERMIT_EXPIRED': SentomaruOfflineError.permitExpired,
    'Offline:CHAIN_FULL': SentomaruOfflineError.chainFull,
    'Offline:INVALID_DIGEST': SentomaruOfflineError.invalidDigest,
    'Offline:CLOCK_UNAVAILABLE': SentomaruOfflineError.clockUnavailable,
    'NotEnrolled': SentomaruOfflineError.notEnrolled,
    'EnrollmentRequired': SentomaruOfflineError.notEnrolled,
    'NotInitialized': SentomaruOfflineError.notInitialized,
    'StorageUnavailable': SentomaruOfflineError.storageUnavailable,
  };

  static bool get _supported => !kIsWeb && defaultTargetPlatform == TargetPlatform.iOS;

  Future<T> _call<T>(String method, Map<String, Object?> arguments) async {
    if (!_supported) throw const SentomaruOfflineException(SentomaruOfflineError.unsupported);
    try {
      final result = await SentomaruFlutterPlatform.instance.invokeOffline<T>(method, arguments);
      if (result == null) throw const SentomaruOfflineException(SentomaruOfflineError.channelError);
      return result;
    } on PlatformException catch (e) {
      final known = _codes[e.code];
      if (known != null) throw SentomaruOfflineException(known);
      if (e.code.startsWith('InvalidRequest')) throw const SentomaruOfflineException(SentomaruOfflineError.invalidRequest);
      throw const SentomaruOfflineException(SentomaruOfflineError.channelError);
    }
  }

  /// Seals one operation of an offline window. [operationDigest] is the SHA-256 of the operation's payload, which never leaves
  /// the app (32 bytes, else [SentomaruOfflineError.invalidDigest]). Calls are serialized natively, so concurrent seals get
  /// consecutive `seq`.
  Future<SentomaruOfflineSeal> sealOperation({required SentomaruOfflinePermit permit, required Uint8List operationDigest}) async {
    final raw = await _call<Map>('offlineSeal', {'permit': permit.json, 'operationDigest': operationDigest});
    try {
      return SentomaruOfflineSeal({for (final e in raw.entries) e.key as String: e.value as Object});
    } on TypeError {
      throw const SentomaruOfflineException(SentomaruOfflineError.channelError);
    }
  }

  /// The strict JSON body of the reconciliation, the seals in the order given. Sign it with operation [reconcileOperation]
  /// after the grant was renewed (the batch never renews the grant). Empty, or more seals than the permit allows, is
  /// [SentomaruOfflineError.invalidRequest]; order and gaps are the server's to check.
  Future<Uint8List> reconcileBody({required SentomaruOfflinePermit permit, required List<SentomaruOfflineSeal> seals}) =>
      _call<Uint8List>('offlineReconcileBody', {'permit': permit.json, 'seals': [for (final s in seals) s.fields]});
}

/// D-26: the verdict of `offline_reconcile` (contract v1.18) as a Dart consumer backend or a test tool reads it. The app itself
/// never gets this answer (the consumer's backend forwards the request); the reader exists so that every SDK applies the same
/// rules as the Android `OfflineReconcileOutcome.Verdict`: [signals] only ever holds the three contract codes and an answer that
/// disagrees with itself (accepted with signals, rejected without) is not a verdict.
///
/// [advisories] (additive) is what the verdict could not check, today `offline_boot_unavailable` (since contract v1.19 such a batch is also refused with offline_chain_broken). It is not a signal and never
/// changes [accepted]. Unknown codes are kept (a newer server may add one), repeats are dropped, at most [maxAdvisories] are
/// read, and a missing or malformed list reads as empty: it is never a reason to refuse the verdict.
class SentomaruOfflineVerdict {
  const SentomaruOfflineVerdict({required this.permitId, required this.accepted, required this.itemCount, required this.signals, required this.advisories});

  final String permitId;
  final bool accepted;
  final int itemCount;
  final List<String> signals;
  final List<String> advisories;

  static const maxAdvisories = 8;
  static const _maxAnswerChars = 16 * 1024;
  static const _signals = {'offline_clock_tampered', 'offline_chain_broken', 'offline_chain_gap_detected'};
  static final _code = RegExp(r'^[a-z_]{1,64}$');
  static final _uuid = RegExp(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$');

  /// `null` when the text is not a well-formed verdict.
  static SentomaruOfflineVerdict? parse(String text) {
    if (text.length > _maxAnswerChars) return null;
    final Object? decoded;
    try {
      decoded = jsonDecode(text);
    } on FormatException {
      return null;
    }
    if (decoded is! Map) return null;
    final id = decoded['permitId'], status = decoded['status'], count = decoded['itemCount'], signals = decoded['signals'];
    if (id is! String || !_uuid.hasMatch(id) || status is! String || count is! int || count < 0 || count > 9999) return null;
    if (signals is! List || signals.any((s) => s is! String || !_signals.contains(s))) return null;
    if (status != 'accepted' && status != 'rejected') return null;
    if ((status == 'accepted') != signals.isEmpty) return null;
    return SentomaruOfflineVerdict(
      permitId: id, accepted: status == 'accepted', itemCount: count, signals: List.unmodifiable(signals.cast<String>()),
      advisories: _advisories(decoded['advisories']),
    );
  }

  static List<String> _advisories(Object? raw) {
    if (raw is! List || raw.any((c) => c is! String || !_code.hasMatch(c))) return const [];
    return List.unmodifiable(raw.cast<String>().toSet().take(maxAdvisories));
  }
}
