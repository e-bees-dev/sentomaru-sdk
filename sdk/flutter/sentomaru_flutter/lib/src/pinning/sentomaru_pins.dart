import 'dart:async';
import 'dart:convert';

import 'package:flutter/foundation.dart';

/// C-03a: why a connection to a pinned host failed (the vocabulary of the Android `SentomaruTransportEvent`, D-07d).
enum SentomaruTransportEventReason {
  /// The TLS handshake completed, but the SHA-256 of the leaf's `SubjectPublicKeyInfo` is in neither `pins` nor
  /// `backupPins` (decided by the plugin; the connection is closed before any byte of the request is written).
  pinMismatch('pin_mismatch'),

  /// The TLS stack refused the certificate before the pin was looked at (unknown CA, expired, wrong name).
  tlsUntrusted('tls_untrusted'),

  /// Any other TLS failure of the handshake.
  tlsOther('tls_other');

  final String wireName;
  const SentomaruTransportEventReason(this.wireName);
}

/// C-03a (0.16.0): an INFORMATIVE, local event of a failed connection to a pinned host, never a verdict; nothing is
/// stored or sent to any server (D-07x9). Closed vocabulary and no PII: [host] is the `host` of the profile section
/// that matched (never the subdomain actually requested), and there is no IP, port, URL, path, header, certificate,
/// presented key, time, installation or device id. A process the attacker controls can suppress or invent it.
/// [sequence] is the order of the events of one [SentomaruPins] (its own counter, separate from the signal stream).
class SentomaruTransportEvent {
  /// Always `transport` (the Android `kind = TRANSPORT`).
  static const String kind = 'transport';

  /// Always `pin_failure`.
  static const String type = 'pin_failure';

  final SentomaruTransportEventReason reason;
  final String host;
  final int sequence;

  const SentomaruTransportEvent._(this.reason, this.host, this.sequence);

  @override
  String toString() => 'SentomaruTransportEvent($type #$sequence ${reason.wireName} $host)';
}

/// One `domains[]` entry of the `network-pinning` v1 section (contracts/devsecops/cli-v1.md, `network-pinning`).
class SentomaruPinnedDomain {
  /// Exact lowercase DNS name (no wildcard, port, trailing dot or IP).
  final String host;
  final bool includeSubdomains;

  /// Keys accepted today (`sha256/<base64>`): the served one and, during a rotation, the next one.
  final List<String> pins;

  /// Keys accepted and not yet served by any certificate.
  final List<String> backupPins;

  final Set<String> _accepted;

  SentomaruPinnedDomain._(this.host, this.includeSubdomains, List<String> pins, List<String> backupPins)
      : pins = List.unmodifiable(pins),
        backupPins = List.unmodifiable(backupPins),
        _accepted = {...pins, ...backupPins};

  /// True when [pin] (`sha256/<base64>`) is in [pins] or [backupPins].
  bool accepts(String pin) => _accepted.contains(pin);
}

/// C-03a (0.16.0): the pins of the `network-pinning` v1 section of the `protect` profile, for the Dart side of a
/// Flutter app (`dio.addSentomaruPinning(pins)`), which does not read the Android `network_security_config`.
///
/// Built from the same section the CLI embeds on the native side ([SentomaruPins.fromProfileSection]) and validated with
/// the same structural rules (closed section and domains, `version` `1`, calendar date, 1 to 16 domains without a
/// repeated host, host pattern, explicit `includeSubdomains`, canonical `sha256/` pins, backup required, no pin in both
/// lists, at most 16 pins per domain). What the plugin does NOT check, unlike the CLI: an [expiration] already past or
/// more than 180 days ahead, because at run time the device clock is not the clock of the build. A past expiration is
/// the field case "app never updated": the pin-set is simply inactive (fail open by design).
///
/// [expiration] follows Android (`XmlConfigSource`/`NetworkSecurityTrustManager`, read in AOSP on 26/10/2026): the date
/// is midnight in the device's time zone, and pins are checked while `now <= expiration`; from the first millisecond
/// after 00:00 local of that day the pin-set is off and pinned hosts go back to the system trust. In a time zone whose
/// daylight-saving jump skips midnight, `DateTime` and `SimpleDateFormat` may place that instant up to one hour apart.
class SentomaruPins {
  final String expiration;
  final List<SentomaruPinnedDomain> domains;
  final DateTime _expiresAt;
  final DateTime Function() _clock;
  final StreamController<SentomaruTransportEvent> _events = StreamController.broadcast();
  int _sequence = 0;

  SentomaruPins._(this.expiration, this._expiresAt, List<SentomaruPinnedDomain> domains, this._clock)
      : domains = List.unmodifiable(domains);

  /// The `network-pinning` section of the `protect` profile as decoded JSON (`profile['controls']['network-pinning']`).
  /// Throws [FormatException] whose message is the field path of the CLI `detail` (`network-pinning.domains.pins`, ...)
  /// and never a value of the profile. [clock] exists for tests of the expiration.
  factory SentomaruPins.fromProfileSection(Object? section, {@visibleForTesting DateTime Function()? clock}) {
    final s = _closedMap(section, const {'version', 'expiration', 'domains'}, 'network-pinning');
    final version = s['version'];
    if (version is! String || version != '1') throw const FormatException('network-pinning.version');
    final expiration = s['expiration'];
    final expiresAt = expiration is String ? _parseDate(expiration) : null;
    if (expiresAt == null) throw const FormatException('network-pinning.expiration');
    final rawDomains = s['domains'];
    if (rawDomains is! List || rawDomains.isEmpty || rawDomains.length > 16) {
      throw const FormatException('network-pinning.domains');
    }
    final domains = <SentomaruPinnedDomain>[];
    for (final raw in rawDomains) {
      final d = _closedMap(raw, const {'host', 'includeSubdomains', 'pins', 'backupPins'}, 'network-pinning.domains');
      final host = d['host'];
      if (host is! String || host.length > 253 || !_host.hasMatch(host)) {
        throw const FormatException('network-pinning.domains.host');
      }
      final include = d['includeSubdomains'];
      if (include is! bool) throw const FormatException('network-pinning.domains.includeSubdomains');
      final pins = _pinList(d['pins'], 'network-pinning.domains.pins');
      final backups = _pinList(d['backupPins'], 'network-pinning.domains.backupPins');
      // Same order as the CLI (NetworkPinning.kt): the total before the overlap, the repeated host after all domains.
      if (pins.length + backups.length > 16) throw const FormatException('network-pinning.domains.pins');
      if (backups.any(pins.contains)) throw const FormatException('network-pinning.domains.backupPins');
      domains.add(SentomaruPinnedDomain._(host, include, pins, backups));
    }
    if (domains.map((d) => d.host).toSet().length != domains.length) {
      throw const FormatException('network-pinning.domains');
    }
    return SentomaruPins._(expiration as String, expiresAt, domains, clock ?? DateTime.now);
  }

  /// Local, informative events of failed connections to pinned hosts (broadcast; nothing is kept while nobody listens).
  Stream<SentomaruTransportEvent> get events => _events.stream;

  /// True while the pin-set is checked (`now <= expiration`, midnight in the device's time zone).
  bool get isActive => !_clock().isAfter(_expiresAt);

  /// The domain entry governing [host] (exact entry first, else the longest `includeSubdomains` parent), or null for a
  /// host the section does not name. One trailing dot is ignored, so `host.` cannot step around its entry.
  SentomaruPinnedDomain? domainFor(String host) {
    var h = host.toLowerCase();
    if (h.endsWith('.')) h = h.substring(0, h.length - 1);
    SentomaruPinnedDomain? best;
    for (final d in domains) {
      if (d.host == h) return d;
      if (d.includeSubdomains && h.endsWith('.${d.host}') && (best == null || d.host.length > best.host.length)) {
        best = d;
      }
    }
    return best;
  }

  static final _host = RegExp(r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$');
  static final _pin = RegExp(r'^sha256/[A-Za-z0-9+/]{43}=$');
  static final _date = RegExp(r'^[0-9]{4}-[0-9]{2}-[0-9]{2}$');

  static Map _closedMap(Object? raw, Set<String> fields, String path) {
    if (raw is! Map) throw FormatException(path);
    // As the CLI: the first unknown field in sorted order, by name only when it is a short field name.
    final unknown = [for (final k in raw.keys) if (k is! String || !fields.contains(k)) k is String ? k : ''];
    if (unknown.isNotEmpty) {
      unknown.sort();
      throw FormatException('$path.${_field.hasMatch(unknown.first) ? unknown.first : 'unknown-field'}');
    }
    for (final f in fields) {
      if (!raw.containsKey(f)) throw FormatException('$path.$f');
    }
    return raw;
  }

  static final _field = RegExp(r'^[A-Za-z0-9_-]{1,64}$');

  static List<String> _pinList(Object? raw, String path) {
    if (raw is! List || raw.isEmpty) throw FormatException(path);
    final out = <String>[];
    for (final p in raw) {
      if (p is! String || !_pin.hasMatch(p) || out.contains(p) || !_canonical(p)) throw FormatException(path);
      out.add(p);
    }
    return out;
  }

  /// Strict base64: 32 bytes whose re-encoding is the same text (the last character leaves the 2 spare bits zero).
  static bool _canonical(String pin) {
    final b64 = pin.substring('sha256/'.length);
    try {
      final bytes = base64.decode(b64);
      return bytes.length == 32 && base64.encode(bytes) == b64;
    } on FormatException {
      return false;
    }
  }

  static DateTime? _parseDate(String text) {
    if (!_date.hasMatch(text)) return null;
    final y = int.parse(text.substring(0, 4));
    final m = int.parse(text.substring(5, 7));
    final d = int.parse(text.substring(8, 10));
    final date = DateTime(y, m, d);
    if (date.year != y || date.month != m || date.day != d) return null;
    return date;
  }
}

/// Emits one event on [pins] (internal: not exported by the library; the connection factory is the only caller, so no
/// public member can inject an event).
void reportTransportEvent(SentomaruPins pins, SentomaruTransportEventReason reason, SentomaruPinnedDomain domain) {
  if (pins._events.isClosed) return;
  pins._events.add(SentomaruTransportEvent._(reason, domain.host, ++pins._sequence));
}
