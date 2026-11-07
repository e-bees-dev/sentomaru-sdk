import 'dart:async';
import 'dart:io';

import '../exceptions.dart';
import 'sentomaru_pins.dart';
import 'spki.dart';

/// Opens a plain TCP connection (http, or to a proxy). Default: `Socket.startConnect`.
typedef SentomaruTcpConnector = Future<ConnectionTask<Socket>> Function(String host, int port);

/// Opens TCP and runs the TLS handshake (trust of [context], host name check, [onBadCertificate]). Default:
/// `SecureSocket.startConnect`, whose cancel also stops a handshake in progress, as the HttpClient's own connect.
typedef SentomaruTlsConnector = Future<ConnectionTask<SecureSocket>> Function(
    String host, int port, SecurityContext? context, bool Function(X509Certificate certificate)? onBadCertificate);

/// The `HttpClient.badCertificateCallback` signature, for hosts outside the pinning section only.
typedef SentomaruBadCertificateCallback = bool Function(X509Certificate certificate, String host, int port);

/// C-03a: the `HttpClient.connectionFactory` that checks a pinned host BEFORE the `HttpClient` writes anything.
///
/// For a host of the section while the pin-set is active it opens TCP, completes the TLS handshake itself, hashes the
/// leaf's `SubjectPublicKeyInfo` and hands the socket to the `HttpClient` only when the pin is in `pins` or
/// `backupPins`; otherwise it destroys the socket and fails with [SentomaruErrorCode.pinningRefused]. The request
/// line, headers, RFC 9421 signature and body are written by the `HttpClient` only after this future completes, so a
/// refused connection carries no byte of the request (the Dio `validateCertificate` runs after the request was sent and
/// is not used). A pinned host through a proxy (the `HttpClient` would run TLS itself over the tunnel, unchecked) or
/// over `http` is refused before any connection. Other hosts connect as the `HttpClient` does without a factory.
class PinnedConnectionFactory {
  final SentomaruPins pins;

  /// Trust for every direct https connection made here; null = the platform default (system anchors).
  final SecurityContext? context;

  /// Applied to hosts outside the section only; a pinned host never accepts a certificate the TLS stack refused.
  final SentomaruBadCertificateCallback? onBadCertificate;

  final SentomaruTcpConnector _connect;
  final SentomaruTlsConnector _connectTls;

  /// [connector] and [tlsConnector] are internal seams: tests map DNS names to loopback with them; the pin check and
  /// the moment the socket reaches the HttpClient stay the code below.
  PinnedConnectionFactory(this.pins,
      {this.context, this.onBadCertificate, SentomaruTcpConnector? connector, SentomaruTlsConnector? tlsConnector})
      : _connect = connector ?? Socket.startConnect,
        _connectTls = tlsConnector ?? _systemTls;

  static Future<ConnectionTask<SecureSocket>> _systemTls(
          String host, int port, SecurityContext? context, bool Function(X509Certificate)? onBadCertificate) =>
      SecureSocket.startConnect(host, port, context: context, onBadCertificate: onBadCertificate);

  Future<ConnectionTask<Socket>> call(Uri url, String? proxyHost, int? proxyPort) async {
    final https = url.isScheme('https');
    if (!https && !url.isScheme('http')) {
      // The HttpClient refuses other schemes only when it has no factory: keep that behavior.
      throw ArgumentError("Unsupported scheme '${url.scheme}'");
    }
    final domain = pins.domainFor(url.host);
    if (domain != null) {
      // Like the Android domain-config (cleartextTrafficPermitted="false"), http stays refused after the expiration.
      if (!https) throw _refused('cleartext', 'http to a pinned host was refused before connecting.');
      if (pins.isActive) {
        // The HttpClient tries the next entry of the app's `findProxy` list after this error: with `...; DIRECT` the
        // host is then reached directly, and that connection is checked below (never unchecked through the proxy).
        if (proxyHost != null) throw _refused('proxy', 'A pinned host through a proxy was refused before connecting.');
        return _secure(url, domain, pinned: true);
      }
    }
    // Unpinned (or expired) host: what the HttpClient does without a factory.
    if (proxyHost != null && proxyPort != null) return _connect(proxyHost, proxyPort);
    if (!https) return _connect(url.host, url.port);
    // An expired entry goes back to the trust of [context] only, as Android goes back to the system anchors: the
    // app's [onBadCertificate] never applies to a host of the section.
    return _secure(url, domain, pinned: false);
  }

  Future<ConnectionTask<Socket>> _secure(Uri url, SentomaruPinnedDomain? domain, {required bool pinned}) async {
    final host = url.host;
    final port = url.port;
    final callback = domain == null ? onBadCertificate : null;
    final event = pinned ? domain : null;
    final task = await _connectTls(
        host, port, context, callback == null ? null : (cert) => callback(cert, host, port));
    // Cancellation (the HttpClient's connectionTimeout, an aborted request) during the handshake is the task's own
    // cancel; a socket that still arrives after it is destroyed, never handed over.
    var cancelled = false;
    Future<Socket> checked() async {
      final SecureSocket secure;
      try {
        secure = await task.socket;
      } on HandshakeException catch (e) {
        if (event != null && !cancelled) reportTransportEvent(pins, _classify(e), event);
        rethrow;
      } on TlsException {
        if (event != null && !cancelled) reportTransportEvent(pins, SentomaruTransportEventReason.tlsOther, event);
        rethrow;
      }
      if (cancelled) {
        secure.destroy();
        throw const SocketException('Connection attempt cancelled');
      }
      if (event != null) {
        final cert = secure.peerCertificate;
        final pin = cert == null ? null : spkiPin(cert.der);
        if (pin == null || !event.accepts(pin)) {
          secure.destroy();
          reportTransportEvent(pins, SentomaruTransportEventReason.pinMismatch, event);
          throw _refused('pin_mismatch', 'The key of the pinned host is not in the pin-set; nothing was sent.');
        }
      }
      return secure;
    }

    return ConnectionTask.fromSocket<Socket>(checked(), () {
      cancelled = true;
      task.cancel();
    });
  }

  /// BoringSSL's verify error text (Dart 3.11). If a later Dart words it differently the event falls back to
  /// `tls_other`; the refusal itself does not depend on it (pinning_transport_test.dart pins the current text).
  static SentomaruTransportEventReason _classify(HandshakeException e) => e.toString().contains('CERTIFICATE_VERIFY_FAILED')
      ? SentomaruTransportEventReason.tlsUntrusted
      : SentomaruTransportEventReason.tlsOther;

  static SentomaruException _refused(String reason, String message) =>
      SentomaruException(SentomaruErrorCode.pinningRefused, message, reason);
}
