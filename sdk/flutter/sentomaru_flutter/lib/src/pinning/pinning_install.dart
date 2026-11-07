import 'dart:io';

import 'package:dio/dio.dart';
import 'package:dio/io.dart';

import '../sentomaru_dio_interceptor.dart';
import 'pinned_connection.dart';
import 'sentomaru_pins.dart';

/// C-03a: the outcome of `addSentomaruPinning`.
enum SentomaruPinningInstall {
  /// The connection factory is on this [Dio] (Android).
  installed,

  /// Not Android: the line does nothing (iOS pinning is not part of this plugin; G-03g is wave 4).
  unsupportedPlatform,
}

final Expando<SentomaruPins> _installed = Expando('sentomaru_pinning');

/// C-03a (0.16.0): the line that turns on pinning for the Dart side of a Flutter app.
extension SentomaruPinningDioExtension on Dio {
  /// Installs the pin check of [pins] on THIS [Dio] (Android only): a connection to a pinned host is checked after the
  /// TLS handshake and before the first byte of the request, and closed if the leaf key is not pinned. Other hosts
  /// connect as before.
  ///
  /// Call it before the first request and before [SentomaruDioExtension.addSentomaru] (or pass `pins:` to that one).
  /// The adapter must be the plain [IOHttpClientAdapter] (the default); any other adapter (`native_dio_adapter`,
  /// Cronet, a subclass) is an [ArgumentError]. The plugin puts a fresh [IOHttpClientAdapter] carrying the app's
  /// `createHttpClient` (or `onHttpClientCreate`) and `validateCertificate`, so proxy and other settings of the app's
  /// `HttpClient` stay; a fresh adapter because the old one may already hold an `HttpClient` built without the factory.
  ///
  /// The factory replaces the `HttpClient`'s own direct TLS connect, which reads `context` and
  /// `badCertificateCallback` the app may have set inside `createHttpClient` (the `HttpClient` does not expose them):
  /// pass them as [context] and [onBadCertificate]. [context] applies to every direct https connection;
  /// [onBadCertificate] only to hosts outside the section. A `connectionFactory` the app sets itself is replaced.
  SentomaruPinningInstall addSentomaruPinning(
    SentomaruPins pins, {
    SecurityContext? context,
    SentomaruBadCertificateCallback? onBadCertificate,
  }) =>
      installSentomaruPinning(this, pins,
          context: context, onBadCertificate: onBadCertificate, platformSupported: Platform.isAndroid);
}

/// Internal (not exported): [addSentomaruPinning] with the platform decided by the caller and the TCP seam of tests.
SentomaruPinningInstall installSentomaruPinning(
  Dio dio,
  SentomaruPins pins, {
  SecurityContext? context,
  SentomaruBadCertificateCallback? onBadCertificate,
  required bool platformSupported,
  SentomaruTcpConnector? connector,
  SentomaruTlsConnector? tlsConnector,
}) {
  if (!platformSupported) return SentomaruPinningInstall.unsupportedPlatform;
  final adapter = dio.httpClientAdapter;
  if (adapter.runtimeType != IOHttpClientAdapter || adapter is! IOHttpClientAdapter) {
    throw ArgumentError('network-pinning needs the default IOHttpClientAdapter on this Dio');
  }
  if (_installed[dio] != null) throw StateError('network-pinning is already installed on this Dio');
  if (dio.interceptors.any((i) => i is SentomaruDioInterceptor)) {
    throw StateError('install network-pinning before addSentomaru, or pass pins: to addSentomaru');
  }
  final appCreate = adapter.createHttpClient;
  // ignore: deprecated_member_use
  final appOnCreate = adapter.onHttpClientCreate;
  final factory = PinnedConnectionFactory(pins,
      context: context, onBadCertificate: onBadCertificate, connector: connector, tlsConnector: tlsConnector);
  dio.httpClientAdapter = IOHttpClientAdapter(
    createHttpClient: () {
      // The same client the old adapter would have built (dio 5 `_createHttpClient`), plus the factory.
      HttpClient client;
      if (appCreate != null) {
        client = appCreate();
      } else {
        client = HttpClient()..idleTimeout = const Duration(seconds: 3);
        client = appOnCreate?.call(client) ?? client;
      }
      return client..connectionFactory = factory.call;
    },
    validateCertificate: adapter.validateCertificate,
  );
  _installed[dio] = pins;
  return SentomaruPinningInstall.installed;
}
