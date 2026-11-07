import 'dart:convert';
import 'dart:typed_data';

import 'package:dio/dio.dart';

import 'exceptions.dart';
import 'models.dart';
import 'pinning/pinning_install.dart';
import 'pinning/sentomaru_pins.dart';
import 'sentomaru_client.dart';
import 'sentomaru_routes.dart';
import 'server_response_sink.dart';

/// Dio HTTP Interceptor that freezes request body bytes, verifies target URI consistency,
/// signs RFC 9421 headers via [SentomaruClient], and enforces redirect security (Decisions E1, E2, E6).
///
/// **Coverage Declaration (Decision E6 / FLT-3):**
/// Only [Dio] instances configured with [SentomaruDioInterceptor] have RFC 9421 signature coverage.
/// Other [Dio] instances or raw HTTP clients (`HttpClient`, `package:http`) execute unsigned.
/// Multiple [Dio] instances sharing the same [SentomaruClient] are concurrently supported.
///
/// **Not initialized (R1, fail closed):** while [SentomaruClient.isInitialized] is false (app boot before
/// `initialize()` completes, a background isolate or WorkManager engine whose Dart client was never initialized,
/// or after a hot restart), a request that declares an operation is rejected with
/// [SentomaruErrorCode.notInitialized] and is never sent. Requests without an operation pass through with
/// Sentomaru headers stripped; they are not covered.
///
/// **Host outside the allowlist (M1):** a declared operation is refused with [SentomaruErrorCode.hostNotAllowed];
/// an undeclared request passes with Sentomaru headers stripped (not covered).
///
/// **Redirects (R2):** for allowlisted hosts automatic redirects are disabled (`followRedirects = false`,
/// `maxRedirects = 0`). Install with [SentomaruDioExtension.addSentomaru] (the constructor requires the owning
/// `dio`, so the old `interceptors.add(SentomaruDioInterceptor(client))` no longer compiles). The interceptor
/// follows a redirect itself only to another allowlisted https host, at most [maxRedirects] hops: 301/302/303 become
/// an unsigned GET without body, 307/308 are re-signed for the new target, and Authorization/Cookie are dropped when
/// the host changes. Follow-up hops are sent through a private Dio that shares only the HTTP adapter and this
/// interceptor, so other interceptors of the app (auth, logging, retry) do not run again and cannot re-add
/// credentials on a cross-host hop. A redirect outside the allowlist is never followed (the 3xx goes back to the
/// caller) and an https→http downgrade is refused with [SentomaruErrorCode.hostNotAllowed].
///
/// **Non-interactive / No Biometrics (Decision E4 / FLT-8):**
/// The interceptor executes purely cryptographic operations without UI dependencies or biometric prompts.
class SentomaruDioInterceptor extends Interceptor {
  /// Maximum payload size allowed for RFC 9421 signing (64 KiB).
  static const int maxBodyBytes = 65536;

  /// RFC 9421 Profile exact Content-Type.
  static const String profileContentType = 'application/json';

  /// Maximum redirects the interceptor follows for one logical request.
  static const int maxRedirects = 5;

  static const List<String> callerHeaders = [
    'x-sentomaru-profile',
    'x-sentomaru-org',
    'x-sentomaru-app',
    'x-sentomaru-environment',
    'x-sentomaru-operation',
    'x-sentomaru-session',
  ];

  static const String _hopKey = 'sentomaru_redirect_hop';
  /// J-04r: set on the one resend after a `session-expired` renewal (never a second one).
  static const String _renewedKey = 'sentomaru_renewed';
  /// D-15c: set by [onRequest] only after it signed this request (cleared first on every pass, so neither the app nor
  /// a copied hop can bring it in).
  static const String _signedKey = 'sentomaru_signed';
  static final RegExp _sessionExpiredCode = RegExp(r'"code"\s*:\s*"session-expired"');
  static const List<String> _operationExtraKeys = ['sentomaru_operation', 'operation'];
  static const List<String> _signalsExtraKeys = ['sentomaru_signals', 'signals'];

  static const List<String> signatureHeaders = [
    'Signature',
    'Signature-Input',
    'Content-Digest',
  ];

  final SentomaruClient client;
  final void Function(SentomaruRiskEvent event)? onRiskEvent;

  /// G-03c: the profile's route table; a request with nothing declared takes its operation from it (first hop only).
  final SentomaruRoutes? routes;

  /// The [Dio] this interceptor is attached to; its adapter and transformer carry the redirect follow-ups.
  final Dio _dio;
  Dio? _followDio;

  SentomaruDioInterceptor(this.client, {required Dio dio, this.onRiskEvent, this.routes}) : _dio = dio;

  Dio get _followUps => _followDio ??= Dio()
    ..httpClientAdapter = _dio.httpClientAdapter
    ..transformer = _dio.transformer
    ..interceptors.add(this);

  @override
  void onRequest(
    RequestOptions options,
    RequestInterceptorHandler handler,
  ) async {
    try {
      options.extra.remove(_signedKey);
      final uri = options.uri;
      final host = uri.host;

      final operation = _extractOperation(options);

      // R1: never send a declared operation unsigned. Not initialized (boot, background isolate/WorkManager engine,
      // hot restart) => typed refusal. Undeclared requests pass with Sentomaru headers stripped (not covered).
      if (!client.isInitialized) {
        if (operation != null) {
          return handler.reject(_dioError(
            options,
            const SentomaruException(
              SentomaruErrorCode.notInitialized,
              'SentomaruClient is not initialized in this isolate; the declared operation was not sent.',
            ),
          ));
        }
        _stripSentomaruHeaders(options.headers);
        return handler.next(options);
      }

      // Decision E6 / SDK-NET-1: host outside the allowlist is not protected. A declared operation is refused
      // (M1, same outcome as an uninitialized client); an undeclared request passes with Sentomaru headers stripped.
      if (!client.config.allowedHosts.contains(host)) {
        if (operation != null) {
          return handler.reject(_dioError(
            options,
            const SentomaruException(
              SentomaruErrorCode.hostNotAllowed,
              'Declared operation to a host outside the allowlist was not sent.',
            ),
          ));
        }
        _stripSentomaruHeaders(options.headers);
        return handler.next(options);
      }

      // Decision E6 / SDK-NET-3: Allowed host strictly requires HTTPS.
      if (uri.scheme != 'https') {
        return handler.reject(_dioError(
          options,
          SentomaruException(
            SentomaruErrorCode.hostNotAllowed,
            'HTTPS is required for allowed host: $host (found ${uri.scheme})',
          ),
        ));
      }

      // R2: the HTTP adapter must never follow redirects for a governed host; [_followRedirect] does it.
      options.followRedirects = false;
      options.maxRedirects = 0;

      // Task 1 review M7 / SDK-SIGN-7: Validate canonical URI representation.
      final urlString = uri.toString();
      final reparsed = Uri.tryParse(urlString)?.toString();
      if (reparsed != urlString) {
        return handler.reject(
          DioException(
            requestOptions: options,
            error: SentomaruException(
              SentomaruErrorCode.invalidRequest,
              'Target URI is not canonical: $urlString',
            ),
            type: DioExceptionType.unknown,
          ),
        );
      }

      // If no operation is declared, allowed host request proceeds unsigned.
      if (operation == null) {
        return handler.next(options);
      }

      // Task 1 review M7 / SIGN-6: Enforce Content-Type exactness before signing.
      final contentTypeHeader = _findHeaderCaseInsensitive(options.headers, 'content-type');
      if (contentTypeHeader != null) {
        final ct = contentTypeHeader.toString().trim().toLowerCase();
        if (ct != profileContentType && ct != '$profileContentType; charset=utf-8') {
          return handler.reject(
            DioException(
              requestOptions: options,
              error: SentomaruException(
                SentomaruErrorCode.invalidRequest,
                'Invalid Content-Type for signed request: $contentTypeHeader (must be $profileContentType)',
              ),
              type: DioExceptionType.unknown,
            ),
          );
        }
      }

      // Decision E2 / SDK-SIGN-2 / SDK-SIGN-8: Freeze request body bytes.
      final frozenBody = _freezeBody(options.data);
      if (frozenBody.length > maxBodyBytes) {
        return handler.reject(
          DioException(
            requestOptions: options,
            error: SentomaruException(
              SentomaruErrorCode.bodyTooLarge,
              'Request body (${frozenBody.length} bytes) exceeds maximum of $maxBodyBytes bytes',
            ),
            type: DioExceptionType.unknown,
          ),
        );
      }

      // J-01f2: optional covered headers are SIGNED, never attached after the signature: the signals snapshot (H3,
      // from the header or `extra`) and the caller's business operation id (J-01f, the same on every retry).
      final optional = <String, String>{};
      final rawSignals = options.headers['x-sentomaru-signals'] ??
          options.extra['sentomaru_signals'] ??
          options.extra['signals'];
      if (rawSignals != null) {
        optional['x-sentomaru-signals'] =
            encodeSignalsHeader(rawSignals is String ? rawSignals : jsonEncode(rawSignals));
      }
      final operationId = _findHeaderCaseInsensitive(options.headers, operationIdHeader) ?? options.extra['sentomaru_operation_id'];
      if (operationId != null) {
        optional[operationIdHeader] = operationId.toString();
      }

      // D-25: the transaction signature, made by the app after the person authenticated (Android SDK
      // `SentomaruTransactionSigner`); signed with the request. The native core validates the grammar. On iOS it comes from
      // `SentomaruTransactionSigner` (advisory evidence for the server, never proof of presence).
      final txSignature = _findHeaderCaseInsensitive(options.headers, txSignatureHeader) ?? options.extra['sentomaru_tx_signature'];
      if (txSignature != null) {
        optional[txSignatureHeader] = txSignature.toString();
      }

      // Sign the request via native SDK (Decision E1).
      final signed = await client.sign(
        method: options.method.toUpperCase(),
        targetUri: urlString,
        operation: operation,
        bodyBytes: frozenBody,
        optionalHeaders: optional,
      );

      // Attach signed headers (the native core returns the optional ones it signed).
      signed.headers.forEach((name, value) {
        options.headers[name] = value;
      });

      // Ensure Content-Type is strictly exact application/json.
      options.headers['content-type'] = profileContentType;
      options.extra[_signedKey] = true;

      // Replace data with frozen bytes so Dio sends exact signed bytes over the wire.
      if (options.data != null || ['POST', 'PUT', 'PATCH'].contains(options.method.toUpperCase())) {
        options.data = frozenBody;
      }

      handler.next(options);
    } on SentomaruException catch (e) {
      handler.reject(
        DioException(
          requestOptions: options,
          error: e,
          type: DioExceptionType.unknown,
        ),
      );
    } catch (e) {
      handler.reject(
        DioException(
          requestOptions: options,
          error: SentomaruException(
            SentomaruErrorCode.channelError,
            'Signing interception failed: $e',
          ),
          type: DioExceptionType.unknown,
        ),
      );
    }
  }

  @override
  void onResponse(Response response, ResponseInterceptorHandler handler) async {
    try {
      final followed = await _followRedirect(response);
      if (followed != null) return handler.resolve(followed);
      final renewed = await _renewAndResend(response);
      if (renewed != null) return handler.resolve(renewed);
    } on DioException catch (e) {
      return handler.reject(e);
    } on SentomaruException catch (e) {
      return handler.reject(_dioError(response.requestOptions, e));
    }
    _reportServerResponse(response);
    handler.next(response);
  }

  @override
  void onError(DioException err, ErrorInterceptorHandler handler) async {
    final response = err.response;
    if (err.type == DioExceptionType.badResponse && response != null) {
      try {
        final followed = await _followRedirect(response);
        if (followed != null) return handler.resolve(followed);
        final renewed = await _renewAndResend(response);
        if (renewed != null) return handler.resolve(renewed);
      } on DioException catch (e) {
        return handler.reject(e);
      } on SentomaruException catch (e) {
        return handler.reject(_dioError(err.requestOptions, e));
      }
      _reportServerResponse(response);
    }
    try {
      final responseData = response?.data;
      if (responseData is Map && responseData.containsKey('riskEvent')) {
        final riskMap = responseData['riskEvent'];
        if (riskMap is Map) {
          onRiskEvent?.call(SentomaruRiskEvent.fromMap(Map<String, dynamic>.from(riskMap)));
        }
      }
    } catch (_) {
      // Ignora erro no parsing do evento de risco para preservar o fluxo do handler
    }
    handler.next(err);
  }

  /// D-15c: the final answer to a request this interceptor SIGNED (marked by [onRequest]) feeds
  /// the client's receiver (`server_response_sink.dart`) (a 401/403 with a closed code becomes a `server_response` event). Not for
  /// an unsigned request, nor for a 3xx this interceptor followed or a `session-expired` it renewed: the hop or resend
  /// that answered is reported by its own pass here, once. [onRiskEvent] is unchanged and separate.
  void _reportServerResponse(Response response) {
    final status = response.statusCode;
    if (status != 401 && status != 403) return;
    if (response.requestOptions.extra[_signedKey] != true) return;
    serverResponseSinks[client]?.call(status, response.data);
  }

  /// J-04r: a signed request refused with `session-expired` (the consumer did nothing: the evaluation rolled back) is
  /// renewed once and resent once with a fresh signature. Null = not that case, or renewal unavailable/failed (the
  /// original refusal goes back to the caller). Never loops: the resend carries [_renewedKey].
  Future<Response?> _renewAndResend(Response response) async {
    final request = response.requestOptions;
    if (response.statusCode != 403 || request.extra[_renewedKey] == true) return null;
    if (!client.isInitialized || client.config.renewalUrl == null) return null;
    if (_findHeaderCaseInsensitive(request.headers, 'x-sentomaru-operation') == null) return null;
    final data = response.data;
    final expired = response.headers.value('sentomaru-error') == 'session-expired' ||
        (data is Map && data['code'] == 'session-expired') ||
        (data is String && _sessionExpiredCode.hasMatch(data)) ||
        (data is List<int> && _sessionExpiredCode.hasMatch(utf8.decode(data, allowMalformed: true)));
    if (!expired) return null;
    try {
      await client.renewSession();
    } on SentomaruException {
      return null;
    }
    final headers = Map<String, dynamic>.from(request.headers);
    _removeHeaders(headers, [...signatureHeaders, 'x-sentomaru-session']);
    return _followUps.fetch<dynamic>(request.copyWith(
      headers: headers,
      extra: Map<String, dynamic>.from(request.extra)..[_renewedKey] = true,
    ));
  }

  /// Follows one redirect hop under the R2 rules, or returns null to hand the response back unfollowed.
  Future<Response?> _followRedirect(Response response) async {
    final request = response.requestOptions;
    final code = response.statusCode ?? 0;
    if (!const {301, 302, 303, 307, 308}.contains(code)) return null;
    if (!client.isInitialized) return null;
    final allowed = client.config.allowedHosts;
    if (!allowed.contains(request.uri.host)) return null;
    final location = response.headers.value('location');
    if (location == null || location.isEmpty) return null;

    final next = request.uri.resolve(location);
    // Off-allowlist: never followed, so nothing (method, body, signature, credentials) reaches it.
    if (!allowed.contains(next.host)) return null;
    // Allowed host over http: refused before sending.
    if (next.scheme != 'https') {
      throw const SentomaruException(
        SentomaruErrorCode.hostNotAllowed,
        'Redirect to a non-https URL of an allowed host was refused.',
      );
    }
    final hop = ((request.extra[_hopKey] as int?) ?? 0) + 1;
    if (hop > maxRedirects) return null;

    final headers = Map<String, dynamic>.from(request.headers);
    final extra = Map<String, dynamic>.from(request.extra)..[_hopKey] = hop;
    _removeHeaders(headers, [...signatureHeaders, 'x-sentomaru-session', 'x-sentomaru-profile',
      'x-sentomaru-org', 'x-sentomaru-app', 'x-sentomaru-environment']);
    if (next.host != request.uri.host) {
      _removeHeaders(headers, const ['authorization', 'cookie']);
    }

    var method = request.method.toUpperCase();
    dynamic data = request.data;
    if (code == 301 || code == 302 || code == 303) {
      // Becomes GET (HEAD stays HEAD) without body; no longer the signed operation.
      method = method == 'HEAD' ? 'HEAD' : 'GET';
      data = null;
      _removeHeaders(headers, [...callerHeaders, 'x-sentomaru-signals', operationIdHeader, txSignatureHeader, 'content-type', 'content-length']);
      for (final key in [..._operationExtraKeys, ..._signalsExtraKeys, 'sentomaru_operation_id', 'sentomaru_tx_signature']) {
        extra.remove(key);
      }
    }
    // 307/308: same method and frozen bytes; the operation marker stays, so onRequest re-signs for `next`.

    final nextOptions = RequestOptions(
      path: next.toString(),
      method: method,
      data: data,
      headers: headers,
      extra: extra,
      responseType: request.responseType,
      validateStatus: request.validateStatus,
      receiveDataWhenStatusError: request.receiveDataWhenStatusError,
      connectTimeout: request.connectTimeout,
      sendTimeout: request.sendTimeout,
      receiveTimeout: request.receiveTimeout,
      cancelToken: request.cancelToken,
    );
    return _followUps.fetch<dynamic>(nextOptions);
  }

  DioException _dioError(RequestOptions options, SentomaruException error) =>
      DioException(requestOptions: options, error: error, type: DioExceptionType.unknown);

  static void _removeHeaders(Map<String, dynamic> headers, List<String> names) {
    final lower = names.map((n) => n.toLowerCase()).toSet();
    headers.removeWhere((key, _) => lower.contains(key.toLowerCase()));
  }

  String? _extractOperation(RequestOptions options) {
    final fromHeader = _findHeaderCaseInsensitive(options.headers, 'x-sentomaru-operation');
    if (fromHeader != null && fromHeader.toString().isNotEmpty) {
      return fromHeader.toString();
    }
    final fromExtra = options.extra['sentomaru_operation'] ?? options.extra['operation'];
    if (fromExtra != null && fromExtra.toString().isNotEmpty) {
      return fromExtra.toString();
    }
    // G-03c: only the caller's request, never a redirect hop (a 301/302/303 hop is an unsigned GET by design; a
    // 307/308 hop keeps its signed operation header).
    if (options.extra[_hopKey] == null) return routes?.operationFor(options.uri);
    return null;
  }

  Uint8List _freezeBody(dynamic data) {
    if (data == null) {
      return Uint8List(0);
    }
    if (data is Uint8List) {
      return data;
    }
    if (data is List<int>) {
      return Uint8List.fromList(data);
    }
    if (data is String) {
      return Uint8List.fromList(utf8.encode(data));
    }
    if (data is Map || data is List) {
      return Uint8List.fromList(utf8.encode(jsonEncode(data)));
    }
    throw SentomaruException(
      SentomaruErrorCode.invalidRequest,
      'Unsupported body type for freezeBody: ${data.runtimeType}',
    );
  }

  void _stripSentomaruHeaders(Map<String, dynamic> headers) {
    _removeHeaders(headers, [...callerHeaders, ...signatureHeaders, 'x-sentomaru-signals', operationIdHeader, txSignatureHeader]);
  }

  dynamic _findHeaderCaseInsensitive(Map<String, dynamic> headers, String target) {
    final lower = target.toLowerCase();
    for (final entry in headers.entries) {
      if (entry.key.toLowerCase() == lower) {
        return entry.value;
      }
    }
    return null;
  }
}

/// J-01f: header of the caller's business operation id (16-64 `[A-Za-z0-9-]`, validated by the native core).
const operationIdHeader = 'x-sentomaru-operation-id';

/// D-25: header of the transaction signature (`sentomaru-tx-v2.<nonce>.<issuedAt>.<signature>`; v1 `sentomaru-tx-v1.<nonce>.<signature>` is still accepted by the server), proof of human presence at
/// signing time, never that the person saw the value. Grammar validated by the native core.
const txSignatureHeader = 'x-sentomaru-tx-signature';

/// Largest `x-sentomaru-signals` value the server accepts (it rejects the whole forwarded message above it).
const int maxSignalsHeaderLength = 4096;

/// Encodes the signals JSON as a single printable-ASCII header value (final review Minor 3): characters above 0x7E
/// are escaped as JSON `\uXXXX`; control characters or a value longer than [maxSignalsHeaderLength] raise a typed
/// [SentomaruException] (`invalidRequest`, details `HEADER_VALUE`) instead of an opaque server 400.
String encodeSignalsHeader(String json) {
  final out = StringBuffer();
  for (final unit in json.codeUnits) {
    if (unit >= 0x20 && unit <= 0x7E) {
      out.writeCharCode(unit);
    } else if (unit >= 0x80) {
      out.write('\\u${unit.toRadixString(16).padLeft(4, '0')}');
    } else {
      throw const SentomaruException(
          SentomaruErrorCode.invalidRequest, 'x-sentomaru-signals has a control character', 'HEADER_VALUE');
    }
  }
  if (out.length > maxSignalsHeaderLength) {
    throw const SentomaruException(
        SentomaruErrorCode.invalidRequest, 'x-sentomaru-signals is longer than 4096 characters', 'HEADER_VALUE');
  }
  return out.toString();
}

/// Attaches Sentomaru to a [Dio] instance with redirect handling wired (mirrors Android `addSentomaru`).
extension SentomaruDioExtension on Dio {
  /// G-03c, the one line that turns on network signing: pass [routes] (the profile's `network-signing` section) and a
  /// request with no declared operation whose host and path match is signed as that route's operation.
  ///
  /// C-03a (0.16.0): [pins] (the `network-pinning` section) installs [SentomaruPinningDioExtension.addSentomaruPinning]
  /// first, so the redirect follow-ups of the interceptor share the pinned adapter. Android only; elsewhere [pins] is
  /// ignored (call `addSentomaruPinning` to get the [SentomaruPinningInstall] outcome).
  SentomaruDioInterceptor addSentomaru(
    SentomaruClient client, {
    void Function(SentomaruRiskEvent event)? onRiskEvent,
    SentomaruRoutes? routes,
    SentomaruPins? pins,
  }) {
    // A route host the client does not allow could only ever fail closed: refuse the installation instead.
    if (routes != null && client.isInitialized && !client.config.allowedHosts.containsAll(routes.hosts)) {
      throw ArgumentError('network-signing.hosts not within allowedHosts');
    }
    if (pins != null) addSentomaruPinning(pins);
    final interceptor = SentomaruDioInterceptor(client, dio: this, onRiskEvent: onRiskEvent, routes: routes);
    interceptors.add(interceptor);
    return interceptor;
  }
}
