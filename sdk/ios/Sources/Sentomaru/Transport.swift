import Foundation

/// Never follows a redirect: the 3xx goes back to the caller, so no signed body or credential goes anywhere else.
final class RefuseRedirects: NSObject, URLSessionTaskDelegate, Sendable {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping @Sendable (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}

enum ServerAnswer {
    /// The JSON `code` member of a refusal; "" when the body is absent, oversized or not a JSON object.
    static func code(_ body: Data?) -> String {
        guard let body, let object = try? JSONSerialization.jsonObject(with: body) as? [String: Any] else { return "" }
        return object["code"] as? String ?? ""
    }
}

/// Sends the signed enrollment and renewal built by the client (the Swift twin of the Flutter plugin's
/// `EnrollmentTransport`):
/// - only to an `https` host of the allowlist, checked again here before any byte is sent;
/// - redirects never followed (a 3xx is a rejection); one send, no retry; ephemeral session (no cookies, no cache);
/// - transport failure: `URLError` (the client maps it to `networkUnavailable`); an HTTP answer that is not a valid
///   grant: `serverRejected(<reason>)`. Server bodies are never echoed in errors.
public final class SentomaruTransport: Sendable {
    public static let maxResponseBytes = 16 * 1024
    static let sessionUnavailable = "session-unavailable"
    static let installationSuspended = "installation-suspended"
    static let predecessorInvalid = "predecessor-invalid"

    let allowedHosts: Set<String>
    let session: URLSession

    public init(allowedHosts: Set<String>, configuration: URLSessionConfiguration = .ephemeral) {
        self.allowedHosts = allowedHosts
        // A copy: the caller's configuration object is never changed.
        let configuration = (configuration.copy() as? URLSessionConfiguration) ?? .ephemeral
        configuration.timeoutIntervalForRequest = 15
        configuration.timeoutIntervalForResource = 30
        configuration.httpCookieStorage = nil
        configuration.urlCache = nil
        self.session = URLSession(configuration: configuration, delegate: RefuseRedirects(), delegateQueue: nil)
    }

    public convenience init(config: SentomaruConfig, configuration: URLSessionConfiguration = .ephemeral) {
        self.init(allowedHosts: config.allowedHosts, configuration: configuration)
    }

    /// Enrollment and rotation (`SentomaruClient.enroll`/`rotate` `send`).
    @Sendable public func enroll(_ signed: SignedMessage) async throws -> EnrollmentGrant {
        let (status, body) = try await exchange(signed)
        return try Self.mapEnrollment(status: status, body: body)
    }

    /// J-04r renewal (`SentomaruClient.renew` `send`).
    @Sendable public func renew(_ signed: SignedMessage) async throws -> RenewedGrant {
        let (status, body) = try await exchange(signed)
        return try Self.mapRenewal(status: status, body: body)
    }

    func exchange(_ signed: SignedMessage) async throws -> (Int, Data?) {
        guard let url = URL(string: signed.targetURI), let parts = URLComponents(string: signed.targetURI) else {
            throw SentomaruError.invalidRequest(.TARGET_URI)
        }
        guard parts.scheme == "https", let host = parts.percentEncodedHost, allowedHosts.contains(host),
              parts.percentEncodedUser == nil, parts.percentEncodedPassword == nil else { throw SentomaruError.hostNotAllowed }
        var request = URLRequest(url: url)
        request.httpMethod = signed.method
        for (name, value) in signed.headers { request.setValue(value, forHTTPHeaderField: name) }
        request.httpBody = signed.body
        let (bytes, response) = try await session.bytes(for: request)
        guard let http = response as? HTTPURLResponse else {
            bytes.task.cancel()
            throw URLError(.badServerResponse)
        }
        return (http.statusCode, try await Self.readBounded(bytes))
    }

    /// The body, read up to `maxResponseBytes + 1` bytes and no further (the limit holds while reading, not after a
    /// full download); nil when it is larger than `maxResponseBytes`. The task is cancelled on an oversized body.
    static func readBounded(_ bytes: URLSession.AsyncBytes, limit: Int = maxResponseBytes) async throws -> Data? {
        var data = Data()
        for try await byte in bytes {
            data.append(byte)
            if data.count > limit {
                bytes.task.cancel()
                return nil
            }
        }
        return data
    }

    /// Pure mapping from an HTTP answer to a grant or a typed refusal; `body` is nil when oversized.
    public static func mapEnrollment(status: Int, body: Data?) throws -> EnrollmentGrant {
        if (200...299).contains(status) {
            guard let body, let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any] else {
                throw SentomaruError.serverRejected(.INVALID)
            }
            func member(_ name: String) throws -> String {
                guard let value = json[name] as? String else { throw SentomaruError.serverRejected(.INVALID) }
                return value
            }
            do {
                return try EnrollmentGrant(installationId: member("installationId"), keyId: member("keyId"),
                                           sessionId: member("sessionId"), hardwareStatus: member("hardwareStatus"),
                                           attestationStatus: member("attestationStatus"))
            } catch {
                throw SentomaruError.serverRejected(.INVALID)
            }
        }
        let code = ServerAnswer.code(body)
        if status == 401 && code == predecessorInvalid { throw SentomaruError.reenrollmentRefused }
        throw SentomaruError.serverRejected(rejection(status: status, serverCode: code))
    }

    /// Renewal: 403 `session-unavailable` = `enrollmentRequired` (the grant is dropped), 403 `installation-suspended`
    /// = `serverRejected(.SUSPENDED)`, anything but a 200 with a valid grant = `InvalidRequest:PARAMS`.
    public static func mapRenewal(status: Int, body: Data?) throws -> RenewedGrant {
        let code = status == 403 ? ServerAnswer.code(body) : ""
        if code == sessionUnavailable { throw SentomaruError.enrollmentRequired }
        if code == installationSuspended { throw SentomaruError.serverRejected(.SUSPENDED) }
        guard status == 200, let body, let text = String(data: body, encoding: .utf8) else {
            throw SentomaruError.invalidRequest(.PARAMS)
        }
        return try RenewedGrant.parse(text)
    }

    /// Same table as the Android/Flutter transport.
    public static func rejection(status: Int, serverCode: String) -> SentomaruError.Rejection {
        if status == 403 && serverCode == installationSuspended { return .SUSPENDED }
        if serverCode == "enrollment-revoked" || serverCode == "installation-revoked" { return .REVOKED }
        if serverCode == "challenge-invalid" || serverCode == "challenge-expired" { return .EXPIRED }
        if status == 409 && serverCode == "enrollment-conflict" { return .CONFLICT }
        if status == 429 || serverCode == "rate-limited" { return .RATE_LIMITED }
        if status >= 500 || serverCode.hasSuffix("-unavailable") { return .UNAVAILABLE }
        return .INVALID // 3xx (redirect refused) and every other 4xx
    }
}

/// Signs and sends the app's own `URLRequest`s (the minimal URLSession counterpart of the Android `addSentomaru`):
/// renewal before signing when due, the body frozen from `httpBody`, one resend after `403 session-expired`.
///
/// Deliberately smaller than the OkHttp/Dio interceptors (D-10a): redirects are never followed (the 3xx goes back to
/// the caller), there is no route table (the caller names the operation) and no streamed body (`httpBodyStream` is
/// refused). A host outside the allowlist is `hostNotAllowed`; nothing leaves unsigned.
public final class SentomaruURLSession: Sendable {
    public let client: SentomaruClient
    let transport: SentomaruTransport
    let session: URLSession
    /// D-10e: collects the snapshot signed in `x-sentomaru-signals` when the request has none; nil = no signals.
    let signals: SignalsCollector?

    /// `signals` (D-10e), off by default like the Android OkHttp interceptor (review R M2): pass `SignalsCollector()` to
    /// collect the six catalog 1.0.0 capabilities anew for every signature (a resend after renewal too) and sign them, so
    /// a policy with `sensitiveOperations` sees them instead of `SIGNALS_MISSING`. nil (the default) sends no snapshot
    /// unless the request carries one.
    public init(client: SentomaruClient, transport: SentomaruTransport? = nil,
                configuration: URLSessionConfiguration = .default, signals: SignalsCollector? = nil) {
        self.client = client
        self.transport = transport ?? SentomaruTransport(config: client.config)
        self.session = URLSession(configuration: configuration, delegate: RefuseRedirects(), delegateQueue: nil)
        self.signals = signals
    }

    /// A copy of `request` with the Sentomaru headers, signed for `operation`. The caller may set
    /// `x-sentomaru-operation-id` and `x-sentomaru-signals` (signed when present); `content-type`, when set, must be
    /// exactly `application/json` (it is set when absent). Any other `x-sentomaru-*` or signature header is refused.
    /// D-10e: without a caller `x-sentomaru-signals` and with a `signals` collector, its snapshot goes in it, signed (H3).
    public func signed(_ request: URLRequest, operation: String) async throws -> URLRequest {
        guard let url = request.url else { throw SentomaruError.invalidRequest(.TARGET_URI) }
        guard request.httpBodyStream == nil else { throw SentomaruError.invalidRequest(.PARAMS) }
        var optional: [String: String] = [:]
        for (name, value) in request.allHTTPHeaderFields ?? [:] {
            let lower = name.lowercased()
            if lower == "content-type" {
                if value != Profile.contentType { throw SentomaruError.invalidRequest(.HEADER_VALUE) }
            } else if Profile.optionalHeaders.contains(lower) {
                optional[lower] = value
            } else if lower == "x-sentomaru-operation" {
                if value != operation { throw SentomaruError.invalidRequest(.HEADER_VALUE) }
            } else if lower.hasPrefix("x-sentomaru-") || lower == Profile.signatureHeader ||
                lower == Profile.signatureInputHeader || lower == Profile.contentDigestHeader {
                throw SentomaruError.invalidRequest(.HEADER_NAME)
            }
        }
        // A failed renewal keeps the current grant: the request still goes out with it (Android behaviour).
        _ = try? await client.renewIfDue(send: transport.renew)
        // Collected after the renewal, right before signing: the freshest observedAt the server can see.
        if optional[Profile.signalsHeader] == nil, let signals {
            optional[Profile.signalsHeader] = try signals.snapshot().headerValue()
        }
        let message = try await client.sign(method: request.httpMethod ?? "GET", targetURI: url.absoluteString,
                                            operation: operation, body: request.httpBody ?? Data(), optional: optional)
        var out = request
        for (name, value) in message.headers { out.setValue(value, forHTTPHeaderField: name) }
        // No body on the wire when the signed body is empty (a GET carries none; the digest is of the empty body).
        out.httpBody = message.body.isEmpty ? nil : message.body
        return out
    }

    /// Sends `request` signed for `operation`. On `403` with `code` `session-expired` (JSON body or
    /// `Sentomaru-Error` header) it renews and resends once, re-signed with a new nonce; a failed renewal returns the
    /// original 403. The grant is marked stale first (as the OkHttp interceptor does), so a renewal that cannot run now
    /// still happens before the next signed request.
    public func data(for request: URLRequest, operation: String) async throws -> (Data, HTTPURLResponse) {
        var (data, response) = try await send(try await signed(request, operation: operation))
        if response.statusCode == 403, Self.sessionExpired(response, data), (try? await client.canRenewNow()) == true {
            try? await client.markGrantStale()
            if (try? await client.renew(send: transport.renew)) != nil {
                (data, response) = try await send(try await signed(request, operation: operation))
            }
        }
        return (data, response)
    }

    private func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else { throw URLError(.badServerResponse) }
        return (data, http)
    }

    static func sessionExpired(_ response: HTTPURLResponse, _ body: Data) -> Bool {
        response.value(forHTTPHeaderField: "Sentomaru-Error") == "session-expired" ||
            ServerAnswer.code(body.count > SentomaruTransport.maxResponseBytes ? nil : body) == "session-expired"
    }
}
