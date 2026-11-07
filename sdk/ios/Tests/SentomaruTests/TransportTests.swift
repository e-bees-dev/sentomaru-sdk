import Foundation
@testable import Sentomaru
@testable import SentomaruCore
import XCTest

/// URLProtocol stand-in: no socket is opened; each test installs a handler and reads the requests that "left".
final class StubProtocol: URLProtocol, @unchecked Sendable {
    struct Reply {
        let status: Int; let headers: [String: String]; let body: Data
        /// Delivered in 4 KiB chunks, one per scheduling turn, until the client stops the load.
        var chunked = false
    }
    private static let lock = NSLock()
    nonisolated(unsafe) private static var delivered = 0
    private let stopped = NSLock()
    nonisolated(unsafe) private var isStopped = false
    nonisolated(unsafe) private static var handler: (@Sendable (URLRequest, Data) throws -> Reply)?
    nonisolated(unsafe) private static var seen: [(URLRequest, Data)] = []

    static func install(_ handler: @escaping @Sendable (URLRequest, Data) throws -> Reply) {
        lock.withLock { self.handler = handler; seen = []; delivered = 0 }
    }

    static var requests: [(URLRequest, Data)] { lock.withLock { seen } }
    /// Body bytes handed to the loading system since `install`.
    static var deliveredBytes: Int { lock.withLock { delivered } }

    static func configuration() -> URLSessionConfiguration {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [StubProtocol.self]
        return configuration
    }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        var body = request.httpBody ?? Data()
        if body.isEmpty, let stream = request.httpBodyStream {
            stream.open()
            var buffer = [UInt8](repeating: 0, count: 4096)
            while stream.hasBytesAvailable {
                let count = stream.read(&buffer, maxLength: buffer.count)
                if count <= 0 { break }
                body.append(buffer, count: count)
            }
            stream.close()
        }
        let (handler, request) = Self.lock.withLock { () -> ((@Sendable (URLRequest, Data) throws -> Reply)?, URLRequest) in
            Self.seen.append((self.request, body))
            return (Self.handler, self.request)
        }
        do {
            let reply = try XCTUnwrap(handler)(request, body)
            let response = HTTPURLResponse(url: request.url!, statusCode: reply.status, httpVersion: "HTTP/1.1",
                                           headerFields: reply.headers)!
            if (300...399).contains(reply.status), let location = reply.headers["Location"], let target = URL(string: location) {
                // As the HTTP loader does: the task delegate decides whether the redirect is followed.
                client?.urlProtocol(self, wasRedirectedTo: URLRequest(url: target), redirectResponse: response)
            }
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            if reply.chunked {
                deliver(reply.body, from: 0)
                return
            }
            Self.lock.withLock { Self.delivered += reply.body.count }
            client?.urlProtocol(self, didLoad: reply.body)
            client?.urlProtocolDidFinishLoading(self)
        } catch {
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    private func deliver(_ body: Data, from offset: Int) {
        if stopped.withLock({ isStopped }) { return }
        guard offset < body.count else { return client?.urlProtocolDidFinishLoading(self) ?? () }
        let chunk = body.subdata(in: offset ..< min(offset + 4096, body.count))
        Self.lock.withLock { Self.delivered += chunk.count }
        client?.urlProtocol(self, didLoad: chunk)
        DispatchQueue.global().asyncAfter(deadline: .now() + .milliseconds(2)) { self.deliver(body, from: offset + chunk.count) }
    }

    override func stopLoading() { stopped.withLock { isStopped = true } }
}

final class TransportTests: XCTestCase {
    func json(_ object: Any) -> Data { try! JSONSerialization.data(withJSONObject: object) }

    func testEnrollmentResponseMapping() throws {
        let grant = ["installationId": UUIDText.random(), "keyId": UUIDText.random(), "sessionId": UUIDText.random(),
                     "hardwareStatus": "device_attested", "attestationStatus": "verified"]
        XCTAssertEqual(try SentomaruTransport.mapEnrollment(status: 201, body: json(grant)).hardwareStatus, "device_attested")
        let cases: [(Int, Data?, String)] = [
            (201, Data("not json".utf8), "ServerRejected:INVALID"),
            (200, json(grant.merging(["hardwareStatus": "trusted"]) { $1 }), "ServerRejected:INVALID"),
            (200, nil, "ServerRejected:INVALID"),
            (401, json(["code": "predecessor-invalid"]), "ReenrollmentRefused"),
            (401, json(["code": "challenge-invalid"]), "ServerRejected:EXPIRED"),
            (409, json(["code": "enrollment-revoked"]), "ServerRejected:REVOKED"),
            (409, json(["code": "enrollment-conflict"]), "ServerRejected:CONFLICT"),
            (403, json(["code": "installation-suspended"]), "ServerRejected:SUSPENDED"),
            (403, json(["code": "enrollment-context"]), "ServerRejected:INVALID"),
            (422, json(["code": "hardware-not-proven"]), "ServerRejected:INVALID"),
            (429, nil, "ServerRejected:RATE_LIMITED"),
            (503, nil, "ServerRejected:UNAVAILABLE"),
            (400, json(["code": "verifier-unavailable"]), "ServerRejected:UNAVAILABLE"),
            (302, nil, "ServerRejected:INVALID"),
            (410, nil, "ServerRejected:INVALID"),
        ]
        for (status, body, code) in cases {
            XCTAssertThrowsError(try SentomaruTransport.mapEnrollment(status: status, body: body), "\(status)") {
                XCTAssertEqual(($0 as? SentomaruError)?.code, code, "\(status)")
            }
        }
    }

    func testRenewalResponseMapping() throws {
        let installation = UUIDText.random(), key = UUIDText.random(), session = UUIDText.random()
        let ok = Data("{\"installationId\":\"\(installation)\",\"keyId\":\"\(key)\",\"sessionId\":\"\(session)\",\"ttlSeconds\":600}".utf8)
        XCTAssertEqual(try SentomaruTransport.mapRenewal(status: 200, body: ok),
                       try RenewedGrant(installationId: installation, keyId: key, sessionId: session, ttlSeconds: 600))
        let duplicated = Data("{\"installationId\":\"\(installation)\",\"keyId\":\"\(key)\",\"keyId\":\"\(key)\",\"sessionId\":\"\(session)\",\"ttlSeconds\":600}".utf8)
        let cases: [(Int, Data?, String)] = [
            (403, json(["code": "session-unavailable"]), "EnrollmentRequired"),
            (403, json(["code": "installation-suspended"]), "ServerRejected:SUSPENDED"),
            (403, json(["code": "session-expired"]), "InvalidRequest:PARAMS"),
            (201, ok, "InvalidRequest:PARAMS"),
            (200, nil, "InvalidRequest:PARAMS"),
            (200, duplicated, "InvalidRequest:PARAMS"),
            (200, Data("{\"installationId\":\"\(installation)\",\"keyId\":\"\(key)\",\"sessionId\":\"\(session)\",\"ttlSeconds\":0}".utf8), "InvalidRequest:PARAMS"),
        ]
        for (status, body, code) in cases {
            XCTAssertThrowsError(try SentomaruTransport.mapRenewal(status: status, body: body), "\(status)") {
                XCTAssertEqual(($0 as? SentomaruError)?.code, code)
            }
        }
    }

    private func signedEnrollment(host: String = "consumer.example") throws -> SignedMessage {
        let id = UUIDText.random()
        let headers = ["content-type": "application/json", "x-sentomaru-profile": "sentomaru-p0", "x-sentomaru-org": "org-a",
                       "x-sentomaru-app": "app-a", "x-sentomaru-environment": "hml", "x-sentomaru-session": id,
                       "x-sentomaru-operation": "enroll"]
        let request = try FrozenRequest(method: "POST", targetURI: "https://\(host)/v1/org-a/app-a/hml/installations",
                                        headers: headers, body: Data("{}".utf8))
        return try MessageSigner.sign(request, params: SignatureParams(created: 1, expires: 2, nonce: id, keyId: id)) { _ in Data(count: 64) }
    }

    func testExchangeSendsTheSignedBytesOnlyToAllowlistedHosts() async throws {
        StubProtocol.install { _, _ in .init(status: 409, headers: [:], body: Data("{\"code\":\"enrollment-conflict\"}".utf8)) }
        let transport = SentomaruTransport(allowedHosts: ["consumer.example"], configuration: StubProtocol.configuration())
        let signed = try signedEnrollment()
        await assertThrows(.serverRejected(.CONFLICT)) { try await transport.enroll(signed) }
        let (request, body) = try XCTUnwrap(StubProtocol.requests.first)
        XCTAssertEqual(StubProtocol.requests.count, 1, "one send, no retry")
        XCTAssertEqual(body, signed.body)
        XCTAssertEqual(request.httpMethod, "POST")
        for (name, value) in signed.headers { XCTAssertEqual(request.value(forHTTPHeaderField: name), value, name) }
        let other = try signedEnrollment(host: "other.example")
        await assertThrows(.hostNotAllowed) { try await transport.enroll(other) }
        XCTAssertEqual(StubProtocol.requests.count, 1, "nothing sent to another host")
    }

    /// Review R M2: the stub reports the redirect to the loading system (`wasRedirectedTo`); the delegate refuses it
    /// and no second request leaves, to any host.
    func testRedirectIsNotFollowed() async throws {
        StubProtocol.install { request, _ in
            request.url?.host == "consumer.example"
                ? .init(status: 307, headers: ["Location": "https://consumer.example/elsewhere"], body: Data())
                : .init(status: 200, headers: [:], body: Data("{}".utf8))
        }
        let transport = SentomaruTransport(allowedHosts: ["consumer.example"], configuration: StubProtocol.configuration())
        await assertThrows(.serverRejected(.INVALID)) { try await transport.enroll(try self.signedEnrollment()) }
        XCTAssertEqual(StubProtocol.requests.map { $0.0.url?.path }, ["/v1/org-a/app-a/hml/installations"], "no second request")
    }

    /// Review R M1: the 16 KiB limit holds while reading. A 1 MiB answer delivered in 4 KiB chunks is refused and the
    /// load is cancelled long before the end; a body of exactly the limit is still read.
    func testOversizedAnswerIsCutWhileReading() async throws {
        let total = 1024 * 1024
        StubProtocol.install { _, _ in .init(status: 200, headers: [:], body: Data(repeating: 0x20, count: total), chunked: true) }
        let transport = SentomaruTransport(allowedHosts: ["consumer.example"], configuration: StubProtocol.configuration())
        await assertThrows(.serverRejected(.INVALID)) { try await transport.enroll(try self.signedEnrollment()) }
        try await Task.sleep(nanoseconds: 50_000_000)
        XCTAssertLessThan(StubProtocol.deliveredBytes, total / 4, "stopped near the limit, not after the full download")
        let exact = Data(repeating: 0x20, count: SentomaruTransport.maxResponseBytes)
        StubProtocol.install { _, _ in .init(status: 409, headers: [:], body: exact, chunked: true) }
        let (status, body) = try await transport.exchange(try signedEnrollment())
        XCTAssertEqual(status, 409)
        XCTAssertEqual(body, exact)
        StubProtocol.install { _, _ in .init(status: 409, headers: [:], body: exact + Data([0x20])) }
        let (_, over) = try await transport.exchange(try signedEnrollment())
        XCTAssertNil(over)
    }

    /// Review R N3: the caller's configuration object is not changed.
    func testCallerConfigurationIsCopied() {
        let configuration = StubProtocol.configuration()
        configuration.timeoutIntervalForRequest = 99
        let transport = SentomaruTransport(allowedHosts: ["consumer.example"], configuration: configuration)
        XCTAssertEqual(configuration.timeoutIntervalForRequest, 99)
        XCTAssertNotNil(configuration.httpCookieStorage)
        // Review R M6: the transport's own copy has the request and whole-resource timeouts.
        XCTAssertEqual(transport.session.configuration.timeoutIntervalForRequest, 15)
        XCTAssertEqual(transport.session.configuration.timeoutIntervalForResource, 30)
    }

    func testConfigValidation() throws {
        XCTAssertThrowsError(try SentomaruConfig(organization: "Org", app: "a", environment: "hml", allowedHosts: ["c.example"],
                                                 enrollmentUrl: "https://c.example/i"))
        XCTAssertThrowsError(try SentomaruConfig(organization: "o", app: "a", environment: "hml", allowedHosts: [],
                                                 enrollmentUrl: "https://c.example/i"))
        XCTAssertThrowsError(try SentomaruConfig(organization: "o", app: "a", environment: "hml", allowedHosts: ["C.example"],
                                                 enrollmentUrl: "https://c.example/i"))
        for url in ["https://other.example/i", "http://c.example/i", "https://u@c.example/i"] {
            XCTAssertThrowsError(try SentomaruConfig(organization: "o", app: "a", environment: "hml", allowedHosts: ["c.example"],
                                                     enrollmentUrl: url)) { XCTAssertEqual($0 as? SentomaruError, .hostNotAllowed, url) }
        }
        XCTAssertThrowsError(try SentomaruConfig(organization: "o", app: "a", environment: "hml", allowedHosts: ["c.example"],
                                                 enrollmentUrl: "https://c.example/i", renewalUrl: "https://x.example/s"))
        XCTAssertThrowsError(try SentomaruConfig(organization: "o", app: "a", environment: "hml", allowedHosts: ["c.example"],
                                                 enrollmentUrl: "https://c.example/i", rotationGracePeriod: 0))
    }
}

/// The app-facing URLRequest helper with the fake client stack and the stub transport.
final class URLSessionHelperTests: XCTestCase {
    var clock: TestClock!
    var appAttest: FakeAppAttest!
    var server: FakeServer!
    var client: SentomaruClient!
    var helper: SentomaruURLSession!

    override func setUp() async throws {
        clock = TestClock(Date())
        appAttest = FakeAppAttest()
        let config = try SentomaruConfig(organization: "org-a", app: "app-a", environment: "hml", allowedHosts: ["consumer.example"],
                                         enrollmentUrl: "https://consumer.example/v1/org-a/app-a/hml/installations",
                                         renewalUrl: "https://consumer.example/v1/org-a/app-a/hml/sessions")
        server = FakeServer(config: config, appAttest: appAttest)
        client = SentomaruClient(config: config, keys: SoftwareKeys(), store: MemoryStore(), appAttest: appAttest, now: clock.function)
        let challenge = try server.challenge(now: clock.now)
        let server = self.server!
        _ = try await client.enroll(challenge) { try await server.enroll($0) }
        // The helper's renewals go through the stub to the fake server.
        StubProtocol.install { request, body in
            guard request.url?.path == "/v1/org-a/app-a/hml/sessions" else {
                return .init(status: 200, headers: [:], body: Data("{\"ok\":true}".utf8))
            }
            return try FakeServer.renewSync(server, request: request, body: body)
        }
        helper = SentomaruURLSession(client: client,
                                     transport: SentomaruTransport(allowedHosts: ["consumer.example"], configuration: StubProtocol.configuration()),
                                     configuration: StubProtocol.configuration())
    }

    func testSignedRequestCarriesTheProfileHeaders() async throws {
        var request = URLRequest(url: URL(string: "https://consumer.example/api/ops?x=1")!)
        request.httpMethod = "POST"
        request.httpBody = Data("{\"a\":1}".utf8)
        request.setValue("op-0123456789abcdef", forHTTPHeaderField: "X-Sentomaru-Operation-Id")
        let signed = try await helper.signed(request, operation: "submit")
        XCTAssertEqual(signed.value(forHTTPHeaderField: "x-sentomaru-operation"), "submit")
        XCTAssertEqual(signed.value(forHTTPHeaderField: "content-type"), "application/json")
        XCTAssertNotNil(signed.value(forHTTPHeaderField: "signature"))
        XCTAssertTrue(try XCTUnwrap(signed.value(forHTTPHeaderField: "signature-input")).contains("\"x-sentomaru-operation-id\""))
        XCTAssertEqual(signed.httpBody, Data("{\"a\":1}".utf8))
    }

    func testRefusals() async throws {
        var request = URLRequest(url: URL(string: "https://other.example/api")!)
        request.httpMethod = "POST"
        await assertThrows(.hostNotAllowed) { try await self.helper.signed(request, operation: "submit") }
        request.url = URL(string: "https://consumer.example/api")!
        request.setValue("text/plain", forHTTPHeaderField: "Content-Type")
        await assertThrows(.invalidRequest(.HEADER_VALUE)) { try await self.helper.signed(request, operation: "submit") }
        request.setValue(nil, forHTTPHeaderField: "Content-Type")
        request.setValue("sig1=:AA==:", forHTTPHeaderField: "Signature")
        await assertThrows(.invalidRequest(.HEADER_NAME)) { try await self.helper.signed(request, operation: "submit") }
        request.setValue(nil, forHTTPHeaderField: "Signature")
        request.httpBodyStream = InputStream(data: Data("{}".utf8))
        await assertThrows(.invalidRequest(.PARAMS)) { try await self.helper.signed(request, operation: "submit") }
    }

    func testDueGrantIsRenewedBeforeSigning() async throws {
        clock.advance(500)
        var request = URLRequest(url: URL(string: "https://consumer.example/api")!)
        request.httpMethod = "POST"
        let before = try await client.sessionId()
        let signed = try await helper.signed(request, operation: "submit")
        let after = try await client.sessionId()
        XCTAssertNotEqual(before, after)
        XCTAssertEqual(signed.value(forHTTPHeaderField: "x-sentomaru-session"), after)
        XCTAssertEqual(server.renewBodies.count, 1)
    }

    func testSessionExpiredRenewsAndResendsOnce() async throws {
        let server = self.server!
        StubProtocol.install { request, body in
            if request.url?.path == "/v1/org-a/app-a/hml/sessions" { return try FakeServer.renewSync(server, request: request, body: body) }
            let first = StubProtocol.requests.filter { $0.0.url?.path == "/api" }.count == 1
            return first ? .init(status: 403, headers: [:], body: Data("{\"code\":\"session-expired\"}".utf8))
                : .init(status: 200, headers: [:], body: Data("{}".utf8))
        }
        var request = URLRequest(url: URL(string: "https://consumer.example/api")!)
        request.httpMethod = "POST"
        let (_, response) = try await helper.data(for: request, operation: "submit")
        XCTAssertEqual(response.statusCode, 200)
        let calls = StubProtocol.requests.filter { $0.0.url?.path == "/api" }
        XCTAssertEqual(calls.count, 2, "one resend")
        XCTAssertNotEqual(calls[0].0.value(forHTTPHeaderField: "signature-input"), calls[1].0.value(forHTTPHeaderField: "signature-input"))
        XCTAssertEqual(server.renewBodies.count, 1)
    }

    /// Review R M4: `session-expired` marks the grant stale before renewing (OkHttp interceptor). A renewal that fails
    /// leaves it stale, so once the backoff ends the next signing renews although the grant's lifetime is not over.
    func testSessionExpiredMarksTheGrantStale() async throws {
        StubProtocol.install { request, _ in
            request.url?.path == "/v1/org-a/app-a/hml/sessions"
                ? .init(status: 503, headers: [:], body: Data())
                : .init(status: 403, headers: ["Sentomaru-Error": "session-expired"], body: Data())
        }
        var request = URLRequest(url: URL(string: "https://consumer.example/api")!)
        request.httpMethod = "POST"
        let (_, response) = try await helper.data(for: request, operation: "submit")
        XCTAssertEqual(response.statusCode, 403, "failed renewal: the original 403")
        XCTAssertEqual(StubProtocol.requests.filter { $0.0.url?.path == "/api" }.count, 1, "no resend")
        let backingOff = try await client.renewalBackingOff()
        XCTAssertTrue(backingOff)
        clock.advance(61) // the grant is 61 s old, far from its renewal margin
        let due = try await client.needsRenewal()
        XCTAssertTrue(due, "stale grant")
    }

    /// Review R M7: an empty body goes out as no body (GET), signed over the empty body's digest.
    func testGetWithoutBodySendsNoBody() async throws {
        var request = URLRequest(url: URL(string: "https://consumer.example/api/items?page=2")!)
        request.httpMethod = "GET"
        let signed = try await helper.signed(request, operation: "list")
        XCTAssertNil(signed.httpBody)
        XCTAssertEqual(signed.value(forHTTPHeaderField: "content-digest"), ContentDigest.sha256(Data()))
        let (_, response) = try await helper.data(for: request, operation: "list")
        XCTAssertEqual(response.statusCode, 200)
        let (sent, body) = try XCTUnwrap(StubProtocol.requests.last)
        XCTAssertEqual(sent.httpMethod, "GET")
        XCTAssertTrue(body.isEmpty)
    }
}

extension FakeServer {
    /// Runs the async fake renewal from the URLProtocol thread (test only).
    static func renewSync(_ server: FakeServer, request: URLRequest, body: Data) throws -> StubProtocol.Reply {
        var headers: [(name: String, value: String)] = []
        for name in ["content-digest"] + Profile.callerHeaders + Profile.optionalHeaders + ["signature-input", "signature"] {
            if let value = request.value(forHTTPHeaderField: name) { headers.append((name, value)) }
        }
        let signed = SignedMessage(method: request.httpMethod ?? "GET", targetURI: request.url!.absoluteString, headers: headers,
                                   body: body, signatureBase: Data())
        let box = ResultBox()
        let done = DispatchSemaphore(value: 0)
        Task {
            do {
                let grant = try await server.renew(signed)
                box.reply = .init(status: 200, headers: [:], body: Data(
                    "{\"installationId\":\"\(grant.installationId)\",\"keyId\":\"\(grant.keyId)\",\"sessionId\":\"\(grant.sessionId)\",\"ttlSeconds\":\(grant.ttlSeconds)}".utf8))
            } catch {
                box.reply = .init(status: 403, headers: [:], body: Data("{\"code\":\"session-unavailable\"}".utf8))
            }
            done.signal()
        }
        done.wait()
        return try XCTUnwrap(box.reply)
    }
}

final class ResultBox: @unchecked Sendable { var reply: StubProtocol.Reply? }
