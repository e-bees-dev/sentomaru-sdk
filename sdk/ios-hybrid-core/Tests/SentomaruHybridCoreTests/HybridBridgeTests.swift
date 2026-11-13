import CryptoKit
import Foundation
@testable import SentomaruHybridCore
import Sentomaru
import XCTest

// D-22: unit tests of SentomaruHybridBridge, the dispatcher any RN/Capacitor/Cordova iOS native module forwards its
// calls to. They run on the Mac host (`swift test`, no Secure Enclave, no App Attest): the SDK client is built with
// software keys, an in-memory store, a fake App Attest and a fake server (`send`), as sdk/ios's own tests do. The
// real objects (Secure Enclave, data protection Keychain, DCAppAttestService, URLSession transport) are only proven
// on a device, same as the Flutter plugin's own iOS bridge tests this file is the twin of. Consuming Sentomaru as a
// separate module (the real shape RN/Capacitor/Cordova will use, unlike Flutter's vendored-source pod) means the
// internal `SignalsEnvironment`/`SignalsCollector(environment:...)` test seams are out of reach here: the signals
// tests below use the live collector, like the Flutter suite's own `testCollectSignalsLive`.

private final class SoftwareKeys: InstallationKeys, @unchecked Sendable {
    private let lock = NSLock()
    private var keys: [String: P256.Signing.PrivateKey] = [:]
    private(set) var generated = 0

    private func locked<T>(_ body: () throws -> T) rethrows -> T { lock.lock(); defer { lock.unlock() }; return try body() }

    func exists(_ alias: String) throws -> Bool { locked { keys[alias] != nil } }
    func generate(_ alias: String) throws -> Data {
        locked {
            let key = P256.Signing.PrivateKey()
            keys[alias] = key
            generated += 1
            return key.publicKey.derRepresentation
        }
    }
    func publicKey(_ alias: String) throws -> Data {
        try locked {
            guard let key = keys[alias] else { throw SentomaruError.keyInvalidated }
            return key.publicKey.derRepresentation
        }
    }
    func sign(_ alias: String, _ bytes: Data) throws -> Data {
        try locked {
            guard let key = keys[alias] else { throw SentomaruError.keyInvalidated }
            return try key.signature(for: bytes).rawRepresentation
        }
    }
    func delete(_ alias: String) throws { locked { keys[alias] = nil } }
    func deleteOwned(prefix: String) throws { locked { keys = keys.filter { !$0.key.hasPrefix(prefix) } } }
    var count: Int { locked { keys.count } }
}

/// Keys of a device without a Secure Enclave (the production `SecureEnclaveKeys` throws this from `generate`).
private final class NoSecureEnclaveKeys: InstallationKeys, @unchecked Sendable {
    func exists(_ alias: String) throws -> Bool { false }
    func generate(_ alias: String) throws -> Data { throw SentomaruError.unsupported(.SECURE_ENCLAVE) }
    func publicKey(_ alias: String) throws -> Data { throw SentomaruError.keyInvalidated }
    func sign(_ alias: String, _ bytes: Data) throws -> Data { throw SentomaruError.keyInvalidated }
    func delete(_ alias: String) throws {}
    func deleteOwned(prefix: String) throws {}
}

private final class MemoryStore: InstallationStore, @unchecked Sendable {
    private let lock = NSLock()
    private var record: InstallationRecord?

    func read() throws -> InstallationRecord? { lock.lock(); defer { lock.unlock() }; return record }
    func write(_ record: InstallationRecord?) throws { lock.lock(); defer { lock.unlock() }; self.record = record }
}

private extension NSLock {
    func scoped<T>(_ body: () throws -> T) rethrows -> T { lock(); defer { unlock() }; return try body() }
}

private final class FakeAppAttest: AppAttestService, @unchecked Sendable {
    private let lock = NSLock()
    private let supported: Bool
    private(set) var generatedKeys = 0
    private(set) var assertions = 0

    init(supported: Bool = true) { self.supported = supported }

    var isSupported: Bool { supported }
    func generateKey() async throws -> String {
        lock.scoped { generatedKeys += 1 }
        return Data((0..<32).map { _ in UInt8.random(in: 0...255) }).base64EncodedString()
    }
    func attestKey(_ keyId: String, clientDataHash: Data) async throws -> Data { Data(repeating: 1, count: 64) + clientDataHash }
    func generateAssertion(_ keyId: String, clientDataHash: Data) async throws -> Data {
        lock.scoped { assertions += 1 }
        return Data(repeating: 2, count: 32) + clientDataHash
    }
}

/// A clock the test moves forward (the SDK's renewal schedule reads it).
private final class TestClock: @unchecked Sendable {
    private let lock = NSLock()
    private var offset: TimeInterval = 0
    func now() -> Date { lock.scoped { Date().addingTimeInterval(offset) } }
    func advance(_ seconds: TimeInterval) { lock.scoped { offset += seconds } }
}

/// The consumer backend stand-in: answers enrollments with a grant for the challenge and renewals with a new session.
private final class FakeServer: @unchecked Sendable {
    private let lock = NSLock()
    let installationId = UUID().uuidString.lowercased()
    var renewalFailure: SentomaruError?
    private(set) var enrollBodies: [Data] = []
    private(set) var renewBodies: [Data] = []
    private(set) var lastSession = UUID().uuidString.lowercased()

    func enroll(_ signed: SignedMessage) async throws -> EnrollmentGrant {
        try lock.scoped { try enrollSync(signed) }
    }

    private func enrollSync(_ signed: SignedMessage) throws -> EnrollmentGrant {
        enrollBodies.append(signed.body)
        let keyId = signed.header("x-sentomaru-session")! // the challenge id (enrollment is signed with it)
        return try EnrollmentGrant(installationId: installationId, keyId: keyId, sessionId: lastSession,
                                   hardwareStatus: "device_attested", attestationStatus: "verified")
    }

    func renew(_ signed: SignedMessage) async throws -> RenewedGrant {
        try lock.scoped { try renewSync(signed) }
    }

    private func renewSync(_ signed: SignedMessage) throws -> RenewedGrant {
        renewBodies.append(signed.body)
        if let renewalFailure { throw renewalFailure }
        let keyId = Self.keyId(signed.header("signature-input")!)
        lastSession = UUID().uuidString.lowercased()
        return try RenewedGrant(installationId: installationId, keyId: keyId, sessionId: lastSession, ttlSeconds: 600)
    }

    static func keyId(_ input: String) -> String {
        let marker = "keyid=\""
        let start = input.range(of: marker)!.upperBound
        return String(input[start...].prefix(36))
    }
}

private final class OrderLog: @unchecked Sendable {
    private let lock = NSLock()
    private var list: [String] = []
    func add(_ item: String) { lock.scoped { list.append(item) } }
    var items: [String] { lock.scoped { list } }
}

/// A one-shot async gate a `@Sendable` closure can park on and a test can release later, without a blocking
/// `DispatchSemaphore.wait()` inside an `async` context (unavailable since this toolchain).
private final class ContinuationGate: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Void, Never>?
    private var released = false

    func wait() async {
        await withCheckedContinuation { continuation in
            lock.scoped {
                if released { continuation.resume() } else { self.continuation = continuation }
            }
        }
    }

    func release() {
        lock.scoped {
            released = true
            continuation?.resume()
            continuation = nil
        }
    }
}

final class SentomaruHybridBridgeTests: XCTestCase {
    private let keys = SoftwareKeys()
    private let store = MemoryStore()
    private var appAttest = FakeAppAttest()
    private let server = FakeServer()
    private let clock = TestClock()

    private func bridge() -> SentomaruHybridBridge {
        let keys = keys, store = store, appAttest = appAttest, server = server, clock = clock
        return SentomaruHybridBridge { config in
            let client = SentomaruClient(config: config, keys: keys, store: store, appAttest: appAttest,
                                         now: { clock.now() })
            return .init(client: client, enroll: { try await server.enroll($0) }, renew: { try await server.renew($0) })
        }
    }

    private func call(_ bridge: SentomaruHybridBridge, _ method: String, _ args: [String: Any]? = nil) async -> BridgeReply {
        await withCheckedContinuation { continuation in
            bridge.handle(method, args) { continuation.resume(returning: $0) }
        }
    }

    private func config(renewal: Bool = true) -> [String: Any] {
        var map: [String: Any] = [
            "organization": "acme", "app": "shop", "environment": "hml",
            "enrollmentUrl": "https://api.example.test/v1/acme/shop/hml/installations",
            "allowedHosts": ["api.example.test"], "rotationGracePeriodDays": 7,
        ]
        if renewal { map["renewalUrl"] = "https://api.example.test/v1/acme/shop/hml/sessions" }
        return map
    }

    private func challenge(requiresHardware: Bool = false, strongBox: Bool = false) -> [String: Any] {
        let random = { Data((0..<32).map { _ in UInt8.random(in: 0...255) }).base64EncodedString() }
        return ["challenge": ["id": UUID().uuidString.lowercased(), "token": random(),
                              "expiresAtEpochMs": Int64((Date().timeIntervalSince1970 + 300) * 1000),
                              "attestationChallengeB64": random()],
                "strongBox": strongBox, "requiresHardware": requiresHardware]
    }

    private func initialized(renewal: Bool = true) async -> SentomaruHybridBridge {
        let b = bridge()
        let reply = await call(b, "initialize", config(renewal: renewal))
        XCTAssertEqual(reply, .success(nil))
        return b
    }

    // MARK: - Configuration

    func testUnknownAndUnimplementedMethods() async {
        let b = bridge()
        // scaffoldInfo is flutterOnly (contract); reattestation and sealed assets have no iOS SDK equivalent here.
        for method in ["scaffoldInfo", "reattestationDue", "reattestIfDue", "reattest",
                       "sealedConfigure", "sealedLoad", "sealedString", "nope"] {
            let reply = await call(b, method)
            XCTAssertEqual(reply, .notImplemented, method)
        }
    }

    func testInitializeRefusesWhatAndroidRefuses() async {
        let b = bridge()
        for broken: (String, Any?) in [("organization", nil), ("organization", "  "), ("allowedHosts", [String]()),
                                       ("allowedHosts", [1]), ("rotationGracePeriodDays", true),
                                       ("rotationGracePeriodDays", 0), ("renewalUrl", "https://other.test/sessions"),
                                       ("enrollmentUrl", "http://api.example.test/x")] {
            var args = config()
            args[broken.0] = broken.1
            let reply = await call(b, "initialize", args)
            XCTAssertEqual(reply, .failure("ConfigurationError"), "\(broken)")
        }
        let state = await call(b, "state")
        XCTAssertEqual(state, .failure("NotInitialized"))
    }

    func testInitializeIgnoresAndroidOnlyArguments() async {
        var args = config()
        args["playIntegrityCloudProjectNumber"] = 123
        args["reattestationChallengeUrl"] = "https://api.example.test/c"
        args["reattestationSubmitUrl"] = "https://api.example.test/s"
        args["reattestationMinIntervalSeconds"] = 60
        let reply = await call(bridge(), "initialize", args)
        XCTAssertEqual(reply, .success(nil))
    }

    // MARK: - Revisor A, rodada 2 (médio A): initialize locks allowedHosts/enrollmentUrl/renewalUrl after the first call

    func testSecondInitializeIdenticalToTheFirstIsAllowed() async {
        let b = bridge()
        let first = await call(b, "initialize", config())
        XCTAssertEqual(first, .success(nil))
        let second = await call(b, "initialize", config())
        XCTAssertEqual(second, .success(nil))
    }

    func testSecondInitializeThatShrinksTheAllowlistIsAllowed() async {
        let b = bridge()
        var wide = config()
        wide["allowedHosts"] = ["api.example.test", "other.example.test"]
        let first = await call(b, "initialize", wide)
        XCTAssertEqual(first, .success(nil))
        let second = await call(b, "initialize", config()) // allowedHosts: just ["api.example.test"]
        XCTAssertEqual(second, .success(nil))
    }

    func testSecondInitializeThatWidensTheAllowlistIsRefused() async {
        // the attack this closes: a WebView page (Capacitor/Cordova) calling `initialize` again to add a host it controls.
        let b = await initialized()
        var wider = config()
        wider["allowedHosts"] = ["api.example.test", "attacker.evil.test"]
        let reply = await call(b, "initialize", wider)
        XCTAssertEqual(reply, .failure("ConfigurationError"))
    }

    func testSecondInitializeWithADifferentEnrollmentPathOnAnAllowedHostIsRefused() async {
        let b = await initialized()
        var other = config()
        other["enrollmentUrl"] = "https://api.example.test/v1/attacker/shop/hml/installations"
        let reply = await call(b, "initialize", other)
        XCTAssertEqual(reply, .failure("ConfigurationError"))
    }

    func testSecondInitializeWithADifferentRenewalPathIsRefused() async {
        let b = await initialized()
        var other = config()
        other["renewalUrl"] = "https://api.example.test/v1/acme/shop/hml/sessions-2"
        let reply = await call(b, "initialize", other)
        XCTAssertEqual(reply, .failure("ConfigurationError"))
    }

    func testSecondInitializeThatDropsRenewalUrlIsRefused() async {
        let b = await initialized(renewal: true)
        let reply = await call(b, "initialize", config(renewal: false))
        XCTAssertEqual(reply, .failure("ConfigurationError"))
    }

    func testBeforeInitialize() async {
        let b = bridge()
        for method in ["state", "enroll", "rotate", "sign", "renewSession", "reenrollmentReason"] {
            let reply = await call(b, method, challenge())
            XCTAssertEqual(reply, .failure("NotInitialized"), method)
        }
        let session = await call(b, "sessionId")
        XCTAssertEqual(session, .success(nil))
        let reset = await call(b, "reset")
        XCTAssertEqual(reset, .success(nil))
    }

    // MARK: - Lifecycle

    func testEnrollSignRenewReset() async throws {
        let b = await initialized()
        var reply = await call(b, "state")
        XCTAssertEqual(reply, .success("NotEnrolled"))

        reply = await call(b, "enroll", challenge(strongBox: true)) // strongBox: Android only, ignored
        XCTAssertEqual(reply.kind, .success)
        let grant = try XCTUnwrap(reply.value as? [String: String])
        XCTAssertEqual(grant["hardwareStatus"], "device_attested")
        XCTAssertEqual(grant["attestationStatus"], "verified")
        XCTAssertEqual(grant["installationId"], server.installationId)
        let body = try XCTUnwrap(String(data: server.enrollBodies.first ?? Data(), encoding: .utf8))
        XCTAssertTrue(body.contains("\"attestationFormat\":\"apple-app-attest\""), body)
        XCTAssertTrue(body.contains("\"requiresHardware\":false"), body)

        reply = await call(b, "state")
        XCTAssertEqual(reply, .success("Enrolled"))
        reply = await call(b, "reenrollmentReason")
        XCTAssertEqual(reply, .success(nil))

        reply = await call(b, "sign", ["method": "POST", "targetUri": "https://api.example.test/v1/checkout",
                                       "operation": "checkout", "body": Data("{\"a\":1}".utf8),
                                       "optional": ["x-sentomaru-operation-id": UUID().uuidString.lowercased()]])
        let headers = try XCTUnwrap(reply.value as? [String: String])
        XCTAssertEqual(headers["x-sentomaru-session"], grant["sessionId"])
        XCTAssertEqual(headers["x-sentomaru-operation"], "checkout")
        XCTAssertNotNil(headers["signature"])
        XCTAssertNotNil(headers["content-digest"])
        XCTAssertTrue(headers["signature-input"]?.contains("keyid=\"\(grant["keyId"]!)\"") ?? false)
        XCTAssertNotNil(headers["x-sentomaru-operation-id"])

        reply = await call(b, "renewSession")
        let renewed = try XCTUnwrap(reply.value as? String)
        XCTAssertNotEqual(renewed, grant["sessionId"])
        let renewBody = String(data: server.renewBodies.last ?? Data(), encoding: .utf8) ?? ""
        XCTAssertTrue(renewBody.hasPrefix("{\"appAssertion\":\""), renewBody) // D-09c
        reply = await call(b, "sessionId")
        XCTAssertEqual(reply, .success(renewed))

        reply = await call(b, "reset")
        XCTAssertEqual(reply, .success(nil))
        reply = await call(b, "state")
        XCTAssertEqual(reply, .success("NotEnrolled"))
        XCTAssertEqual(keys.count, 0)
    }

    func testRotateKeepsInstallation() async throws {
        let b = await initialized()
        let first = await call(b, "enroll", challenge())
        let rotated = await call(b, "rotate", challenge())
        let a = try XCTUnwrap(first.value as? [String: String]), c = try XCTUnwrap(rotated.value as? [String: String])
        XCTAssertEqual(a["installationId"], c["installationId"])
        XCTAssertNotEqual(a["keyId"], c["keyId"])
        XCTAssertTrue((String(data: server.enrollBodies.last!, encoding: .utf8) ?? "").contains("\"predecessor\""))
    }

    // `sign` renews a grant near its end first (the D-09c assertion) and signs with the renewed session.
    func testSignRenewsWhenDueThenSignsWithTheNewSession() async throws {
        let b = await initialized()
        let enrolled = await call(b, "enroll", challenge())
        let first = try XCTUnwrap((enrolled.value as? [String: String])?["sessionId"])
        XCTAssertEqual(appAttest.assertions, 0)
        clock.advance(500) // default lifetime 600 s, margin min(120, 600/5): due from 480 s
        let reply = await call(b, "sign", ["method": "GET", "targetUri": "https://api.example.test/x", "operation": "o"])
        let headers = try XCTUnwrap(reply.value as? [String: String])
        XCTAssertEqual(appAttest.assertions, 1)
        XCTAssertEqual(server.renewBodies.count, 1)
        XCTAssertTrue((String(data: server.renewBodies.first ?? Data(), encoding: .utf8) ?? "").hasPrefix("{\"appAssertion\":\""))
        XCTAssertNotEqual(server.lastSession, first)
        XCTAssertEqual(headers["x-sentomaru-session"], server.lastSession)
        // Not due again right after: no second assertion.
        _ = await call(b, "sign", ["method": "GET", "targetUri": "https://api.example.test/x", "operation": "o"])
        XCTAssertEqual(appAttest.assertions, 1)
    }

    // A failed renewal inside `sign` keeps the current grant and the request is still signed with it.
    func testSignKeepsTheCurrentGrantWhenTheRenewalFails() async throws {
        let b = await initialized()
        let enrolled = await call(b, "enroll", challenge())
        let first = try XCTUnwrap((enrolled.value as? [String: String])?["sessionId"])
        server.renewalFailure = .serverRejected(.UNAVAILABLE)
        clock.advance(500)
        let reply = await call(b, "sign", ["method": "GET", "targetUri": "https://api.example.test/x", "operation": "o"])
        let headers = try XCTUnwrap(reply.value as? [String: String])
        XCTAssertEqual(appAttest.assertions, 1, "the renewal was attempted")
        XCTAssertEqual(headers["x-sentomaru-session"], first)
        XCTAssertNotNil(headers["signature"])
    }

    // Calls run in arrival order, one at a time; a state asked right after an enroll sees it.
    func testCallsRunInArrivalOrder() async throws {
        let b = await initialized()
        let order = OrderLog()
        let done = expectation(description: "both answered")
        done.expectedFulfillmentCount = 2
        b.handle("enroll", challenge()) { reply in order.add("enroll \(reply.kind)"); done.fulfill() }
        b.handle("state", nil) { reply in order.add("state \(reply.value as? String ?? "?")"); done.fulfill() }
        await fulfillment(of: [done], timeout: 5)
        XCTAssertEqual(order.items, ["enroll success", "state Enrolled"])
    }

    func testRequiresHardwareRefusedBeforeAnyKey() async {
        let b = await initialized()
        let reply = await call(b, "enroll", challenge(requiresHardware: true))
        XCTAssertEqual(reply, .failure("InvalidRequest:PARAMS"))
        XCTAssertEqual(keys.generated, 0)
        XCTAssertEqual(appAttest.generatedKeys, 0)
        XCTAssertTrue(server.enrollBodies.isEmpty)
    }

    // The same refusal on `rotate`: no new request key, no new App Attest key, nothing sent.
    func testRotateWithRequiresHardwareCreatesNothing() async {
        let b = await initialized()
        _ = await call(b, "enroll", challenge())
        let keysBefore = keys.generated, attestBefore = appAttest.generatedKeys, sentBefore = server.enrollBodies.count
        let reply = await call(b, "rotate", challenge(requiresHardware: true))
        XCTAssertEqual(reply, .failure("InvalidRequest:PARAMS"))
        XCTAssertEqual(keys.generated, keysBefore)
        XCTAssertEqual(appAttest.generatedKeys, attestBefore)
        XCTAssertEqual(server.enrollBodies.count, sentBefore)
    }

    func testWithoutAppAttestEnrollmentIsUnsupported() async {
        appAttest = FakeAppAttest(supported: false)
        let b = await initialized()
        let reply = await call(b, "enroll", challenge())
        XCTAssertEqual(reply, .failure("Unsupported:APP_ATTEST"))
        XCTAssertEqual(keys.count, 0)
        let state = await call(b, "state")
        XCTAssertEqual(state, .success("NotEnrolled"))
    }

    // Without a Secure Enclave the enrollment is Unsupported:SECURE_ENCLAVE, nothing kept or sent.
    func testWithoutSecureEnclaveEnrollmentIsUnsupported() async {
        let store = store, appAttest = appAttest, server = server
        let b = SentomaruHybridBridge { config in
            .init(client: SentomaruClient(config: config, keys: NoSecureEnclaveKeys(), store: store, appAttest: appAttest),
                  enroll: { try await server.enroll($0) }, renew: { try await server.renew($0) })
        }
        _ = await call(b, "initialize", config())
        let reply = await call(b, "enroll", challenge())
        XCTAssertEqual(reply, .failure("Unsupported:SECURE_ENCLAVE"))
        XCTAssertTrue(server.enrollBodies.isEmpty)
        let state = await call(b, "state")
        XCTAssertEqual(state, .success("NotEnrolled"))
    }

    // An initialize that finishes after the detach keeps nothing.
    func testInitializeAfterDetachKeepsNothing() async {
        let gate = DispatchSemaphore(value: 0)
        let keys = keys, store = store, appAttest = appAttest, server = server
        let b = SentomaruHybridBridge { config in
            gate.wait() // the factory runs until the test detached the bridge
            return .init(client: SentomaruClient(config: config, keys: keys, store: store, appAttest: appAttest),
                         enroll: { try await server.enroll($0) }, renew: { try await server.renew($0) })
        }
        let answered = expectation(description: "no reply after detach")
        answered.isInverted = true
        b.handle("initialize", config()) { _ in answered.fulfill() }
        b.detach()
        gate.signal()
        await fulfillment(of: [answered], timeout: 0.5)
        XCTAssertFalse(b.isInitializedForTesting)
    }

    /// Revisor A, rodada 2 (baixo E), the part that is testable without a cancellation token: `withClient` already
    /// refuses a queued-but-not-yet-started enroll after `detach()` (NotInitialized, no key spent, no network call -
    /// `testInitializeAfterDetachKeepsNothing` above proves the same guard for `initialize`). What is NOT guarded is
    /// an enroll already inside its network round trip (past every `isDetached` check) when `detach()` fires: it
    /// cannot be stopped mid-flight without a cancellation token threaded through `SentomaruClient`/`SentomaruTransport`
    /// (out of scope here - a larger SDK change, not a bridge-level fix). What IS already true, and worth proving: it
    /// runs to completion (an App Attest key already spent there is not wasted a second time by a retry believing it
    /// failed) and its reply is dropped by `send`'s own `isDetached` check at the moment it would be delivered, same
    /// as the queued case - a caller never sees a reply for a call it made before a detach it did not cause.
    func testEnrollInFlightWhenDetachFiresCompletesButItsReplyIsDiscarded() async {
        let ready = expectation(description: "enroll reached the wire")
        let proceed = ContinuationGate()
        let keys = keys, store = store, appAttest = appAttest
        let b = SentomaruHybridBridge { config in
            SentomaruHybridBridge.Native(client: SentomaruClient(config: config, keys: keys, store: store, appAttest: appAttest),
                enroll: { signed in
                    ready.fulfill() // past every isDetached guard, now "on the wire"
                    await proceed.wait() // held here until the test has called detach()
                    return try EnrollmentGrant(installationId: "install", keyId: signed.header("x-sentomaru-session")!,
                                               sessionId: "session", hardwareStatus: "device_attested", attestationStatus: "verified")
                },
                renew: { _ in throw SentomaruError.cancelled })
        }
        _ = await call(b, "initialize", config())
        let answered = expectation(description: "no reply after detach")
        answered.isInverted = true
        b.handle("enroll", challenge()) { _ in answered.fulfill() }
        await fulfillment(of: [ready], timeout: 0.5)
        XCTAssertTrue(b.isInitializedForTesting) // still attached when the enroll went on the wire
        b.detach()
        proceed.release() // let the in-flight enroll finish (it does: nothing stops it)
        await fulfillment(of: [answered], timeout: 0.5)
        XCTAssertFalse(b.isInitializedForTesting)
    }

    func testMalformedChallengeIsInvalidRequest() async {
        let b = await initialized()
        var args = challenge()
        var map = args["challenge"] as! [String: Any]
        map["attestationChallengeB64"] = "not base64"
        args["challenge"] = map
        let reply = await call(b, "enroll", args)
        XCTAssertEqual(reply, .failure("InvalidRequest:PARAMS"))
        let missing = await call(b, "enroll", ["strongBox": false])
        XCTAssertEqual(missing, .failure("InvalidRequest:PARAMS"))
    }

    func testSignRefusals() async {
        let b = await initialized()
        var reply = await call(b, "sign", ["targetUri": "https://api.example.test/x", "operation": "o"])
        XCTAssertEqual(reply, .failure("InvalidRequest:METHOD"))
        reply = await call(b, "sign", ["method": "GET", "operation": "o"])
        XCTAssertEqual(reply, .failure("InvalidRequest:TARGET_URI"))
        reply = await call(b, "sign", ["method": "GET", "targetUri": "https://api.example.test/x"])
        XCTAssertEqual(reply, .failure("InvalidRequest:HEADER_VALUE"))
        reply = await call(b, "sign", ["method": "GET", "targetUri": "https://api.example.test/x", "operation": "o",
                                       "optional": ["x-sentomaru-operation-id": 1]])
        XCTAssertEqual(reply, .failure("InvalidRequest:HEADER_VALUE"))
        reply = await call(b, "sign", ["method": "GET", "targetUri": "https://api.example.test/x", "operation": "o"])
        XCTAssertEqual(reply, .failure("NotEnrolled"))
        _ = await call(b, "enroll", challenge())
        reply = await call(b, "sign", ["method": "GET", "targetUri": "https://elsewhere.test/x", "operation": "o"])
        XCTAssertEqual(reply, .failure("HostNotAllowed"))
    }

    func testRenewSessionGate() async {
        let unrenewable = await initialized(renewal: false)
        _ = await call(unrenewable, "enroll", challenge())
        var reply = await call(unrenewable, "renewSession")
        XCTAssertEqual(reply, .failure("InvalidRequest:PARAMS"))
        _ = await call(unrenewable, "reset") // same store and scope as the next bridge

        let b = await initialized()
        reply = await call(b, "renewSession")
        XCTAssertEqual(reply, .failure("InvalidRequest:PARAMS")) // not enrolled
        _ = await call(b, "enroll", challenge())
        server.renewalFailure = .serverRejected(.SUSPENDED)
        reply = await call(b, "renewSession")
        XCTAssertEqual(reply, .failure("ServerRejected:SUSPENDED"))
        reply = await call(b, "renewSession")
        XCTAssertEqual(reply, .failure("RenewalBackoff", details: "ServerRejected:SUSPENDED"))
        // `sign` still signs with the current grant during the backoff.
        reply = await call(b, "sign", ["method": "GET", "targetUri": "https://api.example.test/x", "operation": "o"])
        XCTAssertEqual(reply.kind, .success)
    }

    // MARK: - Signals

    // The live collector (a Mac host run under `swift test`): six catalog ids always answered.
    func testCollectSignalsLive() async throws {
        let reply = await call(bridge(), "collectSignals")
        let list = try XCTUnwrap(reply.value as? [[String: Any]])
        XCTAssertEqual(list.count, 6)
        XCTAssertEqual(list.compactMap { $0["source"] as? String }, Array(repeating: "client_observed", count: 6))
    }

    func testCollectSignalsSnapshot() async throws {
        let b = bridge()
        var reply = await call(b, "collectSignalsSnapshot", ["rasp": false])
        var map = try XCTUnwrap(reply.value as? [String: Any])
        XCTAssertEqual((map["observations"] as? [Any])?.count, 6)
        XCTAssertNotNil(map["collectedAt"] as? String)

        reply = await call(b, "collectSignalsSnapshot", ["rasp": true, "expectedSignerDigests": [String(repeating: "a", count: 64)]])
        map = try XCTUnwrap(reply.value as? [String: Any])
        let list = try XCTUnwrap(map["observations"] as? [[String: Any]])
        XCTAssertEqual(list.count, 15)
        XCTAssertEqual(Set(list.dropFirst(6).compactMap { $0["state"] as? String }), ["unsupported"])

        reply = await call(b, "collectSignalsSnapshot", ["rasp": "yes"])
        XCTAssertEqual(reply, .failure("InvalidRequest:PARAMS"))
        // A JS number (NSNumber 1 or 0) is not a bool.
        for number in [NSNumber(value: 1), NSNumber(value: 0)] {
            reply = await call(b, "collectSignalsSnapshot", ["rasp": number])
            XCTAssertEqual(reply, .failure("InvalidRequest:PARAMS"), "\(number)")
        }
        reply = await call(b, "collectSignalsSnapshot", ["rasp": NSNumber(value: true)])
        XCTAssertEqual(reply.kind, .success)
    }

    func testDetachDropsReplies() async throws {
        let b = await initialized()
        b.detach()
        let answered = expectation(description: "no reply after detach")
        answered.isInverted = true
        b.handle("state", nil) { _ in answered.fulfill() }
        await fulfillment(of: [answered], timeout: 0.3)
    }

    // The bridge's own codes carry its own messages; SDK codes carry the code, same as Android's hybrid-core.
    func testMessagesAreTheStableOnes() async {
        let b = bridge()
        let notInit = await call(b, "state")
        XCTAssertEqual(notInit.message, "Sentomaru native client not initialized")
        let config = await call(b, "initialize", ["organization": "x"])
        XCTAssertEqual(config.message, "Invalid or missing Sentomaru configuration")
        XCTAssertEqual(BridgeReply.failure("ServerRejected:SUSPENDED").message, "ServerRejected:SUSPENDED")
        XCTAssertEqual(SentomaruHybridBridge.failure(NSError(domain: "x", code: 1)).message, "Native error")
    }
}
