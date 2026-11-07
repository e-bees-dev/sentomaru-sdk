import CryptoKit
import Flutter
import Foundation
@testable import sentomaru_flutter
import XCTest

// D-10b: unit tests of the iOS side of the plugin (method channel bridge over the Swift SDK of sdk/ios). They run on
// the simulator, which has neither the Secure Enclave nor App Attest: the SDK client is built with software keys, an
// in-memory store, a fake App Attest and a fake server (`send`), like `swift test` in sdk/ios. The real objects
// (Secure Enclave, data protection Keychain, DCAppAttestService, URLSession transport) are only proven on a device.

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

extension NSLock {
    /// Synchronous scope (NSLock.lock is unavailable from async contexts in Swift 6).
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

final class SentomaruFlutterBridgeTests: XCTestCase {
    private let keys = SoftwareKeys()
    private let store = MemoryStore()
    private var appAttest = FakeAppAttest()
    private let server = FakeServer()
    private let clock = TestClock()

    private func bridge() -> SentomaruFlutterBridge {
        let keys = keys, store = store, appAttest = appAttest, server = server, clock = clock
        return SentomaruFlutterBridge { config in
            let client = SentomaruClient(config: config, keys: keys, store: store, appAttest: appAttest,
                                         now: { clock.now() })
            return .init(client: client, enroll: { try await server.enroll($0) }, renew: { try await server.renew($0) })
        }
    }

    private func call(_ bridge: SentomaruFlutterBridge, _ method: String, _ args: [String: Any]? = nil) async -> BridgeReply {
        await withCheckedContinuation { continuation in
            bridge.handle(method, args) { continuation.resume(returning: $0) }
        }
    }

    private func config(renewal: Bool = true) -> [String: Any] {
        var map: [String: Any] = [
            "organization": "ebees", "app": "exampleapp", "environment": "hml",
            "enrollmentUrl": "https://api.example.test/v1/ebees/exampleapp/hml/installations",
            "allowedHosts": ["api.example.test"], "rotationGracePeriodDays": 7,
        ]
        if renewal { map["renewalUrl"] = "https://api.example.test/v1/ebees/exampleapp/hml/sessions" }
        return map
    }

    private func challenge(requiresHardware: Bool = false, strongBox: Bool = false) -> [String: Any] {
        let random = { Data((0..<32).map { _ in UInt8.random(in: 0...255) }).base64EncodedString() }
        return ["challenge": ["id": UUID().uuidString.lowercased(), "token": random(),
                              "expiresAtEpochMs": Int64((Date().timeIntervalSince1970 + 300) * 1000),
                              "attestationChallengeB64": random()],
                "strongBox": strongBox, "requiresHardware": requiresHardware]
    }

    private func initialized(renewal: Bool = true) async -> SentomaruFlutterBridge {
        let b = bridge()
        let reply = await call(b, "initialize", config(renewal: renewal))
        XCTAssertEqual(reply, .success(nil))
        return b
    }

    // MARK: - Configuration

    func testScaffoldAndUnknownMethods() async {
        let b = bridge()
        let scaffold = await call(b, "scaffoldInfo")
        XCTAssertEqual(scaffold, .success("sentomaru_flutter:0.0.1"))
        // Answered in Dart before the channel on iOS (reattestation, sealed assets).
        for method in ["reattestationDue", "reattestIfDue", "reattest", "sealedLoad", "nope"] {
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

    // M2 (R): `sign` renews a grant near its end first (J-04r + D-09c assertion) and signs with the renewed session.
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

    // M2 (R): a failed renewal inside `sign` keeps the current grant and the request is still signed with it.
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

    // N1 (R): calls run in arrival order, one at a time; a state asked right after an enroll sees it.
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

    // M2 (R): the same refusal on `rotate`: no new request key, no new App Attest key, nothing sent.
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

    // N4 (conferência da R): without a Secure Enclave the enrollment is Unsupported:SECURE_ENCLAVE, nothing kept or sent.
    func testWithoutSecureEnclaveEnrollmentIsUnsupported() async {
        let store = store, appAttest = appAttest, server = server
        let b = SentomaruFlutterBridge { config in
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

    // N1 (conferência da R): an initialize that finishes after the detach keeps nothing.
    func testInitializeAfterDetachKeepsNothing() async {
        let gate = DispatchSemaphore(value: 0)
        let keys = keys, store = store, appAttest = appAttest, server = server
        let b = SentomaruFlutterBridge { config in
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

    // MARK: - Signals (D-10e)

    /// A clean device as the SDK's collector sees it, at a fixed instant (2026-10-29T12:00:00Z).
    private func signalsBridge(_ runtime: SignalsEnvironment.Runtime = .device) -> SentomaruFlutterBridge {
        let environment = SignalsEnvironment(runtime: runtime, isTraced: { false }, fileExists: { _ in false },
                                             canWriteOutsideSandbox: { false }, loadedImages: { [] }, platform: "ios",
                                             osVersion: { "27.0.0" })
        return SentomaruFlutterBridge(signals: SignalsCollector(environment: environment,
                                                                now: { Date(timeIntervalSince1970: 1_793_275_200) }))
    }

    func testCollectSignalsGivesTheSixCatalogIdsWithoutInitialize() async throws {
        let reply = await call(signalsBridge(), "collectSignals")
        XCTAssertEqual(reply.kind, .success)
        let list = try XCTUnwrap(reply.value as? [[String: Any]])
        XCTAssertEqual(list.compactMap { $0["capabilityId"] as? String },
                       ["debug_attached", "emulator_detected", "root_indicated", "app_signing_digest", "installer_source", "os_version"])
        XCTAssertEqual(list.compactMap { $0["state"] as? String },
                       ["not_detected", "not_detected", "not_detected", "unsupported", "unknown", "detected"])
        let os = try XCTUnwrap(list.last)
        XCTAssertEqual(os["version"] as? String, "1.0.0")
        XCTAssertEqual(os["source"] as? String, "client_observed")
        XCTAssertEqual(os["observedAt"] as? String, "2026-10-29T12:00:00.000Z")
        XCTAssertEqual(os["data"] as? [String: String], ["platform": "ios", "release": "27.0.0"])
    }

    func testCollectSignalsOnTheSimulatorRuntime() async throws {
        let reply = await call(signalsBridge(.simulator), "collectSignals")
        let list = try XCTUnwrap(reply.value as? [[String: Any]])
        XCTAssertEqual(list[1]["state"] as? String, "detected") // emulator_detected
        XCTAssertEqual(list[2]["state"] as? String, "unknown") // root_indicated: never checked on the simulator
    }

    /// The live collector of this test run (a simulator build): answers, emulator detected.
    func testCollectSignalsLive() async throws {
        let reply = await call(bridge(), "collectSignals")
        let list = try XCTUnwrap(reply.value as? [[String: Any]])
        XCTAssertEqual(list.count, 6)
        #if targetEnvironment(simulator)
        XCTAssertEqual(list[1]["state"] as? String, "detected")
        #endif
    }

    func testCollectSignalsSnapshot() async throws {
        let b = signalsBridge()
        var reply = await call(b, "collectSignalsSnapshot", ["rasp": false])
        var map = try XCTUnwrap(reply.value as? [String: Any])
        XCTAssertEqual(map["collectedAt"] as? String, "2026-10-29T12:00:00.000Z")
        XCTAssertEqual(map["durationMs"] as? Int, 0)
        XCTAssertEqual((map["observations"] as? [Any])?.count, 6)

        reply = await call(b, "collectSignalsSnapshot", ["rasp": true, "expectedSignerDigests": [String(repeating: "a", count: 64)]])
        map = try XCTUnwrap(reply.value as? [String: Any])
        let list = try XCTUnwrap(map["observations"] as? [[String: Any]])
        XCTAssertEqual(list.count, 15)
        XCTAssertEqual(Set(list.dropFirst(6).compactMap { $0["state"] as? String }), ["unsupported"])

        reply = await call(b, "collectSignalsSnapshot", ["rasp": "yes"])
        XCTAssertEqual(reply, .failure("InvalidRequest:PARAMS"))
        // Review R N1: a Dart int (NSNumber 1 or 0) is not a bool.
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

    // MARK: - Flutter glue

    // M2 (R): the FlutterResult is called on the main thread, with the Android code and message.
    @MainActor
    func testHandleAnswersOnTheMainThread() async {
        let plugin = SentomaruFlutterPlugin(bridge: bridge())
        let answered = expectation(description: "answered")
        plugin.handle(FlutterMethodCall(methodName: "state", arguments: nil)) { value in
            XCTAssertTrue(Thread.isMainThread)
            let error = value as? FlutterError
            XCTAssertEqual(error?.code, "NotInitialized")
            XCTAssertEqual(error?.message, "Sentomaru native client not initialized")
            answered.fulfill()
        }
        await fulfillment(of: [answered], timeout: 5)
    }

    // N3 (R): the plugin's own codes carry the Android messages; SDK codes carry the code.
    func testMessagesAreTheAndroidOnes() async {
        let b = bridge()
        let notInit = await call(b, "state")
        XCTAssertEqual(notInit.message, "Sentomaru native client not initialized")
        let config = await call(b, "initialize", ["organization": "x"])
        XCTAssertEqual(config.message, "Invalid or missing Sentomaru configuration")
        XCTAssertEqual(BridgeReply.failure("ServerRejected:SUSPENDED").message, "ServerRejected:SUSPENDED")
        XCTAssertEqual(SentomaruFlutterBridge.failure(NSError(domain: "x", code: 1)).message, "Native error")
    }

    func testFlutterValues() {
        let failure = SentomaruFlutterPlugin.resultValue(.failure("RenewalBackoff", details: "ServerRejected:SUSPENDED")) as? FlutterError
        XCTAssertEqual(failure?.code, "RenewalBackoff")
        XCTAssertEqual(failure?.message, "RenewalBackoff")
        XCTAssertEqual(failure?.details as? String, "ServerRejected:SUSPENDED")
        XCTAssertTrue((SentomaruFlutterPlugin.resultValue(.notImplemented) as AnyObject) === (FlutterMethodNotImplemented as AnyObject))
        XCTAssertEqual(SentomaruFlutterPlugin.resultValue(.success("x")) as? String, "x")

        let bytes = Data([1, 2, 3])
        let args = SentomaruFlutterPlugin.arguments(["body": FlutterStandardTypedData(bytes: bytes), "method": "POST"])
        XCTAssertEqual(args?["body"] as? Data, bytes)
        XCTAssertEqual(args?["method"] as? String, "POST")
        XCTAssertNil(SentomaruFlutterPlugin.arguments(nil))
    }

    // MARK: - D-25 / D-26 / D-27 (iOS bridge slices; run on the simulator, which has no Secure Enclave: software stand-ins)

    /// Test-only transaction key (the production one needs the Secure Enclave and a biometric prompt).
    private final class SoftwareTransactionKeys: TransactionKeys, @unchecked Sendable {
        private let lock = NSLock()
        private var keys: [String: P256.Signing.PrivateKey] = [:]
        var failure: TransactionError?
        func exists(_ alias: String) throws -> Bool { lock.scoped { keys[alias] != nil } }
        func generate(_ alias: String, biometricOnly: Bool) throws -> Data {
            lock.scoped {
                let key = P256.Signing.PrivateKey()
                keys[alias] = key
                return key.publicKey.derRepresentation
            }
        }
        func promote(_ staged: String, to alias: String) throws {
            try lock.scoped {
                guard let key = keys[staged] else { throw TransactionError.notEnrolled }
                keys[alias] = key
                keys[staged] = nil
            }
        }
        func sign(_ alias: String, _ bytes: Data, reason: String) throws -> Data {
            try lock.scoped {
                if let failure { throw failure }
                guard let key = keys[alias] else { throw TransactionError.notEnrolled }
                return try key.signature(for: bytes).rawRepresentation
            }
        }
        func delete(_ alias: String) throws { lock.scoped { keys[alias] = nil } }
        func publicKey(_ alias: String) -> Data? { lock.scoped { keys[alias]?.publicKey.derRepresentation } }
    }

    private func transactionBridge(_ txKeys: SoftwareTransactionKeys) -> SentomaruFlutterBridge {
        let keys = keys, store = store, appAttest = appAttest, server = server, clock = clock
        return SentomaruFlutterBridge(factory: { config in
            let client = SentomaruClient(config: config, keys: keys, store: store, appAttest: appAttest, now: { clock.now() },
                                         offlineStore: MemoryOfflineStore(), offlineClocks: .live)
            return .init(client: client, enroll: { try await server.enroll($0) }, renew: { try await server.renew($0) })
        }, transactionKeys: { txKeys })
    }

    private final class MemoryOfflineStore: OfflineStateStore, @unchecked Sendable {
        private let lock = NSLock()
        private var blobs: [String: Data] = [:]
        func read(_ alias: String) throws -> Data? { lock.scoped { blobs[alias] } }
        func write(_ alias: String, _ data: Data) throws { lock.scoped { blobs[alias] = data } }
        func delete(_ alias: String) throws { lock.scoped { blobs[alias] = nil } }
    }

    private func enrolled(_ b: SentomaruFlutterBridge) async {
        _ = await call(b, "initialize", config())
        let reply = await call(b, "enroll", challenge())
        XCTAssertEqual(reply.kind, .success)
    }

    func testTransactionKeyBeforeInitializeAndBeforeEnrollment() async {
        let b = transactionBridge(SoftwareTransactionKeys())
        var reply = await call(b, "txIsEnrolled")
        XCTAssertEqual(reply, .failure("NotInitialized"))
        _ = await call(b, "initialize", config())
        reply = await call(b, "txIsEnrolled") // no installation yet: there is no alias to hang the key on
        XCTAssertEqual(reply, .failure("NotInitialized"))
    }

    func testTransactionKeyCreateSignDiscard() async throws {
        let txKeys = SoftwareTransactionKeys()
        let b = transactionBridge(txKeys)
        await enrolled(b)
        var reply = await call(b, "txIsEnrolled")
        XCTAssertEqual(reply, .success(false))
        reply = await call(b, "txKeyCreate", ["biometricOnly": true])
        XCTAssertEqual((reply.value as? Data)?.count, 91)
        reply = await call(b, "txIsEnrolled") // staged only: the server has not accepted it yet
        XCTAssertEqual(reply, .success(false))
        reply = await call(b, "txKeyCommit")
        XCTAssertEqual(reply, .success(nil))
        reply = await call(b, "txIsEnrolled")
        XCTAssertEqual(reply, .success(true))
        reply = await call(b, "txSign", ["operationId": "0123456789abcdef-op", "body": Data("{\"amount\":10}".utf8), "reason": "Confirmar"])
        let value = try XCTUnwrap(reply.value as? String)
        XCTAssertTrue(TransactionSignature.isHeaderValue(value), value)
        reply = await call(b, "txSign", ["operationId": "x"]) // no body
        XCTAssertEqual(reply, .failure("InvalidRequest:PARAMS"))
        reply = await call(b, "txKeyCreate", ["biometricOnly": "yes"])
        XCTAssertEqual(reply, .failure("InvalidRequest:PARAMS"))
        reply = await call(b, "txDiscard")
        XCTAssertEqual(reply, .success(nil))
        reply = await call(b, "txIsEnrolled")
        XCTAssertEqual(reply, .success(false))
    }

    /// Shield #5: re-enrolling stages a new key; the old one keeps signing until `txKeyCommit` (after the server's 201).
    func testTransactionReEnrollmentKeepsTheOldKeyUntilCommit() async throws {
        let txKeys = SoftwareTransactionKeys()
        let b = transactionBridge(txKeys)
        await enrolled(b)
        var reply = await call(b, "txKeyCreate")
        let first = try XCTUnwrap(reply.value as? Data)
        _ = await call(b, "txKeyCommit")
        reply = await call(b, "txKeyCreate")
        let staged = try XCTUnwrap(reply.value as? Data)
        XCTAssertNotEqual(first, staged)
        reply = await call(b, "txIsEnrolled")
        XCTAssertEqual(reply, .success(true)) // the old key still stands
        reply = await call(b, "txKeyAbort") // the server refused
        XCTAssertEqual(reply, .success(nil))
        reply = await call(b, "txIsEnrolled")
        XCTAssertEqual(reply, .success(true))
        reply = await call(b, "txKeyCommit") // nothing staged any more
        XCTAssertEqual(reply, .failure("Transaction:NOT_ENROLLED"))
        reply = await call(b, "txSign", ["operationId": "0123456789abcdef-op", "body": Data()])
        XCTAssertEqual(reply.kind, .success)
    }

    func testTransactionErrorsAreTheClosedCodes() async {
        let txKeys = SoftwareTransactionKeys()
        let b = transactionBridge(txKeys)
        await enrolled(b)
        _ = await call(b, "txKeyCreate")
        _ = await call(b, "txKeyCommit")
        let cases: [(TransactionError, String)] = [
            (.cancelled, "Transaction:CANCELLED"), (.keyInvalidated, "Transaction:KEY_INVALIDATED"), (.lockedOut, "Transaction:LOCKED_OUT"),
            (.noUserAuthentication, "Transaction:NO_USER_AUTHENTICATION"), (.unavailable, "Transaction:UNAVAILABLE"),
            (.signingFailed, "Transaction:SIGNING_FAILED"), (.notEnrolled, "Transaction:NOT_ENROLLED"),
        ]
        for (error, code) in cases {
            txKeys.failure = error
            let reply = await call(b, "txSign", ["operationId": "0123456789abcdef-op", "body": Data()])
            XCTAssertEqual(reply, .failure(code))
        }
    }

    func testSnapshotWithScreenAddsTheTwoScreenIds() async throws {
        let environment = SignalsEnvironment(runtime: .device, isTraced: { false }, fileExists: { _ in false },
                                             canWriteOutsideSandbox: { false }, loadedImages: { [] }, platform: "ios",
                                             osVersion: { "27.0.0" }, screens: { .init(captured: true, screenCount: 2) })
        let b = SentomaruFlutterBridge(signals: SignalsCollector(environment: environment, now: { Date(timeIntervalSince1970: 1_793_275_200) }))
        var reply = await call(b, "collectSignalsSnapshot", ["rasp": false])
        var ids = try XCTUnwrap((reply.value as? [String: Any])?["observations"] as? [[String: Any]]).compactMap { $0["capabilityId"] as? String }
        XCTAssertFalse(ids.contains("screen_shared"))
        reply = await call(b, "collectSignalsSnapshot", ["rasp": false, "screen": true])
        let observations = try XCTUnwrap((reply.value as? [String: Any])?["observations"] as? [[String: Any]])
        ids = observations.compactMap { $0["capabilityId"] as? String }
        XCTAssertTrue(ids.contains("screen_capture") && ids.contains("screen_shared"), "\(ids)")
        // `screen` runs on the main thread (UIScreen): the facts above reach the observation.
        let shared = try XCTUnwrap(observations.first { $0["capabilityId"] as? String == "screen_shared" })
        XCTAssertEqual(shared["state"] as? String, "detected")
        reply = await call(b, "collectSignalsSnapshot", ["rasp": false, "screen": "yes"])
        XCTAssertEqual(reply, .failure("InvalidRequest:PARAMS"))
    }

    private var permitJson: String {
        let seed = TransactionSignature.base64URL(Data(1...32)) // synthetic
        return """
        {"permitId":"6f1c0000-0000-4000-8000-00000000d026","chainSeed":"\(seed)",
         "issuedAt":"2020-01-01T00:00:00Z","validUntil":"2099-01-01T00:00:00Z","maxItems":2,"driftToleranceSeconds":120}
        """
    }

    func testOfflineSealAndReconcileBody() async throws {
        let b = transactionBridge(SoftwareTransactionKeys())
        await enrolled(b)
        let digest = Data(SHA256.hash(data: Data("payload".utf8)))
        var seals: [[String: Any]] = []
        for _ in 0..<2 {
            let reply = await call(b, "offlineSeal", ["permit": permitJson, "operationDigest": digest])
            seals.append(try XCTUnwrap(reply.value as? [String: Any]))
        }
        XCTAssertEqual(seals.map { $0["seq"] as? Int }, [0, 1])
        XCTAssertEqual(seals[1]["prevHash"] as? String, seals[0]["hash"] as? String)
        var reply = await call(b, "offlineSeal", ["permit": permitJson, "operationDigest": digest])
        XCTAssertEqual(reply, .failure("Offline:CHAIN_FULL"))
        reply = await call(b, "offlineSeal", ["permit": permitJson, "operationDigest": Data(count: 5)])
        XCTAssertEqual(reply, .failure("Offline:INVALID_DIGEST"))
        reply = await call(b, "offlineSeal", ["permit": "{}", "operationDigest": digest])
        XCTAssertEqual(reply, .failure("Offline:PERMIT_INVALID"))

        reply = await call(b, "offlineReconcileBody", ["permit": permitJson, "seals": seals])
        let object = try XCTUnwrap(try JSONSerialization.jsonObject(with: try XCTUnwrap(reply.value as? Data)) as? [String: Any])
        XCTAssertEqual(object["permitId"] as? String, "6f1c0000-0000-4000-8000-00000000d026")
        XCTAssertEqual((object["items"] as? [[String: Any]])?.count, 2)
        reply = await call(b, "offlineReconcileBody", ["permit": permitJson, "seals": [["seq": 0]]])
        XCTAssertEqual(reply, .failure("InvalidRequest:PARAMS"))
    }

    func testOfflineSealNeedsAnInstallation() async {
        let b = transactionBridge(SoftwareTransactionKeys())
        _ = await call(b, "initialize", config())
        let reply = await call(b, "offlineSeal", ["permit": permitJson, "operationDigest": Data(count: 32)])
        XCTAssertEqual(reply, .failure("NotEnrolled"))
    }
}
