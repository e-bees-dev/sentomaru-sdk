import CryptoKit
import Foundation
@testable import Sentomaru
import XCTest

/// Enroll → sign → renew (D-09c assertion) → rotate → reset with fakes (software keys, fake App Attest, memory store,
/// fake server that re-verifies every byte). No simulator, no iPhone, no real Apple object.
final class ClientFlowTests: XCTestCase {
    var clock: TestClock!
    var keys: SoftwareKeys!
    var store: MemoryStore!
    var appAttest: FakeAppAttest!
    var config: SentomaruConfig!
    var server: FakeServer!
    var client: SentomaruClient!

    override func setUpWithError() throws {
        clock = TestClock()
        keys = SoftwareKeys()
        store = MemoryStore()
        appAttest = FakeAppAttest()
        config = try SentomaruConfig(organization: "org-a", app: "app-a", environment: "hml",
                                     allowedHosts: ["consumer.example"],
                                     enrollmentUrl: "https://consumer.example/v1/org-a/app-a/hml/installations",
                                     renewalUrl: "https://consumer.example/v1/org-a/app-a/hml/sessions")
        server = FakeServer(config: config, appAttest: appAttest)
        client = SentomaruClient(config: config, keys: keys, store: store, appAttest: appAttest, now: clock.function)
    }

    private func enroll() async throws -> EnrollmentGrant {
        let challenge = try server.challenge(now: clock.now)
        let server = self.server!
        return try await client.enroll(challenge) { try await server.enroll($0) }
    }

    private var renewSend: SentomaruClient.RenewalSend { let server = self.server!; return { try await server.renew($0) } }

    // MARK: enrollment

    func testEnrollBindsTheSecureEnclaveKeyWithAppAttest() async throws {
        let grant = try await enroll()
        XCTAssertEqual(grant.hardwareStatus, "device_attested")
        XCTAssertEqual(grant.attestationStatus, "verified")
        XCTAssertEqual(grant.issuedAt, clock.now)
        let state = try await client.state()
        XCTAssertEqual(state, .enrolled)
        let record = try XCTUnwrap(try store.read())
        XCTAssertEqual(record.grant, grant)
        XCTAssertNotNil(record.appAttestKeyId)
        XCTAssertEqual(record.publicKey, try keys.publicKey(record.alias))
        XCTAssertTrue(record.alias.hasPrefix("sentomaru.v1.\(config.identity).v1."))
        XCTAssertEqual(appAttest.attestations.count, 1)
        let sessionId = try await client.sessionId()
        XCTAssertEqual(sessionId, grant.sessionId)
    }

    func testEnrollWithoutAppAttestIsUnsupportedAndKeepsNothing() async throws {
        appAttest.supported = false
        let challenge = try server.challenge(now: clock.now)
        let server = self.server!
        await assertThrows(.unsupported(.APP_ATTEST)) { try await self.client.enroll(challenge) { try await server.enroll($0) } }
        XCTAssertNil(try store.read())
        XCTAssertTrue(keys.aliases.isEmpty)
        XCTAssertEqual(keys.generated, 0)
        XCTAssertTrue(server.enrollBodies.isEmpty, "nothing sent")
        let state = try await client.state()
        XCTAssertEqual(state, .notEnrolled)
    }

    func testEnrollWithoutSecureEnclaveIsUnsupportedAndKeepsNothing() async throws {
        keys.failGenerate = .unsupported(.SECURE_ENCLAVE)
        let challenge = try server.challenge(now: clock.now)
        let server = self.server!
        await assertThrows(.unsupported(.SECURE_ENCLAVE)) { try await self.client.enroll(challenge) { try await server.enroll($0) } }
        XCTAssertNil(try store.read())
        XCTAssertTrue(appAttest.attestations.isEmpty)
        XCTAssertTrue(server.enrollBodies.isEmpty)
    }

    func testAppAttestReportedUnsupportedDuringAttestationKeepsNothing() async throws {
        appAttest.failAttest = SentomaruError.unsupported(.APP_ATTEST)
        let challenge = try server.challenge(now: clock.now)
        let server = self.server!
        await assertThrows(.unsupported(.APP_ATTEST)) { try await self.client.enroll(challenge) { try await server.enroll($0) } }
        XCTAssertNil(try store.read())
        XCTAssertTrue(keys.aliases.isEmpty)
    }

    func testAttestationFailureOfAnotherKindIsKeyUnavailableAndRetryable() async throws {
        struct Opaque: Error {}
        appAttest.failAttest = Opaque()
        let challenge = try server.challenge(now: clock.now)
        let server = self.server!
        await assertThrows(.keyUnavailable) { try await self.client.enroll(challenge) { try await server.enroll($0) } }
        appAttest.failAttest = nil
        let grant = try await client.enroll(challenge) { try await server.enroll($0) }
        XCTAssertEqual(grant.keyId, challenge.id)
        XCTAssertEqual(keys.generated, 1, "the same request key is reused")
    }

    /// Review R M5: the App Attest key id is persisted before `attestKey`; after `serverUnavailable` the retry attests
    /// the same key (no orphan key), after another failure a new key is generated (Apple's rule).
    func testAttestationRetryReusesThePersistedAppAttestKey() async throws {
        let challenge = try server.challenge(now: clock.now)
        let server = self.server!
        appAttest.failAttest = SentomaruError.networkUnavailable
        await assertThrows(.networkUnavailable) { try await self.client.enroll(challenge) { try await server.enroll($0) } }
        let pendingKeyId = try XCTUnwrap(try store.read()?.attestingKeyId, "persisted before attestKey")
        XCTAssertNil(try store.read()?.body)
        // A new client (process death) finds the same key id.
        client = SentomaruClient(config: config, keys: keys, store: store, appAttest: appAttest, now: clock.function)
        appAttest.failAttest = nil
        _ = try await client.enroll(challenge) { try await server.enroll($0) }
        XCTAssertEqual(appAttest.generatedKeys, 1, "no orphan App Attest key")
        let record = try XCTUnwrap(try store.read())
        XCTAssertEqual(record.appAttestKeyId, pendingKeyId)
        XCTAssertNil(record.attestingKeyId, "cleared once attested")
    }

    func testAttestationFailureOtherThanServerUnavailableDropsTheAppAttestKey() async throws {
        let challenge = try server.challenge(now: clock.now)
        let server = self.server!
        appAttest.failAttest = SentomaruError.keyInvalidated
        await assertThrows(.keyInvalidated) { try await self.client.enroll(challenge) { try await server.enroll($0) } }
        XCTAssertNil(try store.read()?.attestingKeyId)
        appAttest.failAttest = nil
        _ = try await client.enroll(challenge) { try await server.enroll($0) }
        XCTAssertEqual(appAttest.generatedKeys, 2, "a key that failed attestation is not attested again")
    }

    func testRotationAttestationRetryReusesThePersistedAppAttestKey() async throws {
        _ = try await enroll()
        let challenge = try server.challenge(now: clock.now)
        let server = self.server!
        appAttest.failAttest = SentomaruError.networkUnavailable
        await assertThrows(.networkUnavailable) { try await self.client.rotate(challenge) { try await server.enroll($0) } }
        let pendingKeyId = try XCTUnwrap(try store.read()?.attestingKeyId)
        appAttest.failAttest = nil
        _ = try await client.rotate(challenge) { try await server.enroll($0) }
        XCTAssertEqual(appAttest.generatedKeys, 2, "enrollment key + one rotation key")
        let record = try XCTUnwrap(try store.read())
        XCTAssertEqual(record.appAttestKeyId, pendingKeyId)
        XCTAssertNil(record.attestingKeyId)
    }

    /// Review R N2: one live client per scope; the same scope with another configuration fails clearly.
    func testLiveClientIsOnePerScopeAndRefusesAnotherConfiguration() throws {
        func make(renewal: String?, hosts: Set<String> = ["consumer.example"]) throws -> SentomaruConfig {
            try SentomaruConfig(organization: "org-live", app: "app-a", environment: "hml", allowedHosts: hosts,
                                enrollmentUrl: "https://consumer.example/v1/org-live/app-a/hml/installations", renewalUrl: renewal)
        }
        let renewal = "https://consumer.example/v1/org-live/app-a/hml/sessions"
        let first = try SentomaruClient.live(config: try make(renewal: renewal))
        XCTAssertTrue(first === (try SentomaruClient.live(config: try make(renewal: renewal))))
        XCTAssertThrowsError(try SentomaruClient.live(config: try make(renewal: nil))) {
            XCTAssertEqual($0 as? SentomaruError, .invalidRequest(.PARAMS))
        }
        XCTAssertThrowsError(try SentomaruClient.live(config: try make(renewal: renewal, hosts: ["consumer.example", "b.example"])))
    }

    func testRetryAfterNetworkFailureResendsTheSameFrozenBytes() async throws {
        let challenge = try server.challenge(now: clock.now)
        let server = self.server!
        server.enrollFailures = [URLError(.notConnectedToInternet)]
        await assertThrows(.networkUnavailable) { try await self.client.enroll(challenge) { try await server.enroll($0) } }
        let state = try await client.state()
        XCTAssertEqual(state, .enrollmentRequired)
        clock.advance(5)
        _ = try await client.enroll(challenge) { try await server.enroll($0) }
        XCTAssertEqual(server.enrollBodies.count, 2)
        XCTAssertEqual(server.enrollBodies[0], server.enrollBodies[1], "same frozen body, new signature")
        XCTAssertEqual(appAttest.attestations.count, 1, "attested once")
        // A third call returns the stored grant without sending.
        _ = try await client.enroll(challenge) { try await server.enroll($0) }
        XCTAssertEqual(server.enrollBodies.count, 2)
    }

    func testAnotherChallengeWhilePendingIsEnrollmentRequired() async throws {
        let first = try server.challenge(now: clock.now)
        let server = self.server!
        server.enrollFailures = [URLError(.timedOut)]
        await assertThrows(.networkUnavailable) { try await self.client.enroll(first) { try await server.enroll($0) } }
        let second = try server.challenge(now: clock.now)
        await assertThrows(.enrollmentRequired) { try await self.client.enroll(second) { try await server.enroll($0) } }
    }

    /// Negative "clock": an expired challenge never reaches the key or the network.
    func testExpiredChallengeIsRefusedLocally() async throws {
        let challenge = try server.challenge(now: clock.now, ttl: 120)
        clock.advance(120)
        let server = self.server!
        await assertThrows(.challengeExpired) { try await self.client.enroll(challenge) { try await server.enroll($0) } }
        XCTAssertEqual(keys.generated, 0)
        XCTAssertTrue(server.enrollBodies.isEmpty)
    }

    func testGrantForAnotherKeyIsRefused() async throws {
        let challenge = try server.challenge(now: clock.now)
        await assertThrows(.invalidRequest(.PARAMS)) {
            try await self.client.enroll(challenge) { _ in
                try EnrollmentGrant(installationId: UUIDText.random(), keyId: UUIDText.random(), sessionId: UUIDText.random(),
                                    hardwareStatus: "device_attested", attestationStatus: "verified")
            }
        }
    }

    func testCancelledTaskDoesNotEnroll() async throws {
        let challenge = try server.challenge(now: clock.now)
        let client = self.client!, server = self.server!
        let task = Task { () async throws -> EnrollmentGrant in
            withUnsafeCurrentTask { $0?.cancel() }
            return try await client.enroll(challenge) { try await server.enroll($0) }
        }
        do {
            _ = try await task.value
            XCTFail("enrolled")
        } catch {
            XCTAssertEqual((error as? SentomaruError)?.code, "Cancelled")
        }
        XCTAssertTrue(server.enrollBodies.isEmpty)
    }

    // MARK: signing

    func testSignUsesTheEnrolledKeyAndTheGrant() async throws {
        let grant = try await enroll()
        let signed = try await client.sign(method: "POST", targetURI: "https://consumer.example/api/ops?x=1", operation: "submit",
                                           body: Data("{\"a\":1}".utf8), optional: [Profile.operationIdHeader: "op-0123456789abcdef"])
        let record = try XCTUnwrap(try store.read())
        let params = try FakeServer.verifySignature(signed, spki: try XCTUnwrap(record.publicKey))
        XCTAssertEqual(params.keyId, grant.keyId)
        XCTAssertEqual(signed.header("x-sentomaru-session"), grant.sessionId)
        XCTAssertEqual(signed.header("x-sentomaru-operation-id"), "op-0123456789abcdef")
        // Negative "clock": created/expires come from the injected clock (whole seconds), lifetime 60 s.
        XCTAssertEqual(params.created, Int64(clock.now.timeIntervalSince1970))
        XCTAssertEqual(params.expires, params.created + 60)
    }

    func testSigningRefusals() async throws {
        await assertThrows(.notEnrolled) {
            try await self.client.sign(method: "POST", targetURI: "https://consumer.example/a", operation: "x", body: Data())
        }
        _ = try await enroll()
        await assertThrows(.hostNotAllowed) {
            try await self.client.sign(method: "POST", targetURI: "https://other.example/a", operation: "x", body: Data())
        }
        await assertThrows(.hostNotAllowed) {
            try await self.client.sign(method: "POST", targetURI: "http://consumer.example/a", operation: "x", body: Data())
        }
        await assertThrows(.invalidRequest(.HEADER_NAME)) {
            try await self.client.sign(method: "POST", targetURI: "https://consumer.example/a", operation: "x", body: Data(),
                                       optional: ["x-other": "1"])
        }
        await assertThrows(.bodyTooLarge(size: 65537)) {
            try await self.client.sign(method: "POST", targetURI: "https://consumer.example/a", operation: "x",
                                       body: Data(count: 65537))
        }
        var headers = config.headers(session: UUIDText.random(), operation: "x")
        let frozen = try FrozenRequest(method: "POST", targetURI: "https://consumer.example/a", headers: headers, body: Data())
        await assertThrows(.invalidRequest(.HEADER_VALUE)) { try await self.client.signRequest(frozen) }
        let session = try await client.sessionId()
        headers = config.headers(session: try XCTUnwrap(session), operation: "x")
        _ = try await client.signRequest(try FrozenRequest(method: "POST", targetURI: "https://consumer.example/a",
                                                           headers: headers, body: Data()))
    }

    func testLostSecureEnclaveKeyIsKeyInvalidated() async throws {
        _ = try await enroll()
        keys.lose(try XCTUnwrap(try store.read()).alias)
        let state = try await client.state()
        XCTAssertEqual(state, .keyInvalidated)
        await assertThrows(.keyInvalidated) {
            try await self.client.sign(method: "POST", targetURI: "https://consumer.example/a", operation: "x", body: Data())
        }
        try await client.reset()
        let after = try await client.state()
        XCTAssertEqual(after, .notEnrolled)
    }

    func testForeignRecordIsKeyInvalidated() async throws {
        _ = try await enroll()
        let other = try SentomaruConfig(organization: "org-b", app: "app-a", environment: "hml", allowedHosts: ["consumer.example"],
                                        enrollmentUrl: "https://consumer.example/v1/org-b/app-a/hml/installations")
        let foreign = SentomaruClient(config: other, keys: keys, store: store, appAttest: appAttest, now: clock.function)
        await assertThrows(.keyInvalidated) { try await foreign.state() }
    }

    // MARK: renewal (J-04r + D-09c)

    func testRenewalSendsAnAssertionBoundToSessionNonceAndKey() async throws {
        let first = try await enroll()
        var previous = first
        for round in 1 ... 3 {
            clock.advance(600 - 120)
            let due = try await client.needsRenewal()
            XCTAssertTrue(due, "round \(round)")
            let next = try await client.renew(send: renewSend)
            XCTAssertEqual(next.installationId, first.installationId)
            XCTAssertEqual(next.keyId, first.keyId)
            XCTAssertNotEqual(next.sessionId, previous.sessionId)
            XCTAssertEqual(next.hardwareStatus, "device_attested")
            XCTAssertEqual(next.ttlSeconds, 600)
            XCTAssertEqual(server.installation(first.keyId)?.counter, UInt32(round), "counter advanced")
            previous = next
        }
        XCTAssertEqual(appAttest.assertions.count, 3)
        XCTAssertEqual(Set(appAttest.assertions.map(\.clientDataHash)).count, 3, "a new clientData every time")
        let notDue = try await client.needsRenewal()
        XCTAssertFalse(notDue)
        // The renewed grant signs.
        let signed = try await client.sign(method: "GET", targetURI: "https://consumer.example/a", operation: "x", body: Data())
        XCTAssertEqual(signed.header("x-sentomaru-session"), previous.sessionId)
    }

    func testRenewalScheduleAndRenewIfDue() async throws {
        _ = try await enroll()
        clock.advance(600 - 121)
        let early = try await client.renewIfDue(send: renewSend)
        XCTAssertNil(early)
        XCTAssertTrue(server.renewBodies.isEmpty)
        clock.advance(1)
        let renewed = try await client.renewIfDue(send: renewSend)
        XCTAssertNotNil(renewed)
        try await client.markGrantStale()
        let stale = try await client.needsRenewal()
        XCTAssertTrue(stale)
    }

    func testRenewalFailureBacksOffAndKeepsTheGrant() async throws {
        let grant = try await enroll()
        server.renewFailures = [URLError(.networkConnectionLost)]
        await assertThrows(.networkUnavailable) { try await self.client.renew(send: self.renewSend) }
        let sessionId = try await client.sessionId()
        XCTAssertEqual(sessionId, grant.sessionId)
        var gate = try await client.renewalGate()
        XCTAssertEqual(gate, .init(backingOff: true, canRenewNow: false, lastFailure: "NetworkUnavailable"))
        clock.advance(59)
        let stillBacking = try await client.renewalBackingOff()
        XCTAssertTrue(stillBacking)
        let due = try await client.needsRenewal()
        XCTAssertFalse(due, "backoff wins over a due grant")
        clock.advance(1)
        gate = try await client.renewalGate()
        XCTAssertEqual(gate, .init(backingOff: false, canRenewNow: true, lastFailure: nil))
        _ = try await client.renew(send: renewSend)
    }

    func testSuspendedRenewalsBackOffInSteps() async throws {
        _ = try await enroll()
        server.renewFailures = Array(repeating: SentomaruError.serverRejected(.SUSPENDED), count: 4)
        for step: TimeInterval in [5, 15, 60, 60] {
            await assertThrows(.serverRejected(.SUSPENDED)) { try await self.client.renew(send: self.renewSend) }
            let failure = try await client.lastRenewalFailure()
            XCTAssertEqual(failure, "ServerRejected:SUSPENDED")
            clock.advance(step - 1)
            let backing = try await client.renewalBackingOff()
            XCTAssertTrue(backing, "step \(step)")
            clock.advance(1)
            let free = try await client.canRenewNow()
            XCTAssertTrue(free, "step \(step)")
        }
        _ = try await client.renew(send: renewSend)
        let state = try await client.state()
        XCTAssertEqual(state, .enrolled)
    }

    func testSessionUnavailableDropsTheGrant() async throws {
        _ = try await enroll()
        server.renewFailures = [SentomaruError.enrollmentRequired]
        await assertThrows(.enrollmentRequired) { try await self.client.renew(send: self.renewSend) }
        let state = try await client.state()
        XCTAssertEqual(state, .enrollmentRequired)
        let backing = try await client.renewalBackingOff()
        XCTAssertFalse(backing)
        try await client.reset()
        _ = try await enroll()
    }

    /// A forged `{}` body (no assertion), a replayed assertion and a lost App Attest key are all refused.
    func testServerRefusesAssertionsTheSdkDidNotBind() async throws {
        let grant = try await enroll()
        let record = try XCTUnwrap(try store.read())
        // Replay: a valid assertion of a previous renewal, re-signed with a fresh nonce, is refused by the binding.
        _ = try await client.renew(send: renewSend)
        let replayed = try XCTUnwrap(server.renewBodies.last)
        let session = try XCTUnwrap(server.installation(grant.keyId)?.sessionId)
        let forged = try FrozenRequest(method: "POST", targetURI: try XCTUnwrap(config.renewalUrl),
                                       headers: config.headers(session: session, operation: SentomaruClient.renewOperation), body: replayed)
        let signed = try MessageSigner.sign(forged, params: try SignatureParams.now(clock.now, keyId: grant.keyId, nonce: UUIDText.random())) {
            try self.keys.sign(record.alias, $0)
        }
        await assertThrows(.enrollmentRequired) { try await self.server.renew(signed) }
        // The App Attest key no longer exists on the device: the SDK drops the grant (enroll again).
        appAttest.removeKey(try XCTUnwrap(record.appAttestKeyId))
        await assertThrows(.enrollmentRequired) { try await self.client.renew(send: self.renewSend) }
        let state = try await client.state()
        XCTAssertEqual(state, .enrollmentRequired)
    }

    func testAssertionFailureBacksOffAndKeepsTheGrant() async throws {
        _ = try await enroll()
        appAttest.failAssertion = SentomaruError.networkUnavailable
        await assertThrows(.networkUnavailable) { try await self.client.renew(send: self.renewSend) }
        XCTAssertTrue(server.renewBodies.isEmpty, "nothing sent without an assertion")
        let state = try await client.state()
        XCTAssertEqual(state, .enrolled)
        let backing = try await client.renewalBackingOff()
        XCTAssertTrue(backing)
    }

    func testRenewedGrantOfAnotherKeyIsRefused() async throws {
        let grant = try await enroll()
        await assertThrows(.invalidRequest(.PARAMS)) {
            try await self.client.renew { _ in
                try RenewedGrant(installationId: grant.installationId, keyId: UUIDText.random(), sessionId: UUIDText.random(), ttlSeconds: 600)
            }
        }
        let sessionId = try await client.sessionId()
        XCTAssertEqual(sessionId, grant.sessionId)
    }

    func testRenewalWithoutRenewalUrlOrEnrollment() async throws {
        let plain = try SentomaruConfig(organization: "org-a", app: "app-a", environment: "hml", allowedHosts: ["consumer.example"],
                                        enrollmentUrl: "https://consumer.example/v1/org-a/app-a/hml/installations")
        let noRenewal = SentomaruClient(config: plain, keys: keys, store: MemoryStore(), appAttest: appAttest, now: clock.function)
        await assertThrows(.invalidRequest(.PARAMS)) { try await noRenewal.renew(send: self.renewSend) }
        await assertThrows(.notEnrolled) { try await self.client.renew(send: self.renewSend) }
    }

    /// One renewal at a time per installation: concurrent callers are serialized and every counter is accepted.
    func testConcurrentRenewalsAreSerialized() async throws {
        _ = try await enroll()
        server.renewDelay = 20_000_000
        let client = self.client!, send = renewSend
        try await withThrowingTaskGroup(of: EnrollmentGrant.self) { group in
            for _ in 0 ..< 5 { group.addTask { try await client.renew(send: send) } }
            for try await _ in group {}
        }
        XCTAssertEqual(server.maxConcurrentRenewals, 1)
        XCTAssertEqual(server.renewBodies.count, 5)
    }

    // MARK: rotation (D-04d)

    func testRotateReplacesTheKeyWithAProvenPredecessor() async throws {
        let first = try await enroll()
        let oldAlias = try XCTUnwrap(try store.read()).alias
        let challenge = try server.challenge(now: clock.now)
        let server = self.server!
        let rotated = try await client.rotate(challenge) { try await server.enroll($0) }
        XCTAssertEqual(rotated.keyId, challenge.id)
        XCTAssertNotEqual(rotated.installationId, first.installationId)
        let record = try XCTUnwrap(try store.read())
        XCTAssertNotEqual(record.alias, oldAlias)
        XCTAssertTrue(record.alias.hasPrefix("sentomaru.v1.\(config.identity).v2."))
        XCTAssertEqual(record.generation, 2)
        XCTAssertEqual(appAttest.attestations.count, 2, "a new App Attest key and attestation")
        XCTAssertNotEqual(record.appAttestKeyId, server.installation(first.keyId)?.appAttestKeyId)
        let retired = try await client.retiredKeys()
        XCTAssertEqual(retired.map(\.alias), [oldAlias])
        XCTAssertTrue(keys.aliases.contains(oldAlias))
        let body = try XCTUnwrap(try JSONSerialization.jsonObject(with: try XCTUnwrap(server.enrollBodies.last)) as? [String: Any])
        XCTAssertNotNil(body["predecessor"], "proof checked by the fake server with the old key")
        // The new key renews with the new App Attest key.
        clock.advance(500)
        _ = try await client.renew(send: renewSend)
        // Grace period over: the old key is deleted.
        clock.advance(7 * 24 * 3600)
        _ = try await client.state()
        XCTAssertFalse(keys.aliases.contains(oldAlias))
        let after = try await client.retiredKeys()
        XCTAssertTrue(after.isEmpty)
    }

    func testRotationWhoseAnswerWasLostIsAdoptedWithTheOldBody() async throws {
        _ = try await enroll()
        let lost = try server.challenge(now: clock.now)
        let server = self.server!
        // The server commits the rotation but the answer is lost.
        let committed = SendBox()
        await assertThrows(.networkUnavailable) {
            try await self.client.rotate(lost) { signed in
                committed.grant = try await server.enroll(signed)
                throw URLError(.networkConnectionLost)
            }
        }
        XCTAssertEqual(try XCTUnwrap(try store.read()).pendingRotation?.sent, true)
        clock.advance(300) // the lost challenge expired
        let fresh = try server.challenge(now: clock.now)
        let adopted = try await client.rotate(fresh) { try await server.enroll($0) }
        XCTAssertEqual(adopted.keyId, lost.id, "identical replay returned the original grant")
        XCTAssertEqual(adopted.installationId, committed.grant?.installationId)
        XCTAssertEqual(server.enrollBodies.suffix(2).first, server.enrollBodies.last)
        XCTAssertNil(try XCTUnwrap(try store.read()).pendingRotation)
    }

    /// RB16-1: a sent rotation the server proves it never accepted is dropped (key deleted); if the next attempt then fails
    /// before it persists its own pending rotation (App Attest offline), the stale record must not stay in the store with
    /// its key gone, or every later `rotate` tries to resend it and fails with `keyUnavailable`.
    func testRotationAfterADroppedSentPendingIsNotBlockedByTheStaleRecord() async throws {
        _ = try await enroll()
        let lost = try server.challenge(now: clock.now)
        let server = self.server!
        await assertThrows(.networkUnavailable) {
            try await self.client.rotate(lost) { _ in throw URLError(.networkConnectionLost) }
        }
        XCTAssertEqual(try XCTUnwrap(try store.read()).pendingRotation?.sent, true)
        clock.advance(300)
        let fresh = try server.challenge(now: clock.now)
        appAttest.failAttest = SentomaruError.networkUnavailable
        await assertThrows(.networkUnavailable) {
            try await self.client.rotate(fresh) { _ in throw SentomaruError.serverRejected(.EXPIRED) }
        }
        appAttest.failAttest = nil
        let rotated = try await client.rotate(fresh) { try await server.enroll($0) }
        XCTAssertEqual(rotated.keyId, fresh.id)
    }

    func testRotationRefusedAsPredecessorInvalidDropsThePending() async throws {
        _ = try await enroll()
        let challenge = try server.challenge(now: clock.now)
        await assertThrows(.reenrollmentRefused) {
            try await self.client.rotate(challenge) { _ in throw SentomaruError.reenrollmentRefused }
        }
        // The first refusal keeps the (sent) pending rotation; a resend that is refused drops it.
        let pending = try XCTUnwrap(try XCTUnwrap(try store.read()).pendingRotation)
        XCTAssertTrue(pending.sent)
        let other = try server.challenge(now: clock.now)
        await assertThrows(.reenrollmentRefused) {
            try await self.client.rotate(other) { _ in throw SentomaruError.reenrollmentRefused }
        }
        XCTAssertNil(try XCTUnwrap(try store.read()).pendingRotation)
        XCTAssertFalse(keys.aliases.contains(pending.alias))
        let state = try await client.state()
        XCTAssertEqual(state, .enrolled, "the current key still signs")
    }

    func testRotateRequiresEnrollmentAndAppAttest() async throws {
        let challenge = try server.challenge(now: clock.now)
        let server = self.server!
        await assertThrows(.notEnrolled) { try await self.client.rotate(challenge) { try await server.enroll($0) } }
        _ = try await enroll()
        appAttest.supported = false
        let next = try server.challenge(now: clock.now)
        await assertThrows(.unsupported(.APP_ATTEST)) { try await self.client.rotate(next) { try await server.enroll($0) } }
        let state = try await client.state()
        XCTAssertEqual(state, .enrolled)
    }

    // MARK: reset

    func testResetDeletesOwnedKeysAndTheRecord() async throws {
        _ = try await enroll()
        let challenge = try server.challenge(now: clock.now)
        let server = self.server!
        _ = try await client.rotate(challenge) { try await server.enroll($0) }
        XCTAssertEqual(keys.aliases.count, 2)
        _ = try keys.generate("someone-else")
        try await client.reset()
        XCTAssertEqual(keys.aliases, ["someone-else"])
        XCTAssertNil(try store.read())
        let state = try await client.state()
        XCTAssertEqual(state, .notEnrolled)
    }
}

final class SendBox: @unchecked Sendable { var grant: EnrollmentGrant? }
