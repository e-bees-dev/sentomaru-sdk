import Foundation
@testable import Sentomaru
import Security
import XCTest

private func testUUID() -> String { UUID().uuidString.lowercased() }

private func testChallenge(id: String? = nil, now: Date) throws -> EnrollmentChallenge {
    try EnrollmentChallenge(id: id ?? testUUID(), token: Data(repeating: 7, count: 32).base64EncodedString(),
                            attestationChallenge: Data(repeating: 8, count: 32), expiresAt: now.addingTimeInterval(120))
}

private func testGrant(keyId: String) throws -> EnrollmentGrant {
    try EnrollmentGrant(installationId: testUUID(), keyId: keyId, sessionId: testUUID(), hardwareStatus: "device_attested",
                        attestationStatus: "verified")
}

/// A challenge provider paired with a grant sender whose keyId always matches the challenge just issued
/// (`SentomaruClient.enroll` refuses a mismatched keyId). No `self` capture: safe as a `@Sendable` closure pair.
private func testPaired(now: @escaping @Sendable () -> Date) -> (ChallengeProvider, SentomaruClient.EnrollmentSend) {
    let lastId = Sync("")
    let provider: ChallengeProvider = { _, _ in
        let c = try testChallenge(now: now())
        lastId.set(c.id)
        return c
    }
    let sender: SentomaruClient.EnrollmentSend = { _ in try testGrant(keyId: lastId.get()) }
    return (provider, sender)
}

/// Thread-safe box for test state a `@Sendable` closure needs to read or mutate (Swift's Sendable checker cannot
/// see that `AsyncSerial`/the test's own sequencing makes a plain var safe here).
private final class Sync<T>: @unchecked Sendable {
    private let lock = NSLock()
    private var value: T
    init(_ value: T) { self.value = value }
    func get() -> T { lock.criticalSection { value } }
    func set(_ v: T) { lock.criticalSection { value = v } }
    func update(_ body: (inout T) -> Void) { lock.criticalSection { body(&value) } }
}

/// Polls `flag` until it is set, for a test thread waiting on another `Task`. `@Sendable` (free function, not a
/// local closure) so it can itself be called from inside a `@Sendable` closure.
@Sendable private func testWait(_ flag: Sync<Bool>, timeout: TimeInterval = 2) async throws {
    let deadline = Date().addingTimeInterval(timeout)
    while !flag.get() {
        guard Date() < deadline else { throw XCTSkip("gate never signalled") }
        try await Task.sleep(nanoseconds: 5_000_000)
    }
}

/// D-W-port: `EnrollmentAssurance` against a real `SentomaruClient` with in-memory fakes (model: ClientFlowTests)
/// and a real Keychain-backed `PrincipalStore` under a throwaway file keychain on macOS (model: KeychainTests).
/// No rotation scenarios here: iOS has no `reenrollmentReason`, so `EnrollmentAssurance` never attempts one.
final class EnrollmentAssuranceTests: XCTestCase {
    private var clock: TestClock!
    private var keys: SoftwareKeys!
    private var store: MemoryStore!
    private var appAttest: FakeAppAttest!
    private var config: SentomaruConfig!
    private var client: SentomaruClient!
    private var defaults: UserDefaults!
    private var principalStore: PrincipalStore!
    private var assurance: EnrollmentAssurance!

    #if os(macOS)
    private var keychain: SecKeychain?
    private var keychainPath = ""
    #endif
    private var service = ""

    override func setUpWithError() throws {
        clock = TestClock()
        keys = SoftwareKeys()
        store = MemoryStore()
        appAttest = FakeAppAttest()
        config = try SentomaruConfig(organization: "org-a", app: "app-a", environment: "hml",
                                     allowedHosts: ["consumer.example"],
                                     enrollmentUrl: "https://consumer.example/v1/org-a/app-a/hml/installations")
        client = SentomaruClient(config: config, keys: keys, store: store, appAttest: appAttest, now: clock.function)
        defaults = UserDefaults(suiteName: "sentomaru-test-\(UUID().uuidString)")
        service = "br.com.ebees.sentomaru.test.\(UUID().uuidString)"
        #if os(macOS)
        keychainPath = FileManager.default.temporaryDirectory.appendingPathComponent("sentomaru-test-\(UUID().uuidString).keychain-db").path
        let password = UUID().uuidString
        var created: SecKeychain?
        let status = SecKeychainCreate(keychainPath, UInt32(password.utf8.count), password, false, nil, &created)
        guard status == errSecSuccess, let created else { throw XCTSkip("no file keychain on this host (\(status))") }
        keychain = created
        principalStore = PrincipalStore(location: .file(created, service: service), account: "principal",
                                        defaults: defaults, mirrorKey: "mirror")
        #else
        principalStore = PrincipalStore(location: .dataProtection(service: service), account: "principal",
                                        defaults: defaults, mirrorKey: "mirror")
        #endif
        assurance = EnrollmentAssurance(client: client, principalStore: principalStore, defaults: defaults)
    }

    override func tearDown() {
        #if os(macOS)
        if let keychain { SecKeychainDelete(keychain) }
        try? FileManager.default.removeItem(atPath: keychainPath)
        #else
        SecItemDelete([kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
                       kSecUseDataProtectionKeychain as String: true] as CFDictionary)
        #endif
    }

    private func ensure(_ assurance: EnrollmentAssurance, _ subject: String, _ tenant: String = "t-1") async throws -> EnsureEnrolledResult {
        let now = clock.function
        let (provider, sender) = testPaired(now: now)
        return try await assurance.ensureEnrolled(subject: subject, tenant: tenant, challengeProvider: provider, grantSender: sender)
    }

    // MARK: - principalOf

    func testPrincipalOfIsStableAndSubjectSensitive() {
        XCTAssertEqual(EnrollmentAssurance.principalOf(subject: "u-1", tenant: "t-1").count, 64)
        XCTAssertEqual(EnrollmentAssurance.principalOf(subject: "u-1", tenant: "t-1"),
                       EnrollmentAssurance.principalOf(subject: "u-1", tenant: "t-1"))
        XCTAssertNotEqual(EnrollmentAssurance.principalOf(subject: "u-1", tenant: "t-1"),
                          EnrollmentAssurance.principalOf(subject: "u-2", tenant: "t-1"))
    }

    // MARK: - first enrollment and plain reuse

    func testNotEnrolledEnrollsOnceAndStoresThePrincipal() async throws {
        let reasons = Sync<[ReenrollReason]>([])
        assurance.onReenrollReason = { r in reasons.update { $0.append(r) } }

        let result = try await ensure(assurance, "u-1")

        XCTAssertEqual(keys.generated, 1)
        XCTAssertTrue(result.current)
        XCTAssertNotNil(result.sessionId)
        XCTAssertEqual(reasons.get(), [.stateNotEnrolled])
    }

    func testSameCallerAgainIsReusedWithNoEnrollAndNoReason() async throws {
        _ = try await ensure(assurance, "u-1")
        let reasons = Sync<[ReenrollReason]>([])
        assurance.onReenrollReason = { r in reasons.update { $0.append(r) } }
        let before = keys.generated

        let result = try await ensure(assurance, "u-1")

        XCTAssertEqual(keys.generated, before)
        XCTAssertTrue(result.current)
        XCTAssertNil(result.sessionId)
        XCTAssertTrue(reasons.get().isEmpty)
    }

    func testMirrorAloneDoesNotAuthorizeWithoutThePluginAlsoEnrolled() async throws {
        defaults.set(EnrollmentAssurance.principalOf(subject: "u-1", tenant: "t-1"), forKey: "mirror")

        _ = try await ensure(assurance, "u-1")

        XCTAssertEqual(keys.generated, 1) // state is notEnrolled: reenrolls regardless of the mirror
    }

    // MARK: - reenrolls when it must

    func testEnrolledWithNoPrincipalAnywhereReenrollsOnce() async throws {
        _ = try await ensure(assurance, "u-1")
        // Simulate "installation from before this contract": the plugin is enrolled but nothing is stored.
        principalStore.delete()
        let reasons = Sync<[ReenrollReason]>([])
        assurance.onReenrollReason = { r in reasons.update { $0.append(r) } }
        let before = keys.generated

        _ = try await ensure(assurance, "u-1")

        XCTAssertEqual(keys.generated, before + 1)
        XCTAssertEqual(reasons.get(), [.principalAbsent])
    }

    func testADifferentSubjectReenrollsEvenWithAMirrorForTheOldOne() async throws {
        _ = try await ensure(assurance, "u-1")
        let reasons = Sync<[ReenrollReason]>([])
        assurance.onReenrollReason = { r in reasons.update { $0.append(r) } }
        let before = keys.generated

        _ = try await ensure(assurance, "u-2")

        XCTAssertEqual(keys.generated, before + 1)
        XCTAssertEqual(reasons.get(), [.principalChanged])
    }

    // MARK: - forgetInstallation

    func testForgetInstallationErasesPrincipalAndMirrorAndResets() async throws {
        _ = try await ensure(assurance, "u-1")

        try await assurance.forgetInstallation()

        let state = try await client.state()
        XCTAssertEqual(state, .notEnrolled)
        XCTAssertNil(principalStore.read())
    }

    // MARK: - concurrency: the most recent caller wins

    func testTheMostRecentCallerWinsOverOneStillQueued() async throws {
        let started = Sync(false)
        let proceed = Sync(false)
        let now = clock.function
        let (secondProvider, secondSender) = testPaired(now: now)
        let assurance = self.assurance! // local let: safe to capture in the @Sendable closures below

        let firstId = Sync("")
        let gatedProvider: ChallengeProvider = { _, _ in
            started.set(true)
            try await testWait(proceed)
            let c = try testChallenge(now: now())
            firstId.set(c.id)
            return c
        }
        let firstSender: SentomaruClient.EnrollmentSend = { _ in try testGrant(keyId: firstId.get()) }

        let first = Task<EnsureEnrolledResult, Error> {
            try await assurance.ensureEnrolled(subject: "u-1", tenant: "t-1", challengeProvider: gatedProvider, grantSender: firstSender)
        }
        try await testWait(started)
        let second = Task<EnsureEnrolledResult, Error> {
            try await assurance.ensureEnrolled(subject: "u-2", tenant: "t-1", challengeProvider: secondProvider, grantSender: secondSender)
        }
        proceed.set(true)

        let firstResult = try await first.value
        let secondResult = try await second.value

        XCTAssertFalse(firstResult.current)
        XCTAssertTrue(secondResult.current)
    }

    // MARK: - legacy principal migration hook

    func testLegacyPrincipalMatchReusesAndCopiesIntoOwnStore() async throws {
        _ = try await ensure(assurance, "u-1") // enrolls for real so the plugin itself says enrolled
        principalStore.delete() // drop the SDK's own copy, as if migrating from an app-level store
        let calls = Sync(0)
        let migrating = EnrollmentAssurance(client: client, principalStore: principalStore, defaults: defaults, legacyPrincipal: {
            calls.update { $0 += 1 }
            return EnrollmentAssurance.principalOf(subject: "u-1", tenant: "t-1")
        })
        let before = keys.generated

        let result = try await ensure(migrating, "u-1")

        XCTAssertEqual(keys.generated, before) // reused: no new key
        XCTAssertTrue(result.current)
        XCTAssertEqual(calls.get(), 1)
        XCTAssertEqual(principalStore.read(), EnrollmentAssurance.principalOf(subject: "u-1", tenant: "t-1"))
    }

    func testLegacyPrincipalMismatchReenrolls() async throws {
        _ = try await ensure(assurance, "u-1")
        principalStore.delete()
        let migrating = EnrollmentAssurance(client: client, principalStore: principalStore, defaults: defaults, legacyPrincipal: {
            EnrollmentAssurance.principalOf(subject: "someone-else", tenant: "t-1")
        })
        let before = keys.generated

        _ = try await ensure(migrating, "u-1")

        XCTAssertEqual(keys.generated, before + 1)
        XCTAssertEqual(principalStore.read(), EnrollmentAssurance.principalOf(subject: "u-1", tenant: "t-1"))
    }

    func testLegacyPrincipalNotConsultedWhenNotEnrolled() async throws {
        let calls = Sync(0)
        let migrating = EnrollmentAssurance(client: client, principalStore: principalStore, defaults: defaults, legacyPrincipal: {
            calls.update { $0 += 1 }
            return "whatever"
        })

        _ = try await ensure(migrating, "u-1")

        XCTAssertEqual(calls.get(), 0)
    }

    // MARK: - iOS reinstall guard

    func testFirstCallForgetsAnyPrincipalAndResetsBeforeDeciding() async throws {
        // The Keychain says enrolled (a leftover installation survives reinstall); nothing migrated here is
        // consulted once the guard runs, so set up state directly rather than through `ensure`.
        let c = try testChallenge(now: clock.now)
        let rec = InstallationRecord(scopeIdentity: config.identity, alias: "sentomaru.v1.\(config.identity).v1.leftover",
                                     challenge: c, grant: try testGrant(keyId: c.id))
        try store.write(rec)
        _ = try keys.generate(rec.alias)
        principalStore.write("leftover-principal")

        let result = try await ensure(assurance, "u-1")

        XCTAssertNotNil(result.sessionId) // a real reenrollment happened, not a reuse of the leftover record
        XCTAssertTrue(defaults.bool(forKey: "sentomaru_enrollment_ios_installed"))
    }

    func testSecondCallDoesNotForgetAgain() async throws {
        defaults.set(true, forKey: "sentomaru_enrollment_ios_installed")

        _ = try await ensure(assurance, "u-1")

        XCTAssertEqual(keys.generated, 1) // one enroll from the normal notEnrolled path, no extra reset from the guard
    }

    /// A reset writes `nil` to the store before the enrollment that follows writes its own records; comparing the
    /// write count of a run that never had anything to forget (marker already set: no guard overhead at all)
    /// against a genuinely fresh device (no marker, but also nothing ever enrolled) proves the guard added no
    /// extra `store.write(nil)` in the second case - regardless of the exact number a plain enrollment itself needs.
    func testFreshInstallAlreadyNotEnrolledCostsNoExtraResetFromTheGuard() async throws {
        defaults.set(true, forKey: "sentomaru_enrollment_ios_installed")
        let baselineStore = MemoryStore()
        let baselineClient = SentomaruClient(config: config, keys: SoftwareKeys(), store: baselineStore, appAttest: FakeAppAttest(),
                                             now: clock.function)
        let baselineAssurance = EnrollmentAssurance(client: baselineClient, principalStore: principalStore, defaults: defaults)
        _ = try await ensure(baselineAssurance, "u-1")

        defaults.removeObject(forKey: "sentomaru_enrollment_ios_installed")
        let freshStore = MemoryStore()
        let freshClient = SentomaruClient(config: config, keys: SoftwareKeys(), store: freshStore, appAttest: FakeAppAttest(),
                                          now: clock.function)
        let freshAssurance = EnrollmentAssurance(client: freshClient, principalStore: principalStore, defaults: defaults)
        _ = try await ensure(freshAssurance, "u-1")

        XCTAssertEqual(freshStore.writes, baselineStore.writes)
        XCTAssertTrue(defaults.bool(forKey: "sentomaru_enrollment_ios_installed"))
    }
}
