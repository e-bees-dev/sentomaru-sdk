import CryptoKit
import Foundation
@testable import Sentomaru
import Security
import XCTest

/// Keychain store and Secure Enclave keys, isolated under a random service.
/// - macOS host (`swift test`): every test runs in its own file keychain (created here, deleted in tearDown), so the
///   user's keychains are never touched; the data protection Keychain needs an app entitlement there.
/// - iOS device (hosted in an app, D-10a device run): the production data protection Keychain of the host app, items
///   deleted in tearDown; the accessibility class is read back from the Keychain itself.
final class KeychainTests: XCTestCase {
    private var service = ""
    #if os(macOS)
    private var keychain: SecKeychain?
    private var path = ""

    override func setUpWithError() throws {
        path = FileManager.default.temporaryDirectory.appendingPathComponent("sentomaru-test-\(UUID().uuidString).keychain-db").path
        let password = UUID().uuidString // ephemeral, never stored
        var created: SecKeychain?
        let status = SecKeychainCreate(path, UInt32(password.utf8.count), password, false, nil, &created)
        guard status == errSecSuccess, let created else { throw XCTSkip("no file keychain on this host (\(status))") }
        keychain = created
        service = "br.com.ebees.sentomaru.test.\(UUID().uuidString)"
    }

    override func tearDown() {
        if let keychain { SecKeychainDelete(keychain) }
        try? FileManager.default.removeItem(atPath: path)
    }

    private var location: KeychainLocation { .file(keychain!, service: service) }
    private func location(service: String) -> KeychainLocation { .file(keychain!, service: service) }
    #else
    override func setUpWithError() throws {
        service = "br.com.ebees.sentomaru.test.\(UUID().uuidString)"
    }

    override func tearDown() {
        for item in [service, service + ".other"] {
            SecItemDelete([kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: item,
                           kSecUseDataProtectionKeychain as String: true] as CFDictionary)
        }
    }

    private var location: KeychainLocation { .dataProtection(service: service) }
    private func location(service: String) -> KeychainLocation { .dataProtection(service: service) }

    /// What the Keychain itself reports for an item the SDK wrote: `ThisDeviceOnly` after first unlock, not synchronizable.
    func testDataProtectionItemIsThisDeviceOnlyAfterFirstUnlock() throws {
        let store = KeychainInstallationStore(location: location, account: "scope")
        try store.write(try record())
        try store.write(try record()) // the update path rewrites the class too
        var out: CFTypeRef?
        let status = SecItemCopyMatching([kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
                                          kSecAttrAccount as String: "scope", kSecUseDataProtectionKeychain as String: true,
                                          kSecReturnAttributes as String: true, kSecMatchLimit as String: kSecMatchLimitOne] as CFDictionary, &out)
        XCTAssertEqual(status, errSecSuccess)
        let attributes = try XCTUnwrap(out as? [String: Any])
        XCTAssertEqual(attributes[kSecAttrAccessible as String] as? String, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String)
        XCTAssertFalse((attributes[kSecAttrSynchronizable as String] as? Bool) ?? false)
        // No synchronizable copy exists.
        let synced = SecItemCopyMatching([kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
                                          kSecAttrSynchronizable as String: true, kSecUseDataProtectionKeychain as String: true] as CFDictionary, nil)
        XCTAssertEqual(synced, errSecItemNotFound)
    }
    #endif

    private func record() throws -> InstallationRecord {
        let challenge = try EnrollmentChallenge(id: UUIDText.random(), token: Data(count: 32).base64EncodedString(),
                                                attestationChallenge: Data(repeating: 1, count: 32),
                                                expiresAt: Date(timeIntervalSince1970: 1_800_000_120.123))
        let grant = try EnrollmentGrant(installationId: UUIDText.random(), keyId: challenge.id, sessionId: UUIDText.random(),
                                        hardwareStatus: "device_attested", attestationStatus: "verified",
                                        issuedAt: Date(timeIntervalSince1970: 1_800_000_000.5), ttlSeconds: 600)
        return InstallationRecord(scopeIdentity: "scope", alias: "sentomaru.v1.scope.v1.x", challenge: challenge,
                                  body: Data("{}".utf8), grant: grant, publicKey: Data([1, 2, 3]),
                                  appAttestKeyId: Data(count: 32).base64EncodedString())
    }

    /// Skipped only on a Mac host without the chip; on an iOS device a missing Secure Enclave is a failure, not a skip.
    private func requireSecureEnclave() throws {
        #if os(iOS)
        XCTAssertTrue(SecureEnclave.isAvailable, "the device run must use the real Secure Enclave")
        #endif
        guard SecureEnclave.isAvailable else { throw XCTSkip("no Secure Enclave on this host") }
    }

    func testStoreRoundTripUpdateAndDelete() throws {
        let store = KeychainInstallationStore(location: location, account: "scope")
        XCTAssertNil(try store.read())
        var value = try record()
        try store.write(value)
        XCTAssertEqual(try store.read(), value)
        value.grant = nil
        try store.write(value) // update in place
        XCTAssertEqual(try store.read(), value)
        try store.write(nil)
        XCTAssertNil(try store.read())
        try store.write(nil) // deleting nothing is fine
    }

    func testStoreIsIsolatedByServiceAndAccount() throws {
        let store = KeychainInstallationStore(location: location, account: "scope")
        try store.write(try record())
        XCTAssertNil(try KeychainInstallationStore(location: location(service: service + ".other"), account: "scope").read())
        XCTAssertNil(try KeychainInstallationStore(location: location, account: "other-scope").read())
    }

    func testUnreadableRecordIsKeyInvalidated() throws {
        let items = KeychainItems(location: location)
        try items.set("scope", Data("not json".utf8))
        XCTAssertThrowsError(try KeychainInstallationStore(location: location, account: "scope").read()) {
            XCTAssertEqual($0 as? SentomaruError, .keyInvalidated)
        }
        var other = try record()
        other.version = 2
        try KeychainInstallationStore(location: location, account: "scope").write(other)
        XCTAssertThrowsError(try KeychainInstallationStore(location: location, account: "scope").read()) {
            XCTAssertEqual($0 as? SentomaruError, .keyInvalidated)
        }
    }

    /// Every item the SDK writes is `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` and not synchronizable. A file
    /// keychain does not report the class back, so the attributes handed to the Keychain are checked; the production
    /// location also selects the data protection Keychain.
    func testItemsAreThisDeviceOnlyAfterFirstUnlock() {
        for location in [self.location, KeychainLocation.dataProtection(service: "s")] {
            let items = KeychainItems(location: location)
            let add = items.addAttributes("a", Data([1]))
            XCTAssertEqual(add[kSecAttrAccessible as String] as? String, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String)
            XCTAssertEqual(add[kSecAttrSynchronizable as String] as? Bool, false)
            XCTAssertEqual(items.updateAttributes(Data([1]))[kSecAttrAccessible as String] as? String,
                           kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String)
        }
        XCTAssertEqual(KeychainLocation.dataProtection(service: "s").addAttributes[kSecUseDataProtectionKeychain as String] as? Bool, true)
        XCTAssertEqual(KeychainLocation.dataProtection(service: "s").queryAttributes[kSecUseDataProtectionKeychain as String] as? Bool, true)
    }

    func testSecureEnclaveUnavailableIsExplicitAndCreatesNothing() throws {
        let keys = SecureEnclaveKeys(location: location, isAvailable: { false })
        XCTAssertThrowsError(try keys.generate("sentomaru.v1.scope.v1.a")) {
            XCTAssertEqual($0 as? SentomaruError, .unsupported(.SECURE_ENCLAVE))
        }
        XCTAssertFalse(try keys.exists("sentomaru.v1.scope.v1.a"))
        XCTAssertTrue(try KeychainItems(location: location).accounts().isEmpty)
    }

    /// The real Secure Enclave (Mac host with Apple silicon, or the device), through the production `SecureEnclaveKeys`: the key
    /// blob lives only in the test keychain, the signature is P1363 and verifies over the base with the SPKI.
    func testSecureEnclaveKeysOnTheHost() throws {
        try requireSecureEnclave()
        let keys = SecureEnclaveKeys(location: location)
        let alias = "sentomaru.v1.scope.v1.\(UUIDText.random())"
        let spki = try keys.generate(alias)
        XCTAssertEqual(spki.count, 91)
        XCTAssertTrue(try keys.exists(alias))
        XCTAssertEqual(try keys.publicKey(alias), spki)
        let base = Data("\"@method\": POST".utf8)
        let signature = try keys.sign(alias, base)
        XCTAssertEqual(signature.count, 64)
        let key = try P256.Signing.PublicKey(derRepresentation: spki)
        XCTAssertTrue(key.isValidSignature(try P256.Signing.ECDSASignature(rawRepresentation: signature), for: base))
        // The stored blob is the Secure Enclave-wrapped key, never the private scalar.
        let blob = try XCTUnwrap(try KeychainItems(location: location).get(alias))
        XCTAssertNotEqual(blob.count, 32)
        _ = try keys.generate("sentomaru.v1.scope.v2.\(UUIDText.random())")
        _ = try keys.generate("sentomaru.v1.other.v1.\(UUIDText.random())")
        try keys.deleteOwned(prefix: "sentomaru.v1.scope.")
        XCTAssertEqual(try KeychainItems(location: location).accounts().filter { $0.hasPrefix("sentomaru.v1.scope.") }, [])
        XCTAssertEqual(try KeychainItems(location: location).accounts().count, 1)
        XCTAssertThrowsError(try keys.sign(alias, base)) { XCTAssertEqual($0 as? SentomaruError, .keyInvalidated) }
    }

    /// Full lifecycle with the production key and store types on the host (fake App Attest and server).
    func testClientWithSecureEnclaveKeysAndKeychainStore() async throws {
        try requireSecureEnclave()
        let config = try SentomaruConfig(organization: "org-a", app: "app-a", environment: "hml", allowedHosts: ["consumer.example"],
                                         enrollmentUrl: "https://consumer.example/v1/org-a/app-a/hml/installations",
                                         renewalUrl: "https://consumer.example/v1/org-a/app-a/hml/sessions")
        let appAttest = FakeAppAttest()
        let server = FakeServer(config: config, appAttest: appAttest)
        let clock = TestClock(Date())
        let client = SentomaruClient(config: config, keys: SecureEnclaveKeys(location: location),
                                     store: KeychainInstallationStore(location: location, account: config.identity),
                                     appAttest: appAttest, now: clock.function)
        let challenge = try server.challenge(now: clock.now)
        _ = try await client.enroll(challenge) { try await server.enroll($0) }
        clock.advance(500)
        _ = try await client.renew { try await server.renew($0) }
        XCTAssertEqual(server.installation(challenge.id)?.counter, 1)
        try await client.reset()
        let state = try await client.state()
        XCTAssertEqual(state, .notEnrolled)
        XCTAssertTrue(try KeychainItems(location: location).accounts().isEmpty)
    }
}
