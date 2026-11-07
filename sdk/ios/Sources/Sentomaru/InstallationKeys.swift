import CryptoKit
import Foundation
import Security

/// Platform port for the request key (Android `InstallationKeys`): P-256, `ecdsa-p256-sha256`, 64-byte P1363 output.
/// The implementation owns every private-key operation. Errors are `SentomaruError` (`keyUnavailable`,
/// `unsupported(.SECURE_ENCLAVE)`, `storageUnavailable`).
public protocol InstallationKeys: Sendable {
    func exists(_ alias: String) throws -> Bool
    /// Generates the key under `alias` and returns its SPKI DER (91 bytes for P-256).
    func generate(_ alias: String) throws -> Data
    /// SPKI DER of the key under `alias`.
    func publicKey(_ alias: String) throws -> Data
    /// ECDSA P-256 over SHA-256 of `bytes`, IEEE P1363 `r || s` (64 bytes).
    func sign(_ alias: String, _ bytes: Data) throws -> Data
    func delete(_ alias: String) throws
    func deleteOwned(prefix: String) throws
}

/// Production request key: a CryptoKit `SecureEnclave.P256.Signing.PrivateKey` (non-exportable; created with
/// `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` + `privateKeyUsage`). Only its Secure Enclave-wrapped blob
/// (`dataRepresentation`, useless on any other device) is kept, as a Keychain item of this device.
///
/// No software fallback: without a Secure Enclave (simulator, unsupported hardware) `generate` throws
/// `unsupported(.SECURE_ENCLAVE)` and nothing is created. Tests inject their own `InstallationKeys`.
public struct SecureEnclaveKeys: InstallationKeys {
    public static let defaultService = "br.com.ebees.sentomaru.keys"
    let items: KeychainItems
    let isAvailable: @Sendable () -> Bool

    public init(service: String = SecureEnclaveKeys.defaultService) {
        self.init(location: .dataProtection(service: service))
    }

    init(location: KeychainLocation, isAvailable: @escaping @Sendable () -> Bool = { SecureEnclave.isAvailable }) {
        self.items = KeychainItems(location: location)
        self.isAvailable = isAvailable
    }

    public func exists(_ alias: String) throws -> Bool { try items.get(alias) != nil }

    public func generate(_ alias: String) throws -> Data {
        guard isAvailable() else { throw SentomaruError.unsupported(.SECURE_ENCLAVE) }
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
                                                           .privateKeyUsage, &error) else {
            throw SentomaruError.keyUnavailable
        }
        let key: SecureEnclave.P256.Signing.PrivateKey
        do { key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access) } catch {
            throw SentomaruError.keyUnavailable
        }
        try items.set(alias, key.dataRepresentation)
        return key.publicKey.derRepresentation
    }

    private func key(_ alias: String) throws -> SecureEnclave.P256.Signing.PrivateKey {
        guard isAvailable() else { throw SentomaruError.unsupported(.SECURE_ENCLAVE) }
        guard let blob = try items.get(alias) else { throw SentomaruError.keyInvalidated }
        do { return try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob) } catch {
            throw SentomaruError.keyInvalidated
        }
    }

    public func publicKey(_ alias: String) throws -> Data { try key(alias).publicKey.derRepresentation }

    public func sign(_ alias: String, _ bytes: Data) throws -> Data {
        let key = try key(alias)
        do { return try key.signature(for: bytes).rawRepresentation } catch { throw SentomaruError.keyUnavailable }
    }

    public func delete(_ alias: String) throws { try items.delete(alias) }

    public func deleteOwned(prefix: String) throws {
        for account in try items.accounts() where account.hasPrefix(prefix) { try items.delete(account) }
    }
}
