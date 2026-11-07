import CryptoKit
import Foundation
import LocalAuthentication
import Security

/// D-25: why a transaction signature could not be made. `cancelled` is RECOVERABLE (the person dismissed the prompt): nothing
/// was spent, the installation key, the grant and the stored record are untouched, and a new attempt may follow.
public enum TransactionError: Error, Equatable, Sendable {
    case notEnrolled          // no transaction key under this alias
    case keyInvalidated       // biometrics changed (`biometryCurrentSet`) or the key is unusable: create a new one
    case cancelled            // the prompt was cancelled by the person or the system
    case lockedOut            // too many failed biometric attempts
    case noUserAuthentication // no passcode or no enrolled biometry on the device
    case unavailable          // no Secure Enclave
    case signingFailed
}

/// Platform port for the transaction key (Android `TransactionKeySigner`): a P-256 key whose every use needs the person to
/// authenticate. `sign` blocks while the system prompt is shown: call it off the main thread.
public protocol TransactionKeys: Sendable {
    func exists(_ alias: String) throws -> Bool
    /// Replaces any key under `alias` and returns the new key's SPKI DER. `biometricOnly` = the current biometric set only.
    /// `TransactionSigner` only ever calls it with the provisional alias, never with the one that signs.
    func generate(_ alias: String, biometricOnly: Bool) throws -> Data
    /// Makes the key under `staged` the key under `alias` (replacing the old one) and removes `staged`. `notEnrolled` if there
    /// is no key under `staged`; on any failure the key under `alias` is left as it was.
    func promote(_ staged: String, to alias: String) throws
    /// ECDSA P-256 over SHA-256 of `bytes`, IEEE P1363 `r || s`, after the person authenticated (`reason` is the prompt text).
    func sign(_ alias: String, _ bytes: Data, reason: String) throws -> Data
    func delete(_ alias: String) throws
}

/// Production transaction key: a `SecureEnclave.P256.Signing.PrivateKey` with an access control that demands the person on
/// every use: `.biometryCurrentSet` (only the biometrics enrolled at creation; a new enrollment invalidates the key) or
/// `.userPresence` (biometry or the device passcode). It proves a person who can unlock the device was present at the time of
/// the signature, never that they saw the value.
///
/// LIMIT: Apple gives the server no attestation of this key's access control (App Attest attests the app key, not a Secure
/// Enclave key made here), so the `transaction-keys` enrollment, which proves the requirement from the Android Key Attestation
/// list, cannot enroll it. The key signs and the header format is the same; what the server can conclude from it on iOS is an
/// open decision.
public struct SecureEnclaveTransactionKeys: TransactionKeys {
    let items: KeychainItems
    let isAvailable: @Sendable () -> Bool

    public init(service: String = SecureEnclaveKeys.defaultService + ".tx") {
        self.init(location: .dataProtection(service: service))
    }

    init(location: KeychainLocation, isAvailable: @escaping @Sendable () -> Bool = { SecureEnclave.isAvailable }) {
        self.items = KeychainItems(location: location)
        self.isAvailable = isAvailable
    }

    public func exists(_ alias: String) throws -> Bool { try items.get(alias) != nil }

    public func generate(_ alias: String, biometricOnly: Bool) throws -> Data {
        guard isAvailable() else { throw TransactionError.unavailable }
        var error: Unmanaged<CFError>?
        let flags: SecAccessControlCreateFlags = biometricOnly ? [.privateKeyUsage, .biometryCurrentSet] : [.privateKeyUsage, .userPresence]
        guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, flags, &error) else {
            throw TransactionError.noUserAuthentication // no passcode set: the access control cannot exist
        }
        let key: SecureEnclave.P256.Signing.PrivateKey
        do { key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access) } catch { throw TransactionError.signingFailed }
        try items.set(alias, key.dataRepresentation)
        return key.publicKey.derRepresentation
    }

    public func sign(_ alias: String, _ bytes: Data, reason: String) throws -> Data {
        guard isAvailable() else { throw TransactionError.unavailable }
        guard let blob = try items.get(alias) else { throw TransactionError.notEnrolled }
        let context = LAContext()
        context.localizedReason = reason
        do {
            let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob, authenticationContext: context)
            return try key.signature(for: bytes).rawRepresentation
        } catch {
            throw Self.map(error)
        }
    }

    public func promote(_ staged: String, to alias: String) throws {
        guard let blob = try items.get(staged) else { throw TransactionError.notEnrolled }
        try items.set(alias, blob) // the new key is in place before the provisional one is dropped: a crash here loses nothing
        try items.delete(staged)
    }

    public func delete(_ alias: String) throws { try items.delete(alias) }

    /// Closed mapping of what the system reports; anything unknown is `signingFailed` (never the system's text).
    static func map(_ error: Error) -> TransactionError {
        if let la = error as? LAError {
            switch la.code {
            case .userCancel, .systemCancel, .appCancel, .userFallback: return .cancelled
            case .biometryLockout: return .lockedOut
            case .passcodeNotSet, .biometryNotEnrolled, .biometryNotAvailable: return .noUserAuthentication
            default: return .signingFailed
            }
        }
        let ns = error as NSError
        if ns.domain == NSOSStatusErrorDomain {
            switch Int32(ns.code) {
            case errSecUserCanceled: return .cancelled
            case errSecItemNotFound, errSecInvalidKeyRef, errSecAuthFailed: return .keyInvalidated
            default: break
            }
        }
        return .signingFailed
    }
}

/// D-25: signs one operation at a time with the transaction key and returns the `x-sentomaru-tx-signature` value. The app puts
/// it on the request; `SentomaruClient.sign(..., optional:)` then covers it with the RFC 9421 signature (the header the server
/// refuses if it is not covered). The operation id must be the one in `x-sentomaru-operation-id`, the same on every retry; the
/// nonce is new for every call (a retry never reuses it).
public struct TransactionSigner: Sendable {
    public static let defaultReason = "Confirmar a operação"
    /// Suffix of the provisional alias: a new key lives at `<alias>.pending` until the server has accepted it.
    static let pendingSuffix = ".pending"
    let keys: TransactionKeys
    let alias: String
    var stagedAlias: String { alias + Self.pendingSuffix }
    let nonce: @Sendable () -> Data
    let version: TransactionSignatureVersion
    let now: @Sendable () -> Int

    /// `installationAlias` is `SentomaruClient.installationAlias()`; the transaction key lives under `<alias>.tx`. `version` is
    /// `.v2` (signed clock, 5 minute window at the server) unless the server does not list `v2` in `signatureVersions`.
    public init(keys: TransactionKeys = SecureEnclaveTransactionKeys(), installationAlias: String,
                version: TransactionSignatureVersion = .v2) {
        self.init(keys: keys, alias: installationAlias + ".tx", nonce: { Data((0..<TransactionSignature.nonceBytes).map { _ in UInt8.random(in: 0...255) }) },
                  version: version, now: { Int(Date().timeIntervalSince1970) })
    }

    init(keys: TransactionKeys, alias: String, nonce: @escaping @Sendable () -> Data,
         version: TransactionSignatureVersion = .v1, now: @escaping @Sendable () -> Int = { Int(Date().timeIntervalSince1970) }) {
        self.keys = keys
        self.alias = alias
        self.nonce = nonce
        self.version = version
        self.now = now
    }

    public func isEnrolled() -> Bool { (try? keys.exists(alias)) ?? false }

    /// Creates a NEW transaction key under a provisional alias and returns its SPKI DER for the `transaction-keys` enrollment. The
    /// key that signs (and any enrollment the server already holds for it) is not touched: a failed or refused enrollment leaves
    /// the app with the key it had. Call `commitKey()` once the server answered `201`, or `abortKey()` if it did not. A second
    /// call before either replaces the earlier provisional key.
    public func stageKey(biometricOnly: Bool = true) throws -> Data {
        do { return try keys.generate(stagedAlias, biometricOnly: biometricOnly) } catch let error as TransactionError { throw error } catch {
            throw TransactionError.signingFailed
        }
    }

    /// The server accepted the provisional key: it replaces the old one. `TransactionError.notEnrolled` if nothing is staged.
    public func commitKey() throws {
        do { try keys.promote(stagedAlias, to: alias) } catch let error as TransactionError { throw error } catch {
            throw TransactionError.signingFailed
        }
    }

    /// The server did not accept the provisional key (or the call is abandoned): drops it. The signing key stays.
    public func abortKey() { try? keys.delete(stagedAlias) }

    /// The header value. Shows the system prompt; cancelling is `TransactionError.cancelled` (recoverable, nothing spent).
    public func sign(operationId: String, body: Data, reason: String = TransactionSigner.defaultReason) async throws -> String {
        guard operationId.utf8.count >= 16, operationId.utf8.count <= 64,
              operationId.utf8.allSatisfy({ ($0 >= 0x41 && $0 <= 0x5A) || ($0 >= 0x61 && $0 <= 0x7A) || ($0 >= 0x30 && $0 <= 0x39) || $0 == 0x2D })
        else { throw SentomaruError.invalidRequest(.HEADER_VALUE) }
        let nonce = self.nonce()
        let issuedAt = now()
        // A clock before 2001 would not fit the 10 digits of v2: refuse to sign rather than send a header the server cannot read.
        if version == .v2, !TransactionSignature.isValidIssuedAt(issuedAt) { throw TransactionError.signingFailed }
        let message = version == .v1
            ? TransactionSignature.message(nonce: nonce, operationId: operationId, body: body)
            : TransactionSignature.message(nonce: nonce, issuedAt: issuedAt, operationId: operationId, body: body)
        let (keys, alias) = (self.keys, self.alias)
        let signature = try await Task.detached { try keys.sign(alias, message, reason: reason) }.value
        guard signature.count == TransactionSignature.signatureBytes else { throw TransactionError.signingFailed }
        return version == .v1
            ? TransactionSignature.headerValue(nonce: nonce, signature: signature)
            : TransactionSignature.headerValue(nonce: nonce, issuedAt: issuedAt, signature: signature)
    }

    public func discard() {
        try? keys.delete(alias)
        try? keys.delete(stagedAlias)
    }
}
