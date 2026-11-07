import Foundation
#if canImport(DeviceCheck)
import DeviceCheck
#endif

/// Port over `DCAppAttestService` (DeviceCheck), injectable so tests use a fake. Errors should be `SentomaruError`:
/// `unsupported(.APP_ATTEST)` (feature not supported), `networkUnavailable` (Apple's server could not be reached),
/// `keyInvalidated` (the App Attest key is no longer valid), `keyUnavailable` (anything else).
public protocol AppAttestService: Sendable {
    /// False on the simulator and on devices or builds without App Attest. The SDK then refuses to enroll
    /// (`unsupported(.APP_ATTEST)`); it never enrolls "without attestation".
    var isSupported: Bool { get }
    /// A new App Attest key; returns its key identifier (standard base64 of 32 bytes).
    func generateKey() async throws -> String
    /// The attestation object (CBOR) of `keyId` over `clientDataHash`. Contacts Apple.
    func attestKey(_ keyId: String, clientDataHash: Data) async throws -> Data
    /// An assertion (CBOR `{signature, authenticatorData}`) of `keyId` over `clientDataHash`.
    func generateAssertion(_ keyId: String, clientDataHash: Data) async throws -> Data
}

#if canImport(DeviceCheck)
/// The real App Attest service. The App ID needs the App Attest capability and the
/// `com.apple.developer.devicecheck.appattest-environment` entitlement (`development` or `production`) must match the
/// scope's `apple_attest_environment` on the server, or the enrollment is `aaguid_env_mismatch`.
@available(iOS 14.0, macOS 11.0, *)
public struct DeviceCheckAppAttestService: AppAttestService {
    public init() {}

    public var isSupported: Bool { DCAppAttestService.shared.isSupported }

    public func generateKey() async throws -> String {
        guard isSupported else { throw SentomaruError.unsupported(.APP_ATTEST) }
        do { return try await DCAppAttestService.shared.generateKey() } catch { throw Self.map(error) }
    }

    public func attestKey(_ keyId: String, clientDataHash: Data) async throws -> Data {
        guard isSupported else { throw SentomaruError.unsupported(.APP_ATTEST) }
        do { return try await DCAppAttestService.shared.attestKey(keyId, clientDataHash: clientDataHash) } catch {
            throw Self.map(error)
        }
    }

    public func generateAssertion(_ keyId: String, clientDataHash: Data) async throws -> Data {
        guard isSupported else { throw SentomaruError.unsupported(.APP_ATTEST) }
        do { return try await DCAppAttestService.shared.generateAssertion(keyId, clientDataHash: clientDataHash) } catch {
            throw Self.map(error)
        }
    }

    /// `DCError` to the SDK's codes; nothing from the platform error (message, user info) is kept.
    static func map(_ error: Error) -> SentomaruError {
        if error is CancellationError { return .cancelled }
        guard let dc = error as? DCError else { return .keyUnavailable }
        switch dc.code {
        case .featureUnsupported: return .unsupported(.APP_ATTEST)
        case .serverUnavailable: return .networkUnavailable
        case .invalidKey: return .keyInvalidated
        default: return .keyUnavailable
        }
    }
}
#endif

/// The `clientDataHash` values the profile binds (contracts/p1-apple-attestation-profile.md).
public enum AppAttestBinding {
    /// Enrollment: `SHA-256(attestationChallenge ‖ SPKI)` (32 raw challenge bytes, DER of the enrolled request key).
    public static func attestationClientDataHash(attestationChallenge: Data, spki: Data) -> Data {
        Hashing.sha256(attestationChallenge + spki)
    }

    /// D-09c renewal `clientData` (UTF-8): `"sentomaru-app-assertion-v1\n" ‖ sessionId ‖ "\n" ‖ nonce ‖ "\n" ‖
    /// base64url-without-padding(SHA-256(SPKI))`, with the `x-sentomaru-session` and the `Signature-Input` nonce of
    /// the same renewal request.
    public static func assertionClientData(sessionId: String, nonce: String, spki: Data) -> Data {
        Data(("sentomaru-app-assertion-v1\n" + sessionId + "\n" + nonce + "\n" +
            Hashing.base64URLNoPadding(Hashing.sha256(spki))).utf8)
    }

    public static func assertionClientDataHash(sessionId: String, nonce: String, spki: Data) -> Data {
        Hashing.sha256(assertionClientData(sessionId: sessionId, nonce: nonce, spki: spki))
    }

    /// The D-09c renewal body: exactly `{"appAssertion":"<standard base64 with padding of the CBOR>"}`.
    public static func renewalBody(assertion: Data) -> Data {
        Data(("{\"appAssertion\":\"" + assertion.base64EncodedString() + "\"}").utf8)
    }

    /// Server limits (contract v1.7 / D-09c): key id = 32 bytes, attestation object 1..32768, assertion 1..4096 bytes.
    static func validKeyId(_ keyId: String) -> Bool { CanonicalBase64.decode(keyId)?.count == 32 }
    static let maxAttestationObject = 32768
    static let maxAssertion = 4096
}
