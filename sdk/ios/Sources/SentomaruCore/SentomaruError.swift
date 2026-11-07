import Foundation

/// Categorized, recoverable failure (decision E7). One enum for the whole SDK (Swift enums cannot be extended across
/// modules): the core raises the first four cases, the lifecycle layer the others. `code` is the same stable string as
/// the Android `SentomaruError.code` (`InvalidRequest:TARGET_URI`, `ServerRejected:SUSPENDED`, ...) and never carries
/// request values (no header values, URIs, keys or bodies), so it is safe to log.
public enum SentomaruError: Error, Equatable, Sendable, CustomStringConvertible {
    /// Body over `Profile.maxBodyBytes`; only sizes are kept.
    case bodyTooLarge(size: Int, limit: Int = Profile.maxBodyBytes)
    /// Destination host outside the allowlist (E6). The host is not kept (it may identify a tenant).
    case hostNotAllowed
    /// The request cannot be signed under the profile; `reason` names the part, never its value.
    case invalidRequest(Reason)
    /// The injected signer did not return a 64-byte P1363 signature.
    case signatureFormat(size: Int)

    // Lifecycle (Android `EnrollmentError`).
    case notEnrolled
    case enrollmentRequired
    case keyInvalidated
    case challengeExpired
    case networkUnavailable
    case storageUnavailable
    case keyUnavailable
    case cancelled
    case serverRejected(Rejection)
    /// `401 predecessor-invalid` on `rotate`: call `reset()` and then `enroll()` (D-04d).
    case reenrollmentRefused
    /// iOS only: a platform capability the installation needs is missing on this device or build (App Attest on the
    /// simulator or an unsupported device, no Secure Enclave). Never downgraded to an enrollment without it.
    case unsupported(Capability)

    public enum Reason: String, Sendable, CaseIterable {
        case METHOD, TARGET_URI, HEADER_NAME, HEADER_VALUE, CONTENT_DIGEST, PARAMS
    }

    /// Same names and meaning as the Android `EnrollmentError.Rejection`.
    public enum Rejection: String, Sendable, CaseIterable {
        case EXPIRED, REVOKED, INVALID, RATE_LIMITED, UNAVAILABLE, SUSPENDED, CONFLICT
    }

    public enum Capability: String, Sendable, CaseIterable {
        case APP_ATTEST, SECURE_ENCLAVE
    }

    public var code: String {
        switch self {
        case .bodyTooLarge: return "BodyTooLarge"
        case .hostNotAllowed: return "HostNotAllowed"
        case .invalidRequest(let reason): return "InvalidRequest:\(reason.rawValue)"
        case .signatureFormat: return "SignatureFormat"
        case .notEnrolled: return "NotEnrolled"
        case .enrollmentRequired: return "EnrollmentRequired"
        case .keyInvalidated: return "KeyInvalidated"
        case .challengeExpired: return "ChallengeExpired"
        case .networkUnavailable: return "NetworkUnavailable"
        case .storageUnavailable: return "StorageUnavailable"
        case .keyUnavailable: return "KeyUnavailable"
        case .cancelled: return "Cancelled"
        case .serverRejected(let rejection): return "ServerRejected:\(rejection.rawValue)"
        case .reenrollmentRefused: return "ReenrollmentRefused"
        case .unsupported(let capability): return "Unsupported:\(capability.rawValue)"
        }
    }

    public var description: String { code }
}

@inline(__always)
func invalid(_ reason: SentomaruError.Reason) -> SentomaruError { .invalidRequest(reason) }
