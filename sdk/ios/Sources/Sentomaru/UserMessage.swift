import Foundation
// The Flutter plugin pod compiles SentomaruCore and Sentomaru into one module (no SentomaruCore module to import); under SwiftPM they stay separate.
#if canImport(SentomaruCore)
import SentomaruCore
#endif

/// `sdk-user-message-v1` (contracts/sdk/user-message-v1.md): the default text an app shows when an operation is blocked. The error codes of the SDK do
/// not change; this only adds a presentable message. The text is fixed (no code, reason or detection detail) and the same for every situation.
public enum SentomaruUserMessage {
    /// Stable key of the message.
    public static let key = "critical_operations_blocked"
    public static let fallbackLocale = "en"

    /// Default text per resolved locale (`pt-BR`, `en`, `es`).
    public static let defaultTexts: [String: String] = [
        "pt-BR": "Algumas operações críticas estão bloqueadas até a aprovação. Tente novamente mais tarde ou fale com o suporte.",
        "en": "Some critical operations are blocked until approval. Please try again later or contact support.",
        "es": "Algunas operaciones críticas están bloqueadas hasta su aprobación. Inténtelo de nuevo más tarde o póngase en contacto con el soporte.",
    ]

    /// The closed set of situations. Every one shows the same text today.
    public enum Situation: String, CaseIterable, Sendable {
        case attestationFailed = "attestation_failed"
        case verificationDenied = "verification_denied"
        case challenge
        case defer_ = "defer"
        case unavailable
        case enrollmentPending = "enrollment_pending"
    }

    /// BCP 47 tag (`_` read as `-`, case-insensitive) to `pt-BR`, `es` or `en`; anything else, empty or nil is `en`.
    public static func resolveLocale(_ tag: String?) -> String {
        let normalized = (tag ?? "").trimmingCharacters(in: .whitespacesAndNewlines).lowercased().replacingOccurrences(of: "_", with: "-")
        let primary = normalized.split(separator: "-", maxSplits: 1, omittingEmptySubsequences: false).first.map(String.init) ?? ""
        switch primary {
        case "pt": return "pt-BR"
        case "es": return "es"
        default: return fallbackLocale
        }
    }

    /// The text for `locale` (default: the first preferred language of the device). A host `overrides` entry, keyed by the resolved
    /// locale, replaces the default when it is not blank.
    public static func resolve(_ situation: Situation, locale: String? = nil, overrides: [String: String]? = nil) -> String {
        let resolved = resolveLocale(locale ?? Locale.preferredLanguages.first)
        if let text = overrides?[resolved], !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { return text }
        return defaultTexts[resolved] ?? defaultTexts[fallbackLocale]!
    }

    /// The situation a stable SDK error code presents, or nil when the code is not a block (the app decides what to show).
    public static func situation(forCode code: String) -> Situation? {
        switch code {
        case "KeyInvalidated", "KeyUnavailable", "StorageUnavailable", "StrongBoxUnavailable", "Unsupported:APP_ATTEST",
             "Unsupported:SECURE_ENCLAVE", "ServerRejected:INVALID":
            return .attestationFailed
        case "ServerRejected:REVOKED", "ServerRejected:SUSPENDED", "ServerRejected:CONFLICT", "ServerRejected:EXPIRED", "ReenrollmentRefused":
            return .verificationDenied
        case "NetworkUnavailable", "ServerRejected:UNAVAILABLE", "ServerRejected:RATE_LIMITED", "RenewalBackoff", "PinningRefused":
            return .unavailable
        case "NotEnrolled", "EnrollmentRequired", "ChallengeExpired":
            return .enrollmentPending
        default:
            return nil
        }
    }

    /// The message for a stable error code, or nil when the code is not a block.
    public static func message(forCode code: String, locale: String? = nil, overrides: [String: String]? = nil) -> String? {
        situation(forCode: code).map { resolve($0, locale: locale, overrides: overrides) }
    }
}

extension SentomaruError {
    /// The presentable message of this failure, or nil when it is not a block (`cancelled`, `invalidRequest`, ...). The `code` is unchanged.
    public func userMessage(locale: String? = nil, overrides: [String: String]? = nil) -> String? {
        SentomaruUserMessage.message(forCode: code, locale: locale, overrides: overrides)
    }
}
