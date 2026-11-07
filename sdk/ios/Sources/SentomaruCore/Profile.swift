import Foundation

/// The Sentomaru message profile (contracts/p0-http-profile.md), the single source for the SDK. Mirrors
/// `br.com.ebees.sentomaru.core.Profile` of the Android SDK byte for byte.
///
/// RFC 9421 (HTTP Message Signatures) + RFC 9530 (Content-Digest), `ecdsa-p256-sha256` with a 64-byte P1363
/// signature, exact component set and order, tag `sentomaru-p0`, body <= 65536 bytes, lifetime <= 60 s.
public enum Profile {
    public static let tag = "sentomaru-p0"
    public static let algorithm = "ecdsa-p256-sha256"
    public static let label = "sig1"
    public static let contentType = "application/json"
    public static let maxBodyBytes = 65536
    public static let maxLifetimeSeconds: Int64 = 60
    public static let signatureBytes = 64

    public static let contentDigestHeader = "content-digest"
    public static let signatureInputHeader = "signature-input"
    public static let signatureHeader = "signature"

    /// Headers the caller supplies (everything signed except `content-digest`, which the core computes).
    public static let callerHeaders: [String] = [
        "content-type",
        "x-sentomaru-profile",
        "x-sentomaru-org",
        "x-sentomaru-app",
        "x-sentomaru-environment",
        "x-sentomaru-session",
        "x-sentomaru-operation",
    ]

    /// Covered components, in the order the reference client (and this core) signs them.
    public static let components: [String] = ["@method", "@target-uri", contentDigestHeader] + callerHeaders

    public static let signalsHeader = "x-sentomaru-signals"
    public static let operationIdHeader = "x-sentomaru-operation-id"

    /// D-25: the transaction signature (a person was present at signing time), made with the transaction key.
    public static let txSignatureHeader = "x-sentomaru-tx-signature"

    /// Optional headers signed when present, after `components` and in this order (H3 signals, J-01f operation id, D-25
    /// transaction signature).
    public static let optionalHeaders: [String] = [signalsHeader, operationIdHeader, txSignatureHeader]

    /// The covered components for a request with these headers: `components` plus the optional ones present.
    public static func components(for headers: [String: String]) -> [String] {
        components + optionalHeaders.filter { headers[$0] != nil }
    }
}
