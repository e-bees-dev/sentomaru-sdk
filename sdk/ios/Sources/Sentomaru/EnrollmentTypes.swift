import Foundation

/// Immutable configuration (Android `SentomaruConfig`). Public consumer endpoints only; never the private integrity API.
///
/// Not mirrored from Android: `playIntegrityCloudProjectNumber` (Google only), `requireStrongBox`/`strongBox` (the iOS
/// request key is always in the Secure Enclave or the enrollment fails).
public struct SentomaruConfig: Sendable {
    public let organization: String
    public let app: String
    public let environment: String
    public let allowedHosts: Set<String>
    public let enrollmentUrl: String
    /// How long a rotated-out key stays on the device after `rotate` (default 7 days).
    public let rotationGracePeriod: TimeInterval
    /// J-04r: the consumer's public renewal route; nil = no renewal (a long session ends in `session-expired`).
    public let renewalUrl: String?
    /// D-F1 (ativação de módulos em cliente novo, Fase F): what the app, not the SDK, declares about its own
    /// integration — does it actually enforce the policy's recommendation, does it treat the installation response
    /// (suspend/revoke)? Sent as `sdkModes` at enrollment, purely informational (A-13): the SDK never reads either
    /// back. `false` by default is deliberate: an app that forgets to set this is a true "not enforcing", the same
    /// gap the Prontidão (Fase A) exists to catch.
    public let declaredEnforce: Bool
    public let declaredInstallationResponse: Bool

    /// SHA-256 (hex) of the scope and enrollment URL: names the Keychain record and the key aliases.
    let identity: String

    public init(organization: String, app: String, environment: String, allowedHosts: Set<String>,
                enrollmentUrl: String, rotationGracePeriod: TimeInterval = 7 * 24 * 3600,
                renewalUrl: String? = nil, declaredEnforce: Bool = false, declaredInstallationResponse: Bool = false) throws {
        self.organization = organization
        self.app = app
        self.environment = environment
        self.allowedHosts = allowedHosts
        self.enrollmentUrl = enrollmentUrl
        self.rotationGracePeriod = rotationGracePeriod
        self.renewalUrl = renewalUrl
        self.declaredEnforce = declaredEnforce
        self.declaredInstallationResponse = declaredInstallationResponse
        self.identity = Hashing.hex(Hashing.sha256(Data("\(organization)\n\(app)\n\(environment)\n\(enrollmentUrl)".utf8)))
        guard rotationGracePeriod > 0, !allowedHosts.isEmpty,
              allowedHosts.allSatisfy({ !$0.isEmpty && $0.utf8.allSatisfy { ($0 >= 0x61 && $0 <= 0x7A) || ($0 >= 0x30 && $0 <= 0x39) || $0 == 0x2E || $0 == 0x2D } })
        else { throw SentomaruError.invalidRequest(.PARAMS) }
        try checkHost(enrollmentUrl)
        if let renewalUrl { try checkHost(renewalUrl) }
        // Scope slugs and the enrollment URL must be signable under the profile.
        _ = try SignatureBase.build(method: "POST", targetURI: enrollmentUrl, headers: headers(session: UUIDText.zero, operation: "enroll"),
                                    contentDigest: ContentDigest.sha256(Data()),
                                    params: SignatureParams(created: 0, expires: 1, nonce: UUIDText.zero, keyId: UUIDText.zero))
    }

    /// `https`, host in the allowlist, no userinfo; anything else is `hostNotAllowed` (unparseable: `TARGET_URI`).
    func checkHost(_ uri: String) throws {
        guard let parsed = URLComponents(string: uri) else { throw SentomaruError.invalidRequest(.TARGET_URI) }
        guard parsed.scheme == "https", let host = parsed.percentEncodedHost, allowedHosts.contains(host),
              parsed.percentEncodedUser == nil, parsed.percentEncodedPassword == nil
        else { throw SentomaruError.hostNotAllowed }
    }

    func headers(session: String, operation: String) -> [String: String] {
        ["content-type": Profile.contentType, "x-sentomaru-profile": Profile.tag, "x-sentomaru-org": organization,
         "x-sentomaru-app": app, "x-sentomaru-environment": environment, "x-sentomaru-session": session,
         "x-sentomaru-operation": operation]
    }
}

/// The challenge the app obtained from its backend (`{challengeId, challenge, attestationChallenge, expiresAt}`):
/// `token` is the standard base64 of 32 bytes, `attestationChallenge` the 32 raw bytes.
public struct EnrollmentChallenge: Codable, Equatable, Sendable {
    public let id: String
    public let token: String
    public let attestationChallenge: Data
    public let expiresAt: Date

    public init(id: String, token: String, attestationChallenge: Data, expiresAt: Date) throws {
        guard SignatureParams.isUUID(id), let decoded = CanonicalBase64.decode(token), decoded.count == 32,
              attestationChallenge.count == 32 else { throw SentomaruError.invalidRequest(.PARAMS) }
        self.id = id
        self.token = token
        self.attestationChallenge = attestationChallenge
        self.expiresAt = expiresAt
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(id: c.decode(String.self, forKey: .id), token: c.decode(String.self, forKey: .token),
                      attestationChallenge: c.decode(Data.self, forKey: .attestationChallenge),
                      expiresAt: c.decode(Date.self, forKey: .expiresAt))
    }

    /// Same id, token, attestation bytes and expiry to the millisecond (the store keeps milliseconds).
    public static func == (a: EnrollmentChallenge, b: EnrollmentChallenge) -> Bool {
        a.id == b.id && a.token == b.token && a.attestationChallenge == b.attestationChallenge &&
            (a.expiresAt.timeIntervalSince1970 * 1000).rounded() == (b.expiresAt.timeIntervalSince1970 * 1000).rounded()
    }
}

/// Only the server says hardware/attestation status; local key properties are never authorization. iOS installations
/// verified with App Attest get `device_attested` / `verified` (D-IOS7), never `hardware`.
/// J-04r: `issuedAt` is the local instant the SDK received the grant; `ttlSeconds` its server lifetime when known.
public struct EnrollmentGrant: Codable, Equatable, Sendable {
    public static let defaultTTLSeconds: Int64 = 600
    static let hardwareStatuses: Set<String> = ["hardware", "device_attested", "software", "unknown"]
    static let attestationStatuses: Set<String> = ["verified", "untrusted", "notEvaluated"]

    public let installationId: String
    public let keyId: String
    public let sessionId: String
    public let hardwareStatus: String
    public let attestationStatus: String
    public let issuedAt: Date?
    public let ttlSeconds: Int64?

    public init(installationId: String, keyId: String, sessionId: String, hardwareStatus: String,
                attestationStatus: String, issuedAt: Date? = nil, ttlSeconds: Int64? = nil) throws {
        guard [installationId, keyId, sessionId].allSatisfy(SignatureParams.isUUID),
              Self.hardwareStatuses.contains(hardwareStatus), Self.attestationStatuses.contains(attestationStatus),
              ttlSeconds.map({ (1...86_400).contains($0) }) ?? true
        else { throw SentomaruError.invalidRequest(.PARAMS) }
        self.installationId = installationId
        self.keyId = keyId
        self.sessionId = sessionId
        self.hardwareStatus = hardwareStatus
        self.attestationStatus = attestationStatus
        self.issuedAt = issuedAt
        self.ttlSeconds = ttlSeconds
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(installationId: c.decode(String.self, forKey: .installationId),
                      keyId: c.decode(String.self, forKey: .keyId), sessionId: c.decode(String.self, forKey: .sessionId),
                      hardwareStatus: c.decode(String.self, forKey: .hardwareStatus),
                      attestationStatus: c.decode(String.self, forKey: .attestationStatus),
                      issuedAt: c.decodeIfPresent(Date.self, forKey: .issuedAt),
                      ttlSeconds: c.decodeIfPresent(Int64.self, forKey: .ttlSeconds))
    }

    func issued(at date: Date, ttl: Int64? = nil) -> EnrollmentGrant {
        try! EnrollmentGrant(installationId: installationId, keyId: keyId, sessionId: sessionId, hardwareStatus: hardwareStatus,
                             attestationStatus: attestationStatus, issuedAt: date, ttlSeconds: ttl ?? ttlSeconds)
    }

    /// The same grant without its receipt instant: the next `needsRenewal` answers true.
    func stale() -> EnrollmentGrant {
        try! EnrollmentGrant(installationId: installationId, keyId: keyId, sessionId: sessionId,
                             hardwareStatus: hardwareStatus, attestationStatus: attestationStatus)
    }

    /// Due when the age reaches the lifetime minus min(`maxMargin`, lifetime/5). Unknown age is always due.
    func renewalDue(now: Date, maxMargin: TimeInterval) -> Bool {
        guard let issuedAt else { return true }
        let ttl = TimeInterval(ttlSeconds ?? Self.defaultTTLSeconds)
        let margin = min(maxMargin, ttl / 5)
        return now >= issuedAt.addingTimeInterval(ttl - margin)
    }
}

/// J-04r: answer of the consumer's renewal route (the private `POST …/sessions` passed through).
public struct RenewedGrant: Equatable, Sendable {
    public let installationId: String
    public let keyId: String
    public let sessionId: String
    public let ttlSeconds: Int64

    public init(installationId: String, keyId: String, sessionId: String, ttlSeconds: Int64) throws {
        guard [installationId, keyId, sessionId].allSatisfy(SignatureParams.isUUID), (1...86_400).contains(ttlSeconds)
        else { throw SentomaruError.invalidRequest(.PARAMS) }
        self.installationId = installationId
        self.keyId = keyId
        self.sessionId = sessionId
        self.ttlSeconds = ttlSeconds
    }

    /// The Android rule: fixed members (`installationId`, `keyId`, `sessionId`, `ttlSeconds`; others ignored), each
    /// exactly once, validated here. Anything else is `InvalidRequest:PARAMS`.
    public static func parse(_ text: String) throws -> RenewedGrant {
        func matches(_ pattern: String) -> [String] {
            let regex = try! NSRegularExpression(pattern: pattern)
            let range = NSRange(text.startIndex..., in: text)
            return regex.matches(in: text, range: range).compactMap { Range($0.range(at: 1), in: text).map { String(text[$0]) } }
        }
        func one(_ pattern: String) throws -> String {
            let found = matches(pattern)
            guard found.count == 1 else { throw SentomaruError.invalidRequest(.PARAMS) }
            return found[0]
        }
        func uuid(_ name: String) throws -> String { try one("\"\(name)\"\\s*:\\s*\"([0-9a-f-]{36})\"") }
        guard let ttl = Int64(try one("\"ttlSeconds\"\\s*:\\s*([0-9]{1,6})[,}\\s]")) else {
            throw SentomaruError.invalidRequest(.PARAMS)
        }
        return try RenewedGrant(installationId: uuid("installationId"), keyId: uuid("keyId"), sessionId: uuid("sessionId"),
                                ttlSeconds: ttl)
    }
}

public enum InstallationState: String, Sendable {
    case notEnrolled = "NotEnrolled"
    case enrollmentRequired = "EnrollmentRequired"
    case enrolled = "Enrolled"
    case keyInvalidated = "KeyInvalidated"
}

public struct RetiredKey: Codable, Equatable, Sendable {
    public let alias: String
    public let retiredAt: Date
    public let expiresAt: Date
}

/// A rotation frozen before sending (D-04d): the new request key, its App Attest key id and the exact body.
/// `sent`: the body was handed to `send` at least once, so the server may have committed it.
public struct PendingRotation: Codable, Equatable, Sendable {
    public let alias: String
    public let challenge: EnrollmentChallenge
    public let body: Data
    public let publicKey: Data
    public let appAttestKeyId: String
    public let sent: Bool

    func markedSent() -> PendingRotation {
        PendingRotation(alias: alias, challenge: challenge, body: body, publicKey: publicKey,
                        appAttestKeyId: appAttestKeyId, sent: true)
    }
}

/// What the store keeps (no private-key material): the active key alias, the frozen enrollment body, the grant, the
/// enrolled SPKI and the App Attest key id the renewal assertions use.
public struct InstallationRecord: Codable, Equatable, Sendable {
    public static let currentVersion = 1

    public var version: Int = InstallationRecord.currentVersion
    public var scopeIdentity: String
    public var alias: String
    public var challenge: EnrollmentChallenge
    public var body: Data?
    public var grant: EnrollmentGrant?
    public var generation: Int64
    public var retiredKeys: [RetiredKey]
    public var pendingRotation: PendingRotation?
    /// SPKI DER of the key at `alias`, exactly the one in `body` (set with `body`).
    public var publicKey: Data?
    /// App Attest key identifier attested in `body` (set with `body`); the renewal assertion uses it.
    public var appAttestKeyId: String?
    /// App Attest key generated for an attestation that has not succeeded yet (enrollment or rotation). Persisted
    /// before `attestKey`, so a retry after a lost answer or a process death reuses it instead of leaving an orphan
    /// key; cleared once the attestation succeeds or the key can no longer be attested.
    public var attestingKeyId: String?

    public init(scopeIdentity: String, alias: String, challenge: EnrollmentChallenge, body: Data? = nil,
                grant: EnrollmentGrant? = nil, generation: Int64 = 1, retiredKeys: [RetiredKey] = [],
                pendingRotation: PendingRotation? = nil, publicKey: Data? = nil, appAttestKeyId: String? = nil) {
        self.scopeIdentity = scopeIdentity
        self.alias = alias
        self.challenge = challenge
        self.body = body
        self.grant = grant
        self.generation = generation
        self.retiredKeys = retiredKeys
        self.pendingRotation = pendingRotation
        self.publicKey = publicKey
        self.appAttestKeyId = appAttestKeyId
    }
}

/// Writes must be atomic and durable before returning. The store contains no private-key material. Failures are
/// `storageUnavailable`; an unreadable or foreign record is `keyInvalidated` (the app calls `reset()`).
public protocol InstallationStore: Sendable {
    func read() throws -> InstallationRecord?
    func write(_ record: InstallationRecord?) throws
}
