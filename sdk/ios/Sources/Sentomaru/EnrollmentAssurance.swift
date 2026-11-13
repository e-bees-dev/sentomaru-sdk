import Foundation

/// Asks the app's backend for a fresh, single-use enrollment challenge for `subject`/`tenant`. Called for the
/// first enrollment and, when the server refuses a resend, for the reenrollment that follows — every time a new
/// call, never cached or reused by `EnrollmentAssurance` itself.
public typealias ChallengeProvider = @Sendable (_ subject: String, _ tenant: String) async throws -> EnrollmentChallenge

/// Why `EnrollmentAssurance` just enrolled or reenrolled this installation — no subject, tenant or other personal
/// data, safe for a log line or a metric. Ported from the Android (`ReenrollReason`) and Flutter
/// (`SentomaruReenrollReason`) contracts, minus their `rotationRefused` case: iOS has no `reenrollmentReason`
/// (`SentomaruClient`'s own doc comment: "the App Attest attestation names no app version"), so `EnrollmentAssurance`
/// here has no signal to drive a rotation on its own and never attempts one — see its own doc below.
public enum ReenrollReason: Sendable {
    /// `InstallationState.notEnrolled`: nothing to reuse.
    case stateNotEnrolled
    /// `InstallationState.enrollmentRequired`: the SDK itself discarded the session (renewal exhausted or revoked).
    case stateEnrollmentRequired
    /// `InstallationState.keyInvalidated`: the Secure Enclave key or its App Attest key id is gone.
    case stateKeyInvalidated
    /// Enrolled, but no principal was found for this installation (its own store, mirror and legacy hook all
    /// empty): an installation from before this contract existed, or a storage wipe.
    case principalAbsent
    /// Enrolled with a principal on file, but it belongs to another subject or tenant.
    case principalChanged
}

/// Outcome of `EnrollmentAssurance.ensureEnrolled`.
public struct EnsureEnrolledResult: Sendable {
    /// False when a later call (for a different subject/tenant) superseded this one before it finished: a stale
    /// caller must not bind a session, or otherwise act as if its own call had won.
    public let current: Bool
    /// The session id this call obtained, when it enrolled or reenrolled the installation. `nil` when the existing
    /// installation and session were simply reused — call `SentomaruClient.sessionId()` for the one already
    /// active; this type never carries a copy of its own.
    public let sessionId: String?
}

/// Where `EnrollmentAssurance` keeps the principal (sha256 of `subject\0tenant`) of whoever this installation is
/// enrolled for, so a later call can tell "reuse" from "someone else now" without the app storing anything of its
/// own. Ported from the Android/Flutter ports' `PrincipalStore`/`SentomaruPrincipalStore`, itself from an app-side
/// principal store.
///
/// The value lives in the same data-protection Keychain `SentomaruClient` itself uses (`KeychainItems`, this
/// module), with a plain-text mirror in `UserDefaults`: unlike Android's EncryptedSharedPreferences, the iOS
/// Keychain item itself cannot silently lose its encryption key, but the mirror still guards the same class of
/// failure (a transient Keychain read failure, `errSecInteractionNotAllowed` before first unlock, or any future
/// storage change) without resetting a perfectly good installation. The mirror never authorizes anything by
/// itself: `EnrollmentAssurance` only trusts it together with the SDK itself saying `.enrolled`.
public final class PrincipalStore: @unchecked Sendable {
    public static let defaultService = "br.com.ebees.sentomaru.enrollment"
    private let items: KeychainItems
    private let account: String
    private let defaults: UserDefaults
    private let mirrorKey: String

    /// Production store, in the data protection Keychain.
    public convenience init(service: String = PrincipalStore.defaultService, defaults: UserDefaults = .standard) {
        self.init(location: .dataProtection(service: service), account: "principal", defaults: defaults,
                 mirrorKey: "sentomaru_enrollment_principal_mirror")
    }

    init(location: KeychainLocation, account: String, defaults: UserDefaults, mirrorKey: String) {
        self.items = KeychainItems(location: location)
        self.account = account
        self.defaults = defaults
        self.mirrorKey = mirrorKey
    }

    func read() -> String? {
        if let data = try? items.get(account), let value = String(data: data, encoding: .utf8), !value.isEmpty {
            return value
        }
        guard let backup = defaults.string(forKey: mirrorKey), !backup.isEmpty else { return nil }
        try? items.set(account, Data(backup.utf8)) // the mirror still answers on the next read if this fails
        return backup
    }

    /// Writes the mirror first: a failure of the Keychain item alone must not lose the principal.
    func write(_ principal: String) {
        defaults.set(principal, forKey: mirrorKey)
        try? items.set(account, Data(principal.utf8)) // the mirror alone still allows a reuse later
    }

    func delete() {
        defaults.removeObject(forKey: mirrorKey)
        try? items.delete(account) // nothing left to read either way
    }
}

/// High-level, portable "ensure this device is correctly enrolled" contract: decides on its own whether to reuse
/// the current installation or reenroll from scratch, so no app has to reimplement this logic. Ported from
/// `sentomaru_service.dart` of a first consumer app (11/11/2026 project decision: that logic moves into the SDKs)
/// through its Android/Flutter ports, adapted to this platform's own `SentomaruClient`.
///
/// **No rotation branch.** The Android and Flutter ports also rotate the key after an app update (D-04b/D-04d),
/// driven by `SentomaruClient.reenrollmentReason()`. That method does not exist on iOS (App Attest's attestation
/// never names an app version, per `SentomaruClient`'s own doc comment), so there is no signal to decide "an
/// update happened, rotate now" — `EnrollmentAssurance` here only ever reuses or reenrolls from scratch.
/// `SentomaruClient.rotate(_:send:)` itself still exists (D-04d) for an app that has its own reason to call it, but
/// `ensureEnrolled` never calls it. This also means no background thread, no timeout and no "settle" wait are
/// needed here, unlike the other two ports.
///
/// One instance per `SentomaruClient` (construct once, reuse — it carries its own queue and storage). Concurrent
/// calls serialize (an internal async queue, like `SentomaruClient`'s own), and the most recent subject/tenant
/// wins over one still queued for an older caller (a login followed immediately by a tenant switch never enrolls
/// the old tenant over the new one). `forgetInstallation` joins the same queue.
public final class EnrollmentAssurance: @unchecked Sendable {
    private static let reinstallMarkerKey = "sentomaru_enrollment_ios_installed"

    private let client: SentomaruClient
    private let principalStore: PrincipalStore
    private let defaults: UserDefaults
    /// Consulted at most once per installation, only when this class's own storage (Keychain item + mirror) has
    /// nothing AND the SDK itself says `.enrolled`: an app migrating from its own, app-level principal tracking
    /// supplies its OLD stored value here, so upgrading to this class does not force a one-time reenrollment of
    /// every existing installation. A match is copied into this class's own storage right away; a non-match (or
    /// `nil`, the default) is never consulted again for this installation.
    private let legacyPrincipal: (@Sendable () async -> String?)?
    private let gate = AsyncSerial()
    private let lock = NSLock()
    private var latestPrincipal: String?

    /// Fires every time a call decided to enroll or reenroll rather than reuse the installation — never for a
    /// plain reuse, and never with subject, tenant or any other personal data (see `ReenrollReason`). Set before
    /// the first `ensureEnrolled` call; this class never calls it concurrently with itself.
    public var onReenrollReason: (@Sendable (ReenrollReason) -> Void)?

    public init(client: SentomaruClient, principalStore: PrincipalStore, defaults: UserDefaults = .standard,
                legacyPrincipal: (@Sendable () async -> String?)? = nil) {
        self.client = client
        self.principalStore = principalStore
        self.defaults = defaults
        self.legacyPrincipal = legacyPrincipal
    }

    /// sha256 (hex) of `subject\0tenant`: the same hash `ensureEnrolled` compares against this installation's
    /// stored principal. Exposed so a caller can compare without calling `ensureEnrolled` itself.
    public static func principalOf(subject: String, tenant: String) -> String {
        Hashing.hex(Hashing.sha256(Data("\(subject)\0\(tenant)".utf8)))
    }

    /// Ensures `subject`/`tenant` is enrolled on this device: reuses the installation when it already is for the
    /// same caller, or reenrolls from scratch (`reset` + `enroll`) otherwise. `challengeProvider` is asked for a
    /// fresh, single-use challenge every time one is actually needed; `grantSender` is the same `send` the raw
    /// `SentomaruClient.enroll`/`rotate` already take.
    public func ensureEnrolled(subject: String, tenant: String, challengeProvider: ChallengeProvider,
                                grantSender: SentomaruClient.EnrollmentSend) async throws -> EnsureEnrolledResult {
        let principal = Self.principalOf(subject: subject, tenant: tenant)
        lock.criticalSection { latestPrincipal = principal }
        return try await gate.run {
            // The most recent wins: a call that waited for the queue behind an older one for a different caller
            // never enrolls that one over the caller that arrived after it.
            guard lock.criticalSection({ self.latestPrincipal == principal }) else {
                return EnsureEnrolledResult(current: false, sessionId: nil)
            }
            let sessionId = try await self.ensureEnrolledLocked(principal: principal, subject: subject, tenant: tenant,
                                                                 challengeProvider: challengeProvider, grantSender: grantSender)
            return EnsureEnrolledResult(current: lock.criticalSection { self.latestPrincipal == principal }, sessionId: sessionId)
        }
    }

    private func ensureEnrolledLocked(principal: String, subject: String, tenant: String,
                                      challengeProvider: ChallengeProvider,
                                      grantSender: SentomaruClient.EnrollmentSend) async throws -> String? {
        let state = try await forgetIfReinstalled()
        let stored = await storedPrincipal(state: state)
        if state == .enrolled, stored == principal { return nil } // plain reuse: nothing to rotate on this platform
        onReenrollReason?(Self.reasonFor(state: state, stored: stored))
        // Challenge before reset: a network failure or a 5xx here must not erase an installation that still works.
        let challenge = try await challengeProvider(subject, tenant)
        if state != .notEnrolled { try await client.reset() }
        let grant = try await client.enroll(challenge, send: grantSender)
        principalStore.write(principal)
        return grant.sessionId
    }

    /// Forgets this installation (revoked server-side, or the app's own sign-out-everywhere): the next
    /// `ensureEnrolled` enrolls from scratch, with a fresh attestation. Joins the same queue as `ensureEnrolled`:
    /// never races a reset against one still finishing, and never erases an installation a newer call just made.
    public func forgetInstallation() async throws {
        try await gate.run {
            try await self.client.reset()
            self.principalStore.delete()
        }
    }

    /// Reinstalling does not erase the Keychain: a fresh install could otherwise see a leftover `.enrolled` record
    /// (and principal) from before, with a Secure Enclave key App Attest may no longer vouch for. `UserDefaults`
    /// IS erased on uninstall, so a missing marker means "first run since (re)install" - but checking `state()`
    /// first means a genuinely pristine install (never enrolled on this device at all) costs nothing beyond the
    /// one state read every other path already makes; only a real leftover record (state other than
    /// `.notEnrolled`) pays for a `reset()`. Returns the state read here so `ensureEnrolledLocked` does not read
    /// it twice. Idempotent and cheap once the marker is set (one `UserDefaults` read, one state read); safe to
    /// call at the start of every `ensureEnrolled`.
    private func forgetIfReinstalled() async throws -> InstallationState {
        let state = try await client.state()
        if defaults.bool(forKey: Self.reinstallMarkerKey) { return state }
        defaults.set(true, forKey: Self.reinstallMarkerKey)
        if state == .notEnrolled { return state }
        principalStore.delete()
        try await client.reset()
        return .notEnrolled
    }

    private func storedPrincipal(state: InstallationState) async -> String? {
        if let own = principalStore.read() { return own }
        guard let legacyPrincipal, state == .enrolled else { return nil } // nothing to migrate into otherwise
        guard let legacy = await legacyPrincipal(), !legacy.isEmpty else { return nil }
        principalStore.write(legacy) // consulted at most once for this installation, match or not
        return legacy
    }

    private static func reasonFor(state: InstallationState, stored: String?) -> ReenrollReason {
        switch state {
        case .notEnrolled: return .stateNotEnrolled
        case .enrollmentRequired: return .stateEnrollmentRequired
        case .keyInvalidated: return .stateKeyInvalidated
        case .enrolled: return stored == nil ? .principalAbsent : .principalChanged
        }
    }
}
