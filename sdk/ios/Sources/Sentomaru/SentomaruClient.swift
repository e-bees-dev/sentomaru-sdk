import Foundation

/// The installation lifecycle on iOS, the Swift twin of the Android `SentomaruClient`: enroll (Secure Enclave request
/// key + App Attest), sign requests (RFC 9421 profile, same bytes as Android), renew the grant (J-04r) with an App
/// Attest assertion (D-09c), rotate (D-04d) and reset.
///
/// One instance per scope and store. Every operation is `async` and serialized on the instance, `send` included: a
/// signature waits for a renewal in progress, and one renewal runs at a time (the server orders renewals by the App
/// Attest counter). The public consumer transport is injected (`send`); `SentomaruTransport` is the URLSession one.
///
/// Not mirrored from Android: Play Integrity (C-04b), StrongBox, `requiresHardware` (always false, D-IOS9),
/// `reenrollmentReason` (D-04b; the App Attest attestation names no app version) and reattestation (D-12c, iOS =
/// unsupported in the Flutter plugin).
public final class SentomaruClient: @unchecked Sendable {
    public typealias EnrollmentSend = @Sendable (SignedMessage) async throws -> EnrollmentGrant
    public typealias RenewalSend = @Sendable (SignedMessage) async throws -> RenewedGrant

    /// J-04r: renew this long before the grant's lifetime ends.
    public static let renewalMargin: TimeInterval = 120
    /// J-04r: after a failed renewal, wait this long before trying again.
    public static let renewalBackoff: TimeInterval = 60
    /// Backoff after consecutive `ServerRejected:SUSPENDED` renewals: 5 s, 15 s, then 60 s.
    public static let suspendedRenewalBackoffSteps: [TimeInterval] = [5, 15, 60]
    /// Reserved operation of a renewal (server: SessionRenewalService.Operation).
    public static let renewOperation = "session_renew"
    /// D-04d: refusals of a resent rotation in which the server proves its body was not accepted.
    static let neverAccepted: Set<SentomaruError.Rejection> = [.EXPIRED, .REVOKED, .CONFLICT]

    public let config: SentomaruConfig
    let keys: InstallationKeys
    let store: InstallationStore
    let appAttest: AppAttestService
    let now: @Sendable () -> Date
    let offline: OfflineSealer

    private let gate = AsyncSerial()
    // Mutable state below is only touched inside `gate.run`.
    private var lifecycleGeneration: Int64 = 0
    private var renewalFailedAt: Date?
    private var renewalFailureCode: String?
    private var currentRenewalBackoff: TimeInterval = SentomaruClient.renewalBackoff
    private var suspendedFailures = 0

    public init(config: SentomaruConfig, keys: InstallationKeys, store: InstallationStore, appAttest: AppAttestService,
                now: @escaping @Sendable () -> Date = { Date() },
                offlineStore: OfflineStateStore = KeychainOfflineStateStore(), offlineClocks: OfflineClocks = .live) {
        self.offline = OfflineSealer(keys: keys, store: offlineStore, clocks: offlineClocks)
        self.config = config
        self.keys = keys
        self.store = store
        self.appAttest = appAttest
        self.now = now
    }

    // MARK: - Production wiring

    private static let registryLock = NSLock()
    nonisolated(unsafe) private static var registry: [String: SentomaruClient] = [:]

    /// One client per scope in this process: Secure Enclave keys and the record in the data protection Keychain
    /// (`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`), and `DCAppAttestService`. A second call for the same
    /// scope returns the same client; the same scope with another allowlist, enrollment URL, renewal URL or grace period
    /// is `InvalidRequest:PARAMS`.
    @available(iOS 14.0, macOS 11.0, *)
    public static func live(config: SentomaruConfig) throws -> SentomaruClient {
        try registryLock.criticalSection {
            if let previous = registry[config.identity] {
                let same = previous.config.allowedHosts == config.allowedHosts && previous.config.enrollmentUrl == config.enrollmentUrl &&
                    previous.config.renewalUrl == config.renewalUrl && previous.config.rotationGracePeriod == config.rotationGracePeriod
                guard same else { throw SentomaruError.invalidRequest(.PARAMS) }
                return previous
            }
            let client = SentomaruClient(config: config, keys: SecureEnclaveKeys(), store: KeychainInstallationStore(config: config),
                                         appAttest: DeviceCheckAppAttestService())
            registry[config.identity] = client
            return client
        }
    }

    // MARK: - State

    public func state() async throws -> InstallationState { try await gate.run { try stateLocked() } }

    public func retiredKeys() async throws -> [RetiredKey] { try await gate.run { try record()?.retiredKeys ?? [] } }

    public func sessionId() async throws -> String? { try await gate.run { try record()?.grant?.sessionId } }

    /// D-25: the alias of the installation's key, the base of the transaction key's alias (`<alias>.tx`); nil before the
    /// first enrollment. A new installation (re-enrollment) gets a new alias, so an old transaction key is not reused.
    public func installationAlias() async throws -> String? { try await gate.run { try record()?.alias } }

    // MARK: - Offline proof chain (D-26)

    /// Seals one operation of an offline window under `permit` (the Android `sealOfflineOperation`). `operationDigest` is the
    /// SHA-256 of the operation's payload, which never leaves the app. Needs the installation key and no grant: the window is
    /// offline. Makes no network call. A permit past its `validUntil`, a full chain or a digest that is not 32 bytes is an
    /// `OfflineError`, never a seal.
    public func sealOfflineOperation(permit: OfflinePermit, operationDigest: Data) async throws -> OfflineSeal {
        try await gate.run {
            guard let record = try record() else { throw SentomaruError.notEnrolled }
            guard try keyCall({ try keys.exists(record.alias) }) else { throw SentomaruError.keyInvalidated }
            return try offline.seal(alias: record.alias, permit: permit, operationDigest: operationDigest)
        }
    }

    /// The signed request that asks for a permit (`operation` `offline_permit`, empty body); the app's backend forwards it.
    public func offlinePermitRequest(targetURI: String) async throws -> SignedMessage {
        try await sign(method: "POST", targetURI: targetURI, operation: OfflineRequests.permitOperation, body: Data())
    }

    /// The signed reconciliation request (`operation` `offline_reconcile`) carrying the seals in order (the Android
    /// `reconcileOfflineChain`). Call it online, after the grant was renewed: the batch never renews the grant. The verdict
    /// goes to the consumer's backend, not back to the app.
    public func reconcileOfflineChainRequest(targetURI: String, permit: OfflinePermit, seals: [OfflineSeal]) async throws -> SignedMessage {
        let body = try OfflineRequests.reconcileBody(permit: permit, seals: seals)
        return try await sign(method: "POST", targetURI: targetURI, operation: OfflineRequests.reconcileOperation, body: body)
    }

    private func stateLocked() throws -> InstallationState {
        guard let record = try record() else { return .notEnrolled }
        if record.body != nil, !(try keyCall { try keys.exists(record.alias) }) { return .keyInvalidated }
        return record.grant == nil ? .enrollmentRequired : .enrolled
    }

    private func requireEnrolled() throws {
        switch try stateLocked() {
        case .notEnrolled: throw SentomaruError.notEnrolled
        case .enrollmentRequired: throw SentomaruError.enrollmentRequired
        case .keyInvalidated: throw SentomaruError.keyInvalidated
        case .enrolled: return
        }
    }

    // MARK: - Enrollment

    /// Enrolls with `challenge`: generates the Secure Enclave request key, attests its SPKI with App Attest
    /// (`clientDataHash = SHA-256(attestationChallenge ‖ SPKI)`), freezes the body, signs it and hands it to `send`.
    /// A retry with the same challenge resends the same bytes; another challenge while one is pending is
    /// `EnrollmentRequired` (call `reset()`). Without App Attest or Secure Enclave: `unsupported(...)`, nothing kept.
    public func enroll(_ challenge: EnrollmentChallenge, send: EnrollmentSend) async throws -> EnrollmentGrant {
        try await gate.run { try await enrollLocked(challenge, send: send) }
    }

    private func enrollLocked(_ challenge: EnrollmentChallenge, send: EnrollmentSend) async throws -> EnrollmentGrant {
        try checkCancelled()
        let generation = lifecycleGeneration
        var pending = try record()
        if try stateLocked() == .keyInvalidated { throw SentomaruError.keyInvalidated }
        if let existing = pending {
            if existing.challenge != challenge { throw SentomaruError.enrollmentRequired }
            if let grant = existing.grant { return grant }
        }
        if now() >= challenge.expiresAt { throw SentomaruError.challengeExpired }
        if pending == nil {
            // Fail before creating anything: never an enrollment "without attestation".
            guard appAttest.isSupported else { throw SentomaruError.unsupported(.APP_ATTEST) }
            let alias = "sentomaru.v1.\(config.identity).v1.\(UUIDText.random())"
            pending = InstallationRecord(scopeIdentity: config.identity, alias: alias, challenge: challenge)
            try storeWrite(pending) // ownership persisted before generation, recoverable after process death
        }
        var current = pending!
        if current.body == nil {
            do {
                let spki = try keyCall { try keys.exists(current.alias) ? try keys.publicKey(current.alias) : try keys.generate(current.alias) }
                let evidence = try await attest(attestationChallenge: challenge.attestationChallenge, spki: spki, record: &current)
                current.body = try EnrollmentBody.encode(token: challenge.token, publicKey: spki, appAttest: evidence)
                current.publicKey = spki
                current.appAttestKeyId = evidence.keyId
            } catch SentomaruError.unsupported(let capability) {
                try? keys.delete(current.alias)
                try storeWrite(nil)
                throw SentomaruError.unsupported(capability)
            }
            try storeWrite(current) // exact frozen bytes durable before the first network side effect
        }
        try checkCancelled()
        let alias = current.alias
        let request = try FrozenRequest(method: "POST", targetURI: config.enrollmentUrl,
                                        headers: config.headers(session: challenge.id, operation: "enroll"), body: current.body!)
        let signed = try MessageSigner.sign(request, params: try SignatureParams.now(now(), keyId: challenge.id, nonce: UUIDText.random())) { base in
            try self.keyCall { try self.keys.sign(alias, base) }
        }
        try checkCancelled()
        if generation != lifecycleGeneration { throw SentomaruError.cancelled }
        let grant = try await deliver(send, signed)
        try checkCancelled() // cancelled after the server effect: the frozen bytes remain for an idempotent retry
        if generation != lifecycleGeneration { throw SentomaruError.cancelled }
        guard grant.keyId == challenge.id else { throw SentomaruError.invalidRequest(.PARAMS) }
        let issued = grant.issued(at: now()) // J-04r: the renewal schedule starts at receipt
        current.grant = issued
        try storeWrite(current)
        return issued
    }

    // MARK: - Rotation (D-04d)

    /// Replaces the active key with a new Secure Enclave key and a new App Attest attestation, proven with the current
    /// key (`predecessor`), so the server re-enrolls this installation. The current key keeps signing until the new
    /// grant arrives and stays on the device for `rotationGracePeriod`. Same recovery rules as Android (§2.4).
    public func rotate(_ challenge: EnrollmentChallenge, send: EnrollmentSend) async throws -> EnrollmentGrant {
        try await gate.run { try await rotateLocked(challenge, send: send) }
    }

    private func rotateLocked(_ challenge: EnrollmentChallenge, send: EnrollmentSend) async throws -> EnrollmentGrant {
        try checkCancelled()
        let generation = lifecycleGeneration
        try requireEnrolled()
        let current = try record()!
        if now() >= challenge.expiresAt { throw SentomaruError.challengeExpired }
        var attesting = current // holds the App Attest key id between generateKey and a successful attestKey
        var pending = current.pendingRotation
        if let stale = pending, stale.challenge != challenge {
            // A body already handed to `send` may be committed with its answer lost: its identical replay gets the
            // original grant even with its challenge expired. Adopt it instead of rotating again.
            if stale.sent, let grant = try await recoverSentRotation(current, stale, generation: generation, send: send) {
                return grant
            }
            try? keys.delete(stale.alias)
            pending = nil
            attesting.pendingRotation = nil // the dropped record must not outlive its key: a later resend would fail with the key gone
            try storeWrite(attesting)
        }
        if pending == nil {
            guard appAttest.isSupported else { throw SentomaruError.unsupported(.APP_ATTEST) }
            let newAlias = "sentomaru.v1.\(config.identity).v\(current.generation + 1).\(UUIDText.random())"
            do {
                let spki = try keyCall { try keys.generate(newAlias) }
                let evidence = try await attest(attestationChallenge: challenge.attestationChallenge, spki: spki, record: &attesting)
                let previous = current.grant!.installationId
                let proof = try keyCall {
                    try keys.sign(current.alias, ReenrollmentProof.message(config: config, previousInstallation: previous,
                                                                             challengeId: challenge.id, newKeySpki: spki))
                }
                guard proof.count == 64 else { throw SentomaruError.keyUnavailable }
                let body = try EnrollmentBody.encode(token: challenge.token, publicKey: spki, appAttest: evidence,
                                                     predecessor: ReenrollmentProof.member(previousInstallation: previous, signature: proof))
                pending = PendingRotation(alias: newAlias, challenge: challenge, body: body, publicKey: spki,
                                          appAttestKeyId: evidence.keyId, sent: false)
            } catch {
                try? keys.delete(newAlias) // never persisted: the current key stays active
                throw error
            }
        }
        return try await sendRotation(current, pending!, generation: generation, send: send)
    }

    private func recoverSentRotation(_ current: InstallationRecord, _ pending: PendingRotation, generation: Int64,
                                     send: EnrollmentSend) async throws -> EnrollmentGrant? {
        do {
            return try await sendRotation(current, pending, generation: generation, send: send)
        } catch SentomaruError.serverRejected(let reason) where Self.neverAccepted.contains(reason) {
            return nil
        } catch SentomaruError.reenrollmentRefused {
            try? keys.delete(pending.alias)
            var dropped = current
            dropped.pendingRotation = nil
            try storeWrite(dropped)
            throw SentomaruError.reenrollmentRefused
        }
    }

    private func sendRotation(_ current: InstallationRecord, _ frozen: PendingRotation, generation: Int64,
                              send: EnrollmentSend) async throws -> EnrollmentGrant {
        func persist(_ rotation: PendingRotation) throws {
            var record = current
            record.pendingRotation = rotation
            try storeWrite(record)
        }
        if current.pendingRotation != frozen { try persist(frozen) }
        let challenge = frozen.challenge
        try checkCancelled()
        let request = try FrozenRequest(method: "POST", targetURI: config.enrollmentUrl,
                                        headers: config.headers(session: challenge.id, operation: "enroll"), body: frozen.body)
        let signed = try MessageSigner.sign(request, params: try SignatureParams.now(now(), keyId: challenge.id, nonce: UUIDText.random())) { base in
            try self.keyCall { try self.keys.sign(frozen.alias, base) }
        }
        try checkCancelled()
        if generation != lifecycleGeneration { throw SentomaruError.cancelled }
        let pending = frozen.markedSent()
        if pending != frozen { try persist(pending) } // before `send`: the answer can be lost after the commit
        let grant = try await deliver(send, signed)
        try checkCancelled()
        if generation != lifecycleGeneration { throw SentomaruError.cancelled }
        guard grant.keyId == challenge.id else { throw SentomaruError.invalidRequest(.PARAMS) }
        let retiredAt = now()
        let issued = grant.issued(at: retiredAt)
        let rotated = InstallationRecord(
            scopeIdentity: config.identity, alias: pending.alias, challenge: challenge, body: pending.body, grant: issued,
            generation: current.generation + 1,
            retiredKeys: current.retiredKeys + [RetiredKey(alias: current.alias, retiredAt: retiredAt,
                                                           expiresAt: retiredAt.addingTimeInterval(config.rotationGracePeriod))],
            pendingRotation: nil, publicKey: pending.publicKey, appAttestKeyId: pending.appAttestKeyId)
        try storeWrite(rotated)
        _ = try prune(rotated)
        return issued
    }

    // MARK: - Signing

    /// Signs final frozen bytes with the active key. The host must be an allowlisted `https` host and the scope and
    /// session headers must be the client's; checked before the private key is used.
    public func signRequest(_ frozen: FrozenRequest) async throws -> SignedMessage {
        try await gate.run { try signRequestLocked(frozen) }
    }

    /// Freezes and signs `body` for `operation` with the current grant. `optional` carries only the signed optional
    /// headers (`x-sentomaru-signals`, `x-sentomaru-operation-id`); anything else is `InvalidRequest:HEADER_NAME`.
    public func sign(method: String, targetURI: String, operation: String, body: Data,
                     optional: [String: String] = [:]) async throws -> SignedMessage {
        try await gate.run {
            guard Set(Profile.optionalHeaders).isSuperset(of: optional.keys) else { throw SentomaruError.invalidRequest(.HEADER_NAME) }
            try requireEnrolled()
            let session = try record()!.grant!.sessionId
            let headers = config.headers(session: session, operation: operation).merging(optional) { first, _ in first }
            return try signRequestLocked(try FrozenRequest(method: method, targetURI: targetURI, headers: headers, body: body))
        }
    }

    private func signRequestLocked(_ frozen: FrozenRequest) throws -> SignedMessage {
        try checkCancelled()
        try config.checkHost(frozen.targetURI)
        try requireEnrolled()
        let record = try record()!
        let grant = record.grant!
        let expected = config.headers(session: grant.sessionId, operation: frozen.headers["x-sentomaru-operation"] ?? "")
        if expected.contains(where: { frozen.headers[$0.key] != $0.value }) { throw SentomaruError.invalidRequest(.HEADER_VALUE) }
        let alias = record.alias
        return try MessageSigner.sign(frozen, params: try SignatureParams.now(now(), keyId: grant.keyId, nonce: UUIDText.random())) { base in
            try self.keyCall { try self.keys.sign(alias, base) }
        }
    }

    // MARK: - Renewal (J-04r + D-09c)

    /// One consistent snapshot of the renewal gate (Android `RenewalGate`).
    public struct RenewalGate: Equatable, Sendable {
        public let backingOff: Bool
        public let canRenewNow: Bool
        public let lastFailure: String?
    }

    public func needsRenewal() async throws -> Bool { try await gate.run { try needsRenewalLocked() } }
    public func canRenewNow() async throws -> Bool { try await gate.run { try renewable() && !backoffRunning() } }
    public func renewalBackingOff() async throws -> Bool { try await gate.run { try renewable() && backoffRunning() } }
    public func lastRenewalFailure() async throws -> String? { try await gate.run { try renewalGateLocked().lastFailure } }
    public func renewalGate() async throws -> RenewalGate { try await gate.run { try renewalGateLocked() } }

    private func needsRenewalLocked() throws -> Bool {
        guard try renewable(), !backoffRunning() else { return false }
        return try record()!.grant!.renewalDue(now: now(), maxMargin: Self.renewalMargin)
    }

    private func renewalGateLocked() throws -> RenewalGate {
        let renewable = try renewable()
        let running = backoffRunning()
        let backingOff = renewable && running
        return RenewalGate(backingOff: backingOff, canRenewNow: renewable && !running,
                           lastFailure: backingOff ? renewalFailureCode : nil)
    }

    private func renewable() throws -> Bool { try config.renewalUrl != nil && stateLocked() == .enrolled }

    private func backoffRunning() -> Bool {
        guard let failed = renewalFailedAt else { return false }
        return now() < failed.addingTimeInterval(currentRenewalBackoff)
    }

    private func renewalFailed(_ at: Date, _ error: SentomaruError?) {
        renewalFailedAt = at
        renewalFailureCode = error?.code
        if case .serverRejected(.SUSPENDED)? = error {
            currentRenewalBackoff = Self.suspendedRenewalBackoffSteps[min(suspendedFailures, Self.suspendedRenewalBackoffSteps.count - 1)]
            suspendedFailures += 1
        } else {
            currentRenewalBackoff = Self.renewalBackoff
            suspendedFailures = 0
        }
    }

    private func clearRenewalBackoff() {
        renewalFailedAt = nil
        renewalFailureCode = nil
        currentRenewalBackoff = Self.renewalBackoff
        suspendedFailures = 0
    }

    /// Renews only when `needsRenewal` still holds under the client's serialization; nil when nothing was due.
    public func renewIfDue(send: RenewalSend) async throws -> EnrollmentGrant? {
        try await gate.run { try needsRenewalLocked() ? try await renewLocked(send: send) : nil }
    }

    /// The server said `session-expired`: the next `needsRenewal` answers true.
    public func markGrantStale() async throws {
        try await gate.run {
            guard var current = try record(), let grant = current.grant else { return }
            current.grant = grant.stale()
            try storeWrite(current)
        }
    }

    /// Renews the grant: `POST renewalUrl`, operation `session_renew`, signed by the request key over the current
    /// grant, body exactly `{"appAssertion":"<base64 CBOR>"}` (D-09c) with an App Attest assertion over
    /// `SHA-256("sentomaru-app-assertion-v1\n" ‖ sessionId ‖ "\n" ‖ nonce ‖ "\n" ‖ b64url(SHA-256(SPKI)))`, where
    /// `nonce` is this request's `Signature-Input` nonce. A new assertion (and nonce) on every attempt.
    ///
    /// Failure keeps the current grant and starts the backoff. `enrollmentRequired` from `send` (403
    /// `session-unavailable`, which is also every assertion refusal) and an App Attest key that is no longer valid
    /// drop the grant: `state()` is `enrollmentRequired` and the app calls `reset()` + `enroll()`.
    public func renew(send: RenewalSend) async throws -> EnrollmentGrant {
        try await gate.run { try await renewLocked(send: send) }
    }

    private func renewLocked(send: RenewalSend) async throws -> EnrollmentGrant {
        try checkCancelled()
        guard let url = config.renewalUrl else { throw SentomaruError.invalidRequest(.PARAMS) }
        try requireEnrolled()
        let current = try record()!
        let grant = current.grant!
        let generation = lifecycleGeneration
        guard let appAttestKeyId = current.appAttestKeyId else { throw SentomaruError.keyInvalidated }
        let spki = try current.publicKey ?? keyCall { try keys.publicKey(current.alias) }
        let nonce = UUIDText.random()
        let assertion: Data
        do {
            assertion = try await appAttest.generateAssertion(
                appAttestKeyId, clientDataHash: AppAttestBinding.assertionClientDataHash(sessionId: grant.sessionId, nonce: nonce, spki: spki))
        } catch {
            let mapped = Self.attestError(error)
            if mapped == .cancelled { throw mapped }
            if mapped == .keyInvalidated { // the App Attest key is gone: the server would refuse; enroll again
                try dropGrant(current)
                throw SentomaruError.enrollmentRequired
            }
            renewalFailed(now(), mapped)
            throw mapped
        }
        guard (1...AppAttestBinding.maxAssertion).contains(assertion.count) else {
            renewalFailed(now(), .keyUnavailable)
            throw SentomaruError.keyUnavailable
        }
        try checkCancelled()
        let request = try FrozenRequest(method: "POST", targetURI: url,
                                        headers: config.headers(session: grant.sessionId, operation: Self.renewOperation),
                                        body: AppAttestBinding.renewalBody(assertion: assertion))
        let alias = current.alias
        let signed = try MessageSigner.sign(request, params: try SignatureParams.now(now(), keyId: grant.keyId, nonce: nonce)) { base in
            try self.keyCall { try self.keys.sign(alias, base) }
        }
        let sentAt = now() // conservative: the server's lifetime starts after this
        let renewed: RenewedGrant
        do {
            renewed = try await deliver(send, signed)
        } catch SentomaruError.cancelled {
            throw SentomaruError.cancelled
        } catch SentomaruError.enrollmentRequired {
            try dropGrant(current) // the chain is over: enroll again (no backoff left)
            throw SentomaruError.enrollmentRequired
        } catch let error as SentomaruError {
            renewalFailed(sentAt, error)
            throw error
        } catch {
            renewalFailed(sentAt, nil)
            throw error
        }
        if generation != lifecycleGeneration { throw SentomaruError.cancelled }
        guard renewed.keyId == grant.keyId, renewed.installationId == grant.installationId else {
            renewalFailed(sentAt, .invalidRequest(.PARAMS))
            throw SentomaruError.invalidRequest(.PARAMS)
        }
        let next = try EnrollmentGrant(installationId: grant.installationId, keyId: grant.keyId, sessionId: renewed.sessionId,
                                       hardwareStatus: grant.hardwareStatus, attestationStatus: grant.attestationStatus,
                                       issuedAt: sentAt, ttlSeconds: renewed.ttlSeconds)
        var updated = current
        updated.grant = next
        try storeWrite(updated)
        clearRenewalBackoff()
        return next
    }

    private func dropGrant(_ current: InstallationRecord) throws {
        clearRenewalBackoff()
        var dropped = current
        dropped.grant = nil
        try storeWrite(dropped)
    }

    // MARK: - Reset

    /// Explicit local reset only (server revocation stays with the consumer). Deletes every key this scope owns and
    /// the record. App Attest keys cannot be deleted (no API); a new enrollment generates a new one.
    public func reset() async throws {
        try await gate.run {
            lifecycleGeneration += 1
            clearRenewalBackoff()
            try keyCall { try keys.deleteOwned(prefix: "sentomaru.v1.\(config.identity).") }
            try storeWrite(nil)
        }
    }

    // MARK: - Helpers

    private func record() throws -> InstallationRecord? {
        let current: InstallationRecord?
        do { current = try store.read() } catch let error as SentomaruError { throw error } catch {
            throw SentomaruError.storageUnavailable
        }
        guard let current else { return nil }
        guard current.scopeIdentity == config.identity, current.alias.hasPrefix("sentomaru.v1.\(config.identity).") else {
            throw SentomaruError.keyInvalidated
        }
        return try prune(current)
    }

    private func prune(_ record: InstallationRecord) throws -> InstallationRecord {
        guard !record.retiredKeys.isEmpty else { return record }
        let instant = now()
        let expired = record.retiredKeys.filter { instant >= $0.expiresAt }
        guard !expired.isEmpty else { return record }
        for item in expired { try? keys.delete(item.alias) }
        var updated = record
        updated.retiredKeys = record.retiredKeys.filter { instant < $0.expiresAt }
        try storeWrite(updated)
        return updated
    }

    private func storeWrite(_ record: InstallationRecord?) throws {
        do { try store.write(record) } catch let error as SentomaruError { throw error } catch {
            throw SentomaruError.storageUnavailable
        }
    }

    private func keyCall<T>(_ body: () throws -> T) throws -> T {
        do { return try body() } catch let error as SentomaruError { throw error } catch {
            throw SentomaruError.keyUnavailable
        }
    }

    private func checkCancelled() throws { if Task.isCancelled { throw SentomaruError.cancelled } }

    /// Attests `spki` with App Attest. The key id is persisted in `record.attestingKeyId` before `attestKey`; a retry
    /// reuses it. Apple's rule: after `serverUnavailable` (`networkUnavailable` here) the same key may be attested again;
    /// after a success or any other failure it may not, so the id is cleared then.
    private func attest(attestationChallenge: Data, spki: Data, record: inout InstallationRecord) async throws -> AppAttestEvidence {
        guard appAttest.isSupported else { throw SentomaruError.unsupported(.APP_ATTEST) }
        let keyId: String
        if let saved = record.attestingKeyId, AppAttestBinding.validKeyId(saved) {
            keyId = saved
        } else {
            do { keyId = try await appAttest.generateKey() } catch { throw Self.attestError(error) }
            guard AppAttestBinding.validKeyId(keyId) else { throw SentomaruError.keyUnavailable }
            record.attestingKeyId = keyId
            try storeWrite(record)
        }
        let object: Data
        do {
            object = try await appAttest.attestKey(
                keyId, clientDataHash: AppAttestBinding.attestationClientDataHash(attestationChallenge: attestationChallenge, spki: spki))
        } catch {
            let mapped = Self.attestError(error)
            if mapped != .networkUnavailable && mapped != .cancelled {
                record.attestingKeyId = nil
                try? storeWrite(record)
            }
            throw mapped
        }
        record.attestingKeyId = nil
        try storeWrite(record)
        guard (1...AppAttestBinding.maxAttestationObject).contains(object.count) else { throw SentomaruError.keyUnavailable }
        return AppAttestEvidence(keyId: keyId, attestationObject: object)
    }

    static func attestError(_ error: Error) -> SentomaruError {
        if let error = error as? SentomaruError { return error }
        if error is CancellationError { return .cancelled }
        return .keyUnavailable
    }

    /// `send` errors: `SentomaruError` as is, cancellation as `cancelled`, `URLError` as `networkUnavailable`
    /// (Android `IOException`); anything else propagates unchanged.
    private func deliver<T>(_ send: @Sendable (SignedMessage) async throws -> T, _ signed: SignedMessage) async throws -> T {
        do {
            return try await send(signed)
        } catch let error as SentomaruError {
            throw error
        } catch is CancellationError {
            throw SentomaruError.cancelled
        } catch let error as URLError {
            throw error.code == .cancelled ? SentomaruError.cancelled : SentomaruError.networkUnavailable
        }
    }
}
