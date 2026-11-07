import Foundation
#if canImport(Sentomaru)
import Sentomaru
#endif

/// What a channel call answers, without any Flutter type (the plugin turns it into `FlutterResult` values).
/// `value` holds only channel-codec values (String, NSNumber, Bool, arrays, dictionaries, nil).
struct BridgeReply: @unchecked Sendable, Equatable {
    enum Kind: Equatable { case success, failure, notImplemented }

    let kind: Kind
    let value: Any?
    let code: String?
    let message: String?
    let details: String?

    static func success(_ value: Any?) -> BridgeReply {
        BridgeReply(kind: .success, value: value, code: nil, message: nil, details: nil)
    }
    /// PlatformException `code` and `message`. The message is the Android one for the plugin's own codes
    /// (`SentomaruFlutterBridge.messages`) and the code itself for the SDK's codes, as on Android; never a server body
    /// or a request value.
    static func failure(_ code: String, details: String? = nil, message: String? = nil) -> BridgeReply {
        BridgeReply(kind: .failure, value: nil, code: code,
                    message: message ?? SentomaruFlutterBridge.messages[code] ?? code, details: details)
    }
    static let notImplemented = BridgeReply(kind: .notImplemented, value: nil, code: nil, message: nil, details: nil)

    /// Kind, code, details and value; the message is checked on its own (tests).
    static func == (a: BridgeReply, b: BridgeReply) -> Bool {
        a.kind == b.kind && a.code == b.code && a.details == b.details && String(describing: a.value) == String(describing: b.value)
    }
}

/// D-10b: the iOS side of the `sentomaru_flutter` method channel, the Swift twin of the Android
/// `SentomaruFlutterPlugin` handlers, over the Swift SDK of `sdk/ios` (D-10a). Same method names, arguments, replies and
/// error codes as Android where iOS has an equivalent:
///
/// - `initialize`: `SentomaruClient.live(config:)` (Secure Enclave keys, data protection Keychain
///   `ThisDeviceOnly`, `DCAppAttestService`) and `SentomaruTransport` (allowlist, no redirect). `playIntegrityCloudProjectNumber`
///   and the reattestation routes are ignored (Google only; reattestation is `ReattestationUnsupported` in Dart).
/// - `enroll`/`rotate`: App Attest attestation of the Secure Enclave key; `strongBox` ignored; `requiresHardware: true`
///   refused before anything is created (`InvalidRequest:PARAMS`): an App Attest installation is `device_attested`,
///   never `hardware`, so the server would refuse it with 422 anyway (D-IOS9) and an App Attest key would be spent.
/// - `sign`: renewal first when due (J-04r with the D-09c assertion; a failure keeps the grant), then the signature.
/// - `renewSession`: same gate as Android (`RenewalBackoff` with the failure in details, else `InvalidRequest:PARAMS`).
/// - `reenrollmentReason`: always nil (D-04b has no iOS equivalent: an App Attest attestation names no app version).
/// - `collectSignals` (D-10e): the six catalog 1.0.0 observations of the SDK's `SignalsCollector` (Android map format:
///   state in lower case, `observedAt` ISO-8601, detail in `data`). `collectSignalsSnapshot` (D-10e): the snapshot map of
///   Android (`collectedAt`, `durationMs`, `observations`); `rasp` and `expectedSignerDigests` only add the D-05 and D-12c
///   ids as `unsupported` (no iOS check exists; the digests are never read here). Both run off the main thread and off
///   the serial queue (they touch no client state, as the Android collectors need no `initialize`). Reattestation and
///   sealed asset methods are answered in Dart before the channel on iOS, so they are not implemented.
///
/// Order: every call that reaches the native client runs on one serial queue per bridge, in the order the calls
/// arrived, each to its end before the next starts (the Android single-thread executor). So `sign` does its renewal
/// and its signature with nothing in between, and of two `initialize` calls the later one wins, as on Android. Errors are
/// the SDK's stable codes (`Unsupported:APP_ATTEST`, `Unsupported:SECURE_ENCLAVE`, `ServerRejected:SUSPENDED`, ...);
/// anything else is `ChannelError`.
///
/// Arguments of the wrong type (a body that is not bytes, a non-numeric expiry) are `InvalidRequest:PARAMS` here, where
/// the Android handler fails its cast and answers `ChannelError`.
final class SentomaruFlutterBridge: @unchecked Sendable {
    /// The native objects of one `initialize`, replaced together.
    struct Native: Sendable {
        let client: SentomaruClient
        let enroll: SentomaruClient.EnrollmentSend
        let renew: SentomaruClient.RenewalSend
    }

    typealias Factory = @Sendable (SentomaruConfig) throws -> Native
    typealias Reply = @Sendable (BridgeReply) -> Void

    static let notInitialized = "NotInitialized"
    static let configurationError = "ConfigurationError"
    static let channelError = "ChannelError"
    static let renewalBackoff = "RenewalBackoff"
    static let scaffold = "sentomaru_flutter:0.0.1"
    /// The messages of the Android plugin for its own codes (`SentomaruFlutterPlugin.kt`).
    static let messages: [String: String] = [
        notInitialized: "Sentomaru native client not initialized",
        configurationError: "Invalid or missing Sentomaru configuration",
        channelError: "Native error",
    ]

    /// Production wiring: one client per scope in the process (the SDK registry) and the URLSession transport.
    static let live: Factory = { config in
        let client = try SentomaruClient.live(config: config)
        let transport = SentomaruTransport(config: config)
        return Native(client: client, enroll: transport.enroll, renew: transport.renew)
    }

    private let factory: Factory
    private let transactionKeys: @Sendable () -> TransactionKeys
    private let signals: SignalsCollector
    private let lock = NSLock()
    private var current: Native?
    private var detached = false
    /// The tail of the serial queue: each operation waits for the previous one to finish (see the class comment).
    private var tail: Task<Void, Never>?

    init(factory: @escaping Factory = SentomaruFlutterBridge.live, signals: SignalsCollector = SignalsCollector(),
         transactionKeys: @escaping @Sendable () -> TransactionKeys = { SecureEnclaveTransactionKeys() }) {
        self.transactionKeys = transactionKeys
        self.factory = factory
        self.signals = signals
    }

    private var native: Native? { lock.lock(); defer { lock.unlock() }; return current }

    /// The engine went away: replies still in flight are dropped and new calls are refused.
    func detach() {
        lock.lock(); defer { lock.unlock() }
        detached = true
        current = nil
    }

    private func keep(_ built: Native) {
        lock.lock(); defer { lock.unlock() }
        guard !detached else { return } // an initialize that ends after the detach keeps nothing
        current = built
    }

    /// Tests only: whether an `initialize` result is kept.
    var isInitializedForTesting: Bool { native != nil }

    private var isDetached: Bool { lock.lock(); defer { lock.unlock() }; return detached }

    /// Handles one call. `arguments` is the decoded map of the call (typed data already turned into `Data` by the
    /// plugin); it is read synchronously here, so nothing of it crosses into the task.
    func handle(_ method: String, _ arguments: [String: Any]?, reply: @escaping Reply) {
        let args = arguments ?? [:]
        let send: Reply = { [weak self] answer in
            guard let self, !self.isDetached else { return }
            reply(answer)
        }
        switch method {
        case "scaffoldInfo": send(.success(Self.scaffold))
        case "initialize": initialize(args, send)
        case "state": withClient(send) { native in .success(try await native.client.state().rawValue) }
        case "reenrollmentReason": withClient(send) { _ in .success(nil) }
        case "enroll", "rotate":
            // Parsed now (the arguments do not cross into the task); a refusal is answered after NotInitialized, as on Android.
            let parsed = Result { try Self.enrollmentArguments(args) }
            let rotate = method == "rotate"
            withClient(send) { native in
                let parsed = try parsed.get()
                // D-IOS9: the request key is always the Secure Enclave one and the server never gives an App Attest
                // installation `hardware`; asking for it cannot succeed, so nothing is generated or attested.
                if parsed.1 { throw SentomaruError.invalidRequest(.PARAMS) }
                let grant = rotate ? try await native.client.rotate(parsed.0, send: native.enroll)
                    : try await native.client.enroll(parsed.0, send: native.enroll)
                return .success(Self.grantReply(grant))
            }
        case "sign":
            let parsed = Result { try Self.signArguments(args) }
            withClient(send) { native in
                let request = try parsed.get()
                // J-04r: renew a grant near its lifetime before signing; a failure keeps the current grant (the request
                // still goes out and the server decides) and the SDK backs off.
                _ = try? await native.client.renewIfDue(send: native.renew)
                let signed = try await native.client.sign(method: request.method, targetURI: request.targetURI,
                                                          operation: request.operation, body: request.body,
                                                          optional: request.optional)
                return .success(Self.headersReply(signed))
            }
        case "renewSession":
            withClient(send) { native in
                let gate = try await native.client.renewalGate()
                if let refusal = Self.renewalRefusal(gate) { return refusal }
                try await native.client.markGrantStale()
                return .success(try await native.client.renew(send: native.renew).sessionId)
            }
        case "reset":
            run(send) { [weak self] in
                guard let native = self?.native else { return .success(nil) }
                try await native.client.reset()
                return .success(nil)
            }
        case "sessionId":
            run(send) { [weak self] in
                guard let native = self?.native else { return .success(nil) }
                return .success(try await native.client.sessionId())
            }
        case "collectSignals":
            let signals = self.signals
            collect(send) { .success(Self.observationsReply(signals.snapshot().observations)) }
        case "collectSignalsSnapshot":
            let signals = self.signals
            guard let rasp = Self.flag(args["rasp"]) else { return send(.failure(SentomaruError.invalidRequest(.PARAMS).code)) }
            let appIntegrity = !(args["expectedSignerDigests"] == nil || args["expectedSignerDigests"] is NSNull)
            guard let screen = Self.flag(args["screen"]) else { return send(.failure(SentomaruError.invalidRequest(.PARAMS).code)) }
            if screen {
                // D-27: `UIScreen` is read on the main thread only (off it the two screen ids are UNKNOWN/partial). The
                // collection has a 135 ms deadline, so the main thread is held that long at most.
                Task { @MainActor in
                    send(.success(Self.snapshotReply(signals.snapshot(rasp: rasp, appIntegrity: appIntegrity, screen: true))))
                }
            } else {
                collect(send) { .success(Self.snapshotReply(signals.snapshot(rasp: rasp, appIntegrity: appIntegrity))) }
            }
        case "txKeyCreate", "txKeyCommit", "txKeyAbort", "txSign", "txIsEnrolled", "txDiscard":
            transaction(method, args, send)
        case "offlineSeal", "offlineReconcileBody":
            offline(method, args, send)
        default:
            send(.notImplemented)
        }
    }

    /// D-25 (iOS): the transaction key of the installation, `<installationAlias>.tx` in the Secure Enclave. Runs behind the
    /// serial queue (it reads the installation alias). A `TransactionError` is the closed code `Transaction:<CASE>`; the
    /// signature value is the header `x-sentomaru-tx-signature`, which the app passes to the interceptor. The server
    /// enrolls an iOS key as advisory evidence only: it never proves presence (contract, section 6).
    /// `txKeyCreate` only STAGES a new key (returns its SPKI); the key that signs is untouched until `txKeyCommit`, which the app
    /// calls after the server's `201`. `txKeyAbort` drops the staged key. Same closed codes as Android; no new code.
    private func transaction(_ method: String, _ args: [String: Any], _ send: @escaping Reply) {
        let make = self.transactionKeys
        // Arguments are read before the closure (a dictionary of `Any` is not Sendable).
        let biometricFlag = Self.flag(args["biometricOnly"])
        let biometricOnly = args["biometricOnly"] == nil || args["biometricOnly"] is NSNull ? true : (biometricFlag ?? true)
        let validFlag = biometricFlag != nil
        let operationId = args["operationId"] as? String
        let body = args["body"] as? Data
        let reason = (args["reason"] as? String) ?? TransactionSigner.defaultReason
        withClient(send) { native in
            guard let alias = try await native.client.installationAlias() else { return .failure(Self.notInitialized) }
            let signer = TransactionSigner(keys: make(), installationAlias: alias)
            do {
                switch method {
                case "txIsEnrolled": return .success(signer.isEnrolled())
                case "txDiscard": signer.discard(); return .success(nil)
                case "txKeyCreate":
                    guard validFlag else { throw SentomaruError.invalidRequest(.PARAMS) }
                    return .success(try signer.stageKey(biometricOnly: biometricOnly))
                case "txKeyCommit": try signer.commitKey(); return .success(nil)
                case "txKeyAbort": signer.abortKey(); return .success(nil)
                default:
                    guard let operationId, let body else { throw SentomaruError.invalidRequest(.PARAMS) }
                    return .success(try await signer.sign(operationId: operationId, body: body, reason: reason))
                }
            } catch let error as TransactionError {
                return .failure("Transaction:" + Self.transactionCode(error))
            }
        }
    }

    /// D-26 (iOS): `offlineSeal` seals one operation under the permit (the `201` body of `offline-permits`, as received) and
    /// returns the seal as the map of a reconciliation item; `offlineReconcileBody` builds the strict JSON body from the permit and
    /// the seals (bytes), which the app then signs with the normal `sign` (operation `offline_reconcile`). The permit request is the
    /// normal `sign` too (operation `offline_permit`, empty body). An `OfflineError` is the closed code `Offline:<CASE>`.
    private func offline(_ method: String, _ args: [String: Any], _ send: @escaping Reply) {
        let permitJson = args["permit"] as? Data ?? (args["permit"] as? String).map { Data($0.utf8) }
        let digest = args["operationDigest"] as? Data
        let seals = (args["seals"] as? [[String: Any]]).flatMap { try? $0.map(Self.seal) }
        withClient(send) { native in
            guard let permitJson, let permit = try? OfflinePermit.parse(permitJson) else {
                return .failure("Offline:" + Self.offlineCode(.permitInvalid))
            }
            do {
                if method == "offlineSeal" {
                    guard let digest else { throw SentomaruError.invalidRequest(.PARAMS) }
                    return .success(Self.sealReply(try await native.client.sealOfflineOperation(permit: permit, operationDigest: digest)))
                }
                guard let seals else { throw SentomaruError.invalidRequest(.PARAMS) }
                return .success(try OfflineRequests.reconcileBody(permit: permit, seals: seals))
            } catch let error as OfflineError {
                return .failure("Offline:" + Self.offlineCode(error))
            }
        }
    }

    static func offlineCode(_ error: OfflineError) -> String {
        switch error {
        case .permitInvalid: return "PERMIT_INVALID"
        case .permitExpired: return "PERMIT_EXPIRED"
        case .chainFull: return "CHAIN_FULL"
        case .invalidDigest: return "INVALID_DIGEST"
        case .clockUnavailable: return "CLOCK_UNAVAILABLE"
        }
    }

    /// The item of the reconciliation body: numbers as numbers, binary fields in base64url without padding.
    static func sealReply(_ seal: OfflineSeal) -> [String: Any] {
        ["seq": Int(seal.seq), "bootCount": Int(seal.bootCount), "elapsedRealtimeNanos": Int64(seal.elapsedRealtimeNanos),
         "wallClockMillis": Int64(seal.wallClockMillis), "operationDigest": OfflineChain.base64URL(seal.operationDigest),
         "prevHash": OfflineChain.base64URL(seal.prevHash), "hash": OfflineChain.base64URL(seal.hash),
         "signature": OfflineChain.base64URL(seal.signature)]
    }

    static func seal(_ map: [String: Any]) throws -> OfflineSeal {
        func number(_ key: String) throws -> NSNumber {
            guard let value = map[key] as? NSNumber, !isBool(value) else { throw SentomaruError.invalidRequest(.PARAMS) }
            return value
        }
        func bytes(_ key: String) throws -> Data {
            guard let text = map[key] as? String, let data = OfflineChain.fromBase64URL(text) else { throw SentomaruError.invalidRequest(.PARAMS) }
            return data
        }
        guard let seq = UInt32(exactly: try number("seq").int64Value), let boot = UInt32(exactly: try number("bootCount").int64Value),
              let elapsed = UInt64(exactly: try number("elapsedRealtimeNanos").int64Value),
              let wall = UInt64(exactly: try number("wallClockMillis").int64Value) else { throw SentomaruError.invalidRequest(.PARAMS) }
        return OfflineSeal(seq: seq, bootCount: boot, elapsedRealtimeNanos: elapsed, wallClockMillis: wall, operationDigest: try bytes("operationDigest"),
                           prevHash: try bytes("prevHash"), hash: try bytes("hash"), signature: try bytes("signature"))
    }

    static func transactionCode(_ error: TransactionError) -> String {
        switch error {
        case .notEnrolled: return "NOT_ENROLLED"
        case .keyInvalidated: return "KEY_INVALIDATED"
        case .cancelled: return "CANCELLED"
        case .lockedOut: return "LOCKED_OUT"
        case .noUserAuthentication: return "NO_USER_AUTHENTICATION"
        case .unavailable: return "UNAVAILABLE"
        case .signingFailed: return "SIGNING_FAILED"
        }
    }

    private func initialize(_ args: [String: Any], _ send: @escaping Reply) {
        let config: SentomaruConfig
        do { config = try Self.config(args) } catch { return send(.failure(Self.configurationError)) }
        let factory = self.factory
        run(send) { [weak self] in
            let built: Native
            do { built = try factory(config) } catch let error as SentomaruError { throw error } catch {
                return .failure(Self.channelError, message: "Native initialize failed")
            }
            guard let self else { throw SentomaruError.cancelled }
            self.keep(built)
            return .success(nil)
        }
    }

    /// The client is read when the operation's turn comes, so a call queued behind `initialize` sees its result.
    private func withClient(_ send: @escaping Reply, _ body: @escaping @Sendable (Native) async throws -> BridgeReply) {
        run(send) { [weak self] in
            guard let self, !self.isDetached, let native = self.native else { return .failure(Self.notInitialized) }
            return try await body(native)
        }
    }

    /// D-10e: a signals collection, off the main thread and outside the serial queue (it reads no client state).
    private func collect(_ send: @escaping Reply, _ body: @escaping @Sendable () -> BridgeReply) {
        Task.detached { send(body()) }
    }

    /// Enqueues `body` behind every operation enqueued before it (the order of the calls, taken under the lock).
    private func run(_ send: @escaping Reply, _ body: @escaping @Sendable () async throws -> BridgeReply) {
        lock.lock(); defer { lock.unlock() }
        let previous = tail
        tail = Task {
            await previous?.value
            let answer: BridgeReply
            do { answer = try await body() } catch { answer = Self.failure(error) }
            send(answer)
        }
    }

    // MARK: - Arguments and replies (pure, tested)

    static func failure(_ error: Error) -> BridgeReply {
        if let error = error as? SentomaruError { return .failure(error.code) }
        return .failure(channelError)
    }

    /// The channel's `initialize` map as an SDK configuration. Nothing defaulted but the 7-day grace period; anything
    /// missing or invalid (also what `SentomaruConfig` refuses) is `ConfigurationError`, as on Android.
    static func config(_ args: [String: Any]) throws -> SentomaruConfig {
        struct Invalid: Error {}
        func text(_ key: String) throws -> String {
            guard let value = args[key] as? String, !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { throw Invalid() }
            return value
        }
        guard let rawHosts = args["allowedHosts"] as? [Any], !rawHosts.isEmpty else { throw Invalid() }
        let hosts = try Set(rawHosts.map { item -> String in
            guard let host = item as? String else { throw Invalid() }
            return host
        })
        let graceDays: Int
        switch args["rotationGracePeriodDays"] {
        case nil, is NSNull: graceDays = 7
        case let number as NSNumber where !isBool(number): graceDays = number.intValue
        default: throw Invalid()
        }
        let renewalUrl: String?
        switch args["renewalUrl"] {
        case nil, is NSNull: renewalUrl = nil
        default: renewalUrl = try text("renewalUrl")
        }
        do {
            return try SentomaruConfig(organization: text("organization"), app: text("app"), environment: text("environment"),
                                       allowedHosts: hosts, enrollmentUrl: text("enrollmentUrl"),
                                       rotationGracePeriod: TimeInterval(graceDays) * 24 * 3600, renewalUrl: renewalUrl)
        } catch is Invalid {
            throw Invalid()
        } catch {
            throw Invalid() // slug, allowlist, URL or grace period refused by SentomaruConfig
        }
    }

    /// `challenge` (`id`, `token`, `expiresAtEpochMs`, `attestationChallengeB64`) and `requiresHardware`; `strongBox` is
    /// Android only and ignored. Anything malformed is `InvalidRequest:PARAMS`.
    static func enrollmentArguments(_ args: [String: Any]) throws -> (EnrollmentChallenge, Bool) {
        guard let map = args["challenge"] as? [String: Any], let id = map["id"] as? String, let token = map["token"] as? String,
              let expires = map["expiresAtEpochMs"] as? NSNumber, !isBool(expires),
              let encoded = map["attestationChallengeB64"] as? String, let attestation = Data(base64Encoded: encoded)
        else { throw SentomaruError.invalidRequest(.PARAMS) }
        let requiresHardware: Bool
        switch args["requiresHardware"] {
        case nil, is NSNull: requiresHardware = false
        case let flag as Bool: requiresHardware = flag
        default: throw SentomaruError.invalidRequest(.PARAMS)
        }
        let challenge = try EnrollmentChallenge(id: id, token: token, attestationChallenge: attestation,
                                                expiresAt: Date(timeIntervalSince1970: Double(expires.int64Value) / 1000))
        return (challenge, requiresHardware)
    }

    struct SignArguments: Sendable, Equatable {
        let method: String
        let targetURI: String
        let operation: String
        let body: Data
        let optional: [String: String]
    }

    /// Same refusals as Android: no method = `METHOD`, no target = `TARGET_URI`, no operation or a non-text optional
    /// header = `HEADER_VALUE`. `body` arrives as `Data` (the plugin converts the typed data).
    static func signArguments(_ args: [String: Any]) throws -> SignArguments {
        guard let method = args["method"] as? String else { throw SentomaruError.invalidRequest(.METHOD) }
        guard let target = args["targetUri"] as? String else { throw SentomaruError.invalidRequest(.TARGET_URI) }
        guard let operation = args["operation"] as? String else { throw SentomaruError.invalidRequest(.HEADER_VALUE) }
        let body: Data
        switch args["body"] {
        case nil, is NSNull: body = Data()
        case let bytes as Data: body = bytes
        default: throw SentomaruError.invalidRequest(.PARAMS)
        }
        var optional: [String: String] = [:]
        switch args["optional"] {
        case nil, is NSNull: break
        case let raw as [AnyHashable: Any]:
            for (key, value) in raw {
                guard let name = key as? String, let text = value as? String else { throw SentomaruError.invalidRequest(.HEADER_VALUE) }
                optional[name] = text
            }
        default: throw SentomaruError.invalidRequest(.HEADER_VALUE)
        }
        return SignArguments(method: method, targetURI: target, operation: operation, body: body, optional: optional)
    }

    static func grantReply(_ grant: EnrollmentGrant) -> [String: String] {
        ["installationId": grant.installationId, "keyId": grant.keyId, "sessionId": grant.sessionId,
         "hardwareStatus": grant.hardwareStatus, "attestationStatus": grant.attestationStatus]
    }

    /// Header name to value (lowercase names, as the SDK builds them); the first value of a repeated name wins.
    static func headersReply(_ signed: SignedMessage) -> [String: String] {
        var headers: [String: String] = [:]
        for header in signed.headers where headers[header.name] == nil { headers[header.name] = header.value }
        return headers
    }

    /// Why `renewSession` is not attempted now (Android `renewalRefusalReply`), or nil to renew: inside the backoff of
    /// the last failed renewal = `RenewalBackoff` with the code of that failure in details; unable to renew at all (no
    /// renewal URL, not enrolled) = `InvalidRequest:PARAMS`.
    static func renewalRefusal(_ gate: SentomaruClient.RenewalGate) -> BridgeReply? {
        if gate.backingOff { return .failure(renewalBackoff, details: gate.lastFailure) }
        if !gate.canRenewNow { return .failure(SentomaruError.invalidRequest(.PARAMS).code) }
        return nil
    }

    /// D-10e: observations as the Android plugin sends them (`SentomaruFlutterPlugin.handleCollectSignals`).
    static func observationsReply(_ observations: [SignalObservation]) -> [[String: Any]] {
        observations.map { o in
            ["capabilityId": o.capabilityId, "version": o.version, "state": o.state.rawValue.lowercased(), "source": o.source,
             "observedAt": SignalsSnapshot.instant(o.observedAt), "data": o.detail]
        }
    }

    /// D-10e: the snapshot as the Android plugin sends it (`snapshotReply`).
    static func snapshotReply(_ snapshot: SignalsSnapshot) -> [String: Any] {
        ["collectedAt": SignalsSnapshot.instant(snapshot.collectedAt), "durationMs": snapshot.durationMs,
         "observations": observationsReply(snapshot.observations)]
    }

    /// An optional channel `bool`: nil/absent = false, a boolean (`CFBoolean`) = its value, anything else = nil
    /// (`InvalidRequest:PARAMS`). Review R N1: an `NSNumber` 1 or 0 from a Dart `int` is not a `bool`; `as Bool` would
    /// accept it.
    static func flag(_ value: Any?) -> Bool? {
        switch value {
        case nil, is NSNull: return false
        case let number as NSNumber where isBool(number): return number.boolValue
        default: return nil
        }
    }

    /// The standard codec sends Dart `bool` as an NSNumber of the boolean type; a count must not accept it.
    static func isBool(_ number: NSNumber) -> Bool { CFGetTypeID(number) == CFBooleanGetTypeID() }
}
