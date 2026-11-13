import Foundation
import Sentomaru

/// What a channel call answers, without any per-platform type (a thin native module turns it into its own
/// framework's reply/error shape: `RCTPromiseResolveBlock`/`RCTPromiseRejectBlock` on RN, a `CAPPluginCall` on
/// Capacitor, a `CallbackContext` on Cordova). `value` holds only JSON-codec values (String, NSNumber, Bool, arrays,
/// dictionaries, nil) so any of the three can serialize it.
public struct BridgeReply: @unchecked Sendable, Equatable {
    public enum Kind: Equatable { case success, failure, notImplemented }

    public let kind: Kind
    public let value: Any?
    public let code: String?
    public let message: String?
    public let details: String?

    public static func success(_ value: Any?) -> BridgeReply {
        BridgeReply(kind: .success, value: value, code: nil, message: nil, details: nil)
    }
    /// The error `code` and `message`. The message is this bridge's own for its own codes
    /// (`SentomaruHybridBridge.messages`) and the code itself for the SDK's codes, as on Android; never a server body
    /// or a request value.
    public static func failure(_ code: String, details: String? = nil, message: String? = nil) -> BridgeReply {
        BridgeReply(kind: .failure, value: nil, code: code,
                    message: message ?? SentomaruHybridBridge.messages[code] ?? code, details: details)
    }
    public static let notImplemented = BridgeReply(kind: .notImplemented, value: nil, code: nil, message: nil, details: nil)

    /// Kind, code, details and value; the message is checked on its own (tests).
    public static func == (a: BridgeReply, b: BridgeReply) -> Bool {
        a.kind == b.kind && a.code == b.code && a.details == b.details && String(describing: a.value) == String(describing: b.value)
    }
}

/// D-22 (RN/Capacitor/Cordova iOS): the method dispatcher of `contracts/sdk/hybrid-bridge-v1.json` over the Swift SDK
/// of `sdk/ios`, the iOS twin of the Android `sdk/hybrid-core` (`SentomaruBridge.kt`). One instance per native module;
/// each platform's own plugin class (not part of this package) only decodes its framework's call into a method name
/// and a `[String: Any]` map and forwards it to `handle`, then encodes the `BridgeReply` back. `scaffoldInfo` is
/// Flutter-only (contract `flutterOnly`) and not implemented here.
///
/// - `initialize`: `SentomaruClient.live(config:)` (Secure Enclave keys, data protection Keychain
///   `ThisDeviceOnly`, `DCAppAttestService`) and `SentomaruTransport` (allowlist, no redirect). `playIntegrityCloudProjectNumber`
///   and the reattestation routes are ignored (Google only).
/// - `enroll`/`rotate`: App Attest attestation of the Secure Enclave key; `strongBox` ignored; `requiresHardware: true`
///   refused before anything is created (`InvalidRequest:PARAMS`): an App Attest installation is `device_attested`,
///   never `hardware`, so the server would refuse it with 422 anyway and an App Attest key would be spent.
/// - `sign`: renewal first when due (the D-09c assertion; a failure keeps the grant), then the signature.
/// - `renewSession`: `RenewalBackoff` with the failure in details, else `InvalidRequest:PARAMS`.
/// - `reenrollmentReason`: always nil (no iOS equivalent: an App Attest attestation names no app version).
/// - `collectSignals`/`collectSignalsSnapshot`: the SDK's `SignalsCollector`, off the main thread and outside the
///   serial queue (they touch no client state). `rasp` and `expectedSignerDigests` only add the Android-only ids as
///   `unsupported` (no iOS check exists; the digests are never read here).
/// - `reattestationDue`/`reattestIfDue`/`reattest` (Play Integrity reattestation) and `sealedConfigure`/`sealedLoad`/
///   `sealedString` (sealed asset reader) have no iOS SDK equivalent and are not implemented here, same as Flutter's
///   iOS side.
///
/// Order: every call that reaches the native client runs on one serial queue per bridge, in the order the calls
/// arrived, each to its end before the next starts (the Android single-thread executor). So `sign` does its renewal
/// and its signature with nothing in between. Errors are the SDK's stable codes (`Unsupported:APP_ATTEST`,
/// `Unsupported:SECURE_ENCLAVE`, `ServerRejected:SUSPENDED`, ...); anything else is `ChannelError`.
///
/// Revisor A, rodada 2 (médio A): `allowedHosts`/`enrollmentUrl`/`renewalUrl` come from the channel, i.e. from the
/// JavaScript side; on Capacitor/Cordova that is a WebView page, not necessarily the app's own code. The first
/// `initialize` that actually builds a client locks these three fields for the life of the bridge (see
/// `securityRefusal`/`lockSecurityAfterSuccess`): a later `initialize` may only narrow `allowedHosts` and must
/// repeat `enrollmentUrl`/`renewalUrl` unchanged, or it is refused as `ConfigurationError` before any client is
/// built — otherwise injected page content could call `initialize` again with an attacker host and have the next
/// `enroll`/`sign`/`renewSession` attest, sign and renew against it. Same rule on Android (`InitializeSecurityLock`)
/// and, for whoever writes the .NET MAUI/Xamarin native adapter, `Sentomaru.Hybrid.LockingNativeSentomaru`.
///
/// Revisor A, rodada 2 (baixo E): `detach()` refuses a call not yet started (`isDetached` in `withClient`) and drops
/// the reply of a call still in flight at that moment (`isDetached` again, inside `send`) - but does not and cannot
/// stop a call already past that point from finishing without a cancellation token threaded through
/// `SentomaruClient`/`SentomaruTransport` (out of scope here). `testEnrollInFlightWhenDetachFiresCompletesButItsReplyIsDiscarded`
/// proves exactly this: the in-flight enroll runs to completion, and its reply never reaches the caller.
///
/// Arguments of the wrong type (a body that is not bytes, a non-numeric expiry) are `InvalidRequest:PARAMS` here.
public final class SentomaruHybridBridge: @unchecked Sendable {
    /// The native objects of one `initialize`, replaced together.
    public struct Native: Sendable {
        let client: SentomaruClient
        let enroll: SentomaruClient.EnrollmentSend
        let renew: SentomaruClient.RenewalSend
        public init(client: SentomaruClient, enroll: @escaping SentomaruClient.EnrollmentSend,
                    renew: @escaping SentomaruClient.RenewalSend) {
            self.client = client
            self.enroll = enroll
            self.renew = renew
        }
    }

    public typealias Factory = @Sendable (SentomaruConfig) throws -> Native
    public typealias Reply = @Sendable (BridgeReply) -> Void

    public static let notInitialized = "NotInitialized"
    public static let configurationError = "ConfigurationError"
    public static let channelError = "ChannelError"
    public static let renewalBackoff = "RenewalBackoff"
    public static let messages: [String: String] = [
        notInitialized: "Sentomaru native client not initialized",
        configurationError: "Invalid or missing Sentomaru configuration",
        channelError: "Native error",
    ]

    /// Production wiring: one client per scope in the process (the SDK registry) and the URLSession transport.
    public static let live: Factory = { config in
        let client = try SentomaruClient.live(config: config)
        let transport = SentomaruTransport(config: config)
        return Native(client: client, enroll: transport.enroll, renew: transport.renew)
    }

    private let factory: Factory
    private let signals: SignalsCollector
    private let lock = NSLock()
    private var current: Native?
    private var detached = false
    /// Security-relevant fields of the first accepted `initialize` (see the class comment, "Revisor A, rodada 2").
    private struct Security: Equatable { let hosts: Set<String>; let enrollmentUrl: String; let renewalUrl: String? }
    private var security: Security?
    /// The tail of the serial queue: each operation waits for the previous one to finish (see the class comment).
    private var tail: Task<Void, Never>?

    public init(factory: @escaping Factory = SentomaruHybridBridge.live, signals: SignalsCollector = SignalsCollector()) {
        self.factory = factory
        self.signals = signals
    }

    private var native: Native? { lock.lock(); defer { lock.unlock() }; return current }

    /// The host went away: replies still in flight are dropped and new calls are refused.
    public func detach() {
        lock.lock(); defer { lock.unlock() }
        detached = true
        current = nil
    }

    private func keep(_ built: Native) {
        lock.lock(); defer { lock.unlock() }
        guard !detached else { return } // an initialize that ends after the detach keeps nothing
        current = built
    }

    /// nil = this `config` may proceed (and is locked, if nothing was locked yet); non-nil = the reply to send
    /// instead, without building a client. Locking happens here, before `factory` runs, so a refused call never
    /// spends work (an App Attest key, a network round trip) on an attacker-chosen configuration.
    private func lockSecurity(_ config: SentomaruConfig) -> BridgeReply? {
        lock.lock(); defer { lock.unlock() }
        let candidate = Security(hosts: config.allowedHosts, enrollmentUrl: config.enrollmentUrl, renewalUrl: config.renewalUrl)
        guard let locked = security else {
            security = candidate
            return nil
        }
        guard candidate.hosts.isSubset(of: locked.hosts), candidate.enrollmentUrl == locked.enrollmentUrl,
              candidate.renewalUrl == locked.renewalUrl else {
            return .failure(Self.configurationError)
        }
        return nil
    }

    /// Tests only: whether an `initialize` result is kept.
    public var isInitializedForTesting: Bool { native != nil }

    private var isDetached: Bool { lock.lock(); defer { lock.unlock() }; return detached }

    /// Handles one call. `arguments` is the decoded map of the call. It is read synchronously here, so nothing of it
    /// crosses into the task.
    public func handle(_ method: String, _ arguments: [String: Any]?, reply: @escaping Reply) {
        let args = arguments ?? [:]
        let send: Reply = { [weak self] answer in
            guard let self, !self.isDetached else { return }
            reply(answer)
        }
        switch method {
        case "initialize": initialize(args, send)
        case "state": withClient(send) { native in .success(try await native.client.state().rawValue) }
        case "reenrollmentReason": withClient(send) { _ in .success(nil) }
        case "enroll", "rotate":
            // Parsed now (the arguments do not cross into the task); a refusal is answered after NotInitialized, as on Android.
            let parsed = Result { try Self.enrollmentArguments(args) }
            let rotate = method == "rotate"
            withClient(send) { native in
                let parsed = try parsed.get()
                if parsed.1 { throw SentomaruError.invalidRequest(.PARAMS) }
                let grant = rotate ? try await native.client.rotate(parsed.0, send: native.enroll)
                    : try await native.client.enroll(parsed.0, send: native.enroll)
                return .success(Self.grantReply(grant))
            }
        case "sign":
            let parsed = Result { try Self.signArguments(args) }
            withClient(send) { native in
                let request = try parsed.get()
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
            collect(send) { .success(Self.snapshotReply(signals.snapshot(rasp: rasp, appIntegrity: appIntegrity))) }
        default:
            // reattestationDue/reattestIfDue/reattest, sealedConfigure/sealedLoad/sealedString: no iOS SDK equivalent.
            send(.notImplemented)
        }
    }

    private func initialize(_ args: [String: Any], _ send: @escaping Reply) {
        let config: SentomaruConfig
        do { config = try Self.config(args) } catch { return send(.failure(Self.configurationError)) }
        if let refusal = lockSecurity(config) { return send(refusal) }
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

    /// A signals collection, off the main thread and outside the serial queue (it reads no client state).
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

    public static func failure(_ error: Error) -> BridgeReply {
        if let error = error as? SentomaruError { return .failure(error.code) }
        return .failure(channelError)
    }

    /// The channel's `initialize` map as an SDK configuration. Nothing defaulted but the 7-day grace period; anything
    /// missing or invalid (also what `SentomaruConfig` refuses) is `ConfigurationError`, as on Android.
    public static func config(_ args: [String: Any]) throws -> SentomaruConfig {
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
        func bool(_ key: String) throws -> Bool {
            switch args[key] {
            case nil, is NSNull: return false
            case let flag as Bool: return flag
            default: throw Invalid()
            }
        }
        do {
            return try SentomaruConfig(organization: text("organization"), app: text("app"), environment: text("environment"),
                                       allowedHosts: hosts, enrollmentUrl: text("enrollmentUrl"),
                                       rotationGracePeriod: TimeInterval(graceDays) * 24 * 3600, renewalUrl: renewalUrl,
                                       declaredEnforce: try bool("declaredEnforce"),
                                       declaredInstallationResponse: try bool("declaredInstallationResponse"))
        } catch is Invalid {
            throw Invalid()
        } catch {
            throw Invalid() // slug, allowlist, URL or grace period refused by SentomaruConfig
        }
    }

    /// `challenge` (`id`, `token`, `expiresAtEpochMs`, `attestationChallengeB64`) and `requiresHardware`; `strongBox` is
    /// Android only and ignored. Anything malformed is `InvalidRequest:PARAMS`.
    public static func enrollmentArguments(_ args: [String: Any]) throws -> (EnrollmentChallenge, Bool) {
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

    public struct SignArguments: Sendable, Equatable {
        public let method: String
        public let targetURI: String
        public let operation: String
        public let body: Data
        public let optional: [String: String]
    }

    /// Same refusals as Android: no method = `METHOD`, no target = `TARGET_URI`, no operation or a non-text optional
    /// header = `HEADER_VALUE`. `body` arrives as `Data` (the native module converts the channel's typed data).
    public static func signArguments(_ args: [String: Any]) throws -> SignArguments {
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

    public static func grantReply(_ grant: EnrollmentGrant) -> [String: String] {
        ["installationId": grant.installationId, "keyId": grant.keyId, "sessionId": grant.sessionId,
         "hardwareStatus": grant.hardwareStatus, "attestationStatus": grant.attestationStatus]
    }

    /// Header name to value (lowercase names, as the SDK builds them); the first value of a repeated name wins.
    public static func headersReply(_ signed: SignedMessage) -> [String: String] {
        var headers: [String: String] = [:]
        for header in signed.headers where headers[header.name] == nil { headers[header.name] = header.value }
        return headers
    }

    /// Why `renewSession` is not attempted now (the Android `renewalRefusalReply`), or nil to renew: inside the backoff
    /// of the last failed renewal = `RenewalBackoff` with the code of that failure in details; unable to renew at all
    /// (no renewal URL, not enrolled) = `InvalidRequest:PARAMS`.
    public static func renewalRefusal(_ gate: SentomaruClient.RenewalGate) -> BridgeReply? {
        if gate.backingOff { return .failure(renewalBackoff, details: gate.lastFailure) }
        if !gate.canRenewNow { return .failure(SentomaruError.invalidRequest(.PARAMS).code) }
        return nil
    }

    /// UTC ISO-8601 with milliseconds, the wire format of `SignalsSnapshot.json()` (`instant`, internal to Sentomaru).
    static func instant(_ date: Date) -> String {
        date.formatted(Date.ISO8601FormatStyle(includingFractionalSeconds: true, timeZone: TimeZone(identifier: "UTC")!))
    }

    /// Observations as the Android bridge sends them (state in lower case, `observedAt` ISO-8601, detail in `data`).
    public static func observationsReply(_ observations: [SignalObservation]) -> [[String: Any]] {
        observations.map { o in
            ["capabilityId": o.capabilityId, "version": o.version, "state": o.state.rawValue.lowercased(), "source": o.source,
             "observedAt": Self.instant(o.observedAt), "data": o.detail]
        }
    }

    /// The snapshot as the Android bridge sends it (`collectedAt`, `durationMs`, `observations`).
    public static func snapshotReply(_ snapshot: SignalsSnapshot) -> [String: Any] {
        ["collectedAt": Self.instant(snapshot.collectedAt), "durationMs": snapshot.durationMs,
         "observations": observationsReply(snapshot.observations)]
    }

    /// An optional channel `bool`: nil/absent = false, a boolean (`CFBoolean`) = its value, anything else = nil
    /// (`InvalidRequest:PARAMS`). An `NSNumber` 1 or 0 from a JS `number` is not a `bool`; `as Bool` would accept it.
    public static func flag(_ value: Any?) -> Bool? {
        switch value {
        case nil, is NSNull: return false
        case let number as NSNumber where isBool(number): return number.boolValue
        default: return nil
        }
    }

    /// The standard codec sends a JS `boolean` as an NSNumber of the boolean type; a count must not accept it.
    public static func isBool(_ number: NSNumber) -> Bool { CFGetTypeID(number) == CFBooleanGetTypeID() }
}
