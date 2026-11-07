import CryptoKit
import Foundation

/// D-26 (iOS): why an operation could not be sealed. A seal is never produced in these cases.
public enum OfflineError: Error, Equatable, Sendable {
    case permitInvalid        // the permit response is malformed
    case permitExpired        // the wall clock is past the permit's `validUntil`
    case chainFull            // `maxItems` seals already made under this permit
    case invalidDigest        // not a SHA-256 (32 bytes)
    case clockUnavailable     // the boot session became unavailable (or available) in the middle of one permit
}

/// The `201` of `offline-permits`, parsed.
public struct OfflinePermit: Equatable, Sendable {
    public let permitId: String
    public let chainSeed: Data
    public let issuedAt: Date
    public let validUntil: Date
    public let maxItems: Int
    public let driftToleranceSeconds: Int

    public init(permitId: String, chainSeed: Data, issuedAt: Date, validUntil: Date, maxItems: Int, driftToleranceSeconds: Int) throws {
        guard OfflineChain.uuidBytes(permitId) != nil, chainSeed.count == 32, validUntil > issuedAt,
              (1...OfflineChain.maxItems).contains(maxItems), (0...900).contains(driftToleranceSeconds) else {
            throw OfflineError.permitInvalid
        }
        self.permitId = permitId.lowercased()
        self.chainSeed = chainSeed
        self.issuedAt = issuedAt
        self.validUntil = validUntil
        self.maxItems = maxItems
        self.driftToleranceSeconds = driftToleranceSeconds
    }

    /// Parses the response body of `POST .../offline-permits`.
    public static func parse(_ json: Data) throws -> OfflinePermit {
        guard let object = try? JSONSerialization.jsonObject(with: json) as? [String: Any],
              let id = object["permitId"] as? String, let seedText = object["chainSeed"] as? String,
              let seed = OfflineChain.fromBase64URL(seedText), let issued = (object["issuedAt"] as? String).flatMap(parseDate),
              let until = (object["validUntil"] as? String).flatMap(parseDate),
              let maxItems = (object["maxItems"] as? NSNumber)?.intValue,
              let drift = (object["driftToleranceSeconds"] as? NSNumber)?.intValue else { throw OfflineError.permitInvalid }
        return try OfflinePermit(permitId: id, chainSeed: seed, issuedAt: issued, validUntil: until, maxItems: maxItems,
                                 driftToleranceSeconds: drift)
    }

    private static func parseDate(_ text: String) -> Date? {
        let plain = ISO8601DateFormatter()
        plain.formatOptions = [.withInternetDateTime]
        if let date = plain.date(from: text) { return date }
        let fractional = ISO8601DateFormatter()
        fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return fractional.date(from: text)
    }
}

/// One sealed operation: the item of the reconciliation body (base64url without padding for the binary fields).
public struct OfflineSeal: Equatable, Sendable {
    public let seq: UInt32
    public let bootCount: UInt32
    public let elapsedRealtimeNanos: UInt64
    public let wallClockMillis: UInt64
    public let operationDigest: Data
    public let prevHash: Data
    public let hash: Data
    /// ECDSA P-256 SHA-256, DER, over the record.
    public let signature: Data

    public init(seq: UInt32, bootCount: UInt32, elapsedRealtimeNanos: UInt64, wallClockMillis: UInt64, operationDigest: Data,
                prevHash: Data, hash: Data, signature: Data) {
        self.seq = seq
        self.bootCount = bootCount
        self.elapsedRealtimeNanos = elapsedRealtimeNanos
        self.wallClockMillis = wallClockMillis
        self.operationDigest = operationDigest
        self.prevHash = prevHash
        self.hash = hash
        self.signature = signature
    }
}

/// The clocks a seal reads. `bootSession` is an identifier of the current boot (nil when the system gives none).
public struct OfflineClocks: Sendable {
    public let wall: @Sendable () -> Date
    public let elapsedNanos: @Sendable () -> UInt64
    public let bootSession: @Sendable () -> String?

    public init(wall: @escaping @Sendable () -> Date, elapsedNanos: @escaping @Sendable () -> UInt64,
                bootSession: @escaping @Sendable () -> String?) {
        self.wall = wall
        self.elapsedNanos = elapsedNanos
        self.bootSession = bootSession
    }

    /// iOS has no public boot counter (Android has `BOOT_COUNT`). The equivalents, all public and not settable by the person:
    /// `CLOCK_MONOTONIC` (`mach_continuous_time`: counts the sleep, restarts at boot; it is slewed by NTP, so it can differ from
    /// the true elapsed time by parts in 10^4, far below the permit's drift tolerance) and the `kern.bootsessionuuid` sysctl (a
    /// new UUID on every boot, independent of the wall clock). The SDK turns the UUID into a counter it keeps itself.
    public static let live = OfflineClocks(
        wall: { Date() },
        elapsedNanos: { clock_gettime_nsec_np(CLOCK_MONOTONIC) },
        bootSession: {
            var size = 0
            guard sysctlbyname("kern.bootsessionuuid", nil, &size, nil, 0) == 0, size > 1 else { return nil }
            var buffer = [UInt8](repeating: 0, count: size)
            guard sysctlbyname("kern.bootsessionuuid", &buffer, &size, nil, 0) == 0, size > 1 else { return nil }
            return String(decoding: buffer.prefix(size - 1), as: UTF8.self) // without the terminating NUL
        })
}

/// Private storage of the chain state (the next `seq` and the last hash per permit, and the boot tracker), one blob per
/// installation alias. Errors are `storageUnavailable`.
public protocol OfflineStateStore: Sendable {
    func read(_ alias: String) throws -> Data?
    func write(_ alias: String, _ data: Data) throws
    func delete(_ alias: String) throws
}

public struct KeychainOfflineStateStore: OfflineStateStore {
    public static let defaultService = "br.com.ebees.sentomaru.offline"
    let items: KeychainItems

    public init(service: String = KeychainOfflineStateStore.defaultService) { self.init(location: .dataProtection(service: service)) }
    init(location: KeychainLocation) { self.items = KeychainItems(location: location) }

    public func read(_ alias: String) throws -> Data? { try items.get(alias) }
    public func write(_ alias: String, _ data: Data) throws { try items.set(alias, data) }
    public func delete(_ alias: String) throws { try items.delete(alias) }
}

/// The seal itself (pure of the client's lifecycle; the client serializes calls).
struct OfflineSealer {
    struct State: Codable, Equatable {
        struct Boot: Codable, Equatable { var session: String; var counter: UInt32 }
        struct Chain: Codable, Equatable { var nextSeq: UInt32; var lastHash: String; var bootAvailable: Bool }
        var boot: Boot?
        var chains: [String: Chain] = [:]
        /// Permits older than the newest few are forgotten: a permit is open for 24 h and reconciled within 48 h.
        var order: [String] = []
        static let keepPermits = 4
    }

    let keys: InstallationKeys
    let store: OfflineStateStore
    let clocks: OfflineClocks

    func seal(alias: String, permit: OfflinePermit, operationDigest: Data) throws -> OfflineSeal {
        guard operationDigest.count == 32 else { throw OfflineError.invalidDigest }
        let wall = clocks.wall()
        guard wall <= permit.validUntil else { throw OfflineError.permitExpired }
        var state = try load(alias)
        let key = permit.permitId
        let permitBytes = OfflineChain.uuidBytes(key)!
        let chain = state.chains[key]
        let seq = chain?.nextSeq ?? 0
        guard Int(seq) < permit.maxItems else { throw OfflineError.chainFull }

        let session = clocks.bootSession()
        let bootCount: UInt32
        if let session {
            var boot = state.boot ?? State.Boot(session: session, counter: 1)
            if boot.session != session { boot = State.Boot(session: session, counter: boot.counter &+ 1) }
            state.boot = boot
            bootCount = boot.counter
        } else {
            bootCount = OfflineChain.unavailableBootCount
        }
        if let chain, chain.bootAvailable != (session != nil) { throw OfflineError.clockUnavailable }

        let prevHash = try chain.map { try Self.decode($0.lastHash) } ?? OfflineChain.seedHash(permitId: permitBytes, chainSeed: permit.chainSeed)
        let elapsed = clocks.elapsedNanos()
        let millis = UInt64(max(0, (wall.timeIntervalSince1970 * 1000).rounded(.down)))
        let record = OfflineChain.record(permitId: permitBytes, seq: seq, bootCount: bootCount, elapsedNanos: elapsed, wallMillis: millis,
                                         operationDigest: operationDigest, prevHash: prevHash)
        let hash = OfflineChain.hash(of: record)
        let raw: Data
        do { raw = try keys.sign(alias, record) } catch let error as SentomaruError { throw error } catch { throw SentomaruError.keyUnavailable }
        guard let der = try? OfflineChain.derSignature(fromP1363: raw) else { throw SentomaruError.keyUnavailable }

        // The state moves only after the signature exists, and the seal is returned only after the state is stored: a failure
        // in between leaves no gap and no seal.
        state.chains[key] = State.Chain(nextSeq: seq + 1, lastHash: OfflineChain.base64URL(hash), bootAvailable: session != nil)
        state.order.removeAll { $0 == key }
        state.order.append(key)
        while state.order.count > State.keepPermits { state.chains[state.order.removeFirst()] = nil }
        try save(alias, state)
        return OfflineSeal(seq: seq, bootCount: bootCount, elapsedRealtimeNanos: elapsed, wallClockMillis: millis,
                           operationDigest: operationDigest, prevHash: prevHash, hash: hash, signature: der)
    }

    private func load(_ alias: String) throws -> State {
        guard let data = try store.read(alias) else { return State() }
        guard let state = try? JSONDecoder().decode(State.self, from: data) else { throw SentomaruError.storageUnavailable }
        return state
    }

    private func save(_ alias: String, _ state: State) throws {
        guard let data = try? JSONEncoder().encode(state) else { throw SentomaruError.storageUnavailable }
        try store.write(alias, data)
    }

    private static func decode(_ text: String) throws -> Data {
        guard let data = OfflineChain.fromBase64URL(text), data.count == 32 else { throw SentomaruError.storageUnavailable }
        return data
    }
}

/// Bodies of the two offline routes.
public enum OfflineRequests {
    public static let permitOperation = "offline_permit"
    public static let reconcileOperation = "offline_reconcile"

    private struct Item: Encodable {
        let seq: UInt32, bootCount: UInt32, elapsedRealtimeNanos: UInt64, wallClockMillis: UInt64
        let operationDigest: String, prevHash: String, hash: String, signature: String
    }

    private struct Body: Encodable {
        let permitId: String
        let items: [Item]
    }

    /// The reconciliation body: strict JSON, the seals in order, binary fields in base64url without padding. More seals than
    /// the permit allows, or none, is `InvalidRequest:PARAMS`; the order and the gaps are the server's to check.
    public static func reconcileBody(permit: OfflinePermit, seals: [OfflineSeal]) throws -> Data {
        guard !seals.isEmpty, seals.count <= permit.maxItems else { throw SentomaruError.invalidRequest(.PARAMS) }
        let items = seals.map {
            Item(seq: $0.seq, bootCount: $0.bootCount, elapsedRealtimeNanos: $0.elapsedRealtimeNanos, wallClockMillis: $0.wallClockMillis,
                 operationDigest: OfflineChain.base64URL($0.operationDigest), prevHash: OfflineChain.base64URL($0.prevHash),
                 hash: OfflineChain.base64URL($0.hash), signature: OfflineChain.base64URL($0.signature))
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        guard let data = try? encoder.encode(Body(permitId: permit.permitId, items: items)) else { throw SentomaruError.invalidRequest(.PARAMS) }
        return data
    }
}
