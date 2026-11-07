import CryptoKit
import Foundation
@testable import Sentomaru
import XCTest

/// Test-only software request keys (CryptoKit, in memory). Never shipped: the SDK has no software fallback.
final class SoftwareKeys: InstallationKeys, @unchecked Sendable {
    private let lock = NSLock()
    private var keys: [String: P256.Signing.PrivateKey] = [:]
    var failGenerate: SentomaruError?
    private(set) var generated = 0
    private(set) var signatures = 0

    func exists(_ alias: String) throws -> Bool { lock.withLock { keys[alias] != nil } }

    func generate(_ alias: String) throws -> Data {
        try lock.withLock {
            if let failGenerate { throw failGenerate }
            let key = P256.Signing.PrivateKey()
            keys[alias] = key
            generated += 1
            return key.publicKey.derRepresentation
        }
    }

    func publicKey(_ alias: String) throws -> Data {
        try lock.withLock {
            guard let key = keys[alias] else { throw SentomaruError.keyInvalidated }
            return key.publicKey.derRepresentation
        }
    }

    func sign(_ alias: String, _ bytes: Data) throws -> Data {
        try lock.withLock {
            guard let key = keys[alias] else { throw SentomaruError.keyInvalidated }
            signatures += 1
            return try key.signature(for: bytes).rawRepresentation
        }
    }

    func delete(_ alias: String) throws { lock.withLock { keys[alias] = nil } }

    func deleteOwned(prefix: String) throws { lock.withLock { keys = keys.filter { !$0.key.hasPrefix(prefix) } } }

    var aliases: Set<String> { lock.withLock { Set(keys.keys) } }

    /// Simulates the Secure Enclave losing a key (restore onto another device, key deleted by the OS).
    func lose(_ alias: String) { lock.withLock { keys[alias] = nil } }
}

final class MemoryStore: InstallationStore, @unchecked Sendable {
    private let lock = NSLock()
    private var data: Data?
    private(set) var writes = 0

    func read() throws -> InstallationRecord? {
        try lock.withLock {
            guard let data else { return nil }
            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .millisecondsSince1970
            return try decoder.decode(InstallationRecord.self, from: data)
        }
    }

    func write(_ record: InstallationRecord?) throws {
        try lock.withLock {
            writes += 1
            guard let record else { data = nil; return }
            let encoder = JSONEncoder()
            encoder.dateEncodingStrategy = .millisecondsSince1970
            data = try encoder.encode(record) // round trip like the Keychain store
        }
    }
}

/// App Attest stand-in. Keys are software P-256 keys; `keyId` = base64(SHA-256(uncompressed point)) as Apple does.
/// `attestKey` returns an opaque object that carries the clientDataHash (the server-side checks of a real object are
/// the D-09b verifier's job); `generateAssertion` returns a CBOR `{signature, authenticatorData}` exactly as the
/// D-09c profile reads it: authenticatorData = rpIdHash(32) ‖ flags(1) ‖ counter(4, big-endian), signature = ES256 DER
/// over nonce = SHA-256(authenticatorData ‖ clientDataHash).
final class FakeAppAttest: AppAttestService, @unchecked Sendable {
    let appId: String
    private let lock = NSLock()
    private var keys: [String: (key: P256.Signing.PrivateKey, counter: UInt32)] = [:]
    var supported = true
    var failAttest: Error?
    var failAssertion: Error?
    private(set) var attestations: [(keyId: String, clientDataHash: Data)] = []
    private(set) var assertions: [(keyId: String, clientDataHash: Data)] = []

    init(appId: String = "TESTTEAM01.br.com.example.lab") { self.appId = appId }

    var isSupported: Bool { lock.withLock { supported } }
    /// Every App Attest key generated so far (attested or not).
    var generatedKeys: Int { lock.withLock { keys.count } }

    func generateKey() async throws -> String {
        lock.withLock {
            let key = P256.Signing.PrivateKey()
            let keyId = Data(SHA256.hash(data: key.publicKey.x963Representation)).base64EncodedString()
            keys[keyId] = (key, 0)
            return keyId
        }
    }

    func attestKey(_ keyId: String, clientDataHash: Data) async throws -> Data {
        try lock.withLock {
            if let failAttest { throw failAttest }
            guard keys[keyId] != nil else { throw SentomaruError.keyInvalidated }
            attestations.append((keyId, clientDataHash))
            return Data("fake-attestation:".utf8) + clientDataHash
        }
    }

    func generateAssertion(_ keyId: String, clientDataHash: Data) async throws -> Data {
        try lock.withLock {
            if let failAssertion { throw failAssertion }
            guard var entry = keys[keyId] else { throw SentomaruError.keyInvalidated }
            entry.counter += 1
            keys[keyId] = entry
            assertions.append((keyId, clientDataHash))
            var counter = entry.counter.bigEndian
            let authData = Data(SHA256.hash(data: Data(appId.utf8))) + Data([0x00]) + Data(bytes: &counter, count: 4)
            let nonce = Data(SHA256.hash(data: authData + clientDataHash))
            let signature = try entry.key.signature(for: nonce).derRepresentation
            return CBOR.encodeMap([("signature", .bytes(signature)), ("authenticatorData", .bytes(authData))])
        }
    }

    /// The App Attest public point (65 bytes) the server keeps at enrollment (`app_attest_public_key`).
    func publicPoint(_ keyId: String) -> Data? { lock.withLock { keys[keyId]?.key.publicKey.x963Representation } }

    func removeKey(_ keyId: String) { lock.withLock { keys[keyId] = nil } }
}

/// Mutable test clock.
final class TestClock: @unchecked Sendable {
    private let lock = NSLock()
    private var current: Date

    init(_ start: Date = Date(timeIntervalSince1970: 1_800_000_000)) { current = start }

    var now: Date { lock.withLock { current } }
    func advance(_ seconds: TimeInterval) { lock.withLock { current = current.addingTimeInterval(seconds) } }
    var function: @Sendable () -> Date { { [unowned self] in self.now } }
}

/// Minimal strict CBOR (definite lengths, shortest arguments) for the test fakes and vector checks.
enum CBOR: Equatable {
    case unsigned(UInt64), negative(UInt64), bytes(Data), text(String), array([CBOR]), map([(CBOR, CBOR)])

    static func == (a: CBOR, b: CBOR) -> Bool {
        switch (a, b) {
        case let (.unsigned(x), .unsigned(y)), let (.negative(x), .negative(y)): return x == y
        case let (.bytes(x), .bytes(y)): return x == y
        case let (.text(x), .text(y)): return x == y
        case let (.array(x), .array(y)): return x == y
        case let (.map(x), .map(y)): return x.count == y.count && zip(x, y).allSatisfy { $0.0 == $1.0 && $0.1 == $1.1 }
        default: return false
        }
    }

    static func head(_ major: UInt8, _ value: Int) -> Data {
        switch value {
        case 0 ..< 24: return Data([major << 5 | UInt8(value)])
        case 24 ..< 256: return Data([major << 5 | 24, UInt8(value)])
        case 256 ..< 65536: return Data([major << 5 | 25, UInt8(value >> 8), UInt8(value & 0xFF)])
        default: return Data([major << 5 | 26, UInt8(value >> 24 & 0xFF), UInt8(value >> 16 & 0xFF), UInt8(value >> 8 & 0xFF), UInt8(value & 0xFF)])
        }
    }

    static func encodeMap(_ entries: [(String, CBOR)]) -> Data {
        var out = head(5, entries.count)
        for (key, value) in entries {
            out += head(3, key.utf8.count) + Data(key.utf8)
            guard case .bytes(let bytes) = value else { fatalError("only byte values") }
            out += head(2, bytes.count) + bytes
        }
        return out
    }

    struct Malformed: Error {}

    static func decode(_ data: Data) throws -> CBOR {
        var reader = Reader(bytes: [UInt8](data))
        let item = try reader.item(depth: 0)
        guard reader.index == reader.bytes.count else { throw Malformed() }
        return item
    }

    /// The server's StrictCbor rules on top of `decode` (Integrity.Verification/StrictCbor.cs, reference `_cbor_item`):
    /// depth at most 8 (`MaxDepth`, the top item at 0), map keys only integers or text, no repeated map key.
    static let strictMaxDepth = 8

    static func decodeStrict(_ data: Data) throws -> CBOR {
        var reader = Reader(bytes: [UInt8](data), strict: true)
        let item = try reader.item(depth: 0)
        guard reader.index == reader.bytes.count else { throw Malformed() }
        return item
    }

    struct Reader {
        let bytes: [UInt8]
        var index = 0
        var strict = false

        init(bytes: [UInt8], strict: Bool = false) { self.bytes = bytes; self.strict = strict }

        mutating func byte() throws -> UInt8 {
            guard index < bytes.count else { throw Malformed() }
            defer { index += 1 }
            return bytes[index]
        }

        mutating func argument(_ info: UInt8) throws -> UInt64 {
            switch info {
            case 0 ..< 24: return UInt64(info)
            case 24 ... 27:
                let count = 1 << Int(info - 24)
                var value: UInt64 = 0
                for _ in 0 ..< count { value = value << 8 | UInt64(try byte()) }
                let minimum: UInt64 = info == 24 ? 24 : 1 << (8 * UInt64(count / 2))
                guard value >= minimum else { throw Malformed() } // shortest form only
                return value
            default: throw Malformed()
            }
        }

        mutating func take(_ count: UInt64) throws -> [UInt8] {
            guard count <= UInt64(bytes.count - index) else { throw Malformed() }
            defer { index += Int(count) }
            return Array(bytes[index ..< index + Int(count)])
        }

        mutating func item(depth: Int) throws -> CBOR {
            guard depth < 16, !strict || depth <= CBOR.strictMaxDepth else { throw Malformed() }
            let initial = try byte()
            let value = try argument(initial & 0x1F)
            switch initial >> 5 {
            case 0: return .unsigned(value)
            case 1: return .negative(value)
            case 2: return .bytes(Data(try take(value)))
            case 3:
                guard let text = String(bytes: try take(value), encoding: .utf8) else { throw Malformed() }
                return .text(text)
            case 4: return .array(try (0 ..< value).map { _ in try item(depth: depth + 1) })
            case 5:
                var entries: [(CBOR, CBOR)] = []
                for _ in 0 ..< value {
                    let key = try item(depth: depth + 1)
                    if strict {
                        switch key { case .unsigned, .negative, .text: break; default: throw Malformed() }
                        guard !entries.contains(where: { $0.0 == key }) else { throw Malformed() }
                    }
                    entries.append((key, try item(depth: depth + 1)))
                }
                return .map(entries)
            default: throw Malformed()
            }
        }
    }

    subscript(_ key: String) -> CBOR? {
        guard case .map(let entries) = self else { return nil }
        return entries.first { $0.0 == .text(key) }?.1
    }

    var data: Data? { if case .bytes(let d) = self { return d } else { return nil } }
}

/// The D-09c server checks the SDK's assertion must pass (the Sentomaru Apple attestation profile, "Assertion na
/// renovação", steps 2–6, with the D-09d authData): CBOR with exactly `signature` and `authenticatorData` (37 fixed
/// bytes; AT not interpreted; with ED exactly one CBOR map after them, read with the StrictCbor rules of
/// `CBOR.decodeStrict`; without ED nothing), rpIdHash of the App ID,
/// ES256 over SHA-256(authenticatorData ‖ clientDataHash) and a counter (bytes 33–36) above the stored one.
enum AssertionCheck {
    enum Result: Equatable { case ok(counter: UInt32), refused(String) }

    static func verify(assertion: Data, publicPoint: Data, appId: String, clientDataHash: Data, storedCounter: UInt32) -> Result {
        guard let cbor = try? CBOR.decodeStrict(assertion), case .map(let entries) = cbor, entries.count == 2,
              let signature = cbor["signature"]?.data, let authBytes = cbor["authenticatorData"]?.data,
              (8...72).contains(signature.count), authBytes.count >= 37 else { return .refused("assertion_malformed") }
        let authData = Data(authBytes) // indices from 0
        let extensions = authData.dropFirst(37)
        if authData[32] & 0x80 != 0 {
            guard case .map? = try? CBOR.decodeStrict(Data(extensions)) else { return .refused("assertion_malformed") }
        } else if !extensions.isEmpty {
            return .refused("assertion_malformed")
        }
        guard authData.prefix(32) == Data(SHA256.hash(data: Data(appId.utf8))) else { return .refused("assertion_rpid_mismatch") }
        let nonce = Data(SHA256.hash(data: authData + clientDataHash))
        guard let key = try? P256.Signing.PublicKey(x963Representation: publicPoint),
              let sig = try? P256.Signing.ECDSASignature(derRepresentation: signature),
              key.isValidSignature(sig, for: nonce) else { return .refused("assertion_signature_invalid") }
        let counter = authData[33 ..< 37].reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
        guard counter > storedCounter else { return .refused("assertion_counter_not_increasing") }
        return .ok(counter: counter)
    }
}

extension XCTestCase {
    func assertThrows<T>(_ expected: SentomaruError, file: StaticString = #filePath, line: UInt = #line,
                         _ block: () async throws -> T) async {
        do {
            _ = try await block()
            XCTFail("no error, expected \(expected.code)", file: file, line: line)
        } catch let error as SentomaruError {
            XCTAssertEqual(error.code, expected.code, file: file, line: line)
        } catch {
            XCTFail("unexpected \(type(of: error)), expected \(expected.code)", file: file, line: line)
        }
    }
}
