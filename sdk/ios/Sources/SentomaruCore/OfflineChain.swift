import CryptoKit
import Foundation

/// D-26 (contracts/sdk/offline-proof-chain-v1.md section 3): the bytes of the offline proof chain, the Swift twin of the
/// server's `OfflineChain`. Pure: no key, no clock, no storage. Same golden vectors as the server
/// (`contracts/sdk/offline-proof-chain-v1-vectors.json`).
///
/// Record (big-endian, no separators): `"SMOFF1"` (6), permitId (16), seq u32, bootCount u32 (`0xFFFFFFFF` = unavailable),
/// elapsedNanos u64, wallMillis u64, operationDigest (32), prevHash (32). `hash = SHA-256(record)`. The item 0 `prevHash`
/// is `SHA-256("SMOFF1-seed" ‖ permitId ‖ chainSeed)`.
public enum OfflineChain {
    public static let version = "SMOFF1"
    public static let seedLabel = "SMOFF1-seed"
    public static let unavailableBootCount: UInt32 = 0xFFFF_FFFF
    public static let maxItems = 128
    public static let recordBytes = 6 + 16 + 4 + 4 + 8 + 8 + 32 + 32

    public static func seedHash(permitId: Data, chainSeed: Data) -> Data {
        Data(SHA256.hash(data: Data(seedLabel.utf8) + permitId + chainSeed))
    }

    public static func record(permitId: Data, seq: UInt32, bootCount: UInt32, elapsedNanos: UInt64, wallMillis: UInt64,
                              operationDigest: Data, prevHash: Data) -> Data {
        precondition(permitId.count == 16 && operationDigest.count == 32 && prevHash.count == 32, "offline record sizes")
        var out = Data(version.utf8)
        out += permitId
        out += big(seq)
        out += big(bootCount)
        out += big(elapsedNanos)
        out += big(wallMillis)
        out += operationDigest
        out += prevHash
        return out
    }

    public static func hash(of record: Data) -> Data { Data(SHA256.hash(data: record)) }

    /// A P1363 `r ‖ s` signature (what the installation key returns) as the DER the server verifies.
    public static func derSignature(fromP1363 raw: Data) throws -> Data {
        try P256.Signing.ECDSASignature(rawRepresentation: raw).derRepresentation
    }

    /// 16 bytes of a canonical lowercase or uppercase UUID text; nil when it is not one.
    public static func uuidBytes(_ text: String) -> Data? {
        guard let uuid = UUID(uuidString: text) else { return nil }
        return withUnsafeBytes(of: uuid.uuid) { Data($0) }
    }

    public static func base64URL(_ data: Data) -> String { TransactionSignature.base64URL(data) }

    public static func fromBase64URL(_ text: String) -> Data? {
        var s = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        s += String(repeating: "=", count: (4 - s.count % 4) % 4)
        guard let data = Data(base64Encoded: s), base64URL(data) == text else { return nil }
        return data
    }

    private static func big<T: FixedWidthInteger>(_ value: T) -> Data {
        withUnsafeBytes(of: value.bigEndian) { Data($0) }
    }
}
