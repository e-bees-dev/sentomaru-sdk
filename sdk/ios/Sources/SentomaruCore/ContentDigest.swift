import CryptoKit
import Foundation

/// RFC 9530 `Content-Digest` with the single algorithm of the profile: `sha-256=:<base64>:`.
public enum ContentDigest {
    /// Digest of exactly `body` (never re-serialized).
    public static func sha256(_ body: Data) -> String {
        "sha-256=:" + Data(SHA256.hash(data: body)).base64EncodedString() + ":"
    }

    /// `sha-256=:` + 43 base64 characters + `=` + `:` (the only canonical form of a 32-byte digest).
    static func isCanonical(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        let prefix = Array("sha-256=:".utf8)
        guard bytes.count == prefix.count + 45, bytes.starts(with: prefix),
              bytes[bytes.count - 2] == UInt8(ascii: "="), bytes[bytes.count - 1] == UInt8(ascii: ":") else { return false }
        return bytes[prefix.count ..< prefix.count + 43].allSatisfy(Base64Alphabet.isStandard)
    }
}

enum Base64Alphabet {
    static func isStandard(_ c: UInt8) -> Bool {
        (c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7A) || (c >= 0x30 && c <= 0x39) || c == 0x2B || c == 0x2F
    }
}
