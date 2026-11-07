import CryptoKit
import Foundation

/// D-25 (contracts/api/transaction-keys-v1.md section 2): the bytes the transaction key signs and the header value, the
/// Swift twin of the Android `TransactionSigning`. Pure: no key, no prompt.
///
/// Signed bytes (UTF-8, LF separated, no final LF): `sentomaru-tx-v1`, the nonce (base64url, no padding), the value of
/// `x-sentomaru-operation-id`, the SHA-256 of the body (base64url, no padding). They bind the signature to an operation,
/// a body and a single-use nonce; the route is bound only through the RFC 9421 signature that covers the header.
///
/// v2 (F1, contract section 2a) adds the signer's clock: `sentomaru-tx-v2`, nonce, `issuedAt` (Unix seconds UTC, 10 decimal
/// digits), operation id, body digest. The server accepts it only within 5 minutes of its own clock and remembers the nonce for
/// 11 minutes; v1 has no clock and a 25 h nonce memory.
public enum TransactionSignatureVersion: Sendable { case v1, v2 }

public enum TransactionSignature {
    public static let version = "sentomaru-tx-v1"
    public static let version2 = "sentomaru-tx-v2"
    public static let nonceBytes = 16
    public static let signatureBytes = 64

    public static func message(nonce: Data, operationId: String, body: Data) -> Data {
        Data((version + "\n" + base64URL(nonce) + "\n" + operationId + "\n" + base64URL(Data(SHA256.hash(data: body)))).utf8)
    }

    /// v2 signed bytes. `issuedAt` outside 1_000_000_000...9_999_999_999 (a clock before 2001) is a programming error here; the
    /// signer checks the range first and refuses to sign.
    public static func message(nonce: Data, issuedAt: Int, operationId: String, body: Data) -> Data {
        Data((version2 + "\n" + base64URL(nonce) + "\n" + String(issuedAt) + "\n" + operationId + "\n"
              + base64URL(Data(SHA256.hash(data: body)))).utf8)
    }

    public static func isValidIssuedAt(_ seconds: Int) -> Bool { seconds >= 1_000_000_000 && seconds <= 9_999_999_999 }

    /// `sentomaru-tx-v2.<nonce>.<issuedAt>.<signature>`.
    public static func headerValue(nonce: Data, issuedAt: Int, signature: Data) -> String {
        precondition(nonce.count == nonceBytes && signature.count == signatureBytes && isValidIssuedAt(issuedAt), "tx signature sizes")
        return version2 + "." + base64URL(nonce) + "." + String(issuedAt) + "." + base64URL(signature)
    }

    /// `sentomaru-tx-v1.<nonce>.<signature>`; the nonce is 16 bytes and the signature a 64-byte P1363 `r || s`.
    public static func headerValue(nonce: Data, signature: Data) -> String {
        precondition(nonce.count == nonceBytes && signature.count == signatureBytes, "tx signature sizes")
        return version + "." + base64URL(nonce) + "." + base64URL(signature)
    }

    /// The exact shapes the server accepts: `\Asentomaru-tx-v1\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{86}\z` or
    /// `\Asentomaru-tx-v2\.[A-Za-z0-9_-]{22}\.[0-9]{10}\.[A-Za-z0-9_-]{86}\z`.
    public static func isHeaderValue(_ value: String) -> Bool {
        let parts = value.utf8.split(separator: 0x2E, omittingEmptySubsequences: false)
        let name = parts.first.map { String(decoding: $0, as: UTF8.self) }
        if parts.count == 3, name == version {
            return parts[1].count == 22 && parts[2].count == 86 && parts[1].allSatisfy(isURLSafe) && parts[2].allSatisfy(isURLSafe)
        }
        if parts.count == 4, name == version2 {
            return parts[1].count == 22 && parts[2].count == 10 && parts[3].count == 86 && parts[1].allSatisfy(isURLSafe)
                && parts[2].allSatisfy { $0 >= 0x30 && $0 <= 0x39 } && parts[3].allSatisfy(isURLSafe)
        }
        return false
    }

    public static func base64URL(_ data: Data) -> String {
        data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private static func isURLSafe(_ b: UInt8) -> Bool {
        (b >= 0x41 && b <= 0x5A) || (b >= 0x61 && b <= 0x7A) || (b >= 0x30 && b <= 0x39) || b == 0x2D || b == 0x5F
    }
}
