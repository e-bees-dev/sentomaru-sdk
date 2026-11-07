import Foundation

/// Input validation of the profile, a port of the Android `MessageRules` (same accepted set, same error per vector).
/// Fails closed and early: every form the P1 server is known to refuse or rewrite is refused here instead of being
/// signed. This is NOT a URI or header parser: it accepts only the exact canonical wire form and never normalizes
/// (normalizing would sign bytes other than the ones sent).
///
/// Everything works on UTF-8 bytes. A non-ASCII byte is never in an accepted set, so it fails exactly where the
/// Kotlin rule (on UTF-16 characters) fails, with the same reason.
enum MessageRules {
    private static let maxOperation = 64
    private static let maxURI = 4096
    private static let maxHeaderValue = 4096
    private static let https = Array("https://".utf8)
    // RFC 3986 unreserved + sub-delims + ":" "@" "/" "?" (pchar/query characters), and "%" for escapes.
    private static let uriChars = Set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~!$&'()*+,;=:@/?%".utf8)
    private static let unreservedMarks = Set("-._~".utf8)
    // Octets whose escape the server decodes in the PATH and re-emits raw: NUL, unreserved, sub-delims and ":" "@".
    // In the QUERY only escaped unreserved octets are rewritten.
    private static let pathDecodedMarks = Set("!$&'()*+,;=:@".utf8)

    static func method(_ method: String) throws {
        let bytes = Array(method.utf8)
        guard (1...16).contains(bytes.count), bytes.allSatisfy({ $0 >= 0x41 && $0 <= 0x5A }) else {
            throw invalid(.METHOD)
        }
    }

    /// Absolute `https` URI in the canonical form the server reproduces: lowercase host (DNS name, or strict
    /// dotted-quad IPv4 when the last label is numeric or hex), optional non-default port, non-empty path starting
    /// with `/`, optional query; no userinfo, fragment, raw non-ASCII, space, dot segment, lowercase-hex escape,
    /// escape of an unreserved octet, and in the path no `%00` nor escape of a sub-delim, `:` or `@`. No IPv6 literal.
    static func targetURI(_ uri: String) throws {
        let u = Array(uri.utf8)
        guard (1...maxURI).contains(u.count), u.starts(with: https) else { throw invalid(.TARGET_URI) }
        guard let authorityEnd = u[https.count...].firstIndex(of: UInt8(ascii: "/")) else { throw invalid(.TARGET_URI) }
        try authority(Array(u[https.count ..< authorityEnd]))
        let queryStart = u[authorityEnd...].firstIndex(of: UInt8(ascii: "?")) ?? u.count
        let path = Array(u[authorityEnd ..< queryStart])
        var i = authorityEnd
        while i < u.count {
            let c = u[i]
            guard uriChars.contains(c) else { throw invalid(.TARGET_URI) }
            if c == UInt8(ascii: "%") {
                guard i + 2 < u.count, let high = upperHex(u[i + 1]), let low = upperHex(u[i + 2]) else {
                    throw invalid(.TARGET_URI)
                }
                if rewritten(high * 16 + low, inPath: i < queryStart) { throw invalid(.TARGET_URI) }
                i += 3
                continue
            }
            i += 1
        }
        let segments = path.split(separator: UInt8(ascii: "/"), omittingEmptySubsequences: false)
        if segments.contains(where: { Array($0) == [0x2E] || Array($0) == [0x2E, 0x2E] }) { throw invalid(.TARGET_URI) }
    }

    private static func upperHex(_ c: UInt8) -> UInt8? {
        if c >= 0x30 && c <= 0x39 { return c - 0x30 }
        if c >= 0x41 && c <= 0x46 { return c - 0x41 + 10 }
        return nil
    }

    private static func rewritten(_ octet: UInt8, inPath: Bool) -> Bool {
        let unreserved = (octet >= 0x41 && octet <= 0x5A) || (octet >= 0x61 && octet <= 0x7A) ||
            (octet >= 0x30 && octet <= 0x39) || unreservedMarks.contains(octet)
        return unreserved || (inPath && (octet == 0 || pathDecodedMarks.contains(octet)))
    }

    private static func isHostChar(_ c: UInt8) -> Bool {
        (c >= 0x61 && c <= 0x7A) || (c >= 0x30 && c <= 0x39) || c == 0x2E || c == 0x2D
    }

    private static func isAlnumLower(_ c: UInt8) -> Bool { (c >= 0x61 && c <= 0x7A) || (c >= 0x30 && c <= 0x39) }

    private static func isDigit(_ c: UInt8) -> Bool { c >= 0x30 && c <= 0x39 }

    private static func authority(_ authority: [UInt8]) throws {
        let colon = authority.lastIndex(of: UInt8(ascii: ":"))
        let host = colon.map { Array(authority[..<$0]) } ?? authority
        // HOST: [a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])? and no "..".
        guard (1...253).contains(host.count), isAlnumLower(host[0]), isAlnumLower(host[host.count - 1]),
              host.allSatisfy(isHostChar) else { throw invalid(.TARGET_URI) }
        for i in 1 ..< host.count where host[i] == 0x2E && host[i - 1] == 0x2E { throw invalid(.TARGET_URI) }
        // A host whose last label is a number (decimal or 0x-hex) is read as IPv4 by WHATWG/OkHttp and .NET: only the
        // strict dotted quad (0-255, no leading zero) is accepted.
        let labels = host.split(separator: 0x2E, omittingEmptySubsequences: false).map(Array.init)
        let last = labels[labels.count - 1]
        if last.allSatisfy(isDigit) || last.starts(with: Array("0x".utf8)) {
            if labels.count != 4 || !labels.allSatisfy(octet) { throw invalid(.TARGET_URI) }
        }
        if let colon {
            let port = Array(authority[(colon + 1)...])
            guard !port.isEmpty, port.count <= 5, port.allSatisfy(isDigit), port[0] != 0x30,
                  let value = Int(String(decoding: port, as: UTF8.self)), (1...65535).contains(value), value != 443
            else { throw invalid(.TARGET_URI) }
        }
    }

    private static func octet(_ label: [UInt8]) -> Bool {
        guard !label.isEmpty, label.count <= 3, label.allSatisfy(isDigit), label == [0x30] || label[0] != 0x30,
              let value = Int(String(decoding: label, as: UTF8.self)) else { return false }
        return value <= 255
    }

    private static func isSlug(_ value: [UInt8]) -> Bool {
        // [a-z0-9][a-z0-9-]{0,62}
        guard (1...63).contains(value.count), isAlnumLower(value[0]) else { return false }
        return value.allSatisfy { isAlnumLower($0) || $0 == 0x2D }
    }

    private static func isOperationId(_ value: [UInt8]) -> Bool {
        (16...64).contains(value.count) &&
            value.allSatisfy { ($0 >= 0x41 && $0 <= 0x5A) || ($0 >= 0x61 && $0 <= 0x7A) || isDigit($0) || $0 == 0x2D }
    }

    /// Exactly `Profile.callerHeaders` (canonical lowercase names) plus optional ones, with the profile's value rules.
    static func headers(_ headers: [String: String]) throws {
        let names = Set(headers.keys)
        guard names.isSuperset(of: Profile.callerHeaders),
              Set(Profile.callerHeaders + Profile.optionalHeaders).isSuperset(of: names) else {
            throw invalid(.HEADER_NAME)
        }
        for (name, value) in headers {
            let bytes = Array(value.utf8)
            guard !bytes.isEmpty, bytes.count <= maxHeaderValue, bytes[0] != 0x20, bytes[bytes.count - 1] != 0x20,
                  bytes.allSatisfy({ $0 >= 0x20 && $0 <= 0x7E }) else { throw invalid(.HEADER_VALUE) }
            let ok: Bool
            switch name {
            case "content-type": ok = value == Profile.contentType
            case "x-sentomaru-profile": ok = value == Profile.tag
            case "x-sentomaru-org", "x-sentomaru-app", "x-sentomaru-environment": ok = isSlug(bytes)
            case "x-sentomaru-session": ok = SignatureParams.isUUID(value)
            // The server's rule (InputLimits.OperationMax; equality with the consumer route is checked there).
            case "x-sentomaru-operation": ok = bytes.count <= maxOperation
            // H3: compact JSON, printable ASCII (already checked above), same limit as the server.
            case Profile.signalsHeader: ok = true
            // J-01f: business operation id, the same on every retry of one operation.
            case Profile.operationIdHeader: ok = isOperationId(bytes)
            // D-25: `sentomaru-tx-v1.<nonce 22>.<signature 86>` or v2 `sentomaru-tx-v2.<nonce 22>.<issuedAt 10 digits>.<signature 86>`.
            case Profile.txSignatureHeader: ok = TransactionSignature.isHeaderValue(value)
            default: ok = false
            }
            if !ok { throw invalid(.HEADER_VALUE) }
        }
    }

    static func contentDigest(_ value: String) throws {
        if !ContentDigest.isCanonical(value) { throw invalid(.CONTENT_DIGEST) }
    }

    static func bodySize(_ size: Int) throws {
        if size > Profile.maxBodyBytes { throw SentomaruError.bodyTooLarge(size: size) }
    }
}
