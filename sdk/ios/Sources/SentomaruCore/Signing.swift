import Foundation

/// Signature parameters of the profile. `alg` and `tag` are fixed. Validated on construction: canonical lowercase
/// UUIDs for `keyId`/`nonce`, 0 <= `created` < `expires` <= `created` + 60.
///
/// Serialized as the RFC 9421 inner list with parameters in the order of the Python reference client
/// (created, keyid, alg, expires, nonce, tag); every value is an sf-integer or an sf-string whose characters are
/// restricted by the validation above, so no escaping is needed.
public struct SignatureParams: Equatable, Sendable {
    public let created: Int64
    public let expires: Int64
    public let nonce: String
    public let keyId: String
    /// `Profile.components` plus optional headers in `Profile.optionalHeaders` order.
    public let components: [String]

    private static let maxSFInteger: Int64 = 999_999_999_999_999

    public init(created: Int64, expires: Int64, nonce: String, keyId: String,
                components: [String] = Profile.components) throws {
        let base = Profile.components
        guard (0...Self.maxSFInteger).contains(created), (0...Self.maxSFInteger).contains(expires), expires > created,
              expires - created <= Profile.maxLifetimeSeconds, Self.isUUID(nonce), Self.isUUID(keyId),
              Array(components.prefix(base.count)) == base,
              Array(components.dropFirst(base.count)) == Profile.optionalHeaders.filter({ components.contains($0) })
        else { throw invalid(.PARAMS) }
        self.created = created
        self.expires = expires
        self.nonce = nonce
        self.keyId = keyId
        self.components = components
    }

    /// The same parameters covering `list` (used by `MessageSigner` for the request's optional headers).
    public func with(components list: [String]) throws -> SignatureParams {
        try SignatureParams(created: created, expires: expires, nonce: nonce, keyId: keyId, components: list)
    }

    /// `("@method" ... "x-sentomaru-operation");created=..;keyid="..";alg="..";expires=..;nonce="..";tag=".."`.
    public func serialize() -> String {
        "(" + components.map { "\"\($0)\"" }.joined(separator: " ") + ")" +
            ";created=\(created);keyid=\"\(keyId)\";alg=\"\(Profile.algorithm)\";expires=\(expires)" +
            ";nonce=\"\(nonce)\";tag=\"\(Profile.tag)\""
    }

    /// created = now (whole seconds, truncated), expires = created + `lifetime` (default: the profile maximum).
    public static func now(_ date: Date, keyId: String, nonce: String,
                           lifetime: Int64 = Profile.maxLifetimeSeconds) throws -> SignatureParams {
        let created = Int64((date.timeIntervalSince1970).rounded(.down))
        return try SignatureParams(created: created, expires: created + lifetime, nonce: nonce, keyId: keyId)
    }

    /// Canonical lowercase UUID text `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`.
    public static func isUUID(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        guard bytes.count == 36 else { return false }
        for (i, c) in bytes.enumerated() {
            if i == 8 || i == 13 || i == 18 || i == 23 {
                if c != 0x2D { return false }
            } else if !((c >= 0x30 && c <= 0x39) || (c >= 0x61 && c <= 0x66)) {
                return false
            }
        }
        return true
    }
}

/// RFC 9421 §2.5 signature base for the profile's fixed component list. Every input is validated first, so the base is
/// pure ASCII and each line is `"<name>": <value>` joined by LF, ending with the `"@signature-params"` line.
public enum SignatureBase {
    public static func build(method: String, targetURI: String, headers: [String: String], contentDigest: String,
                             params: SignatureParams) throws -> Data {
        try MessageRules.method(method)
        try MessageRules.targetURI(targetURI)
        try MessageRules.headers(headers)
        try MessageRules.contentDigest(contentDigest)
        if params.components != Profile.components(for: headers) { throw invalid(.PARAMS) }
        var base = ""
        func line(_ name: String, _ value: String) { base += "\"\(name)\": \(value)\n" }
        line("@method", method)
        line("@target-uri", targetURI)
        line(Profile.contentDigestHeader, contentDigest)
        for name in Profile.callerHeaders { line(name, headers[name]!) }
        for name in Profile.optionalHeaders { if let value = headers[name] { line(name, value) } }
        base += "\"@signature-params\": " + params.serialize()
        return Data(base.utf8)
    }
}

/// The signing key lives outside the core (Secure Enclave in the SDK, a software key in tests): the core only hands it
/// the signature base and expects a 64-byte IEEE P1363 `r || s` back. Errors thrown by the signer propagate unchanged.
public typealias SignatureFunction = (Data) throws -> Data

/// A request frozen before signing (E2): the body is copied once and the same bytes are digested, signed and sent.
/// Constructing it validates the body size (`bodyTooLarge`); the rest is validated when signing.
public struct FrozenRequest: Sendable {
    public let method: String
    public let targetURI: String
    public let headers: [String: String]
    public let body: Data

    public init(method: String, targetURI: String, headers: [String: String], body: Data) throws {
        try MessageRules.bodySize(body.count)
        self.method = method
        self.targetURI = targetURI
        self.headers = headers
        self.body = Data(body)
    }
}

/// Result of `MessageSigner.sign`: the headers to send, in order (`content-digest`, the caller's profile headers, the
/// optional ones, `signature-input`, `signature`; lowercase names) and the exact body bytes that were digested.
public struct SignedMessage: Sendable {
    public let method: String
    public let targetURI: String
    public let headers: [(name: String, value: String)]
    public let body: Data
    /// The bytes handed to the signer; exposed for vectors and diagnostics (contains no secret).
    public let signatureBase: Data

    public func header(_ name: String) -> String? { headers.first { $0.name == name }?.value }
}

public enum MessageSigner {
    /// `sig1=<inner list>` for `params`.
    public static func signatureInput(_ params: SignatureParams) -> String { Profile.label + "=" + params.serialize() }

    /// `sig1=:<base64>:` for a 64-byte P1363 signature.
    public static func signatureHeader(_ signature: Data) throws -> String {
        guard signature.count == Profile.signatureBytes else { throw SentomaruError.signatureFormat(size: signature.count) }
        return Profile.label + "=:" + signature.base64EncodedString() + ":"
    }

    public static func sign(_ request: FrozenRequest, params given: SignatureParams,
                            signer: SignatureFunction) throws -> SignedMessage {
        let params = try given.with(components: Profile.components(for: request.headers))
        let digest = ContentDigest.sha256(request.body)
        let base = try SignatureBase.build(method: request.method, targetURI: request.targetURI,
                                           headers: request.headers, contentDigest: digest, params: params)
        let signature = try signatureHeader(try signer(base))
        var headers: [(name: String, value: String)] = [(Profile.contentDigestHeader, digest)]
        for name in Profile.callerHeaders { headers.append((name, request.headers[name]!)) }
        for name in Profile.optionalHeaders { if let value = request.headers[name] { headers.append((name, value)) } }
        headers.append((Profile.signatureInputHeader, signatureInput(params)))
        headers.append((Profile.signatureHeader, signature))
        return SignedMessage(method: request.method, targetURI: request.targetURI, headers: headers,
                             body: request.body, signatureBase: base)
    }
}

/// Trusted envelope the consumer forwards to the private API (B-I2): `{"method","uri","headers":{name:[value]},
/// "body":<standard base64>}`; the enrollment route wraps it as `{"request": MessageDto}`. Byte-identical to the
/// Android `EnvelopeCodec` (checked against core-signed-v1.json). Every string is printable ASCII (validated before
/// signing), so the only escapes are `"` and `\`.
public enum EnvelopeCodec {
    public static func encode(_ message: SignedMessage) -> Data { Data(write(message).utf8) }

    public static func encodeEnrollment(_ message: SignedMessage) -> Data {
        Data(("{\"request\":" + write(message) + "}").utf8)
    }

    private static func write(_ message: SignedMessage) -> String {
        var out = "{\"method\":" + string(message.method) + ",\"uri\":" + string(message.targetURI) + ",\"headers\":{"
        out += message.headers.map { string($0.name) + ":[" + string($0.value) + "]" }.joined(separator: ",")
        out += "},\"body\":" + string(message.body.base64EncodedString()) + "}"
        return out
    }

    private static func string(_ value: String) -> String {
        var out = "\""
        for scalar in value.unicodeScalars {
            switch scalar {
            case "\"", "\\": out += "\\" + String(scalar)
            case " "..."~": out.unicodeScalars.append(scalar)
            default: preconditionFailure("non-printable character in a validated envelope field")
            }
        }
        return out + "\""
    }
}
