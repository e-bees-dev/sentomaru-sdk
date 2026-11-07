import CryptoKit
import Foundation
import SentomaruCore
import XCTest

/// Reader of verification/sdk/vectors (the same files the Kotlin core, the Python verifier and the C# tests read).
/// The repository root is found from this file's path; `SENTOMARU_VECTORS_DIR` overrides the vectors directory.
enum Repository {
    static let root: URL = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent() // SentomaruCoreTests
        .deletingLastPathComponent() // Tests
        .deletingLastPathComponent() // ios
        .deletingLastPathComponent() // sdk
        .deletingLastPathComponent() // repository root

    static var vectorsDir: URL {
        if let dir = ProcessInfo.processInfo.environment["SENTOMARU_VECTORS_DIR"] { return URL(fileURLWithPath: dir) }
        return root.appendingPathComponent("verification/sdk/vectors")
    }
}

struct Vector {
    let id: String
    let positive: Bool
    let route: String
    let method: String
    let targetURI: String
    let headers: [String: String]
    let body: Data
    let created: Int64
    let expires: Int64
    let nonce: String
    let keyId: String
    let contentDigest: String
    let signatureBase: Data?
    let signatureInput: String?
    let pythonSignature: String?
    let coreError: String?

    func params() throws -> SignatureParams {
        try SignatureParams(created: created, expires: expires, nonce: nonce, keyId: keyId,
                            components: Profile.components(for: headers))
    }

    func request() throws -> FrozenRequest {
        try FrozenRequest(method: method, targetURI: targetURI, headers: headers, body: body)
    }
}

struct VectorFile {
    let pythonPublicKeySpki: Data
    let vectors: [Vector]
    var positives: [Vector] { vectors.filter(\.positive) }
    var negatives: [Vector] { vectors.filter { !$0.positive } }

    static func load() throws -> VectorFile {
        let url = Repository.vectorsDir.appendingPathComponent("sdk-vectors-v1.json")
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
        let key = try XCTUnwrap(Data(base64Encoded: try XCTUnwrap(json["pythonPublicKeySpki"] as? String)))
        let list = try XCTUnwrap(json["vectors"] as? [[String: Any]])
        let vectors = try list.map { entry -> Vector in
            let input = try XCTUnwrap(entry["input"] as? [String: Any])
            let params = try XCTUnwrap(input["params"] as? [String: Any])
            let expected = try XCTUnwrap(entry["expected"] as? [String: Any])
            let python = entry["python"] as? [String: Any]
            return Vector(
                id: try XCTUnwrap(entry["id"] as? String),
                positive: (entry["kind"] as? String) == "positive",
                route: try XCTUnwrap(entry["route"] as? String),
                method: try XCTUnwrap(input["method"] as? String),
                targetURI: try XCTUnwrap(input["targetUri"] as? String),
                headers: try XCTUnwrap(input["headers"] as? [String: String]),
                body: try XCTUnwrap(Data(base64Encoded: try XCTUnwrap(input["body"] as? String))),
                created: try XCTUnwrap((params["created"] as? NSNumber)?.int64Value),
                expires: try XCTUnwrap((params["expires"] as? NSNumber)?.int64Value),
                nonce: try XCTUnwrap(params["nonce"] as? String),
                keyId: try XCTUnwrap(params["keyid"] as? String),
                contentDigest: try XCTUnwrap(expected["contentDigest"] as? String),
                signatureBase: (expected["signatureBase"] as? String).flatMap { Data(base64Encoded: $0) },
                signatureInput: expected["signatureInput"] as? String,
                pythonSignature: python?["signature"] as? String,
                coreError: expected["coreError"] as? String
            )
        }
        return VectorFile(pythonPublicKeySpki: key, vectors: vectors)
    }
}

/// core-signed-v1.json, read line by line like the Kotlin reader: the envelope is compared as the exact text.
struct CoreSignedFile {
    struct Entry {
        let id: String
        let route: String
        let envelope: String

        /// The P1363 bytes inside `"signature":["sig1=:<b64>:"]`.
        func signature() throws -> Data {
            let marker = "\"signature\":[\"sig1=:"
            let start = try XCTUnwrap(envelope.range(of: marker)).upperBound
            let end = try XCTUnwrap(envelope.range(of: ":\"]", range: start ..< envelope.endIndex)).lowerBound
            return try XCTUnwrap(Data(base64Encoded: String(envelope[start ..< end])))
        }
    }

    let publicKeySpki: Data
    let entries: [Entry]

    static func load() throws -> CoreSignedFile {
        let text = try String(contentsOf: Repository.vectorsDir.appendingPathComponent("core-signed-v1.json"), encoding: .utf8)
        let lines = text.components(separatedBy: "\n")
        let keyPrefix = " \"publicKeySpki\": \""
        let keyLine = try XCTUnwrap(lines.first { $0.hasPrefix(keyPrefix) })
        let key = String(keyLine.dropFirst(keyPrefix.count).dropLast(2))
        let entryPrefix = "  {\"id\": \""
        let entries = try lines.filter { $0.hasPrefix(entryPrefix) }.map { line -> Entry in
            let rest = line.dropFirst(entryPrefix.count)
            let id = String(rest.prefix { $0 != "\"" })
            let routeStart = try XCTUnwrap(line.range(of: "\"route\": \"")).upperBound
            let route = String(line[routeStart...].prefix { $0 != "\"" })
            var envelope = String(line[try XCTUnwrap(line.range(of: "\"envelope\": ")).upperBound...])
            if envelope.hasSuffix(",") { envelope.removeLast() }
            if envelope.hasSuffix("}") { envelope.removeLast() }
            return Entry(id: id, route: route, envelope: envelope)
        }
        return CoreSignedFile(publicKeySpki: try XCTUnwrap(Data(base64Encoded: key)), entries: entries)
    }
}

enum SoftwareSigner {
    static func signer(_ key: P256.Signing.PrivateKey) -> SignatureFunction {
        { base in try key.signature(for: base).rawRepresentation }
    }

    static func verify(spki: Data, base: Data, signature: Data) -> Bool {
        guard let key = try? P256.Signing.PublicKey(derRepresentation: spki),
              let sig = try? P256.Signing.ECDSASignature(rawRepresentation: signature) else { return false }
        return key.isValidSignature(sig, for: base)
    }
}

func XCTAssertRefused(_ expected: String, _ message: String = "", file: StaticString = #filePath, line: UInt = #line,
                      _ block: () throws -> Void) {
    do {
        try block()
        XCTFail("accepted \(message), expected \(expected)", file: file, line: line)
    } catch let error as SentomaruError {
        XCTAssertEqual(error.code, expected, message, file: file, line: line)
    } catch {
        XCTFail("unexpected \(type(of: error)) for \(message)", file: file, line: line)
    }
}
