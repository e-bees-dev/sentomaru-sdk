import CryptoKit
import Foundation
@testable import Sentomaru
import XCTest

/// The SDK's App Attest bindings against the server-side vectors:
/// - app-attest-v1.json (D-09b, main): the attestation `clientDataHash = SHA-256(attestationChallenge ‖ SPKI)` the SDK
///   computes is the one inside the nonce of the valid vectors' credential certificate, and the SDK's enrollment body
///   has exactly the v1.7 shape of the `apple_ok` request vector;
/// - app-attest-assertion-v1.json (D-09c with the D-09d authData cases, same tree since the onda 2 iOS integration;
///   pinned copy in Fixtures/, compared with the repository file when it exists): the SDK's renewal `clientData` and
///   body reproduce every valid vector byte for byte, and the vectors signed over another session, nonce or SPKI fail with the SDK's clientData.
final class AppAttestVectorTests: XCTestCase {
    /// The repository root, from this file's path; `SENTOMARU_REPOSITORY_ROOT` overrides it (the device run copies the
    /// vector files into the test bundle, where the source path does not exist).
    static let repositoryRoot: URL = {
        if let root = ProcessInfo.processInfo.environment["SENTOMARU_REPOSITORY_ROOT"] { return URL(fileURLWithPath: root) }
        return URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
    }()

    /// A repository file the tests read. The public distribution tree carries only part of the repository, so a file that is not
    /// there makes the test skip (never fail, never pass): the test then says what it could not check.
    static func repositoryFile(_ relative: String) throws -> URL {
        let url = repositoryRoot.appendingPathComponent(relative)
        guard FileManager.default.fileExists(atPath: url.path) else { throw XCTSkip("\(relative) is not part of this tree") }
        return url
    }

    static func fixture(_ name: String) throws -> Data {
        // The public distribution tree does not carry this fixture (it is a real-device capture whose signed data names a real
        // App ID), so the tests that need it skip there.
        guard let url = Bundle.module.url(forResource: name, withExtension: nil, subdirectory: "Fixtures") else {
            throw XCTSkip("Fixtures/\(name) is not part of this tree")
        }
        return try Data(contentsOf: url)
    }

    // MARK: D-09c assertion vectors

    func testPinnedAssertionVectorsMatchTheRepositoryWhenPresent() throws {
        let pinned = try Self.fixture("app-attest-assertion-v1.json")
        XCTAssertEqual(Hashing.hex(Hashing.sha256(pinned)), "039219551fc25d5ce083921ece94ae69575ca09475109212ef3d5a1f56537825",
                       "pinned copy of origin/attest/d09d-real-authdata (cb8d6606), the D-09c vectors with the D-09d authData cases")
        let repository = Self.repositoryRoot.appendingPathComponent("verification/attestation/vectors/app-attest-assertion-v1.json")
        guard FileManager.default.fileExists(atPath: repository.path) else {
            throw XCTSkip("D-09c not merged: verification/attestation/vectors/app-attest-assertion-v1.json absent")
        }
        XCTAssertEqual(try Data(contentsOf: repository), pinned,
                       "D-09c vectors changed: re-pin Fixtures/app-attest-assertion-v1.json and re-run")
    }

    func testRenewalClientDataAndBodyReproduceTheD09cVectors() throws {
        let fixtureData = try Self.fixture("app-attest-assertion-v1.json")
        let json = try XCTUnwrap(try JSONSerialization.jsonObject(with: fixtureData) as? [String: Any])
        XCTAssertEqual(json["clientDataPrefix"] as? String, "sentomaru-app-assertion-v1\n")
        let request = try XCTUnwrap(json["request"] as? [String: String])
        let credential = try XCTUnwrap(json["credential"] as? [String: String])
        let point = try XCTUnwrap(Data(base64Encoded: try XCTUnwrap(credential["publicKey"])))
        XCTAssertEqual(Data(SHA256.hash(data: point)).base64EncodedString(), credential["keyId"], "keyId = SHA-256(point)")
        let appId = try XCTUnwrap(json["appleAppId"] as? String)
        let spki = try XCTUnwrap(Data(base64Encoded: try XCTUnwrap(request["publicKey"])))
        let sessionId = try XCTUnwrap(request["sessionId"]), nonce = try XCTUnwrap(request["nonce"])
        let clientDataHash = AppAttestBinding.assertionClientDataHash(sessionId: sessionId, nonce: nonce, spki: spki)
        XCTAssertEqual(AppAttestBinding.assertionClientData(sessionId: sessionId, nonce: nonce, spki: spki),
                       Data(("sentomaru-app-assertion-v1\n\(sessionId)\n\(nonce)\n" +
                             Hashing.base64URLNoPadding(Data(SHA256.hash(data: spki)))).utf8))
        let vectors = try XCTUnwrap(json["vectors"] as? [[String: Any]])
        XCTAssertEqual(vectors.count, 73) // 58 of the D-09c + 15 of the D-09d (real authData flags and extensions map)
        var reproduced = 0, boundRefusals = 0, strictRefusals = 0, reachedCheck = 0
        for vector in vectors {
            let name = try XCTUnwrap(vector["name"] as? String)
            // body_* vectors test the server's body parser (JSON member, canonical base64), not the assertion.
            if name.hasPrefix("body_") { continue }
            let expected = try XCTUnwrap(vector["expected"] as? [String: Any])
            let stored = try XCTUnwrap(vector["stored"] as? [String: Any])
            guard let bodyText = vector["body"] as? String, let body = Data(base64Encoded: bodyText),
                  let object = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
                  object.count == 1, let encoded = object["appAssertion"] as? String,
                  let assertion = CanonicalBase64.decode(encoded) else { XCTFail("\(name): body"); continue }
            let storedCounter = UInt32(try XCTUnwrap((stored["counter"] as? NSNumber)?.uint32Value))
            let storedAppId = stored["appleAppId"] as? String ?? ""
            let result = AssertionCheck.verify(assertion: assertion, publicPoint: point, appId: storedAppId,
                                               clientDataHash: clientDataHash, storedCounter: storedCounter)
            reachedCheck += 1
            if expected["result"] as? String == "ok" {
                // The SDK builds exactly this body from these assertion bytes, and its clientData verifies them.
                XCTAssertEqual(AppAttestBinding.renewalBody(assertion: assertion), body, name)
                XCTAssertEqual(result, .ok(counter: try XCTUnwrap((expected["counter"] as? NSNumber)?.uint32Value)), name)
                XCTAssertEqual(storedAppId, appId, name)
                reproduced += 1
            } else {
                // Integration PR 1 review R (M1): every vector whose body reaches the check gets the server's reason
                // (the body_* vectors stop at the body parser above and never get here).
                XCTAssertEqual(result, .refused(try XCTUnwrap(expected["reason"] as? String, name)), name)
                if ["sig_other_nonce", "sig_other_session", "sig_other_spki"].contains(name) { boundRefusals += 1 }
                if ["extensions_duplicate_key", "extensions_depth_9", "extensions_bytes_key"].contains(name) { strictRefusals += 1 }
            }
        }
        XCTAssertEqual(reproduced, 11, "every valid vector")
        XCTAssertEqual(boundRefusals, 3)
        XCTAssertEqual(strictRefusals, 3, "StrictCbor rules in the extensions map: repeated key, depth 9, byte-string key")
        XCTAssertEqual(reachedCheck, vectors.filter { !(($0["name"] as? String) ?? "").hasPrefix("body_") }.count,
                       "every non-body_ vector reaches AssertionCheck")
    }

    // MARK: D-09b attestation vectors (main)

    func testAttestationClientDataHashIsTheOneInTheValidVectorsNonce() throws {
        let url = try Self.repositoryFile("verification/attestation/vectors/app-attest-v1.json")
        let json = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
        let challenge = try XCTUnwrap(Data(hex: try XCTUnwrap(json["attestationChallengeHex"] as? String)))
        let spki = try XCTUnwrap(Data(base64Encoded: try XCTUnwrap(json["publicKey"] as? String)))
        let clientDataHash = AppAttestBinding.attestationClientDataHash(attestationChallenge: challenge, spki: spki)
        let vectors = try XCTUnwrap(json["vectors"] as? [[String: Any]])
        var checked = 0
        for name in ["valid_development", "valid_production"] {
            let vector = try XCTUnwrap(vectors.first { $0["name"] as? String == name })
            let appAttest = try XCTUnwrap(vector["appAttest"] as? [String: String])
            let object = try CBOR.decode(try XCTUnwrap(Data(base64Encoded: try XCTUnwrap(appAttest["attestationObject"]))))
            XCTAssertEqual(object["fmt"], .text("apple-appattest"))
            let authData = try XCTUnwrap(object["authData"]?.data)
            guard case .array(let x5c)? = object["attStmt"]?["x5c"], let leaf = x5c.first?.data else {
                return XCTFail("\(name): x5c")
            }
            XCTAssertEqual(try Self.nonceExtension(leaf), Data(SHA256.hash(data: authData + clientDataHash)), name)
            XCTAssertTrue(AppAttestBinding.validKeyId(try XCTUnwrap(appAttest["keyId"])))
            checked += 1
        }
        XCTAssertEqual(checked, 2)
    }

    func testEnrollmentBodyHasTheV17AppleShape() throws {
        let url = try Self.repositoryFile("verification/attestation/vectors/app-attest-v1.json")
        let json = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
        let requests = try XCTUnwrap(json["requestVectors"] as? [[String: Any]])
        let apple = try XCTUnwrap(try XCTUnwrap(requests.first { $0["name"] as? String == "apple_ok" })["body"] as? [String: Any])
        let dto = try XCTUnwrap(apple["appAttest"] as? [String: String])
        let token = Data(repeating: 7, count: 32).base64EncodedString()
        let spki = try XCTUnwrap(Data(base64Encoded: try XCTUnwrap(apple["publicKey"] as? String)))
        let body = try EnrollmentBody.encode(token: token, publicKey: spki, appAttest: AppAttestEvidence(
            keyId: try XCTUnwrap(dto["keyId"]), attestationObject: try XCTUnwrap(Data(base64Encoded: try XCTUnwrap(dto["attestationObject"])))))
        let ours = try XCTUnwrap(try JSONSerialization.jsonObject(with: body) as? [String: Any])
        XCTAssertEqual(Set(ours.keys), Set(apple.keys).union(["requiresHardware"]))
        XCTAssertEqual(ours["publicKey"] as? String, apple["publicKey"] as? String)
        XCTAssertEqual(ours["attestationFormat"] as? String, apple["attestationFormat"] as? String)
        XCTAssertEqual(ours["appAttest"] as? [String: String], dto)
        XCTAssertEqual(ours["requiresHardware"] as? Bool, false)
        // Server limits enforced before sending (otherwise 400 attestation-invalid).
        XCTAssertThrowsError(try EnrollmentBody.encode(token: token, publicKey: spki, appAttest: AppAttestEvidence(
            keyId: "SoyOm622HGr-v-TqdVy_A9jwvY9SOhJPoINPxSGEHjc=", attestationObject: Data([1]))))
        XCTAssertThrowsError(try EnrollmentBody.encode(token: token, publicKey: spki, appAttest: AppAttestEvidence(
            keyId: try XCTUnwrap(dto["keyId"]), attestationObject: Data())))
        XCTAssertThrowsError(try EnrollmentBody.encode(token: token, publicKey: spki, appAttest: AppAttestEvidence(
            keyId: try XCTUnwrap(dto["keyId"]), attestationObject: Data(count: 32769))))
    }

    /// `1.2.840.113635.100.8.2` → `SEQUENCE { [1] EXPLICIT OCTET STRING (32) }` in the credential certificate.
    static func nonceExtension(_ certificate: Data) throws -> Data {
        let bytes = [UInt8](certificate)
        let oid: [UInt8] = [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x63, 0x64, 0x08, 0x02]
        let marker: [UInt8] = [0x30, 0x24, 0xA1, 0x22, 0x04, 0x20]
        guard let at = (0 ... bytes.count - oid.count).first(where: { Array(bytes[$0 ..< $0 + oid.count]) == oid }),
              let start = (at ..< bytes.count - marker.count).first(where: { Array(bytes[$0 ..< $0 + marker.count]) == marker })
        else { throw CBOR.Malformed() }
        return Data(bytes[start + marker.count ..< start + marker.count + 32])
    }
}

extension Data {
    init?(hex: String) {
        guard hex.count % 2 == 0 else { return nil }
        var out = Data()
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index ..< next], radix: 16) else { return nil }
            out.append(byte)
            index = next
        }
        self = out
    }
}
