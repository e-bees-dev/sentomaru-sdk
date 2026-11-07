import CryptoKit
import LocalAuthentication
import XCTest
@testable import Sentomaru

/// D-25 (iOS, client side): the bytes, the header value and the error mapping, with a software key standing in for the Secure
/// Enclave (no Secure Enclave, no prompt on the Mac host). The fixed vector is the one the Android and C# tests check.
final class TransactionSigningTests: XCTestCase {
    private let nonce = Data(repeating: 1, count: 16)
    private let operationId = "0123456789abcdef-op"
    private let body = Data(#"{"amount":10}"#.utf8)

    final class SoftwareKeys: TransactionKeys, @unchecked Sendable {
        var keys: [String: P256.Signing.PrivateKey] = [:]
        var failure: TransactionError?
        var reasons: [String] = []
        var promoteFailure: TransactionError?
        func exists(_ alias: String) throws -> Bool { keys[alias] != nil }
        func generate(_ alias: String, biometricOnly: Bool) throws -> Data {
            let key = P256.Signing.PrivateKey()
            keys[alias] = key
            return key.publicKey.derRepresentation
        }
        func promote(_ staged: String, to alias: String) throws {
            if let promoteFailure { throw promoteFailure }
            guard let key = keys[staged] else { throw TransactionError.notEnrolled }
            keys[alias] = key
            keys[staged] = nil
        }
        func sign(_ alias: String, _ bytes: Data, reason: String) throws -> Data {
            reasons.append(reason)
            if let failure { throw failure }
            guard let key = keys[alias] else { throw TransactionError.notEnrolled }
            return try key.signature(for: bytes).rawRepresentation
        }
        func delete(_ alias: String) throws { keys[alias] = nil }
    }

    func testTheSignedBytesAreTheCrossLanguageVector() {
        let expected = "sentomaru-tx-v1\nAQEBAQEBAQEBAQEBAQEBAQ\n0123456789abcdef-op\nqLiLgv6QoWBI64hR_jgkBTlc05Xa-qfKm-kOwA-Cpys"
        XCTAssertEqual(String(decoding: TransactionSignature.message(nonce: nonce, operationId: operationId, body: body), as: UTF8.self), expected)
    }

    func testTheHeaderValueHasTheServersShapeAndVerifiesWithTheKey() async throws {
        let keys = SoftwareKeys()
        let signer = TransactionSigner(keys: keys, alias: "a.tx", nonce: { Data(repeating: 1, count: 16) })
        let spki = try signer.stageKey()
        XCTAssertFalse(signer.isEnrolled()) // staged only: the signing alias is still empty
        try signer.commitKey()
        XCTAssertTrue(signer.isEnrolled())
        let header = try await signer.sign(operationId: operationId, body: body, reason: "Confirmar")
        XCTAssertTrue(TransactionSignature.isHeaderValue(header))
        XCTAssertEqual(keys.reasons, ["Confirmar"])
        let parts = header.split(separator: ".").map(String.init)
        XCTAssertEqual(parts[1], "AQEBAQEBAQEBAQEBAQEBAQ")
        var padded = parts[2].replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        padded += String(repeating: "=", count: (4 - padded.count % 4) % 4)
        let signature = try P256.Signing.ECDSASignature(rawRepresentation: Data(base64Encoded: padded)!)
        let publicKey = try P256.Signing.PublicKey(derRepresentation: spki)
        XCTAssertTrue(publicKey.isValidSignature(signature, for: TransactionSignature.message(nonce: nonce, operationId: operationId, body: body)))
    }

    func testEveryCallUsesANewNonceByDefault() async throws {
        let keys = SoftwareKeys()
        let signer = TransactionSigner(keys: keys, installationAlias: "a")
        _ = try signer.stageKey()
        try signer.commitKey()
        let first = try await signer.sign(operationId: operationId, body: body)
        let second = try await signer.sign(operationId: operationId, body: body)
        XCTAssertNotEqual(first.split(separator: ".")[1], second.split(separator: ".")[1])
    }

    func testCancellationIsRecoverableAndLeavesTheKey() async throws {
        let keys = SoftwareKeys()
        let signer = TransactionSigner(keys: keys, alias: "a.tx", nonce: { Data(repeating: 2, count: 16) })
        _ = try signer.stageKey()
        try signer.commitKey()
        keys.failure = .cancelled
        do { _ = try await signer.sign(operationId: operationId, body: body); XCTFail("expected a refusal") } catch {
            XCTAssertEqual(error as? TransactionError, .cancelled)
        }
        XCTAssertTrue(signer.isEnrolled())
        keys.failure = nil
        let header = try await signer.sign(operationId: operationId, body: body)
        XCTAssertTrue(TransactionSignature.isHeaderValue(header))
    }

    func testNotEnrolledAndABadOperationIdAreRefusedBeforeAnyPrompt() async throws {
        let keys = SoftwareKeys()
        let signer = TransactionSigner(keys: keys, alias: "a.tx", nonce: { Data(repeating: 3, count: 16) })
        do { _ = try await signer.sign(operationId: operationId, body: body); XCTFail() } catch {
            XCTAssertEqual(error as? TransactionError, .notEnrolled)
        }
        _ = try signer.stageKey()
        try signer.commitKey()
        keys.reasons = []
        for bad in ["short", "has space has space has space", String(repeating: "a", count: 65)] {
            do { _ = try await signer.sign(operationId: bad, body: body); XCTFail() } catch {
                XCTAssertEqual(error as? SentomaruError, .invalidRequest(.HEADER_VALUE))
            }
        }
        XCTAssertTrue(keys.reasons.isEmpty)
    }

    func testTheSystemsErrorsMapToAClosedSet() {
        typealias K = SecureEnclaveTransactionKeys
        XCTAssertEqual(K.map(LAError(.userCancel)), .cancelled)
        XCTAssertEqual(K.map(LAError(.systemCancel)), .cancelled)
        XCTAssertEqual(K.map(LAError(.biometryLockout)), .lockedOut)
        XCTAssertEqual(K.map(LAError(.passcodeNotSet)), .noUserAuthentication)
        XCTAssertEqual(K.map(LAError(.biometryNotEnrolled)), .noUserAuthentication)
        XCTAssertEqual(K.map(NSError(domain: NSOSStatusErrorDomain, code: Int(errSecItemNotFound))), .keyInvalidated)
        XCTAssertEqual(K.map(NSError(domain: "other", code: 1)), .signingFailed)
    }

    // F1: v2 carries the signer's clock. Review B (RC-10): the vector is READ from contracts/api/transaction-keys-v2-vector.json (the file the
    // server and the Python gate check), never copied as a literal.
    func testTheV2SignedBytesAreTheCrossLanguageVector() throws {
        let file = try AppAttestVectorTests.repositoryFile("contracts/api/transaction-keys-v2-vector.json")
        let vector = try XCTUnwrap(try JSONSerialization.jsonObject(with: try Data(contentsOf: file)) as? [String: Any])
        func text(_ name: String) throws -> String { try XCTUnwrap(vector[name] as? String, name) }
        func base64URL(_ value: String) throws -> Data {
            let padded = value.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/") + String(repeating: "=", count: (4 - value.count % 4) % 4)
            return try XCTUnwrap(Data(base64Encoded: padded))
        }
        let issuedAt = try XCTUnwrap((vector["issuedAt"] as? NSNumber)?.intValue)
        let message = TransactionSignature.message(nonce: try base64URL(try text("nonceBase64Url")), issuedAt: issuedAt,
                                                   operationId: try text("operationId"), body: Data(try text("bodyUtf8").utf8))
        XCTAssertEqual(String(decoding: message, as: UTF8.self), try text("signedBytes"))
        // The vector's signature (made by a key outside the SDK) verifies over the bytes the SDK builds, and not over other bytes.
        let key = try P256.Signing.PublicKey(derRepresentation: try XCTUnwrap(Data(base64Encoded: try text("publicKeySpkiBase64"))))
        let signature = try P256.Signing.ECDSASignature(rawRepresentation: try base64URL(try text("signatureP1363Base64Url")))
        XCTAssertTrue(key.isValidSignature(signature, for: message))
        XCTAssertFalse(key.isValidSignature(signature, for: TransactionSignature.message(nonce: try base64URL(try text("nonceBase64Url")), issuedAt: issuedAt + 1,
                                                                                         operationId: try text("operationId"), body: Data(try text("bodyUtf8").utf8))))
        XCTAssertEqual(try text("header").split(separator: ".").map(String.init),
                       ["sentomaru-tx-v2", try text("nonceBase64Url"), String(issuedAt), try text("signatureP1363Base64Url")])
    }

    func testTheV2HeaderCarriesTheClockAndOnlyTheV2BytesVerify() async throws {
        let keys = SoftwareKeys()
        let signer = TransactionSigner(keys: keys, alias: "a.tx", nonce: { Data(repeating: 1, count: 16) }, version: .v2, now: { 1_793_000_000 })
        let spki = try signer.stageKey()
        try signer.commitKey()
        let header = try await signer.sign(operationId: operationId, body: body)
        XCTAssertTrue(TransactionSignature.isHeaderValue(header), header)
        let parts = header.split(separator: ".").map(String.init)
        XCTAssertEqual(parts.count, 4)
        XCTAssertEqual(parts[0], "sentomaru-tx-v2")
        XCTAssertEqual(parts[2], "1793000000")
        var padded = parts[3].replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        padded += String(repeating: "=", count: (4 - padded.count % 4) % 4)
        let signature = try P256.Signing.ECDSASignature(rawRepresentation: Data(base64Encoded: padded)!)
        let publicKey = try P256.Signing.PublicKey(derRepresentation: spki)
        XCTAssertTrue(publicKey.isValidSignature(signature, for: TransactionSignature.message(nonce: nonce, issuedAt: 1_793_000_000, operationId: operationId, body: body)))
        // A v2 signature is not a v1 signature, and another time is another message.
        XCTAssertFalse(publicKey.isValidSignature(signature, for: TransactionSignature.message(nonce: nonce, operationId: operationId, body: body)))
        XCTAssertFalse(publicKey.isValidSignature(signature, for: TransactionSignature.message(nonce: nonce, issuedAt: 1_793_000_001, operationId: operationId, body: body)))
    }

    func testThePublicInitializerSignsV2ByDefault() async throws {
        let keys = SoftwareKeys()
        let signer = TransactionSigner(keys: keys, installationAlias: "a")
        _ = try signer.stageKey()
        try signer.commitKey()
        let header = try await signer.sign(operationId: operationId, body: body)
        XCTAssertTrue(header.hasPrefix("sentomaru-tx-v2."), header)
        XCTAssertTrue(TransactionSignature.isHeaderValue(header))
    }

    func testAClockBeforeTheV2RangeIsRefusedBeforeAnythingIsSigned() async throws {
        let keys = SoftwareKeys()
        let signer = TransactionSigner(keys: keys, alias: "a.tx", nonce: { Data(repeating: 1, count: 16) }, version: .v2, now: { 0 })
        _ = try signer.stageKey()
        try signer.commitKey()
        do { _ = try await signer.sign(operationId: operationId, body: body); XCTFail("must refuse") } catch {
            XCTAssertEqual(error as? TransactionError, .signingFailed)
        }
        XCTAssertEqual(keys.reasons, [], "no prompt was shown")
    }

    func testTheV2HeaderShapeIsChecked() {
        let ok = "sentomaru-tx-v2." + String(repeating: "A", count: 22) + ".1793000000." + String(repeating: "B", count: 86)
        XCTAssertTrue(TransactionSignature.isHeaderValue(ok))
        for bad in [ok.replacingOccurrences(of: ".1793000000.", with: ".179300000."), ok.replacingOccurrences(of: ".1793000000.", with: ".17930000000."),
                    ok.replacingOccurrences(of: ".1793000000.", with: ".17930000a0."), ok.replacingOccurrences(of: "v2", with: "v1"),
                    ok.replacingOccurrences(of: "v2", with: "v3"), ok + "=", ok.replacingOccurrences(of: ".1793000000", with: "")] {
            XCTAssertFalse(TransactionSignature.isHeaderValue(bad), bad)
        }
    }

    func testTheProfileCoversTheHeaderLastAndChecksItsShape() {
        XCTAssertEqual(Profile.optionalHeaders, ["x-sentomaru-signals", "x-sentomaru-operation-id", "x-sentomaru-tx-signature"])
        let value = "sentomaru-tx-v1." + String(repeating: "A", count: 22) + "." + String(repeating: "B", count: 86)
        XCTAssertTrue(TransactionSignature.isHeaderValue(value))
        for bad in [value + "=", "sentomaru-tx-v2" + value.dropFirst(15), "sentomaru-tx-v1.short.short", value + ".x", ""] {
            XCTAssertFalse(TransactionSignature.isHeaderValue(String(bad)), bad)
        }
    }

    // Shield #5: a re-enrollment that the server refuses (or that never finishes) must leave the key that signs.

    func testStagingANewKeyLeavesTheSigningKeyUntilTheServerAccepts() async throws {
        let keys = SoftwareKeys()
        let signer = TransactionSigner(keys: keys, alias: "a.tx", nonce: { Data(repeating: 1, count: 16) })
        let first = try signer.stageKey()
        try signer.commitKey()
        let staged = try signer.stageKey() // re-enrollment starts: the old key must still sign
        XCTAssertNotEqual(first, staged)
        XCTAssertTrue(signer.isEnrolled())
        let header = try await signer.sign(operationId: operationId, body: body)
        let message = TransactionSignature.message(nonce: Data(repeating: 1, count: 16), operationId: operationId, body: body)
        XCTAssertTrue(try verifies(header, with: first, message))
        XCTAssertFalse(try verifies(header, with: staged, message))
    }

    func testARefusedEnrollmentIsAbortedAndTheOldKeyKeepsSigning() async throws {
        let keys = SoftwareKeys()
        let signer = TransactionSigner(keys: keys, alias: "a.tx", nonce: { Data(repeating: 1, count: 16) })
        let first = try signer.stageKey()
        try signer.commitKey()
        _ = try signer.stageKey()
        signer.abortKey()
        XCTAssertNil(keys.keys["a.tx.pending"])
        let header = try await signer.sign(operationId: operationId, body: body)
        XCTAssertTrue(try verifies(header, with: first, TransactionSignature.message(nonce: Data(repeating: 1, count: 16), operationId: operationId, body: body)))
        XCTAssertThrowsError(try signer.commitKey()) { XCTAssertEqual($0 as? TransactionError, .notEnrolled) } // nothing left to commit
    }

    func testCommitReplacesTheOldKeyAndAFailedPromoteKeepsIt() async throws {
        let keys = SoftwareKeys()
        let signer = TransactionSigner(keys: keys, alias: "a.tx", nonce: { Data(repeating: 1, count: 16) })
        let first = try signer.stageKey()
        try signer.commitKey()
        let second = try signer.stageKey()
        keys.promoteFailure = .signingFailed
        XCTAssertThrowsError(try signer.commitKey()) { XCTAssertEqual($0 as? TransactionError, .signingFailed) }
        let message = TransactionSignature.message(nonce: Data(repeating: 1, count: 16), operationId: operationId, body: body)
        var header = try await signer.sign(operationId: operationId, body: body)
        XCTAssertTrue(try verifies(header, with: first, message))
        keys.promoteFailure = nil
        try signer.commitKey()
        header = try await signer.sign(operationId: operationId, body: body)
        XCTAssertTrue(try verifies(header, with: second, message))
        XCTAssertNil(keys.keys["a.tx.pending"])
    }

    func testDiscardDropsTheStagedKeyToo() throws {
        let keys = SoftwareKeys()
        let signer = TransactionSigner(keys: keys, alias: "a.tx", nonce: { Data(repeating: 1, count: 16) })
        _ = try signer.stageKey()
        signer.discard()
        XCTAssertTrue(keys.keys.isEmpty)
    }

    private func verifies(_ header: String, with spki: Data, _ message: Data) throws -> Bool {
        var padded = header.split(separator: ".").map(String.init)[2].replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        padded += String(repeating: "=", count: (4 - padded.count % 4) % 4)
        let signature = try P256.Signing.ECDSASignature(rawRepresentation: Data(base64Encoded: padded)!)
        return try P256.Signing.PublicKey(derRepresentation: spki).isValidSignature(signature, for: message)
    }
}
