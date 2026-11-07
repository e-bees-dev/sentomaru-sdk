import CryptoKit
import Foundation
@testable import SentomaruCore
import XCTest

/// SDK-VEC-1..4 on the Swift side, the twin of the Kotlin `SharedVectorsTest`. Inputs and expectations come from
/// the vendor's vector generator (independent Python implementation, http-message-signatures). ECDSA is randomized:
/// bases, digests, Signature-Input and envelopes are compared byte for byte; signatures are verified, never compared.
final class SharedVectorsTests: XCTestCase {
    /// Exact counts of sdk-vectors-v1.json (81 = 43 positive + 38 negative). A new vector changes these on purpose:
    /// the Swift SDK must be re-run against it, never skip it.
    static let expectedTotal = 81
    static let expectedPositives = 43
    static let expectedNegatives = 38

    private var file: VectorFile!

    override func setUpWithError() throws { file = try VectorFile.load() }

    func testExactVectorCounts() {
        XCTAssertEqual(file.vectors.count, Self.expectedTotal)
        XCTAssertEqual(file.positives.count, Self.expectedPositives)
        XCTAssertEqual(file.negatives.count, Self.expectedNegatives)
        XCTAssertEqual(Set(file.vectors.map(\.id)).count, Self.expectedTotal, "ids are unique")
    }

    /// SDK-VEC-1: Content-Digest identical for every vector.
    func testContentDigestMatchesPython() {
        var checked = 0
        for v in file.vectors {
            XCTAssertEqual(ContentDigest.sha256(v.body), v.contentDigest, v.id)
            checked += 1
        }
        XCTAssertEqual(checked, Self.expectedTotal)
    }

    /// SDK-VEC-2: signature base bytes identical.
    func testSignatureBaseMatchesPython() throws {
        var checked = 0
        for v in file.positives {
            let base = try SignatureBase.build(method: v.method, targetURI: v.targetURI, headers: v.headers,
                                               contentDigest: ContentDigest.sha256(v.body), params: try v.params())
            XCTAssertEqual(base, v.signatureBase, v.id)
            checked += 1
        }
        XCTAssertEqual(checked, Self.expectedPositives)
    }

    /// SDK-VEC-2: Signature-Input identical, and the whole signing path yields the same base and headers.
    func testSignedMessageMatchesPython() throws {
        let key = P256.Signing.PrivateKey()
        var checked = 0
        for v in file.positives {
            let signed = try MessageSigner.sign(try v.request(), params: try v.params(), signer: SoftwareSigner.signer(key))
            XCTAssertEqual(signed.header(Profile.signatureInputHeader), v.signatureInput, v.id)
            XCTAssertEqual(signed.header(Profile.contentDigestHeader), v.contentDigest, v.id)
            XCTAssertEqual(signed.signatureBase, v.signatureBase, v.id)
            XCTAssertEqual(signed.body, v.body, v.id)
            XCTAssertEqual(signed.headers.map(\.name),
                           Array(Profile.components(for: v.headers).dropFirst(2)) +
                               [Profile.signatureInputHeader, Profile.signatureHeader], v.id)
            let header = try XCTUnwrap(signed.header(Profile.signatureHeader))
            let signature = try XCTUnwrap(Data(base64Encoded: String(header.dropFirst("sig1=:".count).dropLast())))
            XCTAssertTrue(SoftwareSigner.verify(spki: key.publicKey.derRepresentation, base: try XCTUnwrap(v.signatureBase),
                                                signature: signature), v.id)
            checked += 1
        }
        XCTAssertEqual(checked, Self.expectedPositives)
    }

    /// SDK-VEC-3: the Python library's signature verifies (CryptoKit) over the SWIFT core's base; one flipped bit fails.
    func testPythonSignatureVerifiesOverSwiftBase() throws {
        var checked = 0
        for v in file.positives {
            let base = try SignatureBase.build(method: v.method, targetURI: v.targetURI, headers: v.headers,
                                               contentDigest: ContentDigest.sha256(v.body), params: try v.params())
            let header = try XCTUnwrap(v.pythonSignature)
            let signature = try XCTUnwrap(Data(base64Encoded: String(header.dropFirst("sig1=:".count).dropLast())))
            XCTAssertEqual(signature.count, 64, v.id)
            XCTAssertTrue(SoftwareSigner.verify(spki: file.pythonPublicKeySpki, base: base, signature: signature), v.id)
            var flipped = base
            flipped[flipped.count / 2] ^= 1
            XCTAssertFalse(SoftwareSigner.verify(spki: file.pythonPublicKeySpki, base: flipped, signature: signature), v.id)
            checked += 1
        }
        XCTAssertEqual(checked, Self.expectedPositives)
    }

    /// SDK-VEC-4 (core side): every negative is refused with the expected typed error, before the signer runs.
    func testNegativesAreRefusedWithTypedErrors() throws {
        var checked = 0
        for v in file.negatives {
            let expected = try XCTUnwrap(v.coreError, v.id)
            XCTAssertRefused(expected, v.id) {
                _ = try MessageSigner.sign(try v.request(), params: try v.params()) { _ in
                    XCTFail("\(v.id): signer reached")
                    return Data(count: 64)
                }
            }
            checked += 1
        }
        XCTAssertEqual(checked, Self.expectedNegatives)
    }

    /// The Kotlin core's checked-in envelopes (core-signed-v1.json) are byte-identical to what THIS core produces with the
    /// same signature, and those signatures verify over the Swift base: envelope parity with the Android SDK.
    func testCoreSignedEnvelopesAreByteIdentical() throws {
        let core = try CoreSignedFile.load()
        XCTAssertEqual(core.entries.map(\.id), file.positives.map(\.id))
        var checked = 0
        for (v, entry) in zip(file.positives, core.entries) {
            XCTAssertEqual(entry.route, v.route, v.id)
            let signature = try entry.signature()
            let signed = try MessageSigner.sign(try v.request(), params: try v.params()) { _ in signature }
            let envelope = v.route == "enrollment" ? EnvelopeCodec.encodeEnrollment(signed) : EnvelopeCodec.encode(signed)
            XCTAssertEqual(String(decoding: envelope, as: UTF8.self), entry.envelope, v.id)
            XCTAssertTrue(SoftwareSigner.verify(spki: core.publicKeySpki, base: signed.signatureBase, signature: signature), v.id)
            checked += 1
        }
        XCTAssertEqual(checked, Self.expectedPositives)
    }
}
