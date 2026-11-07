import Foundation
@testable import SentomaruCore
import XCTest

/// Port of the Kotlin `CoreUnitTest`: the same accepted and refused inputs, the same error codes.
final class CoreUnitTests: XCTestCase {
    let keyId = "11111111-2222-4333-8444-555555555555"
    let nonce = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    lazy var params = try! SignatureParams(created: 1_700_000_000, expires: 1_700_000_060, nonce: nonce, keyId: keyId)
    lazy var headers: [String: String] = [
        "content-type": "application/json",
        "x-sentomaru-profile": "sentomaru-p0",
        "x-sentomaru-org": "org-a",
        "x-sentomaru-app": "app-a",
        "x-sentomaru-environment": "hml",
        "x-sentomaru-session": keyId,
        "x-sentomaru-operation": "submit",
    ]
    let uri = "https://consumer.example/api/ops?x=1"
    let sig64: SignatureFunction = { _ in Data((0 ..< 64).map { UInt8($0) }) }
    let emptyDigest = ContentDigest.sha256(Data())

    func testContentDigestRfc9530Example() {
        XCTAssertEqual(ContentDigest.sha256(Data("{\"hello\": \"world\"}".utf8)),
                       "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:")
        XCTAssertEqual(emptyDigest, "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:")
    }

    func testSignatureParamsSerializeInReferenceOrder() {
        XCTAssertEqual(params.serialize(),
                       "(\"@method\" \"@target-uri\" \"content-digest\" \"content-type\" \"x-sentomaru-profile\" " +
                           "\"x-sentomaru-org\" \"x-sentomaru-app\" \"x-sentomaru-environment\" \"x-sentomaru-session\" " +
                           "\"x-sentomaru-operation\");created=1700000000;keyid=\"\(keyId)\";alg=\"ecdsa-p256-sha256\";" +
                           "expires=1700000060;nonce=\"\(nonce)\";tag=\"sentomaru-p0\"")
        XCTAssertEqual(MessageSigner.signatureInput(params), "sig1=" + params.serialize())
    }

    /// Negative "clock" cases: the window is enforced locally before any signature.
    func testSignatureParamsWindowAndIdentifiers() throws {
        _ = try SignatureParams(created: 0, expires: 1, nonce: nonce, keyId: keyId)
        XCTAssertRefused("InvalidRequest:PARAMS") { _ = try SignatureParams(created: 10, expires: 10, nonce: self.nonce, keyId: self.keyId) }
        XCTAssertRefused("InvalidRequest:PARAMS") { _ = try SignatureParams(created: 10, expires: 71, nonce: self.nonce, keyId: self.keyId) }
        XCTAssertRefused("InvalidRequest:PARAMS") { _ = try SignatureParams(created: 10, expires: 9, nonce: self.nonce, keyId: self.keyId) }
        XCTAssertRefused("InvalidRequest:PARAMS") { _ = try SignatureParams(created: -1, expires: 10, nonce: self.nonce, keyId: self.keyId) }
        XCTAssertRefused("InvalidRequest:PARAMS") { _ = try SignatureParams(created: 10, expires: 20, nonce: self.nonce.uppercased(), keyId: self.keyId) }
        XCTAssertRefused("InvalidRequest:PARAMS") { _ = try SignatureParams(created: 10, expires: 20, nonce: self.nonce, keyId: "{\(self.keyId)}") }
        XCTAssertRefused("InvalidRequest:PARAMS") { _ = try SignatureParams(created: 10, expires: 20, nonce: self.nonce + "\"", keyId: self.keyId) }
        XCTAssertRefused("InvalidRequest:PARAMS") {
            _ = try SignatureParams(created: 1_000_000_000_000_000, expires: 1_000_000_000_000_001, nonce: self.nonce, keyId: self.keyId)
        }
        // Clock before the epoch: no negative `created` is ever signed.
        XCTAssertRefused("InvalidRequest:PARAMS") {
            _ = try SignatureParams.now(Date(timeIntervalSince1970: -5), keyId: self.keyId, nonce: self.nonce)
        }
        let now = try SignatureParams.now(Date(timeIntervalSince1970: 1_800_000_000.999), keyId: keyId, nonce: nonce)
        XCTAssertEqual(now.created, 1_800_000_000)
        XCTAssertEqual(now.expires, 1_800_000_060)
    }

    func testTargetURICanonicalFormOnly() throws {
        let accepted = [
            "https://a.example/", "https://a.example/p?", "https://a.example:8443/p", "https://10.0.0.5/p",
            "https://a.example/caf%C3%A9?q=%2F%20+", "https://a.example/a/b/?k=v&k2=",
            "https://a.example/p?q=a?b/c", "https://a.example/" + String(repeating: "x", count: 4096 - 18),
            "https://a.example/a%2Fb%25c%20d%3Fe%5B%7F%23%01", "https://a.example/a:b@c!d$e&f'g(h)i*j+k,l;m=n",
            "https://a.example/p?q=%3A%40%21%24%26%27%28%29%2A%2B%2C%3B%3D%00", "https://255.255.255.255/",
            "https://0.0.0.0/", "https://1.2.3.4:8443/", "https://0x7f.example/", "https://1e.example/",
        ]
        for u in accepted {
            _ = try SignatureBase.build(method: "POST", targetURI: u, headers: headers, contentDigest: emptyDigest, params: params)
        }
        let refused = [
            "", "http://a.example/", "HTTPS://a.example/", "https://a.example", "https://a.example?x=1",
            "https://A.example/", "https://a.example:443/", "https://a.example:0/", "https://a.example:08443/",
            "https://a.example:65536/", "https://a.example:/", "https://u@a.example/", "https://a.example/#f",
            "https://a.example/a b", "https://a.example/café", "https://a.example/%c3%a9", "https://a.example/%41",
            "https://a.example/%7E", "https://a.example/%2E%2E/x", "https://a.example/%G0", "https://a.example/%C",
            "https://a.example/./x", "https://a.example/a/../x", "https://a.example/a\\b", "https://a.example/{x}",
            "https://[::1]/", "https://a..example/", "https://-a.example/", "https://a.example./",
            "https://a.example/" + String(repeating: "x", count: 4096 - 17), "/relative",
            "https://a.example/a%3Ab", "https://a.example/a%40b", "https://a.example/a%21b", "https://a.example/a%24b",
            "https://a.example/a%26b", "https://a.example/a%27b", "https://a.example/a%28b", "https://a.example/a%29b",
            "https://a.example/a%2Ab", "https://a.example/a%2Bb", "https://a.example/a%2Cb", "https://a.example/a%3Bb",
            "https://a.example/a%3Db", "https://a.example/a%00b", "https://a.example/p?q=%41", "https://a.example/p?q=%7E",
            "https://123/", "https://1.2.3/", "https://0x7f.0.0.1/", "https://010.0.0.1/", "https://256.0.0.1/",
            "https://1.2.3.4.5/", "https://a.123/", "https://a.0x1f/", "https://1.2.3.04/", "https://1.2.3.4:443/",
            // Swift-specific: a CRLF is one Character in Swift; the rules work on bytes and refuse it.
            "https://a.example/a\r\nb", "https://a.example/\u{0301}",
        ]
        for u in refused {
            XCTAssertRefused("InvalidRequest:TARGET_URI", u) {
                _ = try SignatureBase.build(method: "POST", targetURI: u, headers: self.headers,
                                            contentDigest: self.emptyDigest, params: self.params)
            }
        }
    }

    func testHeaderRules() throws {
        func with(_ name: String, _ value: String) -> [String: String] { var h = headers; h[name] = value; return h }
        var missing = headers
        missing["x-sentomaru-app"] = nil
        XCTAssertRefused("InvalidRequest:HEADER_NAME") {
            _ = try SignatureBase.build(method: "POST", targetURI: self.uri, headers: missing, contentDigest: self.emptyDigest, params: self.params)
        }
        for h in [with("X-Sentomaru-App", "app-a"), with("content-digest", emptyDigest)] {
            XCTAssertRefused("InvalidRequest:HEADER_NAME") {
                _ = try SignatureBase.build(method: "POST", targetURI: self.uri, headers: h, contentDigest: self.emptyDigest, params: self.params)
            }
        }
        let badValues: [(String, String)] = [
            ("x-sentomaru-operation", "submit\n"), ("x-sentomaru-operation", "sub\rmit"), ("x-sentomaru-operation", ""),
            ("x-sentomaru-operation", "submit\r\n"), ("x-sentomaru-operation", "submit "),
            ("x-sentomaru-operation", String(repeating: "a", count: 65)),
            ("x-sentomaru-org", "-org"), ("x-sentomaru-org", "org_a"), ("x-sentomaru-environment", String(repeating: "h", count: 64)),
            ("x-sentomaru-session", nonce.uppercased()), ("x-sentomaru-profile", "sentomaru-p1"),
            ("content-type", "application/json;charset=utf-8"), ("x-sentomaru-app", "appã"),
        ]
        for (name, value) in badValues {
            XCTAssertRefused("InvalidRequest:HEADER_VALUE", "\(name)=\(value)") {
                _ = try SignatureBase.build(method: "POST", targetURI: self.uri, headers: with(name, value),
                                            contentDigest: self.emptyDigest, params: self.params)
            }
        }
        _ = try SignatureBase.build(method: "POST", targetURI: uri, headers: with("x-sentomaru-operation", "Checklist.Upload_v2:final"),
                                    contentDigest: emptyDigest, params: params)
        _ = try SignatureBase.build(method: "POST", targetURI: uri, headers: with("x-sentomaru-operation", String(repeating: "o", count: 64)),
                                    contentDigest: emptyDigest, params: params)
        for method in ["Post", "", String(repeating: "P", count: 17)] {
            XCTAssertRefused("InvalidRequest:METHOD") {
                _ = try SignatureBase.build(method: method, targetURI: self.uri, headers: self.headers, contentDigest: self.emptyDigest, params: self.params)
            }
        }
        for digest in ["sha-512=:AA==:", String(emptyDigest.dropLast())] {
            XCTAssertRefused("InvalidRequest:CONTENT_DIGEST") {
                _ = try SignatureBase.build(method: "POST", targetURI: self.uri, headers: self.headers, contentDigest: digest, params: self.params)
            }
        }
    }

    /// Negative "body" and "alg/signature" cases: oversized body and a signer that does not return 64 bytes.
    func testBodyLimitAndSignerOutput() throws {
        _ = try FrozenRequest(method: "POST", targetURI: uri, headers: headers, body: Data(count: Profile.maxBodyBytes))
        XCTAssertThrowsError(try FrozenRequest(method: "POST", targetURI: uri, headers: headers, body: Data(count: Profile.maxBodyBytes + 1))) {
            XCTAssertEqual($0 as? SentomaruError, .bodyTooLarge(size: Profile.maxBodyBytes + 1, limit: Profile.maxBodyBytes))
        }
        for size in [0, 63, 65, 72] {
            XCTAssertRefused("SignatureFormat") {
                _ = try MessageSigner.sign(try FrozenRequest(method: "POST", targetURI: self.uri, headers: self.headers, body: Data()),
                                           params: self.params) { _ in Data(count: size) }
            }
        }
    }

    func testBodyIsFrozenAndSignerSeesExactlyTheBase() throws {
        var body = Data("{\"a\":1}".utf8)
        let request = try FrozenRequest(method: "POST", targetURI: uri, headers: headers, body: body)
        body[0] = UInt8(ascii: "X")
        var seen: Data?
        let signed = try MessageSigner.sign(request, params: params) { base in seen = base; return Data(count: 64) }
        XCTAssertEqual(signed.body, Data("{\"a\":1}".utf8))
        XCTAssertEqual(seen, signed.signatureBase)
        XCTAssertEqual(signed.header("content-digest"), ContentDigest.sha256(Data("{\"a\":1}".utf8)))
    }

    func testEnvelopeMatchesTheOpenApiMessageDto() throws {
        let signed = try MessageSigner.sign(try FrozenRequest(method: "POST", targetURI: uri, headers: headers, body: Data("{\"a\":1}".utf8)),
                                            params: params, signer: sig64)
        let digest = ContentDigest.sha256(Data("{\"a\":1}".utf8))
        let signature = try MessageSigner.signatureHeader(Data((0 ..< 64).map { UInt8($0) }))
        let expected = "{\"method\":\"POST\",\"uri\":\"\(uri)\",\"headers\":{\"content-digest\":[\"\(digest)\"]," +
            "\"content-type\":[\"application/json\"],\"x-sentomaru-profile\":[\"sentomaru-p0\"]," +
            "\"x-sentomaru-org\":[\"org-a\"],\"x-sentomaru-app\":[\"app-a\"],\"x-sentomaru-environment\":[\"hml\"]," +
            "\"x-sentomaru-session\":[\"\(keyId)\"],\"x-sentomaru-operation\":[\"submit\"]," +
            "\"signature-input\":[\"sig1=" + params.serialize().replacingOccurrences(of: "\"", with: "\\\"") + "\"]," +
            "\"signature\":[\"\(signature)\"]},\"body\":\"eyJhIjoxfQ==\"}"
        XCTAssertEqual(String(decoding: EnvelopeCodec.encode(signed), as: UTF8.self), expected)
        XCTAssertEqual(String(decoding: EnvelopeCodec.encodeEnrollment(signed), as: UTF8.self), "{\"request\":\(expected)}")
    }

    func testErrorsCarryNoRequestValues() {
        do {
            _ = try SignatureBase.build(method: "POST", targetURI: "https://secret-tenant.example/a b", headers: headers,
                                        contentDigest: emptyDigest, params: params)
            XCTFail("accepted")
        } catch {
            XCTAssertFalse(String(describing: error).contains("secret"))
            XCTAssertFalse(error.localizedDescription.contains("secret"))
        }
        XCTAssertEqual(SentomaruError.hostNotAllowed.code, "HostNotAllowed")
    }

    func testOptionalHeadersAreSignedAfterTheBaseComponentsInProfileOrder() throws {
        var withOptional = headers
        withOptional[Profile.operationIdHeader] = "op-0123456789abcdef"
        withOptional[Profile.signalsHeader] = "{\"catalogVersion\":\"1.1.0\",\"observations\":[]}"
        // D-25: the transaction signature joins them, last.
        withOptional[Profile.txSignatureHeader] = "sentomaru-tx-v1." + String(repeating: "A", count: 22) + "." + String(repeating: "B", count: 86)
        let signed = try MessageSigner.sign(try FrozenRequest(method: "POST", targetURI: uri, headers: withOptional, body: Data("{}".utf8)),
                                            params: params, signer: sig64)
        let input = try XCTUnwrap(signed.header(Profile.signatureInputHeader))
        XCTAssertTrue(input.hasPrefix("sig1=(" + (Profile.components + Profile.optionalHeaders).map { "\"\($0)\"" }.joined(separator: " ") + ")"))
        let base = String(decoding: signed.signatureBase, as: UTF8.self)
        let operation = try XCTUnwrap(base.range(of: "\"x-sentomaru-operation\": submit\n")).lowerBound
        let signals = try XCTUnwrap(base.range(of: "\"x-sentomaru-signals\": ")).lowerBound
        let id = try XCTUnwrap(base.range(of: "\"x-sentomaru-operation-id\": op-0123456789abcdef\n")).lowerBound
        let tx = try XCTUnwrap(base.range(of: "\"x-sentomaru-tx-signature\": sentomaru-tx-v1.")).lowerBound
        XCTAssertTrue(signals > operation && id > signals && tx > id)
        XCTAssertEqual(signed.headers.map(\.name).filter { Profile.optionalHeaders.contains($0) }, Profile.optionalHeaders)
        let plain = try MessageSigner.sign(try FrozenRequest(method: "POST", targetURI: uri, headers: headers, body: Data("{}".utf8)),
                                           params: params, signer: sig64)
        XCTAssertTrue(try XCTUnwrap(plain.header(Profile.signatureInputHeader))
            .hasPrefix("sig1=(" + Profile.components.map { "\"\($0)\"" }.joined(separator: " ") + ")"))
    }

    func testTheV2TransactionSignatureHeaderIsSignedLastAndItsShapeChecked() throws {
        var withV2 = headers
        withV2[Profile.operationIdHeader] = "op-0123456789abcdef"
        withV2[Profile.txSignatureHeader] = "sentomaru-tx-v2." + String(repeating: "A", count: 22) + ".1793000000." + String(repeating: "B", count: 86)
        let signed = try MessageSigner.sign(try FrozenRequest(method: "POST", targetURI: uri, headers: withV2, body: Data("{}".utf8)),
                                            params: params, signer: sig64)
        XCTAssertTrue(String(decoding: signed.signatureBase, as: UTF8.self).contains("\"x-sentomaru-tx-signature\": sentomaru-tx-v2.AAAAAAAAAAAAAAAAAAAAAA.1793000000."))
        var bad = headers
        bad[Profile.txSignatureHeader] = "sentomaru-tx-v2." + String(repeating: "A", count: 22) + ".179300000." + String(repeating: "B", count: 86)
        XCTAssertThrowsError(try MessageSigner.sign(try FrozenRequest(method: "POST", targetURI: uri, headers: bad, body: Data("{}".utf8)),
                                                    params: params, signer: sig64))
    }

    func testMalformedOperationIdAndUnknownHeadersAreRefused() {
        for bad in ["short", "op with space-0123", String(repeating: "x", count: 65)] {
            var h = headers
            h[Profile.operationIdHeader] = bad
            XCTAssertRefused("InvalidRequest:HEADER_VALUE", bad) {
                _ = try MessageSigner.sign(try FrozenRequest(method: "POST", targetURI: self.uri, headers: h, body: Data("{}".utf8)),
                                           params: self.params, signer: self.sig64)
            }
        }
        var unknown = headers
        unknown["x-sentomaru-other"] = "v"
        XCTAssertRefused("InvalidRequest:HEADER_NAME") {
            _ = try MessageSigner.sign(try FrozenRequest(method: "POST", targetURI: self.uri, headers: unknown, body: Data("{}".utf8)),
                                       params: self.params, signer: self.sig64)
        }
    }

    func testParamsWithComponentsOutsideTheProfileAreRefused() {
        XCTAssertRefused("InvalidRequest:PARAMS") {
            _ = try SignatureParams(created: 1, expires: 2, nonce: self.nonce, keyId: self.keyId,
                                    components: Profile.components + [Profile.operationIdHeader, Profile.signalsHeader])
        }
        XCTAssertRefused("InvalidRequest:PARAMS") {
            _ = try SignatureParams(created: 1, expires: 2, nonce: self.nonce, keyId: self.keyId,
                                    components: Array(Profile.components.dropFirst()))
        }
    }

    func testErrorCodesMatchAndroid() {
        let expected: [(SentomaruError, String)] = [
            (.bodyTooLarge(size: 1), "BodyTooLarge"), (.hostNotAllowed, "HostNotAllowed"),
            (.invalidRequest(.TARGET_URI), "InvalidRequest:TARGET_URI"), (.signatureFormat(size: 1), "SignatureFormat"),
            (.notEnrolled, "NotEnrolled"), (.enrollmentRequired, "EnrollmentRequired"), (.keyInvalidated, "KeyInvalidated"),
            (.challengeExpired, "ChallengeExpired"), (.networkUnavailable, "NetworkUnavailable"),
            (.storageUnavailable, "StorageUnavailable"), (.keyUnavailable, "KeyUnavailable"), (.cancelled, "Cancelled"),
            (.serverRejected(.SUSPENDED), "ServerRejected:SUSPENDED"),
            (.reenrollmentRefused, "ReenrollmentRefused"), (.unsupported(.APP_ATTEST), "Unsupported:APP_ATTEST"),
        ]
        for (error, code) in expected { XCTAssertEqual(error.code, code) }
    }
}
