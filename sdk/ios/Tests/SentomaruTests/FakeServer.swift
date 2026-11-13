import CryptoKit
import Foundation
@testable import Sentomaru
import XCTest

/// Consumer + Sentomaru stand-in for the flow tests. It checks what the real server checks on the SDK's bytes:
/// the RFC 9421 base rebuilt from the sent headers and verified with the enrolled SPKI, the enrollment body (v1.7
/// `apple-app-attest`, attestation bound to SHA-256(attestationChallenge ‖ SPKI)), the D-04d predecessor proof, and
/// the D-09c renewal assertion (counter, clientData bound to session, nonce and SPKI).
final class FakeServer: @unchecked Sendable {
    struct Installation {
        let installationId: String
        let spki: Data
        let appAttestKeyId: String
        var counter: UInt32
        var sessionId: String
        let challengeId: String
    }

    let config: SentomaruConfig
    let appAttest: FakeAppAttest
    private let lock = NSLock()
    private(set) var installations: [String: Installation] = [:] // by keyId (= challenge id)
    private(set) var enrollBodies: [Data] = []
    private(set) var renewBodies: [Data] = []
    private var issued: [String: EnrollmentChallenge] = [:]
    private var grantsByChallenge: [String: (body: Data, grant: EnrollmentGrant)] = [:]
    var enrollFailures: [Error] = []
    var renewFailures: [Error] = []
    var renewDelay: UInt64 = 0
    private(set) var concurrentRenewals = 0
    private(set) var maxConcurrentRenewals = 0

    init(config: SentomaruConfig, appAttest: FakeAppAttest) {
        self.config = config
        self.appAttest = appAttest
    }

    func challenge(now: Date, ttl: TimeInterval = 120) throws -> EnrollmentChallenge {
        func random() -> Data { Data((0 ..< 32).map { _ in UInt8.random(in: 0 ... 255) }) }
        let challenge = try EnrollmentChallenge(id: UUIDText.random(), token: random().base64EncodedString(),
                                                attestationChallenge: random(), expiresAt: now.addingTimeInterval(ttl))
        lock.withLock { issued[challenge.id] = challenge }
        return challenge
    }

    struct Refused: Error, Equatable { let reason: String }

    /// Parses `Signature-Input`, rebuilds the base from the sent message with the core and verifies it with `spki`.
    static func verifySignature(_ signed: SignedMessage, spki: Data) throws -> SignatureParams {
        let input = try XCTUnwrap(signed.header("signature-input"))
        func value(_ name: String, quoted: Bool) throws -> String {
            let pattern = quoted ? ";\(name)=\"([^\"]+)\"" : ";\(name)=([0-9]+)"
            let regex = try NSRegularExpression(pattern: pattern)
            let match = try XCTUnwrap(regex.firstMatch(in: input, range: NSRange(input.startIndex..., in: input)))
            return String(input[try XCTUnwrap(Range(match.range(at: 1), in: input))])
        }
        var headers: [String: String] = [:]
        for (name, value) in signed.headers where !["content-digest", "signature-input", "signature"].contains(name) {
            headers[name] = value
        }
        let params = try SignatureParams(created: try XCTUnwrap(Int64(value("created", quoted: false))),
                                         expires: try XCTUnwrap(Int64(value("expires", quoted: false))),
                                         nonce: value("nonce", quoted: true), keyId: value("keyid", quoted: true),
                                         components: Profile.components(for: headers))
        XCTAssertEqual(input, "sig1=" + params.serialize())
        XCTAssertEqual(signed.header("content-digest"), ContentDigest.sha256(signed.body))
        let base = try SignatureBase.build(method: signed.method, targetURI: signed.targetURI, headers: headers,
                                           contentDigest: ContentDigest.sha256(signed.body), params: params)
        if !signed.signatureBase.isEmpty { XCTAssertEqual(base, signed.signatureBase) } // empty: rebuilt from the wire
        let header = try XCTUnwrap(signed.header("signature"))
        let raw = try XCTUnwrap(Data(base64Encoded: String(header.dropFirst("sig1=:".count).dropLast())))
        let key = try P256.Signing.PublicKey(derRepresentation: spki)
        guard key.isValidSignature(try P256.Signing.ECDSASignature(rawRepresentation: raw), for: base) else {
            throw Refused(reason: "proof-invalid")
        }
        return params
    }

    func enroll(_ signed: SignedMessage) async throws -> EnrollmentGrant {
        try lock.withLock {
            enrollBodies.append(signed.body)
            if !enrollFailures.isEmpty { throw enrollFailures.removeFirst() }
            XCTAssertEqual(signed.method, "POST")
            XCTAssertEqual(signed.targetURI, config.enrollmentUrl)
            XCTAssertEqual(signed.header("x-sentomaru-operation"), "enroll")
            let challengeId = try XCTUnwrap(signed.header("x-sentomaru-session"))
            let body = try XCTUnwrap(try JSONSerialization.jsonObject(with: signed.body) as? [String: Any])
            XCTAssertEqual(Set(body.keys).subtracting(["predecessor", "sdkModes"]),
                           ["challenge", "requiresHardware", "publicKey", "attestationFormat", "appAttest"])
            XCTAssertEqual(body["requiresHardware"] as? Bool, false)
            XCTAssertEqual(body["attestationFormat"] as? String, "apple-app-attest")
            let spki = try XCTUnwrap(Data(base64Encoded: try XCTUnwrap(body["publicKey"] as? String)))
            let params = try Self.verifySignature(signed, spki: spki)
            XCTAssertEqual(params.keyId, challengeId)
            let appAttestDto = try XCTUnwrap(body["appAttest"] as? [String: String])
            XCTAssertEqual(Set(appAttestDto.keys), ["keyId", "attestationObject"])
            let keyId = try XCTUnwrap(appAttestDto["keyId"])
            if let previous = grantsByChallenge[challengeId] {
                guard previous.body == signed.body else { throw SentomaruError.serverRejected(.CONFLICT) }
                return previous.grant // identical replay
            }
            let attestation = try XCTUnwrap(Data(base64Encoded: try XCTUnwrap(appAttestDto["attestationObject"])))
            let recorded = try XCTUnwrap(appAttest.attestations.last { $0.keyId == keyId })
            XCTAssertEqual(attestation, Data("fake-attestation:".utf8) + recorded.clientDataHash)
            // The binding the D-09b verifier checks through the nonce: SHA-256(attestationChallenge ‖ SPKI).
            let issuedChallenge = try XCTUnwrap(issued[challengeId])
            XCTAssertEqual(body["challenge"] as? String, issuedChallenge.token)
            XCTAssertEqual(recorded.clientDataHash, Data(SHA256.hash(data: issuedChallenge.attestationChallenge + spki)))
            if let predecessor = body["predecessor"] as? [String: String] {
                let previous = try XCTUnwrap(installations.values.first { $0.installationId == predecessor["installationId"] })
                let proof = try XCTUnwrap(Data(base64Encoded: try XCTUnwrap(predecessor["signature"])))
                let message = ReenrollmentProof.message(config: config, previousInstallation: previous.installationId,
                                                        challengeId: challengeId, newKeySpki: spki)
                let key = try P256.Signing.PublicKey(derRepresentation: previous.spki)
                guard key.isValidSignature(try P256.Signing.ECDSASignature(rawRepresentation: proof), for: message) else {
                    throw SentomaruError.reenrollmentRefused
                }
            }
            let installation = Installation(installationId: UUIDText.random(), spki: spki, appAttestKeyId: keyId, counter: 0,
                                            sessionId: UUIDText.random(), challengeId: challengeId)
            installations[challengeId] = installation
            let grant = try EnrollmentGrant(installationId: installation.installationId, keyId: challengeId,
                                            sessionId: installation.sessionId, hardwareStatus: "device_attested",
                                            attestationStatus: "verified")
            grantsByChallenge[challengeId] = (signed.body, grant)
            return grant
        }
    }

    /// The attestation clientDataHash the fake App Attest saw for `keyId`.
    func attestationClientDataHash(_ keyId: String) -> Data? { appAttest.attestations.last { $0.keyId == keyId }?.clientDataHash }

    func renew(_ signed: SignedMessage) async throws -> RenewedGrant {
        let delay = lock.withLock { () -> UInt64 in
            concurrentRenewals += 1
            maxConcurrentRenewals = max(maxConcurrentRenewals, concurrentRenewals)
            return renewDelay
        }
        if delay > 0 { try await Task.sleep(nanoseconds: delay) }
        return try lock.withLock {
            defer { concurrentRenewals -= 1 }
            renewBodies.append(signed.body)
            if !renewFailures.isEmpty { throw renewFailures.removeFirst() }
            XCTAssertEqual(signed.targetURI, config.renewalUrl)
            XCTAssertEqual(signed.header("x-sentomaru-operation"), SentomaruClient.renewOperation)
            let keyId = try XCTUnwrap(signed.header("signature-input").flatMap { input in
                input.range(of: ";keyid=\"").map { String(input[$0.upperBound...].prefix(36)) }
            })
            var installation = try XCTUnwrap(installations[keyId])
            let params = try Self.verifySignature(signed, spki: installation.spki)
            let session = try XCTUnwrap(signed.header("x-sentomaru-session"))
            guard session == installation.sessionId else { throw SentomaruError.enrollmentRequired }
            // D-09c step 1: exactly {"appAssertion": "<canonical base64>"}.
            let body = try XCTUnwrap(try JSONSerialization.jsonObject(with: signed.body) as? [String: String])
            XCTAssertEqual(Array(body.keys), ["appAssertion"])
            let assertion = try XCTUnwrap(CanonicalBase64.decode(try XCTUnwrap(body["appAssertion"])))
            XCTAssertEqual(signed.body, AppAttestBinding.renewalBody(assertion: assertion))
            let clientDataHash = AppAttestBinding.assertionClientDataHash(sessionId: session, nonce: params.nonce, spki: installation.spki)
            let point = try XCTUnwrap(appAttest.publicPoint(installation.appAttestKeyId))
            switch AssertionCheck.verify(assertion: assertion, publicPoint: point, appId: appAttest.appId,
                                         clientDataHash: clientDataHash, storedCounter: installation.counter) {
            case .refused:
                throw SentomaruError.enrollmentRequired // every assertion refusal is 403 session-unavailable
            case .ok(let counter):
                installation.counter = counter
            }
            installation.sessionId = UUIDText.random()
            installations[keyId] = installation
            return try RenewedGrant(installationId: installation.installationId, keyId: keyId,
                                    sessionId: installation.sessionId, ttlSeconds: 600)
        }
    }

    func installation(_ keyId: String) -> Installation? { lock.withLock { installations[keyId] } }
}
