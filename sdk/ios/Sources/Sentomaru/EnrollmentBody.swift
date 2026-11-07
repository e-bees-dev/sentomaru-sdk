import Foundation

/// The App Attest part of an enrollment body (contract v1.7 `AppAttestDto`).
struct AppAttestEvidence: Sendable {
    let keyId: String
    let attestationObject: Data
}

/// Fixed JSON schema of the enrollment body, only validated base64/boolean values (no arbitrary-string escaping):
/// `{"challenge","requiresHardware","publicKey","attestationFormat":"apple-app-attest","appAttest":{"keyId",
/// "attestationObject"}[,"predecessor":{...}]}`. Same member order as the Android body, with the App Attest members
/// where Android puts `attestationChain`.
///
/// `requiresHardware` is always false: the app's own `requiresHardware` never accepts `device_attested` (D-IOS9), so
/// `true` would always be refused with 422 on iOS.
enum EnrollmentBody {
    static func encode(token: String, publicKey: Data, appAttest: AppAttestEvidence, predecessor: String = "") throws -> Data {
        guard CanonicalBase64.decode(token) != nil, AppAttestBinding.validKeyId(appAttest.keyId),
              (1...AppAttestBinding.maxAttestationObject).contains(appAttest.attestationObject.count)
        else { throw SentomaruError.keyUnavailable }
        let text = "{\"challenge\":\"\(token)\",\"requiresHardware\":false," +
            "\"publicKey\":\"\(publicKey.base64EncodedString())\"," +
            "\"attestationFormat\":\"apple-app-attest\"," +
            "\"appAttest\":{\"keyId\":\"\(appAttest.keyId)\",\"attestationObject\":\"\(appAttest.attestationObject.base64EncodedString())\"}" +
            predecessor + "}"
        return Data(text.utf8)
    }
}

/// D-04d (the Sentomaru re-enrollment API contract): the proof a `rotate` carries so the server re-enrolls the current
/// installation. Signed with the CURRENT key over the scope, the previous installation id, this rotation's challenge id
/// and the SHA-256 (hex) of the NEW key's SPKI. Byte-identical to the Android `ReenrollmentProof.message`.
enum ReenrollmentProof {
    static let label = "sentomaru-reenroll-v1"

    static func message(config: SentomaruConfig, previousInstallation: String, challengeId: String, newKeySpki: Data) -> Data {
        Data([label, config.organization, config.app, config.environment, previousInstallation.lowercased(),
              challengeId.lowercased(), Hashing.hex(Hashing.sha256(newKeySpki))].joined(separator: "\n").utf8)
    }

    /// `,"predecessor":{"installationId":"<lowercase UUID>","signature":"<standard base64 of 64 bytes>"}`.
    static func member(previousInstallation: String, signature: Data) -> String {
        ",\"predecessor\":{\"installationId\":\"\(previousInstallation.lowercased())\"," +
            "\"signature\":\"\(signature.base64EncodedString())\"}"
    }
}
