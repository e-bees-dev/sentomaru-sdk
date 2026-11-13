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
    /// `config` nil (test vectors with no `SentomaruConfig` of their own) omits `sdkModes` entirely: the body is
    /// byte-identical to before D-F1. A real [SentomaruClient] always passes its own config.
    static func encode(token: String, publicKey: Data, appAttest: AppAttestEvidence, predecessor: String = "",
        config: SentomaruConfig? = nil) throws -> Data {
        guard CanonicalBase64.decode(token) != nil, AppAttestBinding.validKeyId(appAttest.keyId),
              (1...AppAttestBinding.maxAttestationObject).contains(appAttest.attestationObject.count)
        else { throw SentomaruError.keyUnavailable }
        let text = "{\"challenge\":\"\(token)\",\"requiresHardware\":false," +
            "\"publicKey\":\"\(publicKey.base64EncodedString())\"," +
            "\"attestationFormat\":\"apple-app-attest\"," +
            "\"appAttest\":{\"keyId\":\"\(appAttest.keyId)\",\"attestationObject\":\"\(appAttest.attestationObject.base64EncodedString())\"}" +
            predecessor + (config.map(SdkModesJson.encode) ?? "") + "}"
        return Data(text.utf8)
    }
}

/// D-F1 (ativação de módulos em cliente novo, Fase F): the SDK's own self-declaration, additive member of the
/// enrollment/reattestation body (contract v1.20). `playIntegrity` is always `unsupported` on iOS: Play Integrity is a
/// Google API, and [SentomaruConfig.playIntegrityCloudProjectNumber] does not exist on this platform. Purely
/// informational: never read back by the SDK itself.
enum SdkModesJson {
    static let sdk = "sentomaru_ios"
    static let sdkVersion = "0.2.0-rc.5"

    static func encode(_ config: SentomaruConfig) -> String {
        ",\"sdkModes\":{\"enforce\":\(config.declaredEnforce),\"installationResponse\":\(config.declaredInstallationResponse)," +
            "\"playIntegrity\":\"unsupported\",\"sdk\":\"\(sdk)\",\"sdkVersion\":\"\(sdkVersion)\"}"
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
