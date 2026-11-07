package br.com.ebees.sentomaru.sdk

import java.security.MessageDigest
import java.util.Base64

/**
 * D-04d (contracts/api/reenrollment-v1.md): the proof a [SentomaruClient.rotate] carries so the server re-enrolls the
 * current installation instead of creating a new one (same installation code, name, tags and suspension; the previous
 * key stops signing on the server). Signed with the CURRENT key over the scope, the previous installation id, this
 * rotation's challenge id and the SHA-256 of the NEW key's SPKI: it cannot be replayed on another challenge or key.
 * [SentomaruClient.reset] + [SentomaruClient.enroll] carries none (no key left to prove with): a new installation.
 */
internal object ReenrollmentProof {
    const val LABEL = "sentomaru-reenroll-v1"

    /** UTF-8, lines joined by LF, no trailing LF (the server's Integrity.Application.ReenrollmentProof.Message). */
    fun message(config: SentomaruConfig, previousInstallation: String, challengeId: String, newKeySpki: ByteArray): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256").digest(newKeySpki).joinToString("") { "%02x".format(it) }
        return listOf(LABEL, config.organization, config.app, config.environment, previousInstallation.lowercase(),
            challengeId.lowercase(), digest).joinToString("\n").toByteArray(Charsets.UTF_8)
    }
}

/** Key material of a rotation plus the `predecessor` member its frozen body carries ([EnrollmentBody.encode]). */
internal class RotationMaterial(val material: KeyMaterial, val previousInstallation: String, signature: ByteArray) {
    private val proof = signature.copyOf()

    /** `,"predecessor":{...}`: a lowercase UUID and the standard padded base64 of the 64-byte P1363 signature. */
    fun member(): String = ",\"predecessor\":{\"installationId\":\"${previousInstallation.lowercase()}\"," +
        "\"signature\":\"${Base64.getEncoder().encodeToString(proof)}\"}"
}

/**
 * Signs the rotation's proof with [current]'s key (still the active one), for [generated], the key just generated
 * under [newAlias]. A failure deletes the new key (it was never persisted) and rethrows: the current key stays active.
 */
internal fun InstallationKeys.rotationMaterial(config: SentomaruConfig, current: InstallationRecord,
    challenge: EnrollmentChallenge, newAlias: String, generated: KeyMaterial): RotationMaterial = try {
    val previous = current.grant!!.installationId
    val signature = sign(current.alias, ReenrollmentProof.message(config, previous, challenge.id, generated.publicKey()))
    if (signature.size != 64) fail(EnrollmentError.KeyUnavailable())
    RotationMaterial(generated, previous, signature)
} catch (e: Exception) {
    delete(newAlias)
    throw e
}
