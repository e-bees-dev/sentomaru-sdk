package br.com.ebees.sentomaru.sdk

import br.com.ebees.sentomaru.core.SentomaruException
import java.time.Duration
import java.time.Instant
import java.time.OffsetDateTime
import java.util.Base64

/**
 * D-12c: the answer of the consumer's reattestation route, passed through from the private API
 * (the Sentomaru re-attestation API contract): HTTP status, body text and the `Retry-After` seconds when present. The SDK reads
 * the JSON `code` of a refusal itself; the consumer only forwards.
 */
class ReattestationAnswer @JvmOverloads constructor(val status: Int, val body: String, retryAfterSeconds: Long? = null) {
    /** A negative `Retry-After` is not a wait: it becomes `null` instead of throwing (review B, RC-07). */
    val retryAfterSeconds: Long? = retryAfterSeconds?.takeIf { it >= 0 }

    init {
        require(status in 100..599) { "Invalid HTTP status" }
    }
}

/** D-12b challenge: 32 bytes for the attestation challenge of a NEW key, single use, valid until [expiresAt]. */
class ReattestationChallenge(val challengeId: String, attestationChallenge: ByteArray, val expiresAt: Instant) {
    private val bytes = attestationChallenge.copyOf()
    fun attestationChallenge(): ByteArray = bytes.copyOf()

    init {
        validateUuid(challengeId)
        require(challengeId == challengeId.lowercase()) { "Invalid challenge id" }
        require(bytes.size == 32) { "Invalid attestation challenge" }
    }

    companion object {
        /** `{challengeId, attestationChallenge, expiresAt}` (201 or 200), each member once; anything else is null. */
        internal fun parse(text: String): ReattestationChallenge? {
            return try {
                val id = ReattestationJson.string(text, "challengeId") ?: return null
                val encoded = ReattestationJson.string(text, "attestationChallenge") ?: return null
                val decoded = Base64.getDecoder().decode(encoded)
                if (Base64.getEncoder().encodeToString(decoded) != encoded) return null
                val expires = ReattestationJson.string(text, "expiresAt")?.let { OffsetDateTime.parse(it).toInstant() } ?: return null
                ReattestationChallenge(id, decoded, expires)
            } catch (_: RuntimeException) {
                null
            } catch (_: SentomaruException) {
                null
            }
        }
    }
}

/**
 * D-12b result recorded by the server (200). States and reasons are the server's closed codes (D-04a build, D-13a
 * identity, verifier statuses); advisory, never an authorization. [replayed] = the same body was answered before.
 */
class ReattestationResult(
    val installationId: String, val challengeId: String, val reattestedAt: Instant,
    val hardwareStatus: String, val attestationStatus: String, val attestationReason: String?,
    val buildMatchState: String, val buildMatchReason: String?,
    val appIdentityState: String, val appIdentityReason: String?, val replayed: Boolean,
) {
    companion object {
        internal fun parse(text: String): ReattestationResult? = try {
            fun required(name: String) = ReattestationJson.code(text, name, nullable = false)?.value
            fun nullable(name: String) = ReattestationJson.code(text, name, nullable = true)
            val replayed = ReattestationJson.bool(text, "replayed")
            val reasons = listOf("attestationReason", "buildMatchReason", "appIdentityReason").map(::nullable)
            val values = listOf("hardwareStatus", "attestationStatus", "buildMatchState", "appIdentityState").map(::required)
            val installation = ReattestationJson.string(text, "installationId")
            val challenge = ReattestationJson.string(text, "challengeId")
            val at = ReattestationJson.string(text, "reattestedAt")
            if (replayed == null || reasons.any { it == null } || values.any { it == null } || installation == null ||
                challenge == null || at == null) null
            else {
                validateUuid(installation)
                validateUuid(challenge)
                ReattestationResult(installation, challenge, OffsetDateTime.parse(at).toInstant(), values[0]!!, values[1]!!,
                    reasons[0]!!.value, values[2]!!, reasons[1]!!.value, values[3]!!, reasons[2]!!.value, replayed)
            }
        } catch (_: RuntimeException) {
            null
        } catch (_: SentomaruException) {
            null
        }
    }
}

/** Why [ReattestationNotNow]: try again after [ReattestationNotNow.retryAfter], never in a loop. */
enum class ReattestationWait {
    /** `429 rate-limited`: the scope's minimum interval or the server's cap of challenges per day. */
    RATE_LIMITED,
    /** `503 verifier-unavailable` again after the one retry (or a retry that would not fit the challenge). */
    VERIFIER_UNAVAILABLE,
    /** The consumer's route could not be reached (`IOException` from `send`), or answered another 5xx. */
    UNAVAILABLE,
    /** Local: the last reattestation, or a server "not now", is more recent than the interval. Nothing was sent. */
    NOT_DUE,
}

/** Outcome of [SentomaruReattestation.requestChallenge]. */
sealed interface ReattestationChallengeOutcome

/** Outcome of a reattestation submission. */
sealed interface ReattestationOutcome

class ReattestationChallengeIssued(val challenge: ReattestationChallenge) : ReattestationChallengeOutcome

class ReattestationCompleted(val result: ReattestationResult) : ReattestationOutcome

/** "Not now": nothing to fix, try again after [retryAfter] (the SDK's [SentomaruReattestation.due] waits as well). */
class ReattestationNotNow(val reason: ReattestationWait, val retryAfter: Duration) : ReattestationOutcome, ReattestationChallengeOutcome

/**
 * The server refused and trying again now would not change it: [code] is the JSON `code` of the refusal
 * (`reattestation-disabled`, `reattestation-unsupported`, `session-unavailable`, `session-expired` (renew first),
 * `installation-suspended`, `challenge-invalid`, `reattestation-conflict`, `replay` twice, …) or `unexpected-answer`
 * when the answer could not be read; [status] is the HTTP status.
 */
class ReattestationRefused(val code: String, val status: Int) : ReattestationOutcome, ReattestationChallengeOutcome

/** Fixed-schema readers for the two answers (no JSON library, as [RenewedGrant.parse]); each member exactly once. */
internal object ReattestationJson {
    class Code(val value: String?)

    fun string(text: String, name: String): String? =
        Regex("\"${Regex.escape(name)}\"\\s*:\\s*\"([^\"\\\\]{1,128})\"").findAll(text).toList().singleOrNull()?.groupValues?.get(1)
            ?.takeIf { count(text, name) == 1 }

    /** A closed code (`[A-Za-z_]{1,64}`), or `null` when [nullable]; null result = absent, repeated or malformed. */
    fun code(text: String, name: String, nullable: Boolean): Code? {
        if (count(text, name) != 1) return null
        val match = Regex("\"${Regex.escape(name)}\"\\s*:\\s*(null|\"([A-Za-z_]{1,64})\")").find(text) ?: return null
        return if (match.groupValues[1] == "null") (if (nullable) Code(null) else null) else Code(match.groupValues[2])
    }

    fun bool(text: String, name: String): Boolean? {
        if (count(text, name) != 1) return null
        return Regex("\"${Regex.escape(name)}\"\\s*:\\s*(true|false)").find(text)?.groupValues?.get(1)?.toBooleanStrict()
    }

    private fun count(text: String, name: String) = Regex("\"${Regex.escape(name)}\"\\s*:").findAll(text).count()
}
