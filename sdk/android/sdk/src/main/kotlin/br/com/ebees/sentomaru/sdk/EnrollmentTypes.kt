package br.com.ebees.sentomaru.sdk

import br.com.ebees.sentomaru.core.*
import java.net.URI
import java.security.MessageDigest
import java.time.Instant
import java.util.Base64

/**
 * Immutable configuration. Public consumer endpoint only; never the private integrity API.
 * C-04b: [playIntegrityCloudProjectNumber] (Google Cloud project linked to the app in the Play Console) turns on the
 * advisory Play Integrity token at enrollment; null = off. It is not part of the installation identity.
 */
class SentomaruConfig(val organization: String, val app: String, val environment: String,
    allowedHosts: Set<String>, val enrollmentUrl: String,
    val rotationGracePeriod: java.time.Duration = java.time.Duration.ofDays(7),
    val playIntegrityCloudProjectNumber: Long? = null,
    /**
     * J-04r: the consumer's public renewal route (it forwards to the private `POST …/sessions`). With it, the SDK
     * renews the grant (10 min on the server) before it expires, signed by the installation key, without a new
     * attestation; null keeps the pre-J-04r behaviour (a long session ends in `session-expired`).
     */
    val renewalUrl: String? = null) {
    val allowedHosts: Set<String> = allowedHosts.toSet()
    init {
        require(!rotationGracePeriod.isNegative && !rotationGracePeriod.isZero) { "Invalid rotation grace period" }
        require(playIntegrityCloudProjectNumber == null || playIntegrityCloudProjectNumber > 0) { "Invalid cloud project number" }
    }
    internal val identity: String = MessageDigest.getInstance("SHA-256")
        .digest("$organization\n$app\n$environment\n$enrollmentUrl".toByteArray()).joinToString("") { "%02x".format(it) }
    init {
        val slug = Regex("[a-z0-9][a-z0-9-]{0,62}")
        require(listOf(organization, app, environment).all { slug.matches(it) }) { "Invalid scope" }
        require(this.allowedHosts.isNotEmpty()) { "Empty allowlist" }
        require(this.allowedHosts.all { it == it.lowercase() && Regex("[a-z0-9.-]+").matches(it) }) { "Invalid allowlist" }
        checkHost(enrollmentUrl)
        renewalUrl?.let(::checkHost)
        SignatureBase.build("POST", enrollmentUrl, headers(ZERO_UUID, "enroll"),
            ContentDigest.sha256(ByteArray(0)), SignatureParams(0, 1, ZERO_UUID, ZERO_UUID))
    }
    internal fun checkHost(uri: String) {
        val parsed = try { URI(uri) } catch (_: Exception) { fail(SentomaruError.InvalidRequest(SentomaruError.Reason.TARGET_URI)) }
        if (parsed.scheme != "https" || parsed.host !in allowedHosts || parsed.rawUserInfo != null)
            fail(SentomaruError.HostNotAllowed())
    }
    internal fun headers(session: String, operation: String) = linkedMapOf(
        "content-type" to Profile.CONTENT_TYPE, "x-sentomaru-profile" to Profile.TAG,
        "x-sentomaru-org" to organization, "x-sentomaru-app" to app,
        "x-sentomaru-environment" to environment, "x-sentomaru-session" to session,
        "x-sentomaru-operation" to operation)
}

class EnrollmentChallenge(val id: String, val token: String, attestationChallenge: ByteArray, val expiresAt: Instant) {
    private val attestation = attestationChallenge.copyOf()
    fun attestationChallenge(): ByteArray = attestation.copyOf()
    init {
        validateUuid(id)
        val decoded = try { Base64.getDecoder().decode(token) } catch (_: IllegalArgumentException) {
            fail(SentomaruError.InvalidRequest(SentomaruError.Reason.PARAMS))
        }
        require(decoded.size == 32 && Base64.getEncoder().encodeToString(decoded) == token && attestation.size == 32) {
            "Invalid challenge"
        }
    }
    internal fun same(other: EnrollmentChallenge) = id == other.id && token == other.token &&
        expiresAt == other.expiresAt && attestation.contentEquals(other.attestation)
}

/**
 * Only server returns hardware/attestation status; local key properties are never authorization.
 * J-04r: [issuedAt] is the local instant the SDK received the grant (stamped by the SDK, never by the app) and
 * [ttlSeconds] its server lifetime when known (a renewal says it; an enrollment grant uses [DEFAULT_TTL_SECONDS]).
 */
class EnrollmentGrant(val installationId: String, val keyId: String, val sessionId: String,
    val hardwareStatus: String, val attestationStatus: String,
    val issuedAt: java.time.Instant? = null, val ttlSeconds: Long? = null) {
    init {
        listOf(installationId, keyId, sessionId).forEach(::validateUuid)
        require(hardwareStatus in setOf("hardware", "software", "unknown") &&
            attestationStatus in setOf("verified", "untrusted", "notEvaluated")) { "Invalid grant status" }
        require(ttlSeconds == null || ttlSeconds in 1L..86_400L) { "Invalid grant lifetime" }
    }

    internal fun issued(at: java.time.Instant, ttl: Long? = ttlSeconds) =
        EnrollmentGrant(installationId, keyId, sessionId, hardwareStatus, attestationStatus, at, ttl)

    /**
     * Renewal is due when the grant's age reaches its lifetime minus the margin: [maxMargin] or a fifth of the lifetime,
     * whichever is smaller (a short lifetime still leaves most of it usable). An unknown age is always due.
     */
    internal fun renewalDue(now: java.time.Instant, maxMargin: java.time.Duration): Boolean {
        val issued = issuedAt ?: return true
        val ttl = ttlSeconds ?: DEFAULT_TTL_SECONDS
        val margin = minOf(maxMargin, java.time.Duration.ofSeconds(ttl).dividedBy(5))
        return !now.isBefore(issued.plusSeconds(ttl).minus(margin))
    }

    companion object {
        /** Server default grant lifetime (IntegrityServiceOptions.GrantTtl). */
        const val DEFAULT_TTL_SECONDS = 600L
    }
}

/** J-04r: answer of the consumer's renewal route (the private `POST …/sessions` passed through). */
class RenewedGrant(val installationId: String, val keyId: String, val sessionId: String, val ttlSeconds: Long) {
    init {
        listOf(installationId, keyId, sessionId).forEach(::validateUuid)
        require(ttlSeconds in 1L..86_400L) { "Invalid grant lifetime" } // remaining lifetime of the grant handed out
    }

    companion object {
        private fun member(name: String) = Regex("\"$name\"\\s*:\\s*\"([0-9a-f-]{36})\"")
        private val TTL = Regex("\"ttlSeconds\"\\s*:\\s*([0-9]{1,6})[,}\\s]")

        /**
         * Fixed schema (`installationId`, `keyId`, `sessionId`, `ttlSeconds`; other members ignored), each member once,
         * validated here. No JSON library: the same code runs on the JVM tests and on Android.
         */
        fun parse(text: String): RenewedGrant {
            fun invalid(): Nothing = throw SentomaruException(SentomaruError.InvalidRequest(SentomaruError.Reason.PARAMS))
            fun uuid(name: String) = member(name).findAll(text).toList().singleOrNull()?.groupValues?.get(1) ?: invalid()
            val ttl = TTL.findAll(text).toList().singleOrNull()?.groupValues?.get(1)?.toLong() ?: invalid()
            return try { RenewedGrant(uuid("installationId"), uuid("keyId"), uuid("sessionId"), ttl) }
            catch (_: IllegalArgumentException) { invalid() }
        }
    }
}

enum class InstallationState { NotEnrolled, EnrollmentRequired, Enrolled, KeyInvalidated }

/**
 * D-04b: why an [InstallationState.Enrolled] installation should enroll again with a fresh attestation
 * ([SentomaruClient.reenrollmentReason]). A separate answer, not a new [InstallationState]: the installation still signs.
 */
enum class ReenrollmentReason {
    /** The app's `versionCode` differs from the one the current key was attested with (update or downgrade). */
    APP_UPDATED
}

class KeyMaterial(publicKey: ByteArray, chain: List<ByteArray>) {
    private val key = publicKey.copyOf()
    private val certificates = chain.map { it.copyOf() }
    fun publicKey(): ByteArray = key.copyOf()
    fun chain(): List<ByteArray> = certificates.map { it.copyOf() }
}

/** Platform port: implementation owns all private-key operations; no private key leaves Keystore. */
interface InstallationKeys {
    fun exists(alias: String): Boolean
    fun generate(alias: String, challenge: ByteArray, strongBox: Boolean): KeyMaterial
    fun material(alias: String): KeyMaterial
    fun sign(alias: String, bytes: ByteArray): ByteArray
    fun delete(alias: String)
    fun deleteOwned(prefix: String)
}

class RetiredKey(val alias: String, val retiredAt: Instant, val expiresAt: Instant) {
    init {
        require(alias.isNotBlank()) { "Invalid alias" }
        require(retiredAt.isBefore(expiresAt)) { "retiredAt must be before expiresAt" }
    }
}

/**
 * [versionCode] (D-04b): the app's `versionCode` when the new key was generated (attested); null = unknown.
 * [sent] (D-04d): the frozen body was handed to `send` at least once, so the server may have committed it even when the
 * answer was lost; a rotation with a NEW challenge resends this body first (sdk-api-v1 §2.4). A custom
 * [InstallationStore] must persist it (absent = false).
 */
class PendingRotation @JvmOverloads constructor(val alias: String, val challenge: EnrollmentChallenge,
    val strongBox: Boolean, body: ByteArray, val requiresHardware: Boolean = false, val versionCode: Long? = null,
    val sent: Boolean = false) {
    private val frozenBody = body.copyOf()
    fun body(): ByteArray = frozenBody.copyOf()

    internal fun markedSent(): PendingRotation =
        if (sent) this else PendingRotation(alias, challenge, strongBox, frozenBody, requiresHardware, versionCode, true)
}

/**
 * [versionCode] (D-04b): the app's `versionCode` when the key at [alias] was generated, i.e. the one its Key Attestation
 * names; null = unknown (a record from before D-04b, or the version could not be read).
 */
class InstallationRecord @JvmOverloads constructor(val scopeIdentity: String, val alias: String, val challenge: EnrollmentChallenge,
    val strongBox: Boolean, body: ByteArray? = null, val grant: EnrollmentGrant? = null,
    val requiresHardware: Boolean = false, val generation: Long = 1L,
    retiredKeys: List<RetiredKey> = emptyList(),
    val pendingRotation: PendingRotation? = null, val versionCode: Long? = null) {
    private val frozenBody = body?.copyOf()
    val retiredKeys: List<RetiredKey> = retiredKeys.toList()
    fun body(): ByteArray? = frozenBody?.copyOf()
}

/** Writes must be atomic and durable before returning. Store contains no private-key material. */
interface InstallationStore {
    fun read(): InstallationRecord?
    fun write(record: InstallationRecord?)
}

abstract class EnrollmentError(code: String) : SentomaruError(code) {
    class NotEnrolled : EnrollmentError("NotEnrolled")
    class EnrollmentRequired : EnrollmentError("EnrollmentRequired")
    class KeyInvalidated : EnrollmentError("KeyInvalidated")
    class StrongBoxUnavailable : EnrollmentError("StrongBoxUnavailable")
    class ChallengeExpired : EnrollmentError("ChallengeExpired")
    class NetworkUnavailable : EnrollmentError("NetworkUnavailable")
    class StorageUnavailable : EnrollmentError("StorageUnavailable")
    class KeyUnavailable : EnrollmentError("KeyUnavailable")
    class Cancelled : EnrollmentError("Cancelled")
    /**
     * A renewal was not attempted: the backoff of the previous failed renewal is still running
     * ([SentomaruClient.SUSPENDED_RENEWAL_BACKOFF_STEPS] after consecutive suspensions, else
     * [SentomaruClient.RENEWAL_BACKOFF]).
     * The grant is unchanged; try again later.
     */
    class RenewalBackoff : EnrollmentError("RenewalBackoff")
    class ServerRejected(val reason: Rejection) : EnrollmentError("ServerRejected:${reason.name}")
    /**
     * D-04d (contract v1.6): `401 predecessor-invalid` — the server refused to re-enroll this installation with the
     * current key: it was quarantined, already replaced, belongs to another subject/tenant, or the proof does not verify.
     * Rotating again cannot succeed. Call [SentomaruClient.reset] and then [SentomaruClient.enroll]: that creates a NEW
     * installation (new code, no name or tags, and no suspension carried over). A `send` passed to
     * [SentomaruClient.rotate] throws it for that answer (the Flutter plugin's transport does).
     */
    class ReenrollmentRefused : EnrollmentError("ReenrollmentRefused")
    /**
     * [SUSPENDED] (contract v1.5): `403 installation-suspended` — the installation is suspended until a later instant;
     * the grant is kept and the app retries later, it does not enroll again. Appended last (ordinals unchanged).
     */
    /**
     * [CONFLICT] (D-04d): `409 enrollment-conflict` — the challenge already took another body, so the body sent was
     * never accepted. Appended last (ordinals unchanged). A `send` maps [EXPIRED] (`challenge-invalid`), [REVOKED]
     * (`enrollment-revoked`) and [CONFLICT] only from those exact server codes: they let the SDK drop a resent rotation.
     */
    enum class Rejection { EXPIRED, REVOKED, INVALID, RATE_LIMITED, UNAVAILABLE, SUSPENDED, CONFLICT }
}

internal const val ZERO_UUID = "00000000-0000-0000-0000-000000000000"
internal fun validateUuid(id: String) { SignatureParams(0, 1, id, id) }
internal fun fail(error: SentomaruError): Nothing = throw SentomaruException(error)
