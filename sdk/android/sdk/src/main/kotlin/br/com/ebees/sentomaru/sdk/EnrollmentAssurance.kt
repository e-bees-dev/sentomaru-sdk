package br.com.ebees.sentomaru.sdk

import br.com.ebees.sentomaru.core.SentomaruException
import br.com.ebees.sentomaru.core.SignedMessage
import java.security.MessageDigest
import java.util.concurrent.Executors
import java.util.concurrent.ExecutorService
import java.util.concurrent.Future
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

/**
 * Asks the app's backend for a fresh, single-use enrollment challenge for [subject]/[tenant]. Called for the first
 * enrollment, for a key rotation (D-04b) and, when the server refuses that rotation, for the reenrollment that
 * follows — every time a new call, never cached or reused by [EnrollmentAssurance] itself.
 */
typealias ChallengeProvider = (subject: String, tenant: String) -> EnrollmentChallenge

/** Same shape as the `send` parameter of [SentomaruClient.enroll]/[SentomaruClient.rotate]: signs and delivers. */
typealias GrantSender = (SignedMessage) -> EnrollmentGrant

/**
 * Why [EnrollmentAssurance] just enrolled or reenrolled this installation — no subject, tenant or other personal
 * data, safe for a log line or a metric. Ported 1:1 from the reasons the Flutter port
 * (`sentomaru_flutter`'s `SentomaruReenrollReason`, itself from an app-side principal store's `resetReason`) already named.
 */
enum class ReenrollReason {
    /** [InstallationState.NotEnrolled]: nothing to reuse. */
    STATE_NOT_ENROLLED,

    /** [InstallationState.EnrollmentRequired]: the SDK itself discarded the session (renewal exhausted or revoked). */
    STATE_ENROLLMENT_REQUIRED,

    /** [InstallationState.KeyInvalidated]: the platform invalidated the key (biometric enrollment changed, or the
     * Keystore entry was otherwise invalidated). */
    STATE_KEY_INVALIDATED,

    /** Enrolled, but no principal was found for this installation (its own store, mirror and legacy hook all
     * empty): an installation from before this contract existed, or a storage wipe. */
    PRINCIPAL_ABSENT,

    /** Enrolled with a principal on file, but it belongs to another subject or tenant. */
    PRINCIPAL_CHANGED,

    /** [SentomaruClient.rotate] was refused ([EnrollmentError.ReenrollmentRefused]): the server will not re-enroll
     * this installation with the current key, so a new installation was created instead. */
    ROTATION_REFUSED,
}

/** Outcome of [EnrollmentAssurance.ensureEnrolled]. */
class EnsureEnrolledResult(
    /** False when a later call (for a different subject/tenant) superseded this one before it finished: a stale
     * caller must not bind a session, or otherwise act as if its own call had won. */
    val current: Boolean,
    /** The session id this call obtained, when it enrolled, reenrolled or rotated the installation. Null when the
     * existing installation and session were simply reused — call [SentomaruClient.sessionId] for the one already
     * active; this class never keeps a copy of its own. */
    val sessionId: String?,
)

/** Read/write/delete of one named value. [EncryptedSharedPreferencesStore] and [PlainSharedPreferencesStore] are the
 * two real implementations [PrincipalStore] composes; a test substitutes a plain in-memory one for either. */
interface SentomaruKeyValueStore {
    fun read(key: String): String?
    fun write(key: String, value: String)
    fun delete(key: String)
}

/**
 * Where [EnrollmentAssurance] keeps the principal (sha256 of `subject\u0000tenant`) of whoever this installation is
 * enrolled for, so a later call can tell "reuse" from "someone else now" without the app storing anything of its
 * own. Ported from `sentomaru_flutter`'s `SentomaruPrincipalStore`, itself ported from an app-side principal store
 * (a discarded fix branch of that app's own repository; its idea and tests kept).
 *
 * [secure] is meant to be backed by `EncryptedSharedPreferences` (Jetpack Security Crypto): on Android that store
 * can lose its key or fail to decrypt (a partial write, a restore, a Keystore invalidation) and come back empty
 * even though the installation is still enrolled server-side — without [mirror] that empty read looked exactly
 * like "a different caller now" and reset+enrolled a brand new installation for no reason (the bug this class
 * fixes; evidence in production: 3 live installations of the same user in 2.5 h). The mirror never authorizes
 * anything by itself: [EnrollmentAssurance] only trusts it together with the SDK itself saying `Enrolled`.
 */
class PrincipalStore(private val secure: SentomaruKeyValueStore, private val mirror: SentomaruKeyValueStore) {
    fun read(): String? {
        val own = try { secure.read(KEY) } catch (_: Exception) { null }
        if (!own.isNullOrEmpty()) return own
        val backup = try { mirror.read(MIRROR_KEY) } catch (_: Exception) { null }
        if (backup.isNullOrEmpty()) return null
        try { secure.write(KEY, backup) } catch (_: Exception) { /* the mirror still answers on the next read */ }
        return backup
    }

    /** Writes the mirror first: a failure of the secure store alone must not lose the principal. */
    fun write(principal: String) {
        try { mirror.write(MIRROR_KEY, principal) } catch (_: Exception) { /* a lost mirror still leaves the secure copy */ }
        try { secure.write(KEY, principal) } catch (_: Exception) { /* the mirror alone still allows a reuse later */ }
    }

    fun delete() {
        try { mirror.delete(MIRROR_KEY) } catch (_: Exception) { /* nothing left to read either way */ }
        try { secure.delete(KEY) } catch (_: Exception) { /* nothing left to read either way */ }
    }

    companion object {
        const val KEY = "sentomaru_enrollment_principal"
        const val MIRROR_KEY = "sentomaru_enrollment_principal_mirror"
    }
}

/**
 * High-level, portable "ensure this device is correctly enrolled" contract: decides on its own whether to reuse
 * the current installation, rotate it after an app update ([SentomaruClient.reenrollmentReason], D-04b/D-04d, same
 * installation on the server) or reenroll from scratch, so no app has to reimplement this logic. Ported from
 * `sentomaru_service.dart`/`sentomaru_app_update.dart` of a first consumer app (11/11/2026 project decision: that
 * logic moves into the SDKs) through its own `sentomaru_flutter` port, adapted to this SDK's blocking, no-coroutine idiom: a
 * single background thread (started lazily, [close] stops it) carries the app-update rotation check so
 * [ensureEnrolled] can give up waiting on it after [appUpdateTimeoutMs] without losing the attempt; everything else
 * runs on the caller's own thread, same as [SentomaruClient] itself ("blocking worker-thread API").
 *
 * One instance per [SentomaruClient] (construct once, reuse — it carries its own lock and storage). Concurrent
 * calls serialize on the instance lock, and the most recent subject/tenant wins over one still queued for an older
 * caller (a login followed immediately by a tenant switch never enrolls the old tenant over the new one).
 * [forgetInstallation] joins the same lock.
 */
class EnrollmentAssurance @JvmOverloads constructor(
    private val client: SentomaruClient,
    private val principalStore: PrincipalStore,
    /** Ceiling for the app-update rotation check (D-04b: `reenrollmentReason` + a fresh challenge + `rotate`). Past
     * it [ensureEnrolled] returns as if nothing needed rotating — the current key keeps signing — while the
     * attempt keeps running on the background thread; a later [forgetInstallation] or a reenrollment for another
     * caller still waits for it ([settleTimeoutMs]) instead of racing a `reset()` against it. */
    private val appUpdateTimeoutMs: Long = 15_000,
    /** Ceiling to wait for a rotation that outlived [appUpdateTimeoutMs] before this class will touch `reset()`
     * for a different reason. [forgetInstallation] resets anyway past this ceiling (the installation is being
     * revoked; the recovery path must not get stuck); a reenrollment for a different subject/tenant instead
     * throws [TimeoutException], and a later call tries again. */
    private val settleTimeoutMs: Long = 30_000,
    /** Consulted at most once per installation, only when this class's own storage (secure store + mirror) has
     * nothing AND the SDK itself says `Enrolled`: an app migrating from its own, app-level principal tracking
     * supplies its OLD stored value here, so upgrading to this class does not force a one-time reenrollment of
     * every existing installation. A match is copied into this class's own storage right away; a non-match (or
     * `null`, the default) is never consulted again for this installation. */
    private val legacyPrincipal: (() -> String?)? = null,
) {
    private val lock = Object()
    @Volatile private var latestPrincipal: String? = null
    @Volatile private var rotationInFlight: Future<RotateOutcome>? = null
    private val executor: ExecutorService =
        Executors.newSingleThreadExecutor { r -> Thread(r, "sentomaru-enrollment-assurance").apply { isDaemon = true } }

    /** Fires every time a call decided to enroll or reenroll rather than reuse the installation — never for a
     * plain reuse, and never with subject, tenant or any other personal data (see [ReenrollReason]). Set before
     * the first [ensureEnrolled] call; this class never calls it concurrently with itself. */
    var onReenrollReason: ((ReenrollReason) -> Unit)? = null

    /**
     * Ensures [subject]/[tenant] is enrolled on this device: reuses the installation when it already is for the
     * same caller (rotating its key in place after an app update), or reenrolls from scratch (`reset` + `enroll`)
     * otherwise. [challengeProvider] is asked for a fresh, single-use challenge every time one is actually needed;
     * [grantSender] is the same `send` the raw [SentomaruClient.enroll]/[SentomaruClient.rotate] already take.
     *
     * Blocks the calling thread for as long as the network calls it makes take (minus the app-update rotation
     * check, bounded by [appUpdateTimeoutMs]): call it off the main thread, same as every other [SentomaruClient]
     * operation.
     */
    fun ensureEnrolled(
        subject: String,
        tenant: String,
        challengeProvider: ChallengeProvider,
        grantSender: GrantSender,
    ): EnsureEnrolledResult {
        val principal = principalOf(subject, tenant)
        latestPrincipal = principal
        synchronized(lock) {
            // The most recent wins: a call that waited for the lock behind an older one for a different caller
            // never enrolls that one over the caller that arrived after it.
            if (latestPrincipal != principal) return EnsureEnrolledResult(current = false, sessionId = null)
            val sessionId = ensureEnrolledLocked(principal, subject, tenant, challengeProvider, grantSender)
            return EnsureEnrolledResult(current = latestPrincipal == principal, sessionId = sessionId)
        }
    }

    private fun ensureEnrolledLocked(
        principal: String,
        subject: String,
        tenant: String,
        challengeProvider: ChallengeProvider,
        grantSender: GrantSender,
    ): String? {
        val state = client.state()
        val stored = storedPrincipal(state)
        if (state == InstallationState.Enrolled && stored == principal) {
            return rotateIfUpdated(subject, tenant, challengeProvider, grantSender)
        }
        onReenrollReason?.invoke(reasonFor(state, stored))
        // A rotation that outlived appUpdateTimeoutMs may still be running on the background thread: never reset
        // while it is. Throws TimeoutException unguarded (unlike forgetInstallation): this call fails, nothing
        // erased, and a later ensureEnrolled call tries again.
        if (state != InstallationState.NotEnrolled) settle()
        // Challenge before reset: a network failure or a 5xx here must not erase an installation that still works.
        val challenge = challengeProvider(subject, tenant)
        if (state != InstallationState.NotEnrolled) client.reset()
        val grant = client.enroll(challenge, send = grantSender)
        principalStore.write(principal)
        return grant.sessionId
    }

    /** Null when nothing needed rotating and [SentomaruClient.sessionId] already has what the caller needs; the id
     * this call itself obtained otherwise (a D-04b rotation, or the reenrollment a refused rotation falls back
     * to). */
    private fun rotateIfUpdated(
        subject: String,
        tenant: String,
        challengeProvider: ChallengeProvider,
        grantSender: GrantSender,
    ): String? {
        client.reenrollmentReason() ?: return null
        val attempt = executor.submit<RotateOutcome> { attemptRotate(subject, tenant, challengeProvider, grantSender) }
        rotationInFlight = attempt
        val outcome = try {
            attempt.get(appUpdateTimeoutMs, TimeUnit.MILLISECONDS)
        } catch (_: TimeoutException) {
            // The background thread keeps running whatever it was doing; nothing here was erased, and nothing
            // here needs to remember the result — SentomaruClient.sessionId() will already reflect it once it
            // finishes.
            return null
        } catch (_: Exception) {
            // Any other failure of the update check itself: the current key keeps signing, this call does not
            // fail for it.
            return null
        }
        if (!outcome.refused) return outcome.grant?.sessionId
        // Refused: a fresh challenge before reset (same invariant as the normal reenrollment path), and from here
        // on NOT swallowed — the installation is already being replaced, a failure now must reach the caller.
        onReenrollReason?.invoke(ReenrollReason.ROTATION_REFUSED)
        val challenge = try {
            challengeProvider(subject, tenant)
        } catch (_: Exception) {
            return null // the current key keeps signing; this call simply has nothing new to replace it with
        }
        client.reset()
        val grant = client.enroll(challenge, send = grantSender)
        principalStore.write(principalOf(subject, tenant))
        return grant.sessionId
    }

    private fun attemptRotate(
        subject: String,
        tenant: String,
        challengeProvider: ChallengeProvider,
        grantSender: GrantSender,
    ): RotateOutcome {
        val challenge = challengeProvider(subject, tenant)
        return try {
            RotateOutcome(client.rotate(challenge, send = grantSender), refused = false)
        } catch (e: SentomaruException) {
            if (e.error !is EnrollmentError.ReenrollmentRefused) throw e
            RotateOutcome(null, refused = true)
        }
    }

    private class RotateOutcome(val grant: EnrollmentGrant?, val refused: Boolean)

    /**
     * Forgets this installation (revoked server-side, or the app's own sign-out-everywhere): the next
     * [ensureEnrolled] enrolls from scratch, with a fresh attestation. Joins the same lock as [ensureEnrolled]:
     * never races a reset against one still finishing, and never erases an installation a newer call just made.
     * Waits for a rotation in flight up to [settleTimeoutMs], then resets anyway past it — the installation is
     * being revoked, the key no longer matters, and this recovery path must not get stuck.
     */
    fun forgetInstallation() {
        synchronized(lock) {
            try {
                settle()
            } catch (_: TimeoutException) {
                // Revoked either way; proceed.
            }
            client.reset()
            principalStore.delete()
        }
    }

    /** Releases the background thread. Call when this class's owner is disposed (same lifetime as its [client]). */
    fun close() {
        executor.shutdown()
    }

    private fun settle() {
        val future = rotationInFlight ?: return
        try {
            future.get(settleTimeoutMs, TimeUnit.MILLISECONDS)
        } catch (e: TimeoutException) {
            throw e
        } catch (_: Exception) {
            // Finished, just not successfully; irrelevant to settling (only completion matters here).
        }
    }

    private fun storedPrincipal(state: InstallationState): String? {
        val own = principalStore.read()
        if (own != null || legacyPrincipal == null) return own
        if (state != InstallationState.Enrolled) return null // nothing to migrate into if this call reenrolls anyway
        val legacy = legacyPrincipal.invoke()
        if (legacy.isNullOrEmpty()) return null
        principalStore.write(legacy) // consulted at most once for this installation, match or not
        return legacy
    }

    private fun reasonFor(state: InstallationState, stored: String?): ReenrollReason = when (state) {
        InstallationState.NotEnrolled -> ReenrollReason.STATE_NOT_ENROLLED
        InstallationState.EnrollmentRequired -> ReenrollReason.STATE_ENROLLMENT_REQUIRED
        InstallationState.KeyInvalidated -> ReenrollReason.STATE_KEY_INVALIDATED
        InstallationState.Enrolled -> if (stored == null) ReenrollReason.PRINCIPAL_ABSENT else ReenrollReason.PRINCIPAL_CHANGED
    }

    companion object {
        /** sha256 of `subject\u0000tenant`: the same hash [ensureEnrolled] compares against this installation's
         * stored principal. Exposed so a caller can compare without calling [ensureEnrolled] itself. Same hex
         * encoding as [SentomaruConfig.identity]. */
        @JvmStatic
        fun principalOf(subject: String, tenant: String): String =
            MessageDigest.getInstance("SHA-256").digest("$subject\u0000$tenant".toByteArray(Charsets.UTF_8))
                .joinToString("") { "%02x".format(it) }
    }
}
