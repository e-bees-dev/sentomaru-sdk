package br.com.ebees.sentomaru.sdk

import br.com.ebees.sentomaru.core.*
import java.io.IOException
import java.time.Clock
import java.util.Base64
import java.util.UUID

/**
 * Blocking worker-thread API, no Activity/biometric dependency. One instance per scope/store.
 * All lifecycle operations serialize on this instance. Public consumer transport is injected;
 * HTTP redirect/retry handling belongs to Task 3, private envelope construction to the consumer.
 *
 * D-04b: `@JvmOverloads` keeps the Java constructors that existed before [appVersionCode] was appended.
 */
class SentomaruClient @JvmOverloads constructor(val config: SentomaruConfig, internal val keys: InstallationKeys,
    private val store: InstallationStore, private val clock: Clock = Clock.systemUTC(),
    private val integrity: IntegrityTokenSource? = null, private val packageName: String? = null,
    /**
     * D-04b: the `versionCode` of the app running now ([SentomaruClient.initialize] reads it from the PackageManager);
     * null = unknown, and [reenrollmentReason] never answers [ReenrollmentReason.APP_UPDATED]. Zero or negative counts
     * as unknown.
     */
    appVersionCode: Long? = null) {
    private val appVersionCode: Long? = appVersionCode?.takeIf { it > 0 }
    private var lifecycleGeneration = 0L
    private var renewalFailedAt: java.time.Instant? = null
    /** [SentomaruError.code] of the last failed renewal (set and cleared with [renewalFailedAt]); null if it had none. */
    private var renewalFailureCode: String? = null
    /**
     * Backoff started by the last failed renewal: a step of [SUSPENDED_RENEWAL_BACKOFF_STEPS] after a suspension,
     * else [RENEWAL_BACKOFF].
     */
    private var renewalBackoff: java.time.Duration = RENEWAL_BACKOFF
    /** Consecutive SUSPENDED failures (picks the step); any other outcome, success or [reset] sets it back to 0. */
    private var suspendedFailures = 0

    /**
     * D-07d: the hosts `sentomaru protect` pinned in this app (meta-data `br.com.ebees.sentomaru.pinning.hosts`), read
     * once by [initialize]; empty when the app has no such meta-data, the value is malformed, or the client was built
     * directly. Only host names (no subdomain flag, no pin). Used by the SDK's transport for the local `pin_failure`
     * event; it changes nothing else.
     */
    val pinnedHosts: Set<String> get() = pinnedHostSet.hosts
    @Volatile internal var pinnedHostSet: br.com.ebees.sentomaru.sdk.transport.PinnedHosts =
        br.com.ebees.sentomaru.sdk.transport.PinnedHosts.NONE

    @Synchronized fun state(): InstallationState {
        val record = record() ?: return InstallationState.NotEnrolled
        if (record.body() != null && !keys.exists(record.alias)) return InstallationState.KeyInvalidated
        return if (record.grant == null) InstallationState.EnrollmentRequired else InstallationState.Enrolled
    }

    @Synchronized fun retiredKeys(): List<RetiredKey> = record()?.retiredKeys ?: emptyList()

    /**
     * D-04b: why this [InstallationState.Enrolled] installation should enroll again with a fresh attestation, or null.
     * [ReenrollmentReason.APP_UPDATED] when the `versionCode` the current key was attested with
     * ([InstallationRecord.versionCode]) differs from the running app's (an update or a downgrade): the server keeps the
     * build evidence of the enrollment (D-04a) until the app enrolls again. The state stays `Enrolled` and signing keeps
     * working (the SDK cannot fetch a challenge on its own); the app gets a challenge from its backend and calls [rotate]
     * (keeps signing with the current key meanwhile) or [reset] + [enroll]. A record from before D-04b (no stored
     * `versionCode`) or an unknown running version never asks; the next enrollment or rotation stores the version.
     * One read of the record (the same rules as [state] for `Enrolled`).
     */
    @Synchronized fun reenrollmentReason(): ReenrollmentReason? {
        val record = record() ?: return null
        if (record.grant == null || (record.body() != null && !keys.exists(record.alias))) return null // not Enrolled
        val enrolledWith = record.versionCode ?: return null
        val running = appVersionCode ?: return null
        return if (enrolledWith != running) ReenrollmentReason.APP_UPDATED else null
    }

    /**
     * Retry preserves key/challenge/body. Never silently rotates or clears an invalidated installation.
     * C-04b review F1: the advisory Play Integrity token is fetched BEFORE taking the client lock (only when a new body
     * will be built), so a slow Google call never stalls signing on this client.
     */
    fun enroll(challenge: EnrollmentChallenge, strongBox: Boolean = false,
        requiresHardware: Boolean = false, send: (SignedMessage) -> EnrollmentGrant): EnrollmentGrant {
        val token = prefetch(challenge) { needsEnrollmentBody(challenge, strongBox, requiresHardware) }
        return enrollLocked(challenge, strongBox, requiresHardware, token, send)
    }

    @Synchronized private fun needsEnrollmentBody(challenge: EnrollmentChallenge, strongBox: Boolean, requiresHardware: Boolean): Boolean {
        if (state() == InstallationState.KeyInvalidated) return false // fails anyway: never spend a Google call
        val pending = record() ?: return true
        return pending.grant == null && pending.body() == null && pending.challenge.same(challenge) &&
            pending.strongBox == strongBox && pending.requiresHardware == requiresHardware
    }

    @Synchronized private fun enrollLocked(challenge: EnrollmentChallenge, strongBox: Boolean,
        requiresHardware: Boolean, integrityToken: String?, send: (SignedMessage) -> EnrollmentGrant): EnrollmentGrant {
        interrupted()
        val generation = lifecycleGeneration
        var pending = record()
        if (state() == InstallationState.KeyInvalidated) fail(EnrollmentError.KeyInvalidated())
        if (pending != null) {
            if (!pending.challenge.same(challenge) || pending.strongBox != strongBox || pending.requiresHardware != requiresHardware)
                fail(EnrollmentError.EnrollmentRequired())
            pending.grant?.let { return it }
        }
        if (!clock.instant().isBefore(challenge.expiresAt)) fail(EnrollmentError.ChallengeExpired())
        if (pending == null) {
            val alias = "sentomaru.v1.${config.identity}.v1.${UUID.randomUUID()}"
            pending = InstallationRecord(config.identity, alias, challenge, strongBox,
                requiresHardware = requiresHardware, generation = 1L, versionCode = appVersionCode)
            store.write(pending) // persist ownership before generation, recoverable after process death
        }
        var body = pending.body()
        if (body == null) {
            // D-04b: the attestation names the versionCode of the app that generated the key.
            val existing = keys.exists(pending.alias)
            val attestedVersion = if (existing) pending.versionCode else appVersionCode
            val material = try {
                if (existing) keys.material(pending.alias)
                else keys.generate(pending.alias, challenge.attestationChallenge(), strongBox)
            } catch (e: SentomaruException) {
                if (e.error is EnrollmentError.StrongBoxUnavailable) {
                    keys.delete(pending.alias)
                    store.write(null)
                }
                throw e
            }
            body = EnrollmentBody.encode(challenge.token, material, requiresHardware, config, integrityToken)
            pending = InstallationRecord(config.identity, pending.alias, challenge, strongBox, body, requiresHardware = requiresHardware,
                generation = pending.generation, retiredKeys = pending.retiredKeys, pendingRotation = pending.pendingRotation,
                versionCode = attestedVersion)
            store.write(pending) // exact frozen bytes durable before first network side effect
        }
        interrupted()
        val request = FrozenRequest("POST", config.enrollmentUrl, config.headers(challenge.id, "enroll"), body)
        val signed = MessageSigner.sign(request, SignatureParams.now(clock, challenge.id, UUID.randomUUID().toString())) {
            keys.sign(pending.alias, it)
        }
        interrupted()
        if (generation != lifecycleGeneration) fail(EnrollmentError.Cancelled())
        val grant = try { send(signed) }
        catch (_: IOException) { fail(EnrollmentError.NetworkUnavailable()) }
        catch (_: InterruptedException) { Thread.currentThread().interrupt(); fail(EnrollmentError.Cancelled()) }
        interrupted() // if cancelled after server effect, pending bytes remain for idempotent recovery
        if (generation != lifecycleGeneration) fail(EnrollmentError.Cancelled())
        if (grant.keyId != challenge.id) fail(SentomaruError.InvalidRequest(SentomaruError.Reason.PARAMS))
        val issued = grant.issued(clock.instant()) // J-04r: the renewal schedule starts at receipt
        store.write(InstallationRecord(config.identity, pending.alias, challenge, strongBox, body, issued, requiresHardware,
            pending.generation, pending.retiredKeys, pending.pendingRotation, pending.versionCode))
        return issued
    }

    /**
     * Explicit key rotation with coexistence window (E-rot). Replaces active key while retaining old key for grace period.
     * C-04b review F1: the Play Integrity token is fetched outside the lock, as in [enroll]: the app keeps signing with
     * the current key while Google answers.
     */
    fun rotate(challenge: EnrollmentChallenge, strongBox: Boolean = false,
        requiresHardware: Boolean = false, send: (SignedMessage) -> EnrollmentGrant): EnrollmentGrant {
        val token = prefetch(challenge) { needsRotationBody(challenge, strongBox, requiresHardware) }
        return rotateLocked(challenge, strongBox, requiresHardware, token, send)
    }

    @Synchronized private fun needsRotationBody(challenge: EnrollmentChallenge, strongBox: Boolean, requiresHardware: Boolean): Boolean {
        if (state() != InstallationState.Enrolled) return false
        val pending = record()?.pendingRotation ?: return true
        return staleRotation(pending, challenge, strongBox, requiresHardware)
    }

    /**
     * A frozen rotation that must not be resent: other challenge or key options. D-04b: with the SAME challenge it is
     * always resent, even when another `versionCode` froze it: the server refuses another body for a consumed challenge
     * (409 `enrollment-conflict`) and answers an identical replay with the original grant, so the resend recovers a lost
     * grant (the record keeps the old version and [reenrollmentReason] keeps asking). A NEW challenge drops it and a
     * fresh key and attestation store the running version: the app asks for a new challenge every time.
     */
    private fun staleRotation(pending: PendingRotation, challenge: EnrollmentChallenge, strongBox: Boolean,
        requiresHardware: Boolean): Boolean =
        !pending.challenge.same(challenge) || pending.strongBox != strongBox || pending.requiresHardware != requiresHardware

    @Synchronized private fun rotateLocked(challenge: EnrollmentChallenge, strongBox: Boolean,
        requiresHardware: Boolean, integrityToken: String?, send: (SignedMessage) -> EnrollmentGrant): EnrollmentGrant {
        interrupted()
        val generation = lifecycleGeneration
        val current = record()
        when (state()) {
            InstallationState.NotEnrolled -> fail(EnrollmentError.NotEnrolled())
            InstallationState.EnrollmentRequired -> fail(EnrollmentError.EnrollmentRequired())
            InstallationState.KeyInvalidated -> fail(EnrollmentError.KeyInvalidated())
            InstallationState.Enrolled -> Unit
        }
        val currentRecord = current!!
        if (!clock.instant().isBefore(challenge.expiresAt)) fail(EnrollmentError.ChallengeExpired())
        var pending = currentRecord.pendingRotation
        if (pending != null && staleRotation(pending, challenge, strongBox, requiresHardware)) {
            // D-04d: a body already handed to `send` may be committed with its answer lost. Its identical replay gets
            // the original grant even with its challenge expired; adopt it instead of rotating again (the old
            // installation is superseded and could not prove a second rotation).
            if (pending.sent) recoverSentRotation(currentRecord, pending, generation, send)?.let { return it }
            keys.delete(pending.alias)
            pending = null
        }
        if (pending == null) {
            val nextGen = currentRecord.generation + 1
            val newAlias = "sentomaru.v1.${config.identity}.v$nextGen.${UUID.randomUUID()}"
            val material = try {
                keys.generate(newAlias, challenge.attestationChallenge(), strongBox)
                    // D-04d: proven with the current key, the server re-enrolls this installation (contract v1.6).
                    .let { keys.rotationMaterial(config, currentRecord, challenge, newAlias, it) }
            } catch (e: SentomaruException) {
                if (e.error is EnrollmentError.StrongBoxUnavailable) {
                    keys.delete(newAlias)
                }
                throw e
            }
            val body = EnrollmentBody.encode(challenge.token, material, requiresHardware, config, integrityToken)
            pending = PendingRotation(newAlias, challenge, strongBox, body, requiresHardware, appVersionCode)
        }
        return sendRotation(currentRecord, pending, generation, send)
    }

    /**
     * D-04d: resends a stale pending rotation that was already sent. 200 → its grant (adopted). A refusal proving the
     * body was not accepted ([EnrollmentError.ServerRejected] EXPIRED, REVOKED or CONFLICT) → null: the caller drops
     * it and rotates with the new challenge. [EnrollmentError.ReenrollmentRefused] drops it and is thrown (rotating again
     * cannot succeed). Anything else (INVALID, network, unavailable, rate limited, cancelled) keeps it and is thrown.
     */
    private fun recoverSentRotation(current: InstallationRecord, pending: PendingRotation, generation: Long,
        send: (SignedMessage) -> EnrollmentGrant): EnrollmentGrant? = try {
        sendRotation(current, pending, generation, send)
    } catch (e: SentomaruException) {
        when (val error = e.error) {
            is EnrollmentError.ServerRejected -> if (error.reason !in NEVER_ACCEPTED) throw e
            is EnrollmentError.ReenrollmentRefused -> { dropPending(current, pending); throw e }
            else -> throw e
        }
        null
    }

    private fun dropPending(current: InstallationRecord, pending: PendingRotation) {
        keys.delete(pending.alias)
        store.write(InstallationRecord(current.scopeIdentity, current.alias, current.challenge, current.strongBox,
            current.body(), current.grant, current.requiresHardware, current.generation, current.retiredKeys, null,
            current.versionCode))
    }

    /**
     * Persists [frozen], signs it, marks it sent (persisted BEFORE `send`: the answer can be lost after the server
     * committed), sends it and adopts the grant.
     */
    private fun sendRotation(current: InstallationRecord, frozen: PendingRotation, generation: Long,
        send: (SignedMessage) -> EnrollmentGrant): EnrollmentGrant {
        fun persist(rotation: PendingRotation) = store.write(InstallationRecord(current.scopeIdentity, current.alias,
            current.challenge, current.strongBox, current.body(), current.grant, current.requiresHardware,
            current.generation, current.retiredKeys, rotation, current.versionCode))
        if (current.pendingRotation !== frozen) persist(frozen)
        val challenge = frozen.challenge
        interrupted()
        val request = FrozenRequest("POST", config.enrollmentUrl, config.headers(challenge.id, "enroll"), frozen.body())
        val signed = MessageSigner.sign(request, SignatureParams.now(clock, challenge.id, UUID.randomUUID().toString())) {
            keys.sign(frozen.alias, it)
        }
        interrupted()
        if (generation != lifecycleGeneration) fail(EnrollmentError.Cancelled())
        val pending = frozen.markedSent()
        if (pending !== frozen) persist(pending)
        val grant = try { send(signed) }
        catch (_: IOException) { fail(EnrollmentError.NetworkUnavailable()) }
        catch (_: InterruptedException) { Thread.currentThread().interrupt(); fail(EnrollmentError.Cancelled()) }
        interrupted()
        if (generation != lifecycleGeneration) fail(EnrollmentError.Cancelled())
        if (grant.keyId != challenge.id) fail(SentomaruError.InvalidRequest(SentomaruError.Reason.PARAMS))
        val retiredAt = clock.instant()
        val expiresAt = retiredAt.plus(config.rotationGracePeriod)
        val newRetired = current.retiredKeys + RetiredKey(current.alias, retiredAt, expiresAt)
        val issued = grant.issued(retiredAt)
        val rotatedRecord = InstallationRecord(config.identity, pending.alias, challenge, pending.strongBox,
            pending.body(), issued, pending.requiresHardware, current.generation + 1, newRetired, null, pending.versionCode)
        store.write(rotatedRecord)
        pruneExpiredRetiredKeys(rotatedRecord)
        return issued
    }

    /** Caller passes final frozen bytes. Scope and session are checked before private-key use. */
    @Synchronized fun signRequest(frozen: FrozenRequest): SignedMessage {
        interrupted()
        config.checkHost(frozen.targetUri)
        when (state()) {
            InstallationState.NotEnrolled -> fail(EnrollmentError.NotEnrolled())
            InstallationState.EnrollmentRequired -> fail(EnrollmentError.EnrollmentRequired())
            InstallationState.KeyInvalidated -> fail(EnrollmentError.KeyInvalidated())
            InstallationState.Enrolled -> Unit
        }
        val record = record()!!
        val grant = record.grant!!
        val expected = config.headers(grant.sessionId, frozen.headers["x-sentomaru-operation"] ?: "")
        if (expected.any { frozen.headers[it.key] != it.value })
            fail(SentomaruError.InvalidRequest(SentomaruError.Reason.HEADER_VALUE))
        val signed = MessageSigner.sign(frozen, SignatureParams.now(clock, grant.keyId, UUID.randomUUID().toString())) {
            keys.sign(record.alias, it)
        }
        interrupted()
        return signed
    }

    @Synchronized fun sessionId(): String? = record()?.grant?.sessionId

    /** D-25: the Keystore alias of the enrolled installation key, or null; the transaction key lives under `<alias>.tx`. */
    @Synchronized internal fun installationAlias(): String? = record()?.takeIf { it.grant != null }?.alias

    /**
     * D-26c: signs [bytes] with the installation key and returns ASN.1 DER (the form the server verifies). Only the
     * offline chain uses it, with bytes that start with the `SMOFF1` domain tag, so it is never a valid request signature.
     */
    @Synchronized internal fun signInstallationDer(bytes: ByteArray): ByteArray {
        interrupted()
        when (state()) {
            InstallationState.NotEnrolled -> fail(EnrollmentError.NotEnrolled())
            InstallationState.EnrollmentRequired -> fail(EnrollmentError.EnrollmentRequired())
            InstallationState.KeyInvalidated -> fail(EnrollmentError.KeyInvalidated())
            InstallationState.Enrolled -> Unit
        }
        return br.com.ebees.sentomaru.signer.EcdsaSignatureFormat.p1363ToDer(keys.sign(record()!!.alias, bytes))
    }

    /** D-12c: the installation id of the current grant (the reattestation answer must name it), or null. */
    @Synchronized internal fun installationId(): String? = record()?.grant?.installationId

    /**
     * J-04r: whether [renew] should run before the next signature: a renewal URL is configured, the installation is
     * enrolled and its grant is within [RENEWAL_MARGIN] of its lifetime (or of unknown age, a record from before
     * J-04r). After a failed renewal it answers false for [RENEWAL_BACKOFF] (5 s, then 15 s, then 60 s after
     * consecutive suspensions, [SUSPENDED_RENEWAL_BACKOFF_STEPS]), so a dead route is not hammered.
     */
    @Synchronized fun needsRenewal(): Boolean =
        canRenewNow() && record()!!.grant!!.renewalDue(clock.instant(), RENEWAL_MARGIN)

    /**
     * J-04r: a renewal may be attempted now: a renewal URL is configured, the installation is enrolled and no renewal
     * failed in the last [RENEWAL_BACKOFF] (the reactive path on `session-expired` respects it too).
     */
    @Synchronized fun canRenewNow(): Boolean = renewable() && !backoffRunning()

    /**
     * Whether a renewal is possible except for the backoff of the last failed renewal, which is still running:
     * a step of [SUSPENDED_RENEWAL_BACKOFF_STEPS] (5 s, 15 s, 60 s) after consecutive
     * [EnrollmentError.Rejection.SUSPENDED] failures (a released installation recovers on the next try), else
     * [RENEWAL_BACKOFF]. False without a renewal URL or when not enrolled (that is "cannot renew", not "wait"), so a
     * caller can tell [EnrollmentError.RenewalBackoff] apart from `InvalidRequest:PARAMS`.
     */
    @Synchronized fun renewalBackingOff(): Boolean = renewable() && backoffRunning()

    /**
     * [SentomaruError.code] of the renewal failure that started the running backoff (e.g. `ServerRejected:SUSPENDED`,
     * `NetworkUnavailable`), only while [renewalBackingOff] is true; null otherwise or when the failure had no
     * [SentomaruError] (an unexpected exception from `send`). Lets a caller refused with [EnrollmentError.RenewalBackoff]
     * tell a suspension apart from a transient failure even when the failed renewal was the silent one of [renewIfDue].
     */
    @Synchronized fun lastRenewalFailure(): String? = renewalGate().lastFailure

    /**
     * One consistent snapshot of the renewal gate, read under the client lock with a single clock read: a renewal on
     * another thread cannot land between [RenewalGate.backingOff], [RenewalGate.canRenewNow] and
     * [RenewalGate.lastFailure] (separate calls could pair the decision of one failure with the code of another).
     */
    @Synchronized fun renewalGate(): RenewalGate {
        val renewable = renewable()
        val running = backoffRunning()
        val backingOff = renewable && running
        return RenewalGate(backingOff, renewable && !running, if (backingOff) renewalFailureCode else null)
    }

    /**
     * Snapshot from [renewalGate]: [backingOff] = [renewalBackingOff], [canRenewNow] = [canRenewNow], [lastFailure] =
     * [lastRenewalFailure], all from the same instant.
     */
    class RenewalGate(val backingOff: Boolean, val canRenewNow: Boolean, val lastFailure: String?)

    private fun renewable() = config.renewalUrl != null && state() == InstallationState.Enrolled

    private fun backoffRunning(): Boolean {
        val failed = renewalFailedAt ?: return false
        return clock.instant().isBefore(failed.plus(renewalBackoff))
    }

    private fun renewalFailed(at: java.time.Instant, error: SentomaruError? = null) {
        renewalFailedAt = at
        renewalFailureCode = error?.code
        if ((error as? EnrollmentError.ServerRejected)?.reason == EnrollmentError.Rejection.SUSPENDED) {
            renewalBackoff = SUSPENDED_RENEWAL_BACKOFF_STEPS[minOf(suspendedFailures, SUSPENDED_RENEWAL_BACKOFF_STEPS.size - 1)]
            suspendedFailures++
        } else {
            renewalBackoff = RENEWAL_BACKOFF
            suspendedFailures = 0
        }
    }

    /** No backoff and back to the first suspension step: success, [reset], grant dropped (enroll again). */
    private fun clearRenewalBackoff() {
        renewalFailedAt = null
        renewalFailureCode = null
        renewalBackoff = RENEWAL_BACKOFF
        suspendedFailures = 0
    }

    /**
     * J-04r: [renew] only when [needsRenewal] still holds under the client lock, so threads that saw a due grant at
     * the same time renew once (the others read the grant the first one stored). Null when nothing was due.
     */
    @Synchronized fun renewIfDue(send: (SignedMessage) -> RenewedGrant): EnrollmentGrant? =
        if (needsRenewal()) renew(send) else null

    /** J-04r: the next [needsRenewal] answers true (the server said `session-expired`): the grant is stale. */
    @Synchronized fun markGrantStale() {
        val current = record() ?: return
        val grant = current.grant ?: return
        store.write(InstallationRecord(current.scopeIdentity, current.alias, current.challenge, current.strongBox,
            current.body(), EnrollmentGrant(grant.installationId, grant.keyId, grant.sessionId, grant.hardwareStatus,
                grant.attestationStatus), current.requiresHardware, current.generation, current.retiredKeys,
            current.pendingRotation, current.versionCode))
    }

    /**
     * J-04r: renews the grant with a request signed by the installation key over the current (expired or live) grant:
     * `POST` [SentomaruConfig.renewalUrl], operation `session_renew`, body `{}`. [send] delivers it to the consumer and
     * returns its answer. The new grant replaces the old one atomically (the server leaves the old one valid until it
     * expires, and a retry of the same renewal gets the same new grant). A failure keeps the current grant (the caller's
     * request still goes out with it) and starts [RENEWAL_BACKOFF] ([SUSPENDED_RENEWAL_BACKOFF] for
     * [EnrollmentError.Rejection.SUSPENDED]); [EnrollmentError.EnrollmentRequired] from [send]
     * (the server answered session-unavailable: revoked installation, stale epoch, chain ceiling, hardware) drops the
     * grant, so [state] is [InstallationState.EnrollmentRequired] and the app enrolls again ([reset], then [enroll]).
     * The client lock is held during [send]: signing on this client waits for the renewal (one renewal at a time).
     */
    @Synchronized fun renew(send: (SignedMessage) -> RenewedGrant): EnrollmentGrant {
        interrupted()
        val url = config.renewalUrl ?: fail(SentomaruError.InvalidRequest(SentomaruError.Reason.PARAMS))
        when (state()) {
            InstallationState.NotEnrolled -> fail(EnrollmentError.NotEnrolled())
            InstallationState.EnrollmentRequired -> fail(EnrollmentError.EnrollmentRequired())
            InstallationState.KeyInvalidated -> fail(EnrollmentError.KeyInvalidated())
            InstallationState.Enrolled -> Unit
        }
        val current = record()!!
        val grant = current.grant!!
        val generation = lifecycleGeneration
        val request = FrozenRequest("POST", url, config.headers(grant.sessionId, RENEW_OPERATION), RENEW_BODY.copyOf())
        val signed = MessageSigner.sign(request, SignatureParams.now(clock, grant.keyId, UUID.randomUUID().toString())) {
            keys.sign(current.alias, it)
        }
        val sentAt = clock.instant() // conservative: the server's lifetime starts after this
        val renewed = try { send(signed) }
        catch (e: IOException) {
            val error = EnrollmentError.NetworkUnavailable()
            renewalFailed(sentAt, error)
            fail(error)
        }
        catch (e: InterruptedException) { Thread.currentThread().interrupt(); fail(EnrollmentError.Cancelled()) }
        catch (e: SentomaruException) {
            if (e.error is EnrollmentError.EnrollmentRequired) { // the chain is over: enroll again (no backoff left)
                clearRenewalBackoff()
                store.write(InstallationRecord(current.scopeIdentity, current.alias, current.challenge, current.strongBox,
                    current.body(), null, current.requiresHardware, current.generation, current.retiredKeys,
                    current.pendingRotation, current.versionCode))
            } else renewalFailed(sentAt, e.error)
            throw e
        }
        catch (e: Exception) { renewalFailed(sentAt); throw e }
        if (generation != lifecycleGeneration) fail(EnrollmentError.Cancelled())
        if (renewed.keyId != grant.keyId || renewed.installationId != grant.installationId) {
            // Recorded with the code the caller gets (no SentomaruError names "the server answered another key").
            val error = SentomaruError.InvalidRequest(SentomaruError.Reason.PARAMS)
            renewalFailed(sentAt, error)
            fail(error)
        }
        val next = EnrollmentGrant(grant.installationId, grant.keyId, renewed.sessionId, grant.hardwareStatus,
            grant.attestationStatus, sentAt, renewed.ttlSeconds)
        store.write(InstallationRecord(current.scopeIdentity, current.alias, current.challenge, current.strongBox,
            current.body(), next, current.requiresHardware, current.generation, current.retiredKeys, current.pendingRotation,
            current.versionCode))
        clearRenewalBackoff()
        return next
    }

    /**
     * Helper for transport adapters (OkHttp, Dio) to freeze and sign with current active grant. [optional] carries
     * the signed optional headers ([Profile.OPTIONAL_HEADERS]: H3 signals, J-01f operation id); anything else is refused.
     */
    @Synchronized fun sign(method: String, targetUri: String, operation: String, body: ByteArray,
        optional: Map<String, String> = emptyMap()): SignedMessage {
        if (!Profile.OPTIONAL_HEADERS.containsAll(optional.keys)) fail(SentomaruError.InvalidRequest(SentomaruError.Reason.HEADER_NAME))
        when (state()) {
            InstallationState.NotEnrolled -> fail(EnrollmentError.NotEnrolled())
            InstallationState.EnrollmentRequired -> fail(EnrollmentError.EnrollmentRequired())
            InstallationState.KeyInvalidated -> fail(EnrollmentError.KeyInvalidated())
            InstallationState.Enrolled -> Unit
        }
        val record = record()!!
        val headers = config.headers(record.grant!!.sessionId, operation) + optional
        return signRequest(FrozenRequest(method, targetUri, headers, body))
    }

    /** Explicit local reset only; server revocation and consumer drafts remain consumer responsibilities. */
    @Synchronized fun reset() {
        lifecycleGeneration++
        clearRenewalBackoff()
        // Do not parse potentially corrupt state; ownership comes from the SDK's scoped namespace.
        keys.deleteOwned("sentomaru.v1.${config.identity}.")
        store.write(null)
    }

    private fun record(): InstallationRecord? {
        val current = store.read() ?: return null
        if (current.scopeIdentity != config.identity || !current.alias.startsWith("sentomaru.v1.${config.identity}."))
            fail(EnrollmentError.KeyInvalidated())
        return pruneExpiredRetiredKeys(current)
    }

    private fun pruneExpiredRetiredKeys(rec: InstallationRecord): InstallationRecord {
        if (rec.retiredKeys.isEmpty()) return rec
        val now = clock.instant()
        val (expired, active) = rec.retiredKeys.partition { !now.isBefore(it.expiresAt) }
        if (expired.isEmpty()) return rec
        for (item in expired) {
            keys.delete(item.alias)
        }
        val updated = InstallationRecord(rec.scopeIdentity, rec.alias, rec.challenge, rec.strongBox,
            rec.body(), rec.grant, rec.requiresHardware, rec.generation, active, rec.pendingRotation, rec.versionCode)
        store.write(updated)
        return updated
    }

    private fun interrupted() { if (Thread.currentThread().isInterrupted) fail(EnrollmentError.Cancelled()) }

    /**
     * C-04b: advisory Play Integrity token for this challenge, asked outside the lock and only when a new frozen body
     * will be built (a retry resends the same bytes, so the same token). Skipped when the challenge has less than
     * [INTEGRITY_MIN_REMAINING] left (review F4: the Google wait must never make the challenge expire). Any failure, or
     * a token outside the safe alphabet, means "no token"; interruption cancels the enrollment (review F3).
     */
    private fun prefetch(challenge: EnrollmentChallenge, needed: () -> Boolean): String? {
        val source = integrity ?: return null
        val name = packageName ?: return null
        interrupted()
        if (clock.instant().plus(INTEGRITY_MIN_REMAINING).isAfter(challenge.expiresAt) || !needed()) return null
        val token = try {
            source.token(IntegrityRequestHash.of(challenge, name))
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            null
        } catch (_: Exception) {
            null
        }
        interrupted()
        return IntegrityRequestHash.acceptable(token)
    }

    companion object {
        /**
         * D-04d: refusals of a resent rotation in which the server proves its body was not accepted (it is dropped):
         * `challenge-invalid`, `enrollment-revoked`, `409 enrollment-conflict`. Any other refusal (a generic 4xx, a
         * proxy, an unreadable body: INVALID) keeps it.
         */
        private val NEVER_ACCEPTED = setOf(EnrollmentError.Rejection.EXPIRED, EnrollmentError.Rejection.REVOKED,
            EnrollmentError.Rejection.CONFLICT)
        /** Two Play steps of 4 s each (plus one re-prepare) fit with room to sign and send. */
        internal val INTEGRITY_MIN_REMAINING: java.time.Duration = java.time.Duration.ofSeconds(20)
        /** J-04r: renew this long before the grant's lifetime ends (clock skew and a slow network included). */
        val RENEWAL_MARGIN: java.time.Duration = java.time.Duration.ofSeconds(120)
        /** J-04r: after a failed renewal, wait this long before trying again. */
        val RENEWAL_BACKOFF: java.time.Duration = java.time.Duration.ofSeconds(60)
        /**
         * After a renewal refused with [EnrollmentError.Rejection.SUSPENDED] (`403 installation-suspended`): short, so
         * an installation released by the operator renews on the user's next try instead of waiting a minute.
         */
        val SUSPENDED_RENEWAL_BACKOFF: java.time.Duration = java.time.Duration.ofSeconds(5)
        /**
         * Backoff after consecutive SUSPENDED renewals: 5 s, 15 s, then 60 s for every further one (client-side bound on
         * the renewal rate while suspended). Success, [reset] or any non-SUSPENDED outcome starts again at 5 s.
         */
        val SUSPENDED_RENEWAL_BACKOFF_STEPS: List<java.time.Duration> =
            listOf(SUSPENDED_RENEWAL_BACKOFF, java.time.Duration.ofSeconds(15), RENEWAL_BACKOFF)
        /** Reserved operation of a renewal (server: SessionRenewalService.Operation). */
        const val RENEW_OPERATION = "session_renew"
        private val RENEW_BODY = "{}".toByteArray(Charsets.UTF_8)
        private val clients = mutableMapOf<String, SentomaruClient>()

        /**
         * D-04b: `PackageInfo.longVersionCode` (minSdk 28, so no `versionCode` fallback); null if unreadable. A failure is
         * logged only in a debuggable app, with the exception class (no package data).
         */
        @Suppress("DEPRECATION") // getPackageInfo(String, Int): the PackageInfoFlags overload is API 33+
        internal fun appVersionCode(context: android.content.Context): Long? = try {
            context.packageManager.getPackageInfo(context.packageName, 0).longVersionCode.takeIf { it > 0 }
        } catch (e: Exception) {
            val debuggable = try {
                (context.applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0
            } catch (_: Exception) { false }
            if (debuggable) android.util.Log.d("Sentomaru", "versionCode unavailable: ${e.javaClass.simpleName}")
            null
        }

        /** One lifecycle coordinator per scope in this process. Multiple app processes are unsupported in P2. */
        @Synchronized fun initialize(context: android.content.Context, config: SentomaruConfig): SentomaruClient {
            val identity = context.applicationContext.noBackupFilesDir.absolutePath + ":" + config.identity
            val previous = clients[identity]
            if (previous != null) {
                if (previous.config.allowedHosts != config.allowedHosts)
                    fail(SentomaruError.InvalidRequest(SentomaruError.Reason.PARAMS))
                return previous
            }
            val integrity = config.playIntegrityCloudProjectNumber?.let { PlayIntegrityTokenSource(context, it) }
            return SentomaruClient(config, AndroidInstallationKeys(), AndroidInstallationStore(context, config),
                integrity = integrity, packageName = context.packageName, appVersionCode = appVersionCode(context)).also {
                it.pinnedHostSet = br.com.ebees.sentomaru.sdk.transport.PinnedHosts.fromManifest(context)
                clients[identity] = it
            }
        }
    }
}

/**
 * Fixed JSON schema, only validated base64/boolean values: no arbitrary-string escaping or parsing. C-04b: the optional
 * integrityToken is embedded only when it matches [IntegrityRequestHash.acceptable] (checked again here).
 */
internal object EnrollmentBody {
    /** D-04d: a rotation's body: the same schema plus the `predecessor` member (before `integrityToken`). */
    fun encode(token: String, material: RotationMaterial, requiresHardware: Boolean, config: SentomaruConfig,
        integrityToken: String? = null): ByteArray =
        encode(token, material.material, requiresHardware, config, integrityToken, material.member())

    fun encode(token: String, material: KeyMaterial, requiresHardware: Boolean, config: SentomaruConfig,
        integrityToken: String? = null, predecessor: String = ""): ByteArray {
        val encoder = Base64.getEncoder()
        val chain = material.chain()
        if (chain.size > 5 || chain.any { it.isEmpty() || it.size > 4096 }) fail(EnrollmentError.KeyUnavailable())
        val certificates = if (chain.isEmpty()) "" else ",\"attestationChain\":[" +
            chain.joinToString(",") { "\"${encoder.encodeToString(it)}\"" } + "]"
        val integrity = IntegrityRequestHash.acceptable(integrityToken)?.let { ",\"integrityToken\":\"$it\"" } ?: ""
        // sdkModes before integrityToken (never after it): every existing test anchors the optional integrityToken,
        // present or not, as the LAST member before the closing brace.
        return ("{\"challenge\":\"$token\",\"requiresHardware\":$requiresHardware," +
            "\"publicKey\":\"${encoder.encodeToString(material.publicKey())}\"$certificates$predecessor" +
            "${SdkModesJson.encode(config)}$integrity}").toByteArray(Charsets.UTF_8)
    }
}

/**
 * D-F1 (ativação de módulos em cliente novo, Fase F): the SDK's own self-declaration, additive member of the
 * enrollment/reattestation body (contract v1.20). Purely informational: never read back by the SDK itself.
 */
internal object SdkModesJson {
    const val SDK = "sentomaru_android"
    const val SDK_VERSION = "0.2.0-rc.6"

    fun encode(config: SentomaruConfig): String {
        val playIntegrity = if (config.playIntegrityCloudProjectNumber != null) "requested" else "not_configured"
        return ",\"sdkModes\":{\"enforce\":${config.declaredEnforce},\"installationResponse\":${config.declaredInstallationResponse}," +
            "\"playIntegrity\":\"$playIntegrity\",\"sdk\":\"$SDK\",\"sdkVersion\":\"$SDK_VERSION\"}"
    }
}
