package br.com.ebees.sentomaru.hybrid

import android.content.Context
import android.os.Handler
import android.os.Looper
import br.com.ebees.sentomaru.core.SentomaruError
import br.com.ebees.sentomaru.core.SentomaruException
import br.com.ebees.sentomaru.core.SignedMessage
import br.com.ebees.sentomaru.sdk.*
import br.com.ebees.sentomaru.signals.AndroidPlatformEnvironment
import br.com.ebees.sentomaru.signals.CodeDigestCache
import br.com.ebees.sentomaru.signals.PlatformEnvironment
import br.com.ebees.sentomaru.signals.SentomaruServerResponseEvent
import br.com.ebees.sentomaru.signals.SentomaruSignalEvent
import br.com.ebees.sentomaru.signals.SentomaruSignalEvents
import br.com.ebees.sentomaru.signals.SignalsCollector
import br.com.ebees.sentomaru.signals.SignalsSnapshot
import java.time.Duration
import java.time.Instant
import java.util.Base64
import java.util.concurrent.Executors

/** One call of the hybrid bridge (contracts/sdk/hybrid-bridge-v1.json): a method name and its named arguments. */
interface BridgeCall {
    val method: String
    fun <T> argument(key: String): T?
}

/** The answer to one [BridgeCall]: exactly one of these is called, always on the main looper. */
interface BridgeResult {
    fun success(value: Any?)
    fun error(code: String, message: String?, details: Any?)
    fun notImplemented()
}

/** D-15c: where the collectors of `collectSignalsSnapshot` get the events instance, only while the app listens. */
fun interface SignalEventFeed {
    fun current(): SentomaruSignalEvents?
}

/**
 * D-22a1: the native side of the bridge, shared by the Flutter plugin and the hybrid layers (React Native, Capacitor,
 * MAUI). Moved from `SentomaruFlutterPlugin` without a change of behaviour: the layer only turns its framework's call
 * and reply into [BridgeCall] and [BridgeResult]. Purely cryptographic background execution; strictly no biometric
 * prompts (Decision E4 / FLT-8).
 */
class SentomaruBridge(private val feed: SignalEventFeed) {
    /** The application context the layer attached; null while detached (`NoActivity`). */
    @Volatile var context: Context? = null

    /**
     * Review R of the D-12e: the client, its transport and its reattestation are replaced together by `initialize` and
     * read together by every handler (one volatile snapshot), so a handler never mixes a new client with an old
     * transport or reattestation.
     */
    private class Native(val client: SentomaruClient, val transport: EnrollmentTransport, val reattestation: SentomaruReattestation?)

    @Volatile private var native: Native? = null

    /** D-26 (Flutter): the initialized client, for the layer's own Flutter-only methods; null before `initialize`. */
    val client: SentomaruClient? get() = native?.client
    private val executor = Executors.newSingleThreadExecutor()
    /**
     * D-12e: the reattestation runs on its own worker thread, never the main thread nor [executor]: a flow can hold
     * the Keystore, two network calls and a retry wait of up to 30 s, and `sign` must not queue behind it. The native
     * client is thread-safe (its calls are synchronized); one reattestation at a time (the SDK's flow lock).
     */
    private val reattestExecutor = Executors.newSingleThreadExecutor()
    private val mainHandler = Handler(Looper.getMainLooper())

    /** Every method of the contract except the framework-specific ones (`scaffoldInfo`, the sealed reader). */
    fun onMethodCall(call: BridgeCall, result: BridgeResult) {
        when (call.method) {
            "initialize" -> handleInitialize(call, result)
            "state" -> handleState(result)
            "reenrollmentReason" -> handleReenrollmentReason(result)
            "enroll" -> handleEnroll(call, result)
            "rotate" -> handleRotate(call, result)
            "sign" -> handleSign(call, result)
            "reset" -> handleReset(result)
            "collectSignals" -> handleCollectSignals(result)
            "collectSignalsSnapshot" -> handleCollectSignalsSnapshot(call, result)
            "sessionId" -> handleSessionId(result)
            "renewSession" -> handleRenewSession(result)
            "reattestationDue" -> handleReattestationDue(result)
            "reattestIfDue" -> handleReattestIfDue(call, result, ignoreLocalWait = false)
            "reattest" -> handleReattestIfDue(call, result, ignoreLocalWait = true)
            else -> result.notImplemented()
        }
    }

    /** On detach: stops the workers. A reattestation in flight is interrupted (the SDK turns it into `Cancelled`). */
    fun shutdown() {
        context = null
        executor.shutdown()
        // Review R of the D-12e: interrupt a reattestation in flight (the SDK turns the interrupt into `Cancelled` and
        // deletes its key). Its reply, if any, is still posted to the main looper after the detach; Flutter drops a
        // reply for a detached engine, so nothing reaches Dart.
        reattestExecutor.shutdownNow()
    }

    private fun handleInitialize(call: BridgeCall, result: BridgeResult) {
        val ctx = context ?: run {
            replyError(result, "NoActivity", "Plugin context is detached", null)
            return
        }
        executor.execute {
            try {
                val config = PluginConfig.parse(call.argument<Any>("organization"), call.argument<Any>("app"),
                    call.argument<Any>("environment"), call.argument<Any>("enrollmentUrl"),
                    call.argument<Any>("allowedHosts"), call.argument<Any>("rotationGracePeriodDays"),
                    call.argument<Any>("playIntegrityCloudProjectNumber"), call.argument<Any>("renewalUrl"))
                val reattest = PluginConfig.parseReattestation(call.argument<Any>("reattestationChallengeUrl"),
                    call.argument<Any>("reattestationSubmitUrl"), call.argument<Any>("reattestationMinIntervalSeconds"))
                val c = SentomaruClient.initialize(ctx, config)
                // D-12e: built before anything is kept, so a refused route leaves the plugin as it was.
                val r = reattest?.let { PluginConfig.reattestation(c, it) }
                native = Native(c, EnrollmentTransport(config.allowedHosts), r)
                replySuccess(result, null)
            } catch (e: PluginConfig.Invalid) {
                replyError(result, PluginConfig.ERROR_CODE, "Invalid or missing Sentomaru configuration", null)
            } catch (e: SentomaruException) {
                replyError(result, e.error.code, e.error.code, null)
            } catch (e: Exception) {
                replyError(result, "ChannelError", "Native initialize failed", null)
            }
        }
    }

    private fun handleState(result: BridgeResult) {
        val n = native ?: run {
            replyError(result, NOT_INITIALIZED, "Sentomaru native client not initialized", null)
            return
        }
        val c = n.client
        executor.execute {
            try {
                replySuccess(result, c.state().name)
            } catch (e: SentomaruException) {
                replyError(result, e.error.code, e.error.code, null)
            } catch (e: Exception) {
                replyError(result, "ChannelError", "Native error", null)
            }
        }
    }

    /** D-04b: [ReenrollmentReason] name (`APP_UPDATED`) or null; never re-enrolls by itself. */
    private fun handleReenrollmentReason(result: BridgeResult) {
        val n = native ?: run {
            replyError(result, NOT_INITIALIZED, "Sentomaru native client not initialized", null)
            return
        }
        val c = n.client
        executor.execute {
            try {
                replySuccess(result, reenrollmentReply(c))
            } catch (e: SentomaruException) {
                replyError(result, e.error.code, e.error.code, null)
            } catch (e: Exception) {
                replyError(result, "ChannelError", "Native error", null)
            }
        }
    }

    private fun handleEnroll(call: BridgeCall, result: BridgeResult) {
        val n = native ?: run {
            replyError(result, NOT_INITIALIZED, "Sentomaru native client not initialized", null)
            return
        }
        val c = n.client
        executor.execute {
            try {
                val challengeMap = call.argument<Map<String, Any>>("challenge")
                    ?: throw SentomaruException(SentomaruError.InvalidRequest(SentomaruError.Reason.PARAMS))
                val strongBox = call.argument<Boolean>("strongBox") ?: false
                val requiresHardware = call.argument<Boolean>("requiresHardware") ?: false

                val challenge = parseChallenge(challengeMap)
                val grant = c.enroll(challenge, strongBox = strongBox, requiresHardware = requiresHardware) { signed ->
                    n.transport.send(signed)
                }

                val grantMap = mapOf(
                    "installationId" to grant.installationId,
                    "keyId" to grant.keyId,
                    "sessionId" to grant.sessionId,
                    "hardwareStatus" to grant.hardwareStatus,
                    "attestationStatus" to grant.attestationStatus
                )
                replySuccess(result, grantMap)
            } catch (e: SentomaruException) {
                replyError(result, e.error.code, e.error.code, null)
            } catch (e: Exception) {
                replyError(result, "ChannelError", "Native error", null)
            }
        }
    }

    private fun handleRotate(call: BridgeCall, result: BridgeResult) {
        val n = native ?: run {
            replyError(result, NOT_INITIALIZED, "Sentomaru native client not initialized", null)
            return
        }
        val c = n.client
        executor.execute {
            try {
                val challengeMap = call.argument<Map<String, Any>>("challenge")
                    ?: throw SentomaruException(SentomaruError.InvalidRequest(SentomaruError.Reason.PARAMS))
                val strongBox = call.argument<Boolean>("strongBox") ?: false
                val requiresHardware = call.argument<Boolean>("requiresHardware") ?: false

                val challenge = parseChallenge(challengeMap)
                val grant = c.rotate(challenge, strongBox = strongBox, requiresHardware = requiresHardware) { signed ->
                    n.transport.send(signed)
                }

                val grantMap = mapOf(
                    "installationId" to grant.installationId,
                    "keyId" to grant.keyId,
                    "sessionId" to grant.sessionId,
                    "hardwareStatus" to grant.hardwareStatus,
                    "attestationStatus" to grant.attestationStatus
                )
                replySuccess(result, grantMap)
            } catch (e: SentomaruException) {
                replyError(result, e.error.code, e.error.code, null)
            } catch (e: Exception) {
                replyError(result, "ChannelError", "Native error", null)
            }
        }
    }

    private fun handleSign(call: BridgeCall, result: BridgeResult) {
        val n = native ?: run {
            replyError(result, NOT_INITIALIZED, "Sentomaru native client not initialized", null)
            return
        }
        val c = n.client
        executor.execute {
            try {
                val method = call.argument<String>("method")
                    ?: throw SentomaruException(SentomaruError.InvalidRequest(SentomaruError.Reason.METHOD))
                val targetUri = call.argument<String>("targetUri")
                    ?: throw SentomaruException(SentomaruError.InvalidRequest(SentomaruError.Reason.TARGET_URI))
                val operation = call.argument<String>("operation")
                    ?: throw SentomaruException(SentomaruError.InvalidRequest(SentomaruError.Reason.HEADER_VALUE))
                val body = call.argument<ByteArray>("body") ?: ByteArray(0)
                // J-01f2: optional covered headers (signals, operation id), signed by the core like the base ones.
                // Review R5: no unchecked cast; anything but string keys and values is a typed refusal.
                val raw = call.argument<Map<*, *>>("optional") ?: emptyMap<Any, Any>()
                val optional = raw.entries.associate { (key, value) ->
                    if (key !is String || value !is String)
                        throw SentomaruException(SentomaruError.InvalidRequest(SentomaruError.Reason.HEADER_VALUE))
                    key to value
                }

                // J-04r: renew a grant near its lifetime before signing; a failure keeps the current grant (the
                // request still goes out and the server decides) and the SDK backs off.
                try { c.renewIfDue { n.transport.renew(it) } } catch (_: SentomaruException) { }
                val signed = c.sign(method, targetUri, operation, body, optional)
                replySuccess(result, signed.headers.toMap())
            } catch (e: SentomaruException) {
                replyError(result, e.error.code, e.error.code, null)
            } catch (e: Exception) {
                replyError(result, "ChannelError", "Native error", null)
            }
        }
    }

    /** J-04r: the consumer answered `session-expired`: renew now (once) and return the new session id. */
    private fun handleRenewSession(result: BridgeResult) {
        val n = native ?: run {
            replyError(result, NOT_INITIALIZED, "Sentomaru native client not initialized", null)
            return
        }
        val c = n.client
        executor.execute {
            try {
                // The backoff after a failed renewal applies here too (review of #166): 5 s after a suspension, else
                // 60 s. A refusal for backoff has its own code (RenewalBackoff), apart from "cannot renew" (PARAMS),
                // and carries the code of the failure that started the backoff in details (0.9.2): the silent renewal
                // of sign may have been the one that failed, so the app still tells a suspension from a transient error.
                // One snapshot (review of #184): decision and code come from the same instant under the client lock.
                renewalRefusalReply(c.renewalGate())?.let { refusal ->
                    replyError(result, refusal.code, refusal.code, refusal.details)
                    return@execute
                }
                c.markGrantStale()
                replySuccess(result, c.renew { n.transport.renew(it) }.sessionId)
            } catch (e: SentomaruException) {
                replyError(result, e.error.code, e.error.code, null)
            } catch (e: Exception) {
                replyError(result, "ChannelError", "Native error", null)
            }
        }
    }

    private fun handleReset(result: BridgeResult) {
        val n = native ?: run {
            replySuccess(result, null)
            return
        }
        val c = n.client
        executor.execute {
            try {
                c.reset()
                replySuccess(result, null)
            } catch (e: SentomaruException) {
                replyError(result, e.error.code, e.error.code, null)
            } catch (e: Exception) {
                replyError(result, "ChannelError", "Native error", null)
            }
        }
    }

    private fun handleCollectSignals(result: BridgeResult) {
        val ctx = context ?: run {
            replyError(result, "NoActivity", "Plugin context is detached", null)
            return
        }
        executor.execute {
            try {
                val snapshot = SignalsCollector().snapshot(ctx)
                val list = snapshot.observations.map { obs ->
                    mapOf(
                        "capabilityId" to obs.capabilityId,
                        "version" to obs.version,
                        "state" to obs.state.name.lowercase(),
                        "source" to obs.source,
                        "observedAt" to obs.observedAt,
                        "data" to obs.detail
                    )
                }
                replySuccess(result, list)
            } catch (e: Exception) {
                replyError(result, "ChannelError", "Native error", null)
            }
        }
    }

    /**
     * D-05e: the snapshot with `collectedAt` and `durationMs` from the native collector. `rasp` adds the D-05 detectors
     * with [SignalsCollector.RASP_DEADLINE_MS]; with a deadline the collector refuses the main thread, so it runs on the
     * plugin executor like every other call. `collectSignals` above stays the frozen path (six capabilities, no deadline).
     */
    private fun handleCollectSignalsSnapshot(call: BridgeCall, result: BridgeResult) {
        val ctx = context ?: run {
            replyError(result, "NoActivity", "Plugin context is detached", null)
            return
        }
        val rasp = call.argument<Boolean>("rasp") ?: false
        val raw = call.argument<Any>("expectedSignerDigests")
        executor.execute {
            val collector = try {
                signalsCollector(rasp, expectedSignerDigests(raw))
            } catch (_: IllegalArgumentException) {
                // D-12e: a signer list the SDK refuses (not a SHA-256) is the app's configuration, never a signal state.
                replyError(result, PluginConfig.ERROR_CODE, "Invalid expectedSignerDigests", null)
                return@execute
            } catch (_: Exception) {
                replyError(result, "ChannelError", "Native error", null) // review R: anything else is not configuration
                return@execute
            }
            // D-15c: events only while Dart listens; the snapshot itself is the same either way (D-15a).
            feedEvents(collector, feed)
            try {
                replySuccess(result, snapshotReply(collector.snapshot(ctx)))
            } catch (e: Exception) {
                replyError(result, "ChannelError", "Native error", null)
            }
        }
    }

    /** D-12e: whether `reattestIfDue` would ask now. Never blocks (a volatile read in the SDK), so it answers here. */
    private fun handleReattestationDue(result: BridgeResult) {
        val n = native ?: run {
            result.error(NOT_INITIALIZED, "Sentomaru native client not initialized", null)
            return
        }
        val r = n.reattestation ?: run {
            result.error(NOT_CONFIGURED, NOT_CONFIGURED, null)
            return
        }
        result.success(r.due())
    }

    /**
     * D-12e: [SentomaruReattestation.reattestIfDue] on [reattestExecutor]; the answer is [reattestationReply]. Local
     * failures (`NotEnrolled`, `KeyUnavailable`, `StrongBoxUnavailable`, `Cancelled`) come back as their code.
     * D-06h (0.15.0): with [ignoreLocalWait], the same flow through [SentomaruReattestation.reattest] (the native call that
     * ignores the local wait), for a `challenge` of kind `reattest`: the server decided. Same thread, reply and errors.
     */
    private fun handleReattestIfDue(call: BridgeCall, result: BridgeResult, ignoreLocalWait: Boolean) {
        val n = native ?: run {
            replyError(result, NOT_INITIALIZED, "Sentomaru native client not initialized", null)
            return
        }
        val r = n.reattestation ?: run {
            replyError(result, NOT_CONFIGURED, NOT_CONFIGURED, null)
            return
        }
        val strongBox = call.argument<Boolean>("strongBox") ?: false
        val task = Runnable {
            replyReattestation(result) {
                if (ignoreLocalWait) r.reattest(strongBox) { n.transport.reattest(it) }
                else r.reattestIfDue(strongBox) { n.transport.reattest(it) }
            }
        }
        try {
            reattestExecutor.execute(task)
        } catch (_: java.util.concurrent.RejectedExecutionException) {
            replyError(result, "Cancelled", "Cancelled", null) // detached: the executor no longer takes work
        }
    }

    /** Review R of the D-12e: the [result] is always answered, whatever [run] throws (an `Error` included). */
    private fun replyReattestation(result: BridgeResult, run: () -> ReattestationOutcome) {
        val reply = reattestationReplyOrError(run)
        if (reply.error == null) replySuccess(result, reply.value) else replyError(result, reply.error, reply.error, null)
    }

    private fun handleSessionId(result: BridgeResult) {
        val n = native ?: run {
            replySuccess(result, null)
            return
        }
        val c = n.client
        executor.execute {
            try {
                replySuccess(result, c.sessionId())
            } catch (e: SentomaruException) {
                replyError(result, e.error.code, e.error.code, null)
            } catch (e: Exception) {
                replyError(result, "ChannelError", "Native error", null)
            }
        }
    }

    private fun parseChallenge(map: Map<String, Any>): EnrollmentChallenge {
        val id = map["id"] as? String
            ?: throw SentomaruException(SentomaruError.InvalidRequest(SentomaruError.Reason.PARAMS))
        val token = map["token"] as? String
            ?: throw SentomaruException(SentomaruError.InvalidRequest(SentomaruError.Reason.PARAMS))
        val expiresEpoch = (map["expiresAtEpochMs"] as? Number)?.toLong()
            ?: throw SentomaruException(SentomaruError.InvalidRequest(SentomaruError.Reason.PARAMS))
        val attestationB64 = map["attestationChallengeB64"] as? String
            ?: throw SentomaruException(SentomaruError.InvalidRequest(SentomaruError.Reason.PARAMS))

        val attestation = Base64.getDecoder().decode(attestationB64)
        val expiresAt = Instant.ofEpochMilli(expiresEpoch)
        return EnrollmentChallenge(id, token, attestation, expiresAt)
    }

    private fun replySuccess(result: BridgeResult, value: Any?) {
        mainHandler.post { result.success(value) }
    }

    private fun replyError(result: BridgeResult, code: String, message: String?, details: Any?) {
        mainHandler.post { result.error(code, message, details) }
    }

    internal companion object {
        private const val NOT_INITIALIZED = "NotInitialized"

        /** D-15c: what the EventChannel sends to Dart for a signal event (closed fields only, as the SDK built them). */
        fun signalEventReply(event: SentomaruSignalEvent): Map<String, Any> = mapOf(
            "kind" to "signal",
            "type" to event.type,
            "capabilityId" to event.capabilityId,
            "capabilityVersion" to event.capabilityVersion,
            "state" to event.state.name,
            "reasonCodes" to event.reasonCodes.toList(),
            "catalogVersion" to event.catalogVersion,
            "sequence" to event.sequence,
        )

        /** D-15c: what the EventChannel sends to Dart for a server response event. */
        fun serverResponseReply(event: SentomaruServerResponseEvent): Map<String, Any?> = mapOf(
            "kind" to "server_response",
            "code" to event.code,
            "challengeKind" to event.challengeKind,
            "httpStatus" to event.httpStatus,
            "sequence" to event.sequence,
        )

        /** D-12e: reattestation asked without its routes in the configuration (as `renewSession` without `renewalUrl`). */
        const val NOT_CONFIGURED = "InvalidRequest:PARAMS"

        /**
         * D-05e: without [rasp] the frozen collector of `collectSignals` (six detectors, no deadline); with it
         * `defaultDetectors() + raspDetectors()` and [SignalsCollector.RASP_DEADLINE_MS]. The plugin does not depend on
         * `signals-rasp`: the host app adds it to run the `root_artifacts` package check.
         *
         * D-12e: [expectedSignerDigests] non-null adds `appIntegrityDetectors(expectedSignerDigests)` last. With [rasp]
         * the deadline gets [SignalsCollector.APP_INTEGRITY_BUDGET_MS] more over [SignalsCollector.RASP_DEADLINE_MS];
         * without it there is still no deadline (review R: the six keep their 0.12.0 behaviour). Null keeps both paths
         * above exactly as they were. [env] and
         * [codeDigests] are the SDK defaults; tests pass doubles.
         */
        /** D-15c: gives [collector] the bridge's events only while Dart listens (review R I-3: testable on the JVM). */
        fun feedEvents(collector: SignalsCollector, feed: SignalEventFeed) {
            feed.current()?.let { collector.events = it }
        }

        fun signalsCollector(
            rasp: Boolean,
            expectedSignerDigests: List<String>? = null,
            env: PlatformEnvironment = AndroidPlatformEnvironment,
            codeDigests: CodeDigestCache = CodeDigestCache.shared,
        ): SignalsCollector {
            if (!rasp && expectedSignerDigests == null && env === AndroidPlatformEnvironment) return SignalsCollector()
            val detectors = SignalsCollector.defaultDetectors(env = env) +
                (if (rasp) SignalsCollector.raspDetectors(env = env) else emptyList()) +
                (expectedSignerDigests?.let { SignalsCollector.appIntegrityDetectors(it, env = env, codeDigests = codeDigests) }
                    ?: emptyList())
            // Review R of the D-12e: no deadline without rasp, so opting in to the app integrity signals never turns the
            // six frozen ones into UNKNOWN timeout; the three bound themselves (code_integrity waits at most 15 ms).
            val deadline = when {
                !rasp -> null
                expectedSignerDigests != null -> SignalsCollector.RASP_DEADLINE_MS + SignalsCollector.APP_INTEGRITY_BUDGET_MS
                else -> SignalsCollector.RASP_DEADLINE_MS
            }
            return SignalsCollector(detectors = detectors, deadlineMs = deadline)
        }

        /** D-12e: the channel's `expectedSignerDigests`: absent = null (not collected); a list of strings, else refused. */
        fun expectedSignerDigests(raw: Any?): List<String>? = when (raw) {
            null -> null
            is List<*> -> raw.map { it as? String ?: throw IllegalArgumentException("expected signer digest is not text") }
            else -> throw IllegalArgumentException("expectedSignerDigests is not a list")
        }

        /**
         * Review R of the D-12e: runs a reattestation and never lets it escape: a [SentomaruException] is its code, an
         * interrupt is `Cancelled`, any other [Throwable] (an `Error` included) is `ChannelError`.
         */
        fun reattestationReplyOrError(run: () -> ReattestationOutcome): ReattestationReply = try {
            ReattestationReply(reattestationReply(run()), null)
        } catch (e: SentomaruException) {
            ReattestationReply(null, e.error.code)
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            ReattestationReply(null, "Cancelled")
        } catch (e: Throwable) {
            ReattestationReply(null, "ChannelError")
        }

        /**
         * D-12e: what `reattestIfDue` sends to Dart. `outcome` is `completed` (with the server's `result`), `notNow`
         * (`reason` = [ReattestationWait] name, `retryAfterMs`) or `refused` (`code`, `status`; status 0 = refused
         * locally, e.g. an expired challenge).
         */
        fun reattestationReply(outcome: ReattestationOutcome): Map<String, Any?> = when (outcome) {
            is ReattestationCompleted -> mapOf("outcome" to "completed", "result" to outcome.result.let { r ->
                mapOf(
                    "installationId" to r.installationId,
                    "challengeId" to r.challengeId,
                    "reattestedAt" to r.reattestedAt.toString(),
                    "hardwareStatus" to r.hardwareStatus,
                    "attestationStatus" to r.attestationStatus,
                    "attestationReason" to r.attestationReason,
                    "buildMatchState" to r.buildMatchState,
                    "buildMatchReason" to r.buildMatchReason,
                    "appIdentityState" to r.appIdentityState,
                    "appIdentityReason" to r.appIdentityReason,
                    "replayed" to r.replayed,
                )
            })
            is ReattestationNotNow -> mapOf("outcome" to "notNow", "reason" to outcome.reason.name,
                "retryAfterMs" to outcome.retryAfter.toMillis())
            is ReattestationRefused -> mapOf("outcome" to "refused", "code" to outcome.code, "status" to outcome.status)
        }

        /** What `collectSignalsSnapshot` sends to Dart; each observation as in `collectSignals` (`data` = detail). */
        fun snapshotReply(snapshot: SignalsSnapshot): Map<String, Any> = mapOf(
            "collectedAt" to snapshot.collectedAt,
            "durationMs" to snapshot.durationMs,
            "observations" to snapshot.observations.map { obs ->
                mapOf(
                    "capabilityId" to obs.capabilityId,
                    "version" to obs.version,
                    "state" to obs.state.name.lowercase(),
                    "source" to obs.source,
                    "observedAt" to obs.observedAt,
                    "data" to obs.detail
                )
            },
        )

        /** D-04b: what `reenrollmentReason` sends to Dart: the [ReenrollmentReason] name (`APP_UPDATED`) or null. */
        fun reenrollmentReply(client: SentomaruClient): String? = client.reenrollmentReason()?.name

        /**
         * Why `renewSession` is not attempted now, or null to renew: inside the backoff of the last failed renewal ->
         * [EnrollmentError.RenewalBackoff] (Dart `renewalBackoff`; wait and retry); otherwise unable to renew at all (no
         * renewal URL, not enrolled) -> `InvalidRequest:PARAMS`.
         */
        fun renewalRefusal(backingOff: Boolean, canRenewNow: Boolean): SentomaruError? = when {
            backingOff -> EnrollmentError.RenewalBackoff()
            !canRenewNow -> SentomaruError.InvalidRequest(SentomaruError.Reason.PARAMS)
            else -> null
        }

        /**
         * PlatformException details of a `renewSession` refusal: for [EnrollmentError.RenewalBackoff] the
         * [SentomaruError.code] of the failure that started the backoff (`ServerRejected:SUSPENDED`, the same string the
         * serverRejected path sends as code), else null.
         */
        fun refusalDetails(refusal: SentomaruError, lastFailure: String?): String? =
            if (refusal is EnrollmentError.RenewalBackoff) lastFailure else null

        /** The PlatformException `handleRenewSession` replies for [gate] (code = message), or null to renew. */
        fun renewalRefusalReply(gate: SentomaruClient.RenewalGate): RefusalReply? =
            renewalRefusal(gate.backingOff, gate.canRenewNow)?.let {
                RefusalReply(it.code, refusalDetails(it, gate.lastFailure))
            }
    }

    /** What a reattestation answers: the [value] map, or the PlatformException [error] code (also the message). */
    class ReattestationReply(val value: Map<String, Any?>?, val error: String?)

    /** A `renewSession` refusal as sent to Dart: PlatformException code (also the message) and details. */
    class RefusalReply(val code: String, val details: String?)
}
