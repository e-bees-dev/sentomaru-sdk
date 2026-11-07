package br.com.ebees.sentomaru.signals

import java.util.Collections
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executor

/**
 * D-15a: an INFORMATIVE event about one signal the app itself collected. Not a verdict: it says nothing about whether
 * the app or the device is safe, and a process the attacker controls can suppress or invent it. The decision stays with
 * the server, on every request (the app may at most warn and log; leaving the app on a signal event alone is
 * discouraged, see the integration guide).
 *
 * Every field comes from a closed vocabulary: [type] from `SignalsCatalog.EVENT_TYPES`, [reasonCodes] from
 * `SignalsCatalog.EVENT_REASON_CODES`, [capabilityVersion] and [catalogVersion] from the SDK catalog. No wall-clock time
 * (it would become a correlation mark), no detail text, no installation, session or key id, no package name, path,
 * device property, digest or identifier. [sequence] is a local counter of the [SentomaruSignalEvents] that emitted it.
 */
data class SentomaruSignalEvent(
    val kind: Kind,
    val type: String,
    val capabilityId: String,
    val capabilityVersion: String,
    val state: SignalState,
    val reasonCodes: List<String>,
    val catalogVersion: String,
    val sequence: Long,
) {
    /** The event family: always [SIGNAL]. A [SentomaruServerResponseEvent] (D-15b) has its own kind. */
    enum class Kind { SIGNAL }
}

/** D-15a: receives [SentomaruSignalEvent]s on the executor it was registered with. */
fun interface SentomaruSignalEventListener {
    fun onSignalEvent(event: SentomaruSignalEvent)
}

/**
 * D-15a: signal events, opt-in. Set it on a collector (`collector.events = signalEvents`) (or feed snapshots with
 * [observe]); nothing is emitted otherwise, and `SignalsCollector()` without it is unchanged.
 *
 * It keeps in memory the last state of each D-05/D-12c capability and emits one event on the first observation of a
 * capability and on each change of its state (DETECTED, NOT_DETECTED, UNKNOWN, UNSUPPORTED, ERROR). It runs inside the
 * collection the app already makes: no collection of its own, no thread, timer, alarm or service, nothing on disk, and
 * nothing sent anywhere. A listener runs on the executor given to [addListener]; an exception it throws (or a rejected
 * execution) is swallowed and never reaches the collection. There is deliberately no "is compromised", score or
 * summary: the events are not a security verdict.
 *
 * The executor must not block: a direct executor (`Executor { it.run() }`) runs the listener inside the collection and
 * delays the snapshot by as long as the listener takes. Concurrent collections on one instance are each turned into
 * events atomically, in the order they reach [observe], which is not always the order they started: the remembered
 * state is that of the last snapshot observed, and events of two collections may reach a listener interleaved; use
 * [SentomaruSignalEvent.sequence] to order them. A capability that hits the collector's deadline once goes
 * DETECTED, UNKNOWN (`timeout`) and DETECTED again: each change is an event.
 */
class SentomaruSignalEvents {
    private class Registration(val executor: Executor, val listener: SentomaruSignalEventListener)

    private val lock = Any()
    private val lastState = HashMap<String, SignalState>()
    private var sequence = 0L
    private val listeners = CopyOnWriteArrayList<Registration>()
    private class ResponseRegistration(val executor: Executor, val listener: SentomaruServerResponseListener)
    private val responseListeners = CopyOnWriteArrayList<ResponseRegistration>()

    /** Registers [listener]; its events run on [executor] (e.g. the app's main executor). */
    fun addListener(executor: Executor, listener: SentomaruSignalEventListener) {
        listeners += Registration(executor, listener)
    }

    /** Removes every registration of [listener]; true when there was one. */
    fun removeListener(listener: SentomaruSignalEventListener): Boolean = listeners.removeAll { it.listener === listener }

    /**
     * D-15b: registers [listener] for [SentomaruServerResponseEvent]s (the closed codes a consumer answered to a signed
     * request), on [executor]. Same delivery rules as [addListener]; the [SentomaruSignalEvent.sequence] and
     * [SentomaruServerResponseEvent.sequence] share one counter, so both kinds can be ordered together.
     */
    fun addServerResponseListener(executor: Executor, listener: SentomaruServerResponseListener) {
        responseListeners += ResponseRegistration(executor, listener)
    }

    /** Removes every registration of [listener]; true when there was one. */
    fun removeServerResponseListener(listener: SentomaruServerResponseListener): Boolean =
        responseListeners.removeAll { it.listener === listener }

    /**
     * D-15b: turns one answer to a SIGNED request into a [SentomaruServerResponseEvent] when it carries a closed code
     * ([ServerResponseCodes.read]); anything else is ignored. Called by the SDK's signing interceptor (`addSentomaru(client,
     * routes, events)`), with at most [ServerResponseCodes.MAX_BODY_CHARS] characters of the body. Every answer is an event
     * (not only changes): two refusals in a row are two events. The sequence is taken under the same lock as the signal
     * events, delivery happens outside it: order by sequence, not by arrival. Never throws (except a `VirtualMachineError`).
     */
    fun observeServerResponse(httpStatus: Int, body: String?) {
        val event = try {
            val (code, kind) = ServerResponseCodes.read(httpStatus, body) ?: return
            synchronized(lock) { SentomaruServerResponseEvent(code, kind, httpStatus, ++sequence) }
        } catch (e: VirtualMachineError) {
            throw e
        } catch (_: Throwable) {
            return
        }
        for (registration in responseListeners) deliver(registration.executor) { registration.listener.onServerResponseEvent(event) }
    }

    /** True when someone listens to server response events (the transport skips reading the body otherwise). */
    val hasServerResponseListeners: Boolean get() = responseListeners.isNotEmpty()

    private class TransportRegistration(val executor: Executor, val listener: SentomaruTransportListener)
    private val transportListeners = CopyOnWriteArrayList<TransportRegistration>()

    /**
     * D-07d: registers [listener] for [SentomaruTransportEvent]s (`pin_failure` on a host pinned by `sentomaru protect`),
     * on [executor]. Same delivery rules as [addListener]; the sequence is the one shared with the other two kinds.
     */
    fun addTransportListener(executor: Executor, listener: SentomaruTransportListener) {
        transportListeners += TransportRegistration(executor, listener)
    }

    /** Removes every registration of [listener]; true when there was one. */
    fun removeTransportListener(listener: SentomaruTransportListener): Boolean =
        transportListeners.removeAll { it.listener === listener }

    /** True when someone listens to transport events (the transport skips classifying a failure otherwise). */
    val hasTransportListeners: Boolean get() = transportListeners.isNotEmpty()

    /**
     * D-07d: one `pin_failure` on [host] with [reason]. Called by the SDK's transport only for a host of the app's
     * pinning meta-data, after classifying a TLS failure; the failure itself still reaches the app unchanged. A [reason]
     * outside [TransportEventCodes.REASONS] or a [host] that is not a lower-case host name (the CLI's rule) is ignored,
     * so nothing but the closed vocabulary and a host name ever reaches an event. Every failure is an event (not only
     * changes). Never throws (except a `VirtualMachineError`).
     */
    fun observePinFailure(host: String, reason: String) {
        val event = try {
            if (reason !in TransportEventCodes.REASONS) return
            if (!TransportEventCodes.isHostName(host)) return
            synchronized(lock) { SentomaruTransportEvent(TransportEventCodes.PIN_FAILURE, reason, host, ++sequence) }
        } catch (e: VirtualMachineError) {
            throw e
        } catch (_: Throwable) {
            return
        }
        for (registration in transportListeners) deliver(registration.executor) { registration.listener.onTransportEvent(event) }
    }

    /**
     * Turns one collected snapshot into events (first observation and state changes only) and delivers them. Never
     * throws (except a `VirtualMachineError`): a broken listener or snapshot costs only its events.
     */
    fun observe(snapshot: SignalsSnapshot) {
        val events = try {
            transitions(snapshot)
        } catch (e: VirtualMachineError) {
            throw e
        } catch (_: Throwable) {
            return
        }
        for (event in events) for (registration in listeners) deliver(registration.executor) { registration.listener.onSignalEvent(event) }
    }

    private fun transitions(snapshot: SignalsSnapshot): List<SentomaruSignalEvent> = synchronized(lock) {
        snapshot.observations.mapNotNull { observation ->
            val id = observation.capabilityId
            val type = SignalsCatalog.EVENT_TYPES[id] ?: return@mapNotNull null
            val definition = SignalsCatalog.CAPABILITIES.firstOrNull { it.capabilityId == id } ?: return@mapNotNull null
            if (observation.state == SignalState.STALE) return@mapNotNull null // only the server sets STALE
            if (lastState.put(id, observation.state) == observation.state) return@mapNotNull null
            SentomaruSignalEvent(
                kind = SentomaruSignalEvent.Kind.SIGNAL,
                type = type,
                capabilityId = id,
                capabilityVersion = definition.version,
                state = observation.state,
                reasonCodes = reasonCodes(id, observation.detail),
                catalogVersion = SignalsCatalog.VERSION,
                sequence = ++sequence,
            )
        }
    }

    private fun deliver(executor: Executor, call: () -> Unit) {
        try {
            executor.execute {
                try {
                    call()
                } catch (e: VirtualMachineError) {
                    throw e
                } catch (_: Throwable) {
                    // A listener's failure is its own; the collection and the other listeners go on.
                }
            }
        } catch (e: VirtualMachineError) {
            throw e
        } catch (_: Throwable) {
            // Rejected (executor shut down) or a direct executor that let something escape: dropped.
        }
    }

    internal companion object {
        /**
         * The codes of an observation's detail, filtered by the capability's allowlist (anything else is dropped,
         * so no value of the detail can reach an event unless it IS one of the fixed codes).
         */
        fun reasonCodes(capabilityId: String, detail: Map<String, String>): List<String> {
            val allowed = SignalsCatalog.EVENT_REASON_CODES[capabilityId] ?: return emptyList()
            return Collections.unmodifiableList(rawReasonCodes(capabilityId, detail).filter { it in allowed }.distinct())
        }

        /** The candidate codes read from the detail's fixed keys, before the allowlist (tests check they are listed). */
        fun rawReasonCodes(capabilityId: String, detail: Map<String, String>): List<String> {
            val raw = ArrayList<String>()
            detail["indicators"]?.split(',')?.filter { it != "none" }?.let(raw::addAll)
            if (detail.containsKey("partial")) raw += "partial"
            if (detail.containsKey("timeout")) raw += "timeout"
            detail["result"]?.let(raw::add)
            detail["class"]?.let { raw += "class_$it" }
            detail["initiator"]?.let { raw += "initiator_$it" }
            if (capabilityId == "code_integrity") {
                detail["reason"]?.let(raw::add)
                detail["cause"]?.let(raw::add)
            }
            return raw
        }
    }
}
