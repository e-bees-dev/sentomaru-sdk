package br.com.ebees.sentomaru.signals

/**
 * D-07d: an INFORMATIVE, LOCAL event about one TLS failure on a host pinned by `sentomaru protect` (`network-pinning`,
 * contract `contracts/devsecops/cli-v1.md`, ADR 0002), seen by the SDK's own transport (`addSentomaru` on OkHttp,
 * `SentomaruUrlConnection.send`). The platform's `network_security_config` refused the handshake; the SDK only names
 * the refusal. It is never a verdict, never sent to the server (D-07x9) and never written anywhere; the SDK does not
 * retry, switch off anything or try another path. A process the attacker controls can suppress or invent it.
 *
 * Its own class and vocabulary ([TransportEventCodes]), outside the signals catalog, which does not change. No URL,
 * path, query, port, address, certificate, pin, exception text or wall-clock time: only the pinned [host] as the
 * CLI wrote it in the app's meta-data and a closed [reason]. [sequence] is the counter shared with
 * [SentomaruSignalEvent] and [SentomaruServerResponseEvent] of the [SentomaruSignalEvents] that emitted it.
 *
 * @property type always [TransportEventCodes.PIN_FAILURE] (`pin_failure`).
 * @property reason [TransportEventCodes.PIN_MISMATCH], [TransportEventCodes.TLS_UNTRUSTED] or [TransportEventCodes.TLS_OTHER].
 * @property host one of the hosts of the meta-data `br.com.ebees.sentomaru.pinning.hosts`, exactly as listed there.
 */
data class SentomaruTransportEvent(
    val type: String,
    val reason: String,
    val host: String,
    val sequence: Long,
) {
    /** Always [Kind.TRANSPORT] (wire value `transport`); its own enum, like [SentomaruServerResponseEvent.Kind]. */
    val kind: Kind get() = Kind.TRANSPORT

    enum class Kind { TRANSPORT }
}

/** D-07d: receives [SentomaruTransportEvent]s on the executor it was registered with. */
fun interface SentomaruTransportListener {
    fun onTransportEvent(event: SentomaruTransportEvent)
}

/** D-07d: the closed vocabulary of [SentomaruTransportEvent]; lives only in the SDK (not in the signals catalog). */
object TransportEventCodes {
    const val PIN_FAILURE = "pin_failure"

    /** The platform's pin check refused the chain (no key of the chain is in the pin-set). */
    const val PIN_MISMATCH = "pin_mismatch"
    /** Another certificate failure: unknown CA, expired or not yet valid, wrong name. */
    const val TLS_UNTRUSTED = "tls_untrusted"
    /** Any other TLS failure (protocol, alert, a connection cut during the handshake). */
    const val TLS_OTHER = "tls_other"

    @JvmField val REASONS: Set<String> = setOf(PIN_MISMATCH, TLS_UNTRUSTED, TLS_OTHER)

    private val HOST = Regex("""\A(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?\z""")
    private const val MAX_HOST_CHARS = 253

    /**
     * A lower-case host name of at most 253 characters: labels of letters, digits and inner hyphens, a letter-led last
     * label, so no IP address, port, path, scheme or user. The CLI's `network-pinning.domains.host` rule is this one
     * plus at least one dot; a single-label name (`localhost`) is accepted here and never written by the CLI.
     */
    fun isHostName(value: String): Boolean = value.length <= MAX_HOST_CHARS && HOST.matches(value)
}
