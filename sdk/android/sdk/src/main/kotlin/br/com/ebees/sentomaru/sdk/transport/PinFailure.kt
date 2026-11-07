package br.com.ebees.sentomaru.sdk.transport

import android.content.Context
import android.content.pm.PackageManager
import br.com.ebees.sentomaru.sdk.SentomaruClient
import br.com.ebees.sentomaru.signals.SentomaruSignalEvents
import br.com.ebees.sentomaru.signals.TransportEventCodes
import java.security.cert.CertPathValidatorException
import java.security.cert.CertificateException
import java.util.Collections
import java.util.IdentityHashMap
import javax.net.ssl.SSLException
import javax.net.ssl.SSLPeerUnverifiedException

/**
 * D-07d (D-07x11): the hosts `sentomaru protect` pinned in this app, read from the `<application>` meta-data
 * [META_DATA] the CLI writes only when the app has the SDK (comma-separated host names, no space, in the profile's
 * order; contract `cli-v1.md`, "network-pinning (D-07)"). The SDK never reads the profile. A value that is not
 * that ([TransportEventCodes.isHostName] per item; an empty item, a space, upper case, more than [MAX_HOSTS] hosts, a
 * repeated host) is ignored whole: no host, no event. Matching is exact on the host name: a subdomain covered by `includeSubdomains` is pinned by the platform but
 * gives no event (the meta-data carries no subdomain flag).
 */
internal class PinnedHosts private constructor(val hosts: Set<String>) {
    val isEmpty: Boolean get() = hosts.isEmpty()

    /**
     * The pinned host as listed in the meta-data for a request host (one final dot ignored), or null. ASCII only: the
     * CLI writes ASCII names, so an internationalized host must be pinned and requested in its punycode form.
     */
    fun match(requestHost: String): String? {
        if (hosts.isEmpty()) return null
        val name = requestHost.lowercase().removeSuffix(".")
        return name.takeIf { it in hosts }
    }

    companion object {
        const val META_DATA = "br.com.ebees.sentomaru.pinning.hosts"
        /** The CLI's `network-pinning.domains` ceiling. */
        const val MAX_HOSTS = 16
        val NONE = PinnedHosts(emptySet())

        /** Parses the meta-data value; null or anything malformed is [NONE]. */
        fun parse(value: String?): PinnedHosts {
            if (value.isNullOrEmpty()) return NONE
            val items = value.split(',')
            if (items.size > MAX_HOSTS) return NONE
            if (!items.all(TransportEventCodes::isHostName)) return NONE
            val set = LinkedHashSet(items)
            if (set.size != items.size) return NONE
            return PinnedHosts(Collections.unmodifiableSet(set))
        }

        /**
         * Reads [META_DATA] through the PackageManager (one binder call, under the lock of [SentomaruClient.initialize],
         * once per client); any failure (no meta-data, a non-string value, a PackageManager error) is [NONE].
         */
        @Suppress("DEPRECATION") // getApplicationInfo(String, Int): the ApplicationInfoFlags overload is API 33+
        fun fromManifest(context: Context): PinnedHosts = try {
            val metaData = context.packageManager.getApplicationInfo(context.packageName, PackageManager.GET_META_DATA).metaData
            parse(metaData?.get(META_DATA) as? String)
        } catch (e: VirtualMachineError) {
            throw e
        } catch (_: Throwable) {
            NONE
        }
    }
}

/**
 * D-07d: names a TLS failure. The platform refuses a handshake that does not match a pin-set
 * (`NetworkSecurityTrustManager.checkPins` throws `CertificateException("Pin verification failed")`, read in AOSP on
 * 26/10/2026; Conscrypt passes it on as the cause of an `SSLHandshakeException`); the message is the only mark that
 * tells it apart from another certificate failure, and the device proof (D-07e, API 28 and 34 in the emulator, Android
 * 15 on the reference device) confirms it per version. Only the cause chain of the exception is read (at most [MAX_DEPTH]
 * links, no cycle); suppressed exceptions are not.
 */
internal object PinFailure {
    const val PLATFORM_PIN_MESSAGE = "Pin verification failed"
    private const val MAX_DEPTH = 16

    /**
     * `pin_mismatch` when a [CertificateException] of the chain carries the platform's pin message; `tls_untrusted`
     * for any other [CertificateException], a [CertPathValidatorException] (a path check passed on without a
     * `CertificateException` around it) or an [SSLPeerUnverifiedException] (OkHttp's hostname check, an app's own
     * `CertificatePinner`); `tls_other` for any other [SSLException]; null when the chain has no TLS failure.
     *
     * Deliberate refinement of the spec's "another CertificateException/SSLHandshakeException is tls_untrusted" (review
     * R I-1): an `SSLHandshakeException` with no certificate failure in its chain (alert, protocol version, connection
     * cut during the handshake) is `tls_other`, because nothing says the peer was not trusted.
     */
    fun classify(failure: Throwable): String? {
        val seen = Collections.newSetFromMap(IdentityHashMap<Throwable, Boolean>())
        var current: Throwable? = failure
        var certificate = false
        var tls = false
        var depth = 0
        while (current != null && depth < MAX_DEPTH && seen.add(current)) {
            if (current is CertificateException) {
                if (current.message == PLATFORM_PIN_MESSAGE) return TransportEventCodes.PIN_MISMATCH
                certificate = true
            }
            if (current is SSLPeerUnverifiedException || current is CertPathValidatorException) certificate = true
            if (current is SSLException) tls = true
            current = current.cause
            depth++
        }
        return when {
            certificate -> TransportEventCodes.TLS_UNTRUSTED
            tls -> TransportEventCodes.TLS_OTHER
            else -> null
        }
    }
}

/**
 * D-07d: hands a failed exchange with a pinned host to the events; the failure itself is always rethrown unchanged by
 * the caller. Exists only when the app passed `events` and the client has pinned hosts ([of]); otherwise the transports
 * behave exactly as before. Never throws (except a `VirtualMachineError`).
 */
internal class PinFailureReporter private constructor(private val pinned: PinnedHosts, private val events: SentomaruSignalEvents) {
    fun observe(requestHost: String, failure: Throwable) {
        try {
            if (!events.hasTransportListeners) return
            val host = pinned.match(requestHost) ?: return
            val reason = PinFailure.classify(failure) ?: return
            events.observePinFailure(host, reason)
        } catch (e: VirtualMachineError) {
            throw e
        } catch (_: Throwable) {
            // Costs only the event.
        }
    }

    companion object {
        fun of(client: SentomaruClient, events: SentomaruSignalEvents?): PinFailureReporter? {
            val pinned = client.pinnedHostSet
            return if (events == null || pinned.isEmpty) null else PinFailureReporter(pinned, events)
        }
    }
}
