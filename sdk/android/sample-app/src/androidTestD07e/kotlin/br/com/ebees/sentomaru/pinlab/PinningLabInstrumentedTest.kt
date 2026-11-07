package br.com.ebees.sentomaru.pinlab

import android.os.Bundle
import android.security.NetworkSecurityPolicy
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import br.com.ebees.sentomaru.sdk.SentomaruClient
import br.com.ebees.sentomaru.sdk.SentomaruConfig
import br.com.ebees.sentomaru.sdk.transport.SentomaruUrlConnection
import br.com.ebees.sentomaru.sdk.transport.addSentomaru
import br.com.ebees.sentomaru.signals.SentomaruSignalEvents
import br.com.ebees.sentomaru.signals.SentomaruTransportEvent
import java.net.HttpURLConnection
import java.net.Proxy
import java.net.URL
import java.security.cert.CertificateException
import java.util.Collections
import java.util.IdentityHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.TimeUnit
import okhttp3.Call
import okhttp3.ConnectionPool
import okhttp3.EventListener
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import org.json.JSONObject
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * D-07e / C-03b: one pass of the pinning matrix for the native stacks, in the process of the
 * app under test (`br.com.ebees.sentomaru.pinlab`), so the app's `network_security_config` (written by `sentomaru
 * protect`, or absent in the control build) is the one that decides. The app's own code is not changed; this test only
 * drives the transports a client app already has:
 *  - `okhttp`: OkHttp with the one line `addSentomaru(client, null, events)` (D-07d event on a pin failure);
 *  - `urlconnection`: `SentomaruUrlConnection.send(...)` with the same events (the Java path of JavaUrlConnectionSample);
 *  - `plain`: a bare `HttpURLConnection`, no SDK (the platform refuses it too; no event by design);
 *  - `http-pinned-*` / `http-other-*`: the same stacks over http to the pinned host and to another host (cleartext row);
 *  - `measure-handshake`: `-e measure N` fresh OkHttp clients (no SDK, no shared pool): connect and TLS time.
 *
 * No enrollment and no call to any Sentomaru API: the SDK client's allowlist holds only `sentomaru-d07e.invalid`, so
 * every request here passes the interceptor unsigned (outside the allowlist), and the pin failure event still fires
 * for a host of the app's pinning meta-data. Nothing is installed on the server (no A-18 cleanup for this test).
 *
 * Each case is one instrumentation status `d07eCase` (JSON) with fields of limited format only: the case id, `ok` or
 * `refused`, the HTTP status, the simple class names of the failure chain, whether the chain carries the platform's
 * pin message, the event reason and whether its host is the pinned host, and times in ms. Never a URL, address, host
 * name, certificate, exception message or device identifier. The gabarito is checked by the vendor's run d07e device check.
 */
@RunWith(AndroidJUnit4::class)
class PinningLabInstrumentedTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val args: Bundle = InstrumentationRegistry.getArguments()

    @Test
    fun matrixPass() {
        val run = args.getString("run").orEmpty()
        val base = args.getString("base") ?: DEFAULT_BASE
        val httpOther = args.getString("httpOther")
        val cases = args.getString("cases").orEmpty().split(',').filter { it.isNotEmpty() }
        val measure = args.getString("measure")?.toIntOrNull() ?: 0
        assertTrue("run must be 8-16 [a-z0-9]", RUN.matches(run))
        assertTrue("base must be https://<host>[:port]", BASE.matches(base))
        assertTrue("httpOther must be http://<host>:<port>", httpOther == null || HTTP_OTHER.matches(httpOther))
        assertTrue("unknown case", cases.isNotEmpty() && cases.all { it in CASES })
        assertTrue("measure 0..50", measure in 0..50)
        val pinnedHost = URL(base).host

        val context = instrumentation.targetContext
        val client = SentomaruClient.initialize(context, SentomaruConfig("d07e", "pin-lab", "lab",
            setOf(ALLOWLIST_HOST), "https://$ALLOWLIST_HOST/v1/d07e/pin-lab/lab/installations"))
        val seen = CopyOnWriteArrayList<SentomaruTransportEvent>()
        val events = SentomaruSignalEvents().apply { addTransportListener({ it.run() }) { seen.add(it) } }
        val policy = NetworkSecurityPolicy.getInstance()
        send(JSONObject().put("id", "meta").put("pinnedHosts", client.pinnedHosts.size)
            .put("pinnedHostListed", pinnedHost in client.pinnedHosts)
            .put("cleartextPinned", policy.isCleartextTrafficPermitted(pinnedHost))
            .put("cleartextOther", httpOther?.let { policy.isCleartextTrafficPermitted(URL(it).host) } ?: JSONObject.NULL))

        val okhttp = OkHttpClient.Builder().callTimeout(25, TimeUnit.SECONDS).connectTimeout(15, TimeUnit.SECONDS)
            .proxy(Proxy.NO_PROXY).addSentomaru(client, null, events).build()
        for (case in cases) {
            if (case == "measure-handshake") {
                send(measureHandshake(base, run, measure))
                continue
            }
            val url = when {
                case.startsWith("http-pinned-") -> "http://$pinnedHost/d07e/$run/$case"
                case.startsWith("http-other-") -> "${httpOther ?: continue}/d07e/$run/$case"
                else -> "$base/d07e/$run/$case"
            }
            val before = seen.size
            val started = System.nanoTime()
            // I-6: the device's wall clock at the start (the runner links the MITM connections by time, minus skew).
            val out = JSONObject().put("id", case).put("startedAt", System.currentTimeMillis())
            try {
                val status = when {
                    case.endsWith("okhttp") -> okhttp.newCall(Request.Builder().url(url).build()).execute().use {
                        it.body?.bytes(); it.code
                    }
                    case.endsWith("urlconnection") -> SentomaruUrlConnection.send(client, null, "GET", URL(url), null,
                        emptyMap(), null, events, null).let { c -> c.connectTimeout = 15_000; c.readTimeout = 15_000; read(c) }
                    else -> (URL(url).openConnection(Proxy.NO_PROXY) as HttpURLConnection).let { c ->
                        c.connectTimeout = 15_000; c.readTimeout = 15_000; read(c)
                    }
                }
                out.put("outcome", "ok").put("status", status)
            } catch (e: Exception) {
                out.put("outcome", "refused").put("error", chain(e)).put("chainPin", carriesPinMessage(e))
            }
            out.put("ms", (System.nanoTime() - started) / 1_000_000)
            val fresh = seen.drop(before)
            out.put("event", fresh.firstOrNull()?.reason ?: "none").put("events", fresh.size)
            if (fresh.isNotEmpty()) out.put("eventHostPinned", fresh.all { it.host == pinnedHost && it.type == "pin_failure" })
            send(out)
        }
    }

    private fun read(c: HttpURLConnection): Int {
        val status = c.responseCode
        (if (status < 400) c.inputStream else c.errorStream)?.use { it.readBytes() }
        c.disconnect()
        return status
    }

    /** `-e measure N`: N fresh clients (no SDK, own pool): connect and TLS handshake time of the first call, in ms. */
    private fun measureHandshake(base: String, run: String, n: Int): JSONObject {
        val tls = mutableListOf<Double>()
        val total = mutableListOf<Double>()
        var failures = 0
        repeat(n) { i ->
            val marks = LongArray(4)
            val listener = object : EventListener() {
                override fun connectStart(call: Call, inetSocketAddress: java.net.InetSocketAddress, proxy: Proxy) { marks[0] = System.nanoTime() }
                override fun secureConnectStart(call: Call) { marks[1] = System.nanoTime() }
                override fun secureConnectEnd(call: Call, handshake: okhttp3.Handshake?) { marks[2] = System.nanoTime() }
                override fun connectEnd(call: Call, inetSocketAddress: java.net.InetSocketAddress, proxy: Proxy, protocol: Protocol?) { marks[3] = System.nanoTime() }
            }
            val fresh = OkHttpClient.Builder().connectionPool(ConnectionPool(0, 1, TimeUnit.SECONDS)).proxy(Proxy.NO_PROXY)
                .eventListener(listener).callTimeout(20, TimeUnit.SECONDS).build()
            try {
                fresh.newCall(Request.Builder().url("$base/d07e/$run/measure-$i").build()).execute().use { it.body?.bytes() }
                if (marks[1] > 0 && marks[2] > marks[1]) tls.add((marks[2] - marks[1]) / 1e6)
                if (marks[0] > 0 && marks[3] > marks[0]) total.add((marks[3] - marks[0]) / 1e6)
            } catch (_: Exception) {
                failures++
            } finally {
                fresh.connectionPool.evictAll()
            }
        }
        return JSONObject().put("id", "measure-handshake").put("n", tls.size).put("failures", failures)
            .put("tlsMs", stats(tls)).put("connectMs", stats(total))
    }

    private fun stats(values: List<Double>): JSONObject {
        if (values.isEmpty()) return JSONObject().put("n", 0)
        val sorted = values.sorted()
        fun rank(p: Int) = sorted[((p * sorted.size + 99) / 100 - 1).coerceIn(0, sorted.size - 1)]
        fun r(v: Double) = Math.round(v * 10) / 10.0
        return JSONObject().put("n", sorted.size).put("p50", r(rank(50))).put("p90", r(rank(90)))
            .put("min", r(sorted.first())).put("max", r(sorted.last()))
    }

    private fun send(out: JSONObject) = instrumentation.sendStatus(STATUS_CODE, Bundle().apply { putString(KEY, out.toString()) })

    companion object {
        const val KEY = "d07eCase"
        const val STATUS_CODE = 2
        const val DEFAULT_BASE = "https://lab-pin.sentomaru.com.br"
        const val ALLOWLIST_HOST = "sentomaru-d07e.invalid"
        val CASES = setOf("okhttp", "urlconnection", "plain", "http-pinned-okhttp", "http-pinned-urlconnection",
            "http-pinned-plain", "http-other-okhttp", "http-other-urlconnection", "http-other-plain", "measure-handshake")
        private val RUN = Regex("[a-z0-9]{8,16}")
        private val BASE = Regex("https://[a-z0-9.-]{1,253}(:[0-9]{1,5})?")
        private val HTTP_OTHER = Regex("http://[a-z0-9.-]{1,253}:[0-9]{1,5}")
        private val NAME = Regex("[A-Za-z][A-Za-z0-9]{0,63}")
        private const val MAX_CHAIN = 6

        /** Simple class names of the cause chain (at most [MAX_CHAIN], no cycle), joined by `<`; never a message. */
        fun chain(e: Throwable): String {
            val seen = Collections.newSetFromMap(IdentityHashMap<Throwable, Boolean>())
            val names = mutableListOf<String>()
            var current: Throwable? = e
            while (current != null && names.size < MAX_CHAIN && seen.add(current)) {
                names.add(current.javaClass.simpleName.takeIf { NAME.matches(it) } ?: "Other")
                current = current.cause
            }
            return names.joinToString("<")
        }

        /** Whether a CertificateException of the chain carries the platform's pin message (D-07d, per Android version). */
        fun carriesPinMessage(e: Throwable): Boolean {
            val seen = Collections.newSetFromMap(IdentityHashMap<Throwable, Boolean>())
            var current: Throwable? = e
            while (current != null && seen.add(current)) {
                if (current is CertificateException && current.message == "Pin verification failed") return true
                current = current.cause
            }
            return false
        }

    }
}
