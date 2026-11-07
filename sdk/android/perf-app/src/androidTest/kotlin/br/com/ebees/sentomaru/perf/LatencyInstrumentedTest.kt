package br.com.ebees.sentomaru.perf

import android.os.Bundle
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

/**
 * J-03 end-to-end latency: per iteration, a fresh installation (reset), then challenge, enrollment (local key
 * generation with attestation + send), signing and the signed operation (consumer -> API /evaluations).
 * Arguments: `cert` (consumer certificate, base64 DER), `iterations` (default 30), `warmup` (default 3).
 * The rows go to the instrumentation result `j03` as JSON, written before any assertion.
 */
@RunWith(AndroidJUnit4::class)
class LatencyInstrumentedTest {

    @Test
    fun journey_latency() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val arguments = InstrumentationRegistry.getArguments()
        val journey = Journey(requireNotNull(arguments.getString("cert")) { "cert argument required" })
        val iterations = arguments.getString("iterations")?.toInt() ?: 30
        val warmup = arguments.getString("warmup")?.toInt() ?: 3
        val client = PerfScope.client(instrumentation.targetContext)
        val rows = JSONArray()
        val rejected = JSONArray()
        val body = "{\"j03\":true}".toByteArray()
        try {
            repeat(warmup + iterations) { index ->
                client.reset()
                var mark = System.nanoTime()
                fun lap(): Long = System.nanoTime().let { now -> (now - mark).also { mark = now } }
                journey.health()
                val health = lap()
                val challenge = journey.challenge()
                val challengeNs = lap()
                var sendNs = 0L
                val grant = journey.enroll(client, challenge) { sendNs = it }
                val enrollNs = lap()
                val signed = client.sign("POST", PerfScope.OPERATION_URL, "submit", body)
                val signNs = lap()
                val status = journey.submit(signed.targetUri, signed.headers, body)
                val operationNs = lap()
                if (status != "valid") rejected.put(status)
                if (index >= warmup) rows.put(JSONObject()
                    .put("healthMs", ms(health)).put("challengeMs", ms(challengeNs))
                    .put("enrollMs", ms(enrollNs)).put("enrollSendMs", ms(sendNs))
                    .put("signMs", ms(signNs)).put("operationMs", ms(operationNs))
                    .put("hardware", grant.hardwareStatus).put("attestation", grant.attestationStatus)
                    .put("status", status))
            }
        } finally {
            client.reset()
            instrumentation.addResults(Bundle().apply {
                putString("j03", JSONObject().put("warmup", warmup).put("rows", rows).put("rejected", rejected).toString())
            })
        }
        assertEquals("rejected operations: $rejected", 0, rejected.length())
    }

    private fun ms(nanos: Long): Double = Math.round(nanos / 10_000.0) / 100.0
}
