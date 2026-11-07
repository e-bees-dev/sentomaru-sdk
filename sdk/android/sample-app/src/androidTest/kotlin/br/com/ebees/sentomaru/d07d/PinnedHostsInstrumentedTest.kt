package br.com.ebees.sentomaru.d07d

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import br.com.ebees.sentomaru.sdk.SentomaruClient
import br.com.ebees.sentomaru.sdk.SentomaruConfig
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * D-07d on Android: [SentomaruClient.initialize] reads the meta-data `br.com.ebees.sentomaru.pinning.hosts` through the
 * real PackageManager. The test APK carries it (src/androidTest/AndroidManifest.xml); the sample app does not, and its
 * client has no pinned host (no meta-data, no event, nothing else changes). Compiled in this slice; the run in the
 * emulator and the pin failure itself (platform `network_security_config`) are the D-07e matrix. Own package, so the
 * C-06 and G-03c suites are unchanged.
 */
@RunWith(AndroidJUnit4::class)
class PinnedHostsInstrumentedTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()

    private fun config(app: String) = SentomaruConfig("d07d", app, "lab", setOf("api.example.test"),
        "https://api.example.test/v1/d07d/$app/lab/installations")

    @Test
    fun theMetaDataOfTheApkIsReadInItsOrder() {
        val client = SentomaruClient.initialize(instrumentation.context, config("with-meta"))
        assertEquals(listOf("lab-pin.sentomaru.test", "api.example.test"), client.pinnedHosts.toList())
    }

    @Test
    fun anAppWithoutTheMetaDataHasNoPinnedHost() {
        val client = SentomaruClient.initialize(instrumentation.targetContext, config("without-meta"))
        assertTrue(client.pinnedHosts.isEmpty())
    }
}
