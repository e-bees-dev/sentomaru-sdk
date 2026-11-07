package br.com.ebees.sentomaru.sentomaru_flutter

import br.com.ebees.sentomaru.hybrid.PluginConfig
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class PluginConfigTest {
    private val hosts = listOf("api.example.com")
    private val url = "https://api.example.com/enroll"

    @Test fun validArgumentsBuildTheExactScope() {
        val config = PluginConfig.parse("acme", "field", "prod", url, hosts, 3)
        assertEquals("acme", config.organization)
        assertEquals("field", config.app)
        assertEquals("prod", config.environment)
        assertEquals(setOf("api.example.com"), config.allowedHosts)
        assertEquals(3L, config.rotationGracePeriod.toDays())
    }

    @Test fun missingScopeIsAConfigurationErrorNeverADefaultScope() {
        val cases = listOf<Array<Any?>>(
            arrayOf(null, "field", "prod", url, hosts),
            arrayOf("acme", null, "prod", url, hosts),
            arrayOf("acme", "field", null, url, hosts),
            arrayOf("acme", "field", " ", url, hosts),
            arrayOf("acme", "field", "prod", null, hosts),
            arrayOf("acme", "field", "prod", url, null),
            arrayOf("acme", "field", "prod", url, emptyList<String>()),
            arrayOf("acme", "field", "prod", url, listOf(1)),
            arrayOf("Acme!", "field", "prod", url, hosts),
            arrayOf("acme", "field", "prod", "https://other.example.com/enroll", hosts),
            arrayOf("acme", "field", "prod", "http://api.example.com/enroll", hosts),
        )
        for (args in cases) {
            assertThrows(PluginConfig.Invalid::class.java) {
                PluginConfig.parse(args[0], args[1], args[2], args[3], args[4], null)
            }
        }
    }

    @Test fun playIntegrityProjectNumberIsOptionalAndValidated() {
        assertEquals(null, PluginConfig.parse("acme", "field", "prod", url, hosts, null).playIntegrityCloudProjectNumber)
        assertEquals(123456789012L, PluginConfig.parse("acme", "field", "prod", url, hosts, null, 123456789012L).playIntegrityCloudProjectNumber)
        assertEquals(42L, PluginConfig.parse("acme", "field", "prod", url, hosts, null, 42).playIntegrityCloudProjectNumber)
        for (bad in listOf<Any>(0, -1L, "123", 1.5)) {
            assertThrows(PluginConfig.Invalid::class.java) { PluginConfig.parse("acme", "field", "prod", url, hosts, null, bad) }
        }
    }

    // J-04r: renewalUrl is optional; when present it must be https on an allowlisted host.
    @Test fun renewalUrlIsOptionalAndValidated() {
        assertEquals(null, PluginConfig.parse("acme", "field", "prod", url, hosts, 3).renewalUrl)
        assertEquals("https://api.example.com/sessions",
            PluginConfig.parse("acme", "field", "prod", url, hosts, 3, null, "https://api.example.com/sessions").renewalUrl)
        for (bad in listOf<Any>("http://api.example.com/sessions", "https://other.example.com/sessions", " ", 42))
            assertThrows(PluginConfig.Invalid::class.java) { PluginConfig.parse("acme", "field", "prod", url, hosts, 3, null, bad) }
    }
}
