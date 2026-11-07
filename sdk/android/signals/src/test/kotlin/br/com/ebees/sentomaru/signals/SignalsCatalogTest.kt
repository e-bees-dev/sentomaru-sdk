package br.com.ebees.sentomaru.signals

import org.junit.Assert.*
import org.junit.Test

class SignalsCatalogTest {
    @Test
    fun catalogStatesMatchDecisionE5() {
        assertEquals(
            listOf("DETECTED", "NOT_DETECTED", "UNKNOWN", "UNSUPPORTED", "ERROR", "STALE"),
            SignalState.values().map { it.name },
        )
        // Absence of detection must stay distinguishable from "clean" (SDK-SIG-2).
        assertNotEquals(SignalState.NOT_DETECTED, SignalState.UNKNOWN)
        assertNotEquals(SignalState.NOT_DETECTED, SignalState.UNSUPPORTED)
    }

    @Test
    fun catalogRegistersTheFrozenSixAndTheD05Six() {
        val frozen = listOf(
            "debug_attached",
            "emulator_detected",
            "root_indicated",
            "app_signing_digest",
            "installer_source",
            "os_version",
        )
        val rasp = listOf(
            "debugger_attached",
            "app_debuggable",
            "dev_settings_enabled",
            "root_artifacts",
            "emulator_indicated",
            "hook_framework_java",
        )
        assertEquals(frozen, SignalsCatalog.DEFAULT_CAPABILITY_IDS)
        assertEquals(rasp, SignalsCatalog.RASP_CAPABILITY_IDS)
        val appIntegrity = listOf("app_signer_mismatch", "installer_class", "code_integrity")
        assertEquals(appIntegrity, SignalsCatalog.APP_INTEGRITY_CAPABILITY_IDS)
        val deviceThreat = listOf("a11y_risk", "overlay", "ime_untrusted", "synthetic_input", "known_malware")
        assertEquals(deviceThreat, SignalsCatalog.DEVICE_THREAT_CAPABILITY_IDS)
        val screen = listOf("screen_capture", "screen_shared")
        assertEquals(screen, SignalsCatalog.SCREEN_CAPABILITY_IDS)
        val session = listOf("location_mock", "call_active")
        assertEquals(session, SignalsCatalog.SESSION_CAPABILITY_IDS)
        assertEquals(frozen + rasp + appIntegrity + deviceThreat + screen + session, SignalsCatalog.CAPABILITIES.map { it.capabilityId })
        assertEquals(24, SignalsCatalog.CAPABILITIES.size)
        assertEquals("1.15.0", SignalsCatalog.VERSION)
    }

    @Test
    fun capabilitiesFollowDecisionE5RulesAndBudgets() {
        for (cap in SignalsCatalog.CAPABILITIES) {
            assertEquals(if (cap.capabilityId == "synthetic_input" || cap.capabilityId == "screen_capture") "1.1.0" else "1.0.0", cap.version) // D-27: injected_touch; D-20: screen_capture scope all (catalog 1.15.0)
            assertEquals("client_observed", cap.source)
            assertTrue("Platform must be android", cap.supportedPlatforms.contains("android"))
            assertEquals(28, cap.minSdk)
            assertTrue("Budget must be positive", cap.budgetMs > 0)
            assertTrue("Limitations must be documented", cap.limitations.isNotEmpty())
            // D-12c: code_integrity is never decided by the SDK (the server compares), so it declares no DETECTED.
            if (cap.capabilityId != "code_integrity")
                assertTrue("Supported states must include DETECTED", cap.supportedStates.contains(SignalState.DETECTED))
        }
        // Catalog 1.7.0: ios only where the iOS SDK (D-10e) collects a value; every entry keeps android and minSdk.
        assertEquals(
            listOf("debug_attached", "emulator_detected", "root_indicated", "os_version", "screen_shared"),
            SignalsCatalog.CAPABILITIES.filter { "ios" in it.supportedPlatforms }.map { it.capabilityId },
        )
        assertTrue(SignalsCatalog.CAPABILITIES.all { setOf("android", "ios").containsAll(it.supportedPlatforms) })
        val budget = SignalsCatalog.CAPABILITIES.associate { it.capabilityId to it.budgetMs }
        val frozenBudget = SignalsCatalog.DEFAULT_CAPABILITY_IDS.sumOf { budget.getValue(it) }
        assertTrue("Total individual budgets should be <= overall budget", frozenBudget <= SignalsCollector.OVERALL_BUDGET_MS)
        val d05 = SignalsCatalog.DEFAULT_CAPABILITY_IDS + SignalsCatalog.RASP_CAPABILITY_IDS
        assertTrue("All twelve budgets fit the D-05 deadline", d05.sumOf { budget.getValue(it) } <= SignalsCollector.RASP_DEADLINE_MS)
        assertEquals(SignalsCollector.APP_INTEGRITY_BUDGET_MS, SignalsCatalog.APP_INTEGRITY_CAPABILITY_IDS.sumOf { budget.getValue(it) })
        assertEquals(SignalsCollector.DEVICE_THREAT_BUDGET_MS, SignalsCatalog.DEVICE_THREAT_CAPABILITY_IDS.sumOf { budget.getValue(it) })
        assertEquals(SignalsCollector.SCREEN_BUDGET_MS, SignalsCatalog.SCREEN_CAPABILITY_IDS.sumOf { budget.getValue(it) })
        assertEquals(SignalsCollector.SESSION_BUDGET_MS, SignalsCatalog.SESSION_CAPABILITY_IDS.sumOf { budget.getValue(it) })
    }

    @Test
    fun d05CapabilitiesDeclareEveryStateTheirDetectorsEmit() {
        // DETECTED/NOT_DETECTED/UNKNOWN (partial, timeout) and ERROR (unexpected exception in the detector).
        for (id in SignalsCatalog.RASP_CAPABILITY_IDS) {
            val states = SignalsCatalog.CAPABILITIES.single { it.capabilityId == id }.supportedStates
            assertTrue(id, states.containsAll(listOf(SignalState.DETECTED, SignalState.NOT_DETECTED, SignalState.UNKNOWN, SignalState.ERROR)))
            assertFalse("STALE is set by the server only", states.contains(SignalState.STALE))
        }
    }

    @Test
    fun appIntegrityCapabilitiesNeverDeclareACleanStateTheSdkCannotProve() {
        val states = SignalsCatalog.CAPABILITIES.associate { it.capabilityId to it.supportedStates }
        for (id in SignalsCatalog.APP_INTEGRITY_CAPABILITY_IDS) {
            assertTrue(id, states.getValue(id).containsAll(listOf(SignalState.UNKNOWN, SignalState.ERROR)))
            assertFalse("STALE is set by the server only", states.getValue(id).contains(SignalState.STALE))
        }
        assertFalse(states.getValue("code_integrity").contains(SignalState.NOT_DETECTED))
        assertFalse(states.getValue("code_integrity").contains(SignalState.DETECTED))
        assertFalse(states.getValue("installer_class").contains(SignalState.NOT_DETECTED))
        assertTrue(states.getValue("app_signer_mismatch").containsAll(listOf(SignalState.DETECTED, SignalState.NOT_DETECTED)))
    }
}
