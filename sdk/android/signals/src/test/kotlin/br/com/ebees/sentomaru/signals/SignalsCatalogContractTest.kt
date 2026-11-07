package br.com.ebees.sentomaru.signals

import org.junit.Assert.*
import org.junit.Test
import java.io.File

/** D-05b: the SDK catalog (and so `CATALOG_VERSION`) comes from `contracts/sdk/signals-catalog-v1.json`. */
class SignalsCatalogContractTest {
    @Suppress("UNCHECKED_CAST")
    private val contract: Map<String, Any?> by lazy {
        val path = requireNotNull(System.getProperty("sentomaru.signalsCatalog")) { "sentomaru.signalsCatalog not set" }
        StrictJson.parse(File(path).readText()) as Map<String, Any?>
    }

    @Suppress("UNCHECKED_CAST")
    private val clientObserved: List<Map<String, Any?>>
        get() = (contract["capabilities"] as List<Map<String, Any?>>).filter { it["source"] == "client_observed" }

    @Test
    fun catalogVersionIsTheContractVersion() {
        assertEquals(contract["version"], SignalsCatalog.VERSION)
        assertEquals(contract["version"], SignalsCollector.CATALOG_VERSION)
    }

    @Test
    fun sdkCatalogIsExactlyTheClientObservedPartOfTheContract() {
        assertEquals(clientObserved.map { it["capabilityId"] }, SignalsCatalog.CAPABILITIES.map { it.capabilityId })
        for (json in clientObserved) {
            val cap = SignalsCatalog.CAPABILITIES.single { it.capabilityId == json["capabilityId"] }
            val id = cap.capabilityId
            assertEquals(id, json["version"], cap.version)
            assertEquals(id, json["description"], cap.description)
            assertEquals(id, json["source"], cap.source)
            assertEquals(id, json["supportedPlatforms"], cap.supportedPlatforms)
            assertEquals(id, (json["minSdk"] as Long).toInt(), cap.minSdk)
            assertEquals(id, json["supportedStates"], cap.supportedStates.map { it.name })
            assertEquals(id, json["budgetMs"], cap.budgetMs)
            assertEquals(id, json["limitations"], cap.limitations)
        }
    }

    @Test
    fun serverVerifiedCapabilitiesAreNeverCollectedByTheSdk() {
        @Suppress("UNCHECKED_CAST")
        val serverOnly = (contract["capabilities"] as List<Map<String, Any?>>)
            .filter { it["source"] != "client_observed" }.map { it["capabilityId"] }
        assertTrue(serverOnly.containsAll(listOf("play_integrity_failed", "build_unregistered", "app_identity_mismatch")))
        val collected = (SignalsCollector.defaultDetectors() + SignalsCollector.raspDetectors() +
            SignalsCollector.appIntegrityDetectors(emptyList()) + SignalsCollector.deviceThreatDetectors() + SignalsCollector.screenDetectors() + SignalsCollector.sessionDetectors()).map { it.capabilityId }
        assertTrue(collected.none { it in serverOnly })
    }

    @Test
    fun everyDetectorMatchesItsCatalogEntryAndFixture() {
        for (detector in SignalsCollector.defaultDetectors() + SignalsCollector.raspDetectors() +
            SignalsCollector.appIntegrityDetectors(emptyList()) + SignalsCollector.deviceThreatDetectors() + SignalsCollector.screenDetectors() + SignalsCollector.sessionDetectors()) {
            val cap = SignalsCatalog.CAPABILITIES.single { it.capabilityId == detector.capabilityId }
            assertEquals(detector.capabilityId, cap.version, detector.version)
            assertEquals(detector.capabilityId, cap.budgetMs, detector.budgetMs)
        }
        // The D-05 fixtures carry the clean detail the detectors send (indicators=none).
        for (json in clientObserved.filter { it["capabilityId"] in SignalsCatalog.RASP_CAPABILITY_IDS }) {
            @Suppress("UNCHECKED_CAST")
            val fixture = json["fixture"] as Map<String, Any?>
            assertEquals(mapOf("indicators" to "none"), fixture["detail"])
        }
    }
}
