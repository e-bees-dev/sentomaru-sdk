package br.com.ebees.sentomaru.signals.rasp

import br.com.ebees.sentomaru.signals.SignalsCatalog
import br.com.ebees.sentomaru.signals.detectors.RootArtifactsDetector
import org.junit.Assert.*
import org.junit.Test
import java.io.File

/** D-05: the opt-in signals-rasp manifest asks for nothing but the fixed root-manager `<queries>` of the catalog. */
class SignalsManifestTest {
    private val manifest: String by lazy {
        File(requireNotNull(System.getProperty("sentomaru.signalsManifest")) { "sentomaru.signalsManifest not set" })
            .readText()
            .replace(Regex("<!--.*?-->", RegexOption.DOT_MATCHES_ALL), "")
    }

    @Test
    fun queriesListExactlyTheCatalogRootManagerPackages() {
        val queries = Regex("<queries>(.*?)</queries>", RegexOption.DOT_MATCHES_ALL).findAll(manifest).toList()
        assertEquals("one <queries> block", 1, queries.size)
        val packages = Regex("""<package\s+android:name="([^"]+)"\s*/>""").findAll(queries.single().groupValues[1])
            .map { it.groupValues[1] }.toList()
        assertEquals(SignalsCatalog.ROOT_MANAGER_PACKAGES, packages)
        assertEquals("no <intent> or <provider> query", 0, Regex("<(intent|provider)\\b").findAll(queries.single().value).count())
    }

    @Test
    fun noPermissionAndNeverQueryAllPackages() {
        assertFalse(manifest.contains("QUERY_ALL_PACKAGES"))
        assertFalse(manifest.contains("uses-permission"))
        assertFalse(manifest.contains("<application"))
    }

    @Test
    fun detectorLooksUpThisArtifactsMarker() {
        assertEquals(RootManagerQueries::class.java.name, RootArtifactsDetector.QUERIES_MARKER)
    }
}
