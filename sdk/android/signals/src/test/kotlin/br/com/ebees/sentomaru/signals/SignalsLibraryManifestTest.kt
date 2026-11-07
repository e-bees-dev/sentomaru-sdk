package br.com.ebees.sentomaru.signals

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test
import java.io.File

/**
 * Shield #2: a host app merges this library's manifest. It must add no permission (the screen shield's
 * `DETECT_SCREEN_*` belong to the app that installs [ScreenShield]) and only the launcher-intent `<queries>` of D-24d.
 */
class SignalsLibraryManifestTest {
    private val manifest: String by lazy {
        File(requireNotNull(System.getProperty("sentomaru.signalsLibraryManifest")) { "sentomaru.signalsLibraryManifest not set" })
            .readText().replace(Regex("<!--.*?-->", RegexOption.DOT_MATCHES_ALL), "")
    }

    @Test
    fun theLibraryDeclaresNoPermissionAtAll() {
        assertFalse(manifest, manifest.contains("uses-permission"))
        assertFalse(manifest.contains("DETECT_SCREEN"))
        assertFalse(manifest.contains("QUERY_ALL_PACKAGES"))
    }

    @Test
    fun queriesAreOnlyTheLauncherIntent() {
        assertEquals(1, Regex("<queries>").findAll(manifest).count())
        assertEquals(1, Regex("<intent>").findAll(manifest).count())
        assertFalse(manifest.contains("<package"))
        assertFalse(manifest.contains("<application"))
    }
}
