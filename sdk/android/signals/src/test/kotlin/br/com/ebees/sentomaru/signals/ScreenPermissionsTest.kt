package br.com.ebees.sentomaru.signals

import android.content.Context
import android.content.pm.PackageManager
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Shield #2: the library declares no permission, so the screen shield checks the host's at run time and degrades to UNKNOWN without it. */
class ScreenPermissionsTest {
    private val context: Context = object : android.content.ContextWrapper(null) {}

    @Test fun grantedOnlyWhenThePlatformSaysGranted() {
        val asked = mutableListOf<String>()
        assertTrue(ScreenPermissions.granted(context, ScreenPermissions.CAPTURE) { _, p -> asked += p; PackageManager.PERMISSION_GRANTED })
        assertFalse(ScreenPermissions.granted(context, ScreenPermissions.RECORDING) { _, p -> asked += p; PackageManager.PERMISSION_DENIED })
        assertEquals(listOf("android.permission.DETECT_SCREEN_CAPTURE", "android.permission.DETECT_SCREEN_RECORDING"), asked)
    }

    @Test fun aFailingCheckIsNotGranted() {
        assertFalse(ScreenPermissions.granted(context, ScreenPermissions.CAPTURE) { _, _ -> throw SecurityException("no") })
    }

    @Test fun theNamesAreTheTwoPermissionsOfTheManifestTheHostDeclares() {
        assertEquals("android.permission.DETECT_SCREEN_CAPTURE", ScreenPermissions.CAPTURE)
        assertEquals("android.permission.DETECT_SCREEN_RECORDING", ScreenPermissions.RECORDING)
    }
}
