package br.com.ebees.sentomaru.sdk

import org.junit.Assert.assertEquals
import org.junit.Test

class SdkScaffoldTest {
    @Test
    fun sdkSeesTheJvmCore() {
        assertEquals("sdk over core profile sentomaru-p0", SdkScaffold.describe())
    }
}
