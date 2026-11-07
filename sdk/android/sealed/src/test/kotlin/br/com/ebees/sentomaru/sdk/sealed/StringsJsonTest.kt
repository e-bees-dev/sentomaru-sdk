package br.com.ebees.sentomaru.sdk.sealed

import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Test

/** The strings file after opening: a flat JSON object of texts in UTF-8, else `integrity`. */
class StringsJsonTest {
    private fun integrity(text: String) {
        try {
            StringsJson.parse(text)
            fail("expected integrity for $text")
        } catch (e: SentomaruSealedException) {
            assertEquals(SentomaruSealedException.Code.INTEGRITY, e.code)
        }
    }

    @Test
    fun `flat objects of texts parse, escapes included`() {
        assertEquals(emptyMap<String, String>(), StringsJson.parse(" { } "))
        assertEquals(mapOf("a" to "x", "b.c_1" to ""), StringsJson.parse("{\"a\":\"x\", \"b.c_1\" : \"\"}"))
        assertEquals(mapOf("k" to "\"\\/\b\u000c\n\r\tá€"), StringsJson.parse("{\"k\":\"\\\"\\\\\\/\\b\\f\\n\\r\\t\\u00e1\\u20AC\"}"))
        assertEquals(mapOf("k" to "2"), StringsJson.parse("{\"k\":\"1\",\"k\":\"2\"}"))  // last wins, as the reference
    }

    @Test
    fun `anything but a flat object of texts is integrity`() {
        for (text in listOf("", "[]", "\"x\"", "null", "{", "{\"a\"}", "{\"a\":1}", "{\"a\":null}", "{\"a\":{}}",
                "{\"a\":[\"x\"]}", "{\"a\":\"x\",}", "{\"a\":\"x\"} x", "{a:\"x\"}", "{\"a\":\"\\x\"}", "{\"a\":\"\\u12\"}",
                "{\"a\":\"\\u+123\"}", "{\"a\":\"line\nbreak\"}", "{\"a\":'x'}")) {
            integrity(text)
        }
    }

    @Test
    fun `invalid UTF-8 is integrity`() {
        try {
            StringsJson.lookup(byteArrayOf('{'.code.toByte(), '"'.code.toByte(), 0xc3.toByte(), '"'.code.toByte()), "a")
            fail("expected integrity")
        } catch (e: SentomaruSealedException) {
            assertEquals(SentomaruSealedException.Code.INTEGRITY, e.code)
        }
    }
}
