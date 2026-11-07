package br.com.ebees.sentomaru.sdk.transport

import br.com.ebees.sentomaru.core.SentomaruError
import br.com.ebees.sentomaru.core.SentomaruException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class SignalsHeaderTest {
    @Test fun `ascii json passes unchanged`() {
        val json = """{"catalogVersion":"1.0.0","observations":[]}"""
        assertEquals(json, SignalsHeader.encode(json))
    }

    @Test fun `non ascii is escaped so the value stays printable ascii and valid json`() {
        val encoded = SignalsHeader.encode("""{"installer":"lojação ✓ 😀"}""")
        val bs = "\\"
        assertEquals("{\"installer\":\"loja${bs}u00e7${bs}u00e3o ${bs}u2713 ${bs}ud83d${bs}ude00\"}", encoded)
        assertTrue(encoded.all { it.code in 0x20..0x7E })
    }

    @Test fun `control characters and over long values are typed errors`() {
        for (bad in listOf("{\"a\":\"x\ny\"}", "{\"a\":\"\u007f\"}", "{\"a\":\"" + "x".repeat(SignalsHeader.MAX_LENGTH) + "\"}")) {
            val error = assertThrows(SentomaruException::class.java) { SignalsHeader.encode(bad) }.error
            assertEquals(SentomaruError.Reason.HEADER_VALUE, (error as SentomaruError.InvalidRequest).reason)
        }
    }

    @Test fun `exactly the limit is accepted`() {
        val json = "\"" + "x".repeat(SignalsHeader.MAX_LENGTH - 2) + "\""
        assertEquals(SignalsHeader.MAX_LENGTH, SignalsHeader.encode(json).length)
    }
}
