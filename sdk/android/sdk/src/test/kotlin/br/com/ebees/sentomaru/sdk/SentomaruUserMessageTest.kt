package br.com.ebees.sentomaru.sdk

import br.com.ebees.sentomaru.core.SentomaruError
import br.com.ebees.sentomaru.core.SentomaruException
import java.io.File
import java.util.Locale
import org.junit.Assert.*
import org.junit.Test

/** sdk-user-message-v1: the default text, the language resolution, the host override and the code map are pinned by the shared vector. */
class SentomaruUserMessageTest {
    private val vectors: String = listOf("contracts/sdk/user-message-vectors-v1.json", "../../../contracts/sdk/user-message-vectors-v1.json",
        "../../contracts/sdk/user-message-vectors-v1.json").map { File(it) }.first { it.isFile }.readText()

    private fun strings(text: String) = Regex("\"((?:[^\"\\\\]|\\\\.)*)\"\\s*:\\s*(\"((?:[^\"\\\\]|\\\\.)*)\"|null)").findAll(text)
        .associate { it.groupValues[1] to it.groups[3]?.value }

    @Test fun defaultTextsMatchTheVector() {
        val texts = strings(vectors.substringAfter("\"texts\": {").substringBefore("}"))
        assertEquals(setOf("pt-BR", "en", "es"), texts.keys)
        texts.forEach { (locale, text) -> assertEquals(text, SentomaruUserMessage.resolve(locale)) }
        assertEquals("critical_operations_blocked", SentomaruUserMessage.KEY)
    }

    @Test fun localeResolutionMatchesTheVector() {
        val section = vectors.substringAfter("\"localeResolution\": [").substringBefore("\n ]")
        val cases = Regex("\"tag\":\\s*(null|\"([^\"]*)\"),\\s*\"locale\":\\s*\"([^\"]+)\"").findAll(section).toList()
        assertTrue(cases.size >= 10)
        cases.forEach { assertEquals(it.groupValues[3], SentomaruUserMessage.resolveLocale(if (it.groupValues[1] == "null") null else it.groupValues[2])) }
        assertEquals("pt-BR", SentomaruUserMessage.resolveLocale(Locale.forLanguageTag("pt-BR").toLanguageTag()))
    }

    @Test fun overridesBehaveAsTheVectorSays() {
        val cases = Regex("\"locale\":\\s*\"([^\"]+)\",\\s*\"overrides\":\\s*(null|\\{([^}]*)\\}),\\s*\"expected\":\\s*\"([^\"]*)\"")
            .findAll(vectors.substringAfter("\"overrides\": [")).toList()
        assertEquals(5, cases.size)
        cases.forEach {
            val map = if (it.groupValues[2] == "null") null else strings(it.groupValues[3]).mapValues { e -> e.value!! }
            assertEquals(it.groupValues[4], SentomaruUserMessage.resolve(it.groupValues[1], map))
        }
    }

    @Test fun codeMapMatchesTheVector() {
        val section = vectors.substringAfter("\"mobileCodes\": {").substringAfter("\"map\": {").substringBefore("}")
        val map = strings(section)
        assertTrue(map.size >= 25)
        map.forEach { (code, situation) ->
            val got = SentomaruUserMessage.situationFor(code)
            assertEquals(code, situation?.uppercase(), got?.name)
            assertEquals(code, got != null, SentomaruUserMessage.forCode(code, "en") != null)
        }
        assertNull(SentomaruUserMessage.forCode("NeverSeenBefore"))
        assertNull(SentomaruUserMessage.forCode(null))
    }

    @Test fun textNeverCarriesInternalDetail() {
        val words = Regex("\"([^\"]+)\"").findAll(vectors.substringAfter("\"forbiddenInText\": [").substringBefore("]")).map { it.groupValues[1] }.toList()
        assertTrue(words.isNotEmpty())
        SentomaruUserMessage.defaults.values.forEach { text -> words.forEach { assertFalse("$it in $text", text.contains(it, ignoreCase = true)) } }
    }

    @Test fun errorCodesAreUnchanged() {
        assertEquals("InvalidRequest:PARAMS", SentomaruError.InvalidRequest(SentomaruError.Reason.PARAMS).code)
    }

    /** README's integration example: `SentomaruException.userMessage()`/`SentomaruError.userMessage()`, same text as `forCode`, on a real thrown error. */
    @Test fun aRealThrownExceptionResolvesTheSameWayAsForCode() {
        try {
            throw SentomaruException(EnrollmentError.KeyInvalidated())
        } catch (e: SentomaruException) {
            assertEquals(SentomaruUserMessage.defaults["en"], e.userMessage("en"))
            assertEquals(e.error.userMessage("en"), e.userMessage("en"))
            assertEquals(SentomaruUserMessage.Situation.ATTESTATION_FAILED, SentomaruUserMessage.situationFor(e.error.code))
        }
    }

    @Test fun accessorOverridesByLanguageAndGivesNullForANonBlock() {
        val blocked = SentomaruException(EnrollmentError.KeyInvalidated())
        assertEquals("Texto do app.", blocked.userMessage("pt-BR", mapOf("pt-BR" to "Texto do app.")))
        assertEquals(SentomaruUserMessage.defaults["es"], blocked.userMessage("es", mapOf("pt-BR" to "Texto do app.")))

        val notBlocked = SentomaruException(SentomaruError.InvalidRequest(SentomaruError.Reason.PARAMS))
        assertNull(notBlocked.userMessage("en"))
        assertNull(notBlocked.error.userMessage("en"))
        assertEquals("InvalidRequest:PARAMS", notBlocked.error.code)
    }
}
