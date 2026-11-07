package br.com.ebees.sentomaru.protect

import com.google.gson.JsonArray
import com.google.gson.JsonElement
import com.google.gson.JsonNull
import com.google.gson.JsonObject
import com.google.gson.JsonPrimitive
import com.google.gson.Strictness
import com.google.gson.stream.JsonReader
import com.google.gson.stream.JsonToken
import java.io.StringReader
import java.math.BigDecimal
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction

/**
 * RFC 8259 JSON only: strict UTF-8 (no BOM), no comments or lenient syntax, no trailing content, no duplicate member
 * names (Gson's own tree keeps the last one silently), bounded depth. Any violation is `profile-format`.
 */
object StrictJson {
    private const val MAX_DEPTH = 32

    fun parse(bytes: ByteArray): JsonElement {
        // Gson's reader skips a byte order mark silently; RFC 8259 §8.1 says not to add one.
        if (bytes.size >= 3 && bytes[0] == 0xEF.toByte() && bytes[1] == 0xBB.toByte() && bytes[2] == 0xBF.toByte()) fail("byte order mark")
        val text = try {
            Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()
        } catch (e: Exception) {
            fail("not UTF-8")
        }
        try {
            val reader = JsonReader(StringReader(text)).apply { strictness = Strictness.STRICT }
            val root = read(reader, 0)
            if (reader.peek() != JsonToken.END_DOCUMENT) fail("trailing content")
            return root
        } catch (e: ProtectException) {
            throw e
        } catch (e: Exception) {
            fail("not JSON")
        }
    }

    private fun read(r: JsonReader, depth: Int): JsonElement {
        if (depth > MAX_DEPTH) fail("nesting")
        return when (r.peek()) {
            JsonToken.BEGIN_OBJECT -> JsonObject().also { o ->
                r.beginObject()
                while (r.hasNext()) {
                    val name = r.nextName()
                    if (o.has(name)) fail("duplicate member $name")
                    o.add(name, read(r, depth + 1))
                }
                r.endObject()
            }
            JsonToken.BEGIN_ARRAY -> JsonArray().also { a ->
                r.beginArray()
                while (r.hasNext()) a.add(read(r, depth + 1))
                r.endArray()
            }
            JsonToken.STRING -> JsonPrimitive(r.nextString())
            JsonToken.NUMBER -> JsonPrimitive(BigDecimal(r.nextString()))
            JsonToken.BOOLEAN -> JsonPrimitive(r.nextBoolean())
            JsonToken.NULL -> { r.nextNull(); JsonNull.INSTANCE }
            else -> fail("not JSON")
        }
    }

    private fun fail(detail: String): Nothing = throw ProtectException(ErrorCode.PROFILE_FORMAT, detail)
}
