package br.com.ebees.sentomaru.capacitor

import org.json.JSONArray
import org.json.JSONObject
import br.com.ebees.sentomaru.hybrid.CanonicalBase64
import java.util.Base64

/**
 * the only conversions the Capacitor layer makes. A Capacitor call carries JSON, so (as in the React Native layer) a
 * byte value crosses as Base64 text: the `body` argument of `sign` comes in as Base64, a `bytes` reply (`sealedLoad`) goes out
 * as Base64. JSON is turned into the Maps/Lists the shared core expects and back; integral numbers stay Int/Long, a
 * fractional one stays a Double (the core refuses it where it wants an integer).
 */
internal object BridgeValues {
    private val BYTE_ARGUMENTS = setOf("body")

    /** The `args` object of a call as the core expects it; null or absent is empty. */
    fun arguments(raw: JSONObject?): Map<String, Any?> {
        if (raw == null) return emptyMap()
        val out = LinkedHashMap<String, Any?>()
        for (key in raw.keys()) {
            val value = fromJson(raw.get(key))
            out[key] = if (key in BYTE_ARGUMENTS && value is String) CanonicalBase64.decode(value) else value
        }
        return out
    }

    private fun fromJson(value: Any?): Any? = when (value) {
        JSONObject.NULL, null -> null
        is JSONObject -> value.keys().asSequence().associateWith { fromJson(value.get(it)) }
        is JSONArray -> (0 until value.length()).map { fromJson(value.get(it)) }
        else -> value // String, Boolean, Int, Long, Double
    }

    /** A reply as the JSON-friendly value Capacitor resolves under `value`: bytes become Base64, collections convert element by element. */
    fun reply(value: Any?): Any? = when (value) {
        null -> JSONObject.NULL
        is ByteArray -> Base64.getEncoder().encodeToString(value)
        is Map<*, *> -> JSONObject().also { o -> value.forEach { (k, v) -> o.put(k.toString(), reply(v)) } }
        is Iterable<*> -> JSONArray().also { a -> value.forEach { a.put(reply(it)) } }
        else -> value
    }
}
