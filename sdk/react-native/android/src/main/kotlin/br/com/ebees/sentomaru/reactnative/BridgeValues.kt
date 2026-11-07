package br.com.ebees.sentomaru.reactnative

import br.com.ebees.sentomaru.hybrid.CanonicalBase64
import java.util.Base64

/**
 * the only conversions the React Native layer makes. JavaScript has no byte array, so a byte value crosses the
 * bridge as Base64 text: the `body` argument of `sign` (the contract's `bytes` argument) comes in as Base64, and a
 * `bytes` reply (`sealedLoad`) goes out as Base64. Everything else is passed through unchanged.
 */
internal object BridgeValues {
    private val BYTE_ARGUMENTS = setOf("body")

    /** Arguments as the core expects them: Base64 `body` decoded, anything else as it came. */
    fun arguments(raw: Map<String, Any?>): Map<String, Any?> = raw.mapValues { (key, value) ->
        if (key in BYTE_ARGUMENTS && value is String) CanonicalBase64.decode(value) else integral(value)
    }

    // ReadableMap.toHashMap() gives every JavaScript number as Double; the core takes Int/Long for its integer settings, so an
    // integral value inside the exact range of a Double (2^53) becomes a Long. A fractional one stays a Double and is refused.
    private fun integral(value: Any?): Any? = when (value) {
        is Double -> if (value.isFinite() && value == Math.rint(value) && Math.abs(value) <= MAX_EXACT) value.toLong() else value
        is Map<*, *> -> value.entries.associate { (k, v) -> k to integral(v) }
        is List<*> -> value.map { integral(it) }
        else -> value
    }

    private const val MAX_EXACT = 9007199254740992.0

    /** A reply for JavaScript: bytes become Base64, collections are converted element by element. */
    fun reply(value: Any?): Any? = when (value) {
        is ByteArray -> Base64.getEncoder().encodeToString(value)
        is Map<*, *> -> value.entries.associate { (k, v) -> k.toString() to reply(v) }
        is List<*> -> value.map { reply(it) }
        is Set<*> -> value.map { reply(it) }
        else -> value
    }
}
