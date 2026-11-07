package br.com.ebees.sentomaru.sdk.transport

import br.com.ebees.sentomaru.core.SentomaruError
import br.com.ebees.sentomaru.core.SentomaruException

/**
 * Encoding of the `x-sentomaru-signals` header (final review Minor 3). The server rejects the whole forwarded message
 * (400 `message-format`) when a header value is longer than [MAX_LENGTH], has a non-printable or non-ASCII character,
 * or has more than one value. This fails earlier and typed instead: non-ASCII characters are escaped as JSON `\uXXXX`
 * (valid inside JSON strings), control characters and over-long values raise `InvalidRequest(HEADER_VALUE)`.
 */
internal object SignalsHeader {
    const val NAME = "x-sentomaru-signals"
    const val MAX_LENGTH = 4096

    fun encode(json: String): String {
        val out = StringBuilder(json.length)
        for (ch in json) {
            val code = ch.code
            when {
                code in 0x20..0x7E -> out.append(ch)
                code >= 0x80 -> out.append("\\u").append(String.format(java.util.Locale.ROOT, "%04x", code))
                else -> throw SentomaruException(SentomaruError.InvalidRequest(SentomaruError.Reason.HEADER_VALUE))
            }
        }
        if (out.length > MAX_LENGTH) throw SentomaruException(SentomaruError.InvalidRequest(SentomaruError.Reason.HEADER_VALUE))
        return out.toString()
    }
}
