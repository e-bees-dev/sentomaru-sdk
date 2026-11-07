package br.com.ebees.sentomaru.core

import java.util.Base64

/**
 * Trusted envelope the consumer forwards to the private API (B-I2, the private integrity API):
 * `MessageDto = {"method","uri","headers":{name:[value]},"body":<standard base64 with padding>}` with no other
 * member; the enrollment route wraps it as `{"request": MessageDto}`. Evaluations add `operation`/`context`, which
 * belong to the consumer, so only the message is produced here.
 *
 * Output is compact UTF-8 JSON. Every string written is printable ASCII (validated before signing), so the only
 * escapes needed are `"` and `\`; anything else is refused rather than escaped.
 */
object EnvelopeCodec {
    fun encode(message: SignedMessage): ByteArray = message(StringBuilder(), message).toString().toByteArray(Charsets.UTF_8)

    fun encodeEnrollment(message: SignedMessage): ByteArray =
        message(StringBuilder("{\"request\":"), message).append('}').toString().toByteArray(Charsets.UTF_8)

    private fun message(out: StringBuilder, message: SignedMessage): StringBuilder {
        out.append("{\"method\":")
        string(out, message.method)
        out.append(",\"uri\":")
        string(out, message.targetUri)
        out.append(",\"headers\":{")
        message.headers.forEachIndexed { index, (name, value) ->
            if (index > 0) out.append(',')
            string(out, name)
            out.append(":[")
            string(out, value)
            out.append(']')
        }
        out.append("},\"body\":")
        string(out, Base64.getEncoder().encodeToString(message.body()))
        return out.append('}')
    }

    private fun string(out: StringBuilder, value: String) {
        out.append('"')
        for (c in value) {
            when (c) {
                '"', '\\' -> out.append('\\').append(c)
                in ' '..'~' -> out.append(c)
                else -> throw IllegalStateException("non-printable character in a validated envelope field")
            }
        }
        out.append('"')
    }
}
