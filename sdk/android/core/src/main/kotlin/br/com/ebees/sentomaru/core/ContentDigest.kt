package br.com.ebees.sentomaru.core

import java.security.MessageDigest
import java.util.Base64

/** RFC 9530 `Content-Digest` with the single algorithm of the profile: `sha-256=:<base64>:` (JDK SHA-256). */
object ContentDigest {
    private val CANONICAL = Regex("""\Asha-256=:[A-Za-z0-9+/]{43}=:\z""")

    /** Digest of exactly [body] (never re-serialized). Size is checked by the caller that freezes the body. */
    fun sha256(body: ByteArray): String =
        "sha-256=:" + Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(body)) + ":"

    internal fun isCanonical(value: String): Boolean = CANONICAL.matches(value)
}
