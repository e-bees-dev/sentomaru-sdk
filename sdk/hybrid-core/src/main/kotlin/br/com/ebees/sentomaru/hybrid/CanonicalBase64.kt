package br.com.ebees.sentomaru.hybrid

import java.util.Base64

/**
 * The text of a `bytes` value on a text channel (contracts/sdk/hybrid-bridge-v1.json, notes): RFC 4648 section 4 Base64 in its
 * canonical form, the one text a writer produces for those bytes. `java.util.Base64` alone accepts missing padding and non-zero
 * trailing bits; here the decoded bytes must encode back to exactly the text, so there is one spelling per value. Refused with
 * [IllegalArgumentException], as the plain decoder does for an illegal character.
 */
object CanonicalBase64 {
    fun decode(text: String): ByteArray {
        val bytes = Base64.getDecoder().decode(text)
        require(Base64.getEncoder().encodeToString(bytes) == text) { "not canonical Base64" }
        return bytes
    }
}
