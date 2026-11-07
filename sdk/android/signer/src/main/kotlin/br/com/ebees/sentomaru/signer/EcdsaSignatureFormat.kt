package br.com.ebees.sentomaru.signer

/**
 * Strict conversion between the DER `ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }`
 * produced by AndroidKeyStore `SHA256withECDSA` and the fixed-width IEEE P1363 `r || s`
 * required by the RFC 9421 `ecdsa-p256-sha256` profile.
 *
 * Needed because Android does not list `SHA256withECDSAinP1363Format` among its supported
 * Signature algorithms (developer.android.com/reference/java/security/Signature, 2026-10-07).
 * Scope is deliberately limited to this one structure: short-form lengths only (a P-256
 * signature is at most 72 bytes), minimal positive non-zero INTEGERs, no trailing data.
 * Covered by fixed vectors and by cross-checks against the JDK SunEC P1363 implementation.
 *
 * Range checks of r and s against the curve order n (r, s in [1, n-1]) are deliberately left
 * to the verifier; this class only enforces encoding (non-zero, positive, fits in the field width).
 */
object EcdsaSignatureFormat {
    const val P256_FIELD_BYTES = 32

    private const val TAG_SEQUENCE = 0x30
    private const val TAG_INTEGER = 0x02

    fun derToP1363(der: ByteArray, fieldBytes: Int = P256_FIELD_BYTES): ByteArray {
        require(der.size >= 2 && (der[0].toInt() and 0xff) == TAG_SEQUENCE) { "not a DER SEQUENCE" }
        val seqLen = der[1].toInt() and 0xff
        require(seqLen < 0x80) { "long-form length not allowed" }
        require(seqLen == der.size - 2) { "SEQUENCE length mismatch" }
        val out = ByteArray(fieldBytes * 2)
        val afterR = readInteger(der, 2, out, 0, fieldBytes)
        val afterS = readInteger(der, afterR, out, fieldBytes, fieldBytes)
        require(afterS == der.size) { "trailing data" }
        return out
    }

    fun p1363ToDer(p1363: ByteArray, fieldBytes: Int = P256_FIELD_BYTES): ByteArray {
        require(p1363.size == fieldBytes * 2) { "P1363 signature must be ${fieldBytes * 2} bytes" }
        val r = encodeInteger(p1363.copyOfRange(0, fieldBytes))
        val s = encodeInteger(p1363.copyOfRange(fieldBytes, fieldBytes * 2))
        val body = r + s
        require(body.size < 0x80) { "unsupported field size" }
        return byteArrayOf(TAG_SEQUENCE.toByte(), body.size.toByte()) + body
    }

    /** Reads one INTEGER at [pos] into out[outOff, outOff+width) left-padded; returns next offset. */
    private fun readInteger(der: ByteArray, pos: Int, out: ByteArray, outOff: Int, width: Int): Int {
        require(pos + 2 <= der.size) { "truncated INTEGER header" }
        require((der[pos].toInt() and 0xff) == TAG_INTEGER) { "expected INTEGER" }
        val len = der[pos + 1].toInt() and 0xff
        require(len in 1..0x7f) { "invalid INTEGER length" }
        val start = pos + 2
        val end = start + len
        require(end <= der.size) { "truncated INTEGER" }
        val first = der[start].toInt() and 0xff
        require(first and 0x80 == 0) { "negative INTEGER" }
        var valueStart = start
        if (first == 0) {
            require(len > 1) { "zero INTEGER" }
            require((der[start + 1].toInt() and 0x80) != 0) { "non-minimal INTEGER" }
            valueStart = start + 1
        }
        val valueLen = end - valueStart
        require(valueLen <= width) { "INTEGER too long" }
        System.arraycopy(der, valueStart, out, outOff + width - valueLen, valueLen)
        return end
    }

    private fun encodeInteger(fixed: ByteArray): ByteArray {
        var i = 0
        while (i < fixed.size && fixed[i] == 0.toByte()) i++
        require(i < fixed.size) { "zero component" }
        val magnitude = fixed.copyOfRange(i, fixed.size)
        val value = if ((magnitude[0].toInt() and 0x80) != 0) byteArrayOf(0) + magnitude else magnitude
        return byteArrayOf(TAG_INTEGER.toByte(), value.size.toByte()) + value
    }
}
