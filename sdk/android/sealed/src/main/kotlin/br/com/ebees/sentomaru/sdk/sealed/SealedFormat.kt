package br.com.ebees.sentomaru.sdk.sealed

import java.security.GeneralSecurityException
import java.security.MessageDigest
import java.util.zip.DataFormatException
import java.util.zip.Inflater
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * D-14b: the constants and primitives of the sealed format v1 (contracts/devsecops/cli-v1.md, asset-encryption,
 * "Formato selado v1"). Only platform primitives (D-14x9): `HmacSHA256` and `AES/GCM/NoPadding` from `javax.crypto`
 * (Conscrypt on Android, the JCA on the JVM tests) and `java.util.zip.Inflater`. HKDF (RFC 5869) is written here over
 * the HMAC and checked against the RFC's cases in the shared vectors.
 */
internal object SealedFormat {
    /**
     * `K_fmt` = SHA-256("Sentomaru sealed assets format v1 public constant"). Public by design: it is in every reader the
     * client ships, so the format is data obfuscation, not secrecy (D-14x1).
     */
    val K_FMT: ByteArray = hex("d49d16621c97d973d3d27ade53b09e223c5a07297beb57df176fe4827a498921")

    const val SEALED_DIR = "assets/sentomaru/sealed/"
    const val HEADER = SEALED_DIR + "header.bin"
    val HEADER_MAGIC = "SNTS".toByteArray(Charsets.US_ASCII)
    val ASSET_MAGIC = "SNTA".toByteArray(Charsets.US_ASCII)
    const val VERSION: Byte = 1

    const val MAX_FILE = 4 * 1024 * 1024
    /** 5 magic+version, 16 salt, 12 nonce, 32 dek, 16 tag. */
    const val MIN_HEADER = 5 + 16 + 12 + 32 + 16
    /** The strings path is up to 512 bytes. */
    const val MAX_HEADER = MIN_HEADER + 512
    /** 5 magic+version, 4 length, 12 nonce, 16 tag. */
    const val MIN_ENTRY = 5 + 4 + 12 + 16
    /** 4 KiB for the DEFLATE overhead of incompressible data; the CLI never writes more. */
    const val MAX_ENTRY = MIN_ENTRY + MAX_FILE + 4096

    /** `assets/sentomaru/sealed/<sha256(path) in lowercase hex>.bin`. */
    fun entryName(path: String): String =
        SEALED_DIR + MessageDigest.getInstance("SHA-256").digest(path.toByteArray(Charsets.UTF_8)).toHex() + ".bin"

    fun hex(s: String): ByteArray = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it.toInt() and 0xff) }
}

/** HKDF-SHA256 (RFC 5869) over `javax.crypto.Mac`. An empty salt is 32 zero bytes, as the RFC says. */
internal object Hkdf {
    private const val HASH_LEN = 32

    fun derive(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int = HASH_LEN): ByteArray {
        require(length in 1..255 * HASH_LEN) { "HKDF length out of range" }
        // SecretKeySpec refuses an empty key; HMAC pads a short key with zeros anyway, so this is the RFC's default.
        val prk = hmac(if (salt.isEmpty()) ByteArray(HASH_LEN) else salt, ikm)
        val out = ByteArray(length)
        var previous = ByteArray(0)
        var at = 0
        var counter = 1
        while (at < length) {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(prk, "HmacSHA256"))
            mac.update(previous)
            mac.update(info)
            mac.update(counter.toByte())
            previous = mac.doFinal()
            val n = minOf(HASH_LEN, length - at)
            System.arraycopy(previous, 0, out, at, n)
            at += n
            counter++
        }
        prk.fill(0)
        previous.fill(0)
        return out
    }

    private fun hmac(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }
}

/** AES-256-GCM open: 96-bit nonce, 128-bit tag at the end of the ciphertext (the `javax.crypto` convention). */
internal fun interface AeadOpen {
    /** The plaintext, or null when the tag does not verify (or the decryption fails in any other way). */
    fun open(key: ByteArray, nonce: ByteArray, sealed: ByteArray, aad: ByteArray): ByteArray?

    companion object {
        val GCM = AeadOpen { key, nonce, sealed, aad ->
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
            cipher.updateAAD(aad)
            // Any failure of the decryption itself (a bad tag, or a provider that reports one as another
            // GeneralSecurityException) is `integrity`; getInstance/init stay outside: a broken platform is not a bad file.
            try {
                cipher.doFinal(sealed)
            } catch (e: GeneralSecurityException) {
                null
            }
        }
    }
}

/** What a capped raw-DEFLATE inflation produced, and whether the stream ended cleanly. */
internal class Inflated(val bytes: ByteArray, val finished: Boolean, val trailing: Int)

/** Raw DEFLATE (RFC 1951, no zlib or gzip wrapper) that never writes more than [Inflate.inflate]'s `max` bytes. */
internal fun interface Inflate {
    /** Null for an invalid stream. */
    fun inflate(data: ByteArray, max: Int): Inflated?

    companion object {
        val RAW = Inflate { data, max ->
            val inflater = Inflater(true)
            try {
                inflater.setInput(data)
                val out = ByteArray(max)
                var n = 0
                while (n < max && !inflater.finished()) {
                    val r = inflater.inflate(out, n, max - n)
                    if (r == 0) break   // needs input (truncated stream) or a dictionary: not a valid v1 stream
                    n += r
                }
                Inflated(out.copyOf(n), inflater.finished(), inflater.remaining)
            } catch (e: DataFormatException) {
                null
            } finally {
                inflater.end()
            }
        }
    }
}
