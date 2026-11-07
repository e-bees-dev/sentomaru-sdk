package br.com.ebees.sentomaru.sdk.sealed

import br.com.ebees.sentomaru.sdk.sealed.SentomaruSealedException.Code
import java.io.FileNotFoundException
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction

/**
 * The installed `base` module's assets, by canonical path (`assets/...`, as `bundletool` shows it without `base/`).
 * Android reads them through the `AssetManager`; the tests through a map or a directory.
 */
internal interface SealedSource {
    /** At most `limit + 1` bytes of the entry (so an entry above the limit is seen without reading it all), or null. */
    fun read(path: String, limit: Int): ByteArray?

    /** The whole entry, for the plain fallback only; throws [FileNotFoundException] when absent. */
    fun readAll(path: String): ByteArray
}

/** The opened `header.bin`: the `dek` stays in the process memory; the canonical path of the strings file, if any. */
internal class SealedHeader(val dek: ByteArray, val stringsPath: String?)

/**
 * D-14b: the contract's reader (contracts/devsecops/cli-v1.md, asset-encryption, "Leitura"), in the order of the
 * checks the reference reader of the vendor's reference reader follows: header absent → not-sealed;
 * header shape → format-unsupported; header size or tag → integrity; entry absent → not-sealed (never plain in a
 * sealed package); entry shape → format-unsupported; entry size, declared length, tag, DEFLATE stream → integrity.
 * Sizes are checked before any AEAD; inflation stops at the declared length + 1 byte.
 *
 * [aead] and [inflate] are seams for the vectors' `probe` cases (the outcome alone does not prove those rules).
 */
internal class SealedReader(
    private val source: SealedSource,
    private val packageName: String,
    private val versionCode: Long,
    private val aead: AeadOpen = AeadOpen.GCM,
    private val inflate: Inflate = Inflate.RAW,
) {
    private val lock = Any()
    @Volatile private var opened: SealedHeader? = null
    @Volatile private var absent = false

    /**
     * The opened header, or null when the package has no `header.bin` (an unsealed build). Both outcomes are kept for
     * the process (the installed assets do not change under it); a failure is not, and the next call reads again.
     */
    fun headerOrNull(): SealedHeader? {
        opened?.let { return it }
        if (absent) return null
        synchronized(lock) {
            opened?.let { return it }
            if (absent) return null
            val data = source.read(SealedFormat.HEADER, SealedFormat.MAX_HEADER)
            if (data == null) {
                absent = true
                return null
            }
            return openHeader(data).also { opened = it }
        }
    }

    private fun openHeader(data: ByteArray): SealedHeader {
        if (data.size < 5 || !data.startsWith(SealedFormat.HEADER_MAGIC) || data[4] != SealedFormat.VERSION) {
            throw SentomaruSealedException(Code.FORMAT_UNSUPPORTED)
        }
        if (data.size !in SealedFormat.MIN_HEADER..SealedFormat.MAX_HEADER) throw SentomaruSealedException(Code.INTEGRITY)
        val salt = data.copyOfRange(5, 21)
        val nonce = data.copyOfRange(21, 33)
        val kek = Hkdf.derive(SealedFormat.K_FMT, salt, utf8("sentomaru-sealed-v1|$packageName|$versionCode"))
        val plain = try {
            aead.open(kek, nonce, data.copyOfRange(33, data.size), utf8("header|v1|$packageName|$versionCode"))
        } finally {
            kek.fill(0)
        }
        if (plain == null) throw SentomaruSealedException(Code.INTEGRITY)
        try {
            val strings = strictUtf8(plain, 32, plain.size - 32)
            return SealedHeader(plain.copyOfRange(0, 32), strings.ifEmpty { null })
        } finally {
            plain.fill(0)
        }
    }

    /** The plaintext of a sealed file; the package must be sealed (see [SealedAssets] for the plain fallback). */
    fun bytes(path: String): ByteArray {
        val header = headerOrNull() ?: throw SentomaruSealedException(Code.NOT_SEALED)
        return openEntry(header, path)
    }

    private fun openEntry(header: SealedHeader, path: String): ByteArray {
        val data = source.read(SealedFormat.entryName(path), SealedFormat.MAX_ENTRY)
            ?: throw SentomaruSealedException(Code.NOT_SEALED)
        if (data.size < 5 || !data.startsWith(SealedFormat.ASSET_MAGIC) || data[4] != SealedFormat.VERSION) {
            throw SentomaruSealedException(Code.FORMAT_UNSUPPORTED)
        }
        if (data.size !in SealedFormat.MIN_ENTRY..SealedFormat.MAX_ENTRY) throw SentomaruSealedException(Code.INTEGRITY)
        val declared = ByteBuffer.wrap(data, 5, 4).int.toLong() and 0xffffffffL
        if (declared > SealedFormat.MAX_FILE) throw SentomaruSealedException(Code.INTEGRITY)
        val key = Hkdf.derive(header.dek, ByteArray(0), utf8("asset|$path"))
        val deflated = try {
            aead.open(key, data.copyOfRange(9, 21), data.copyOfRange(21, data.size),
                utf8("asset|v1|$packageName|$versionCode|$path"))
        } finally {
            key.fill(0)
        }
        if (deflated == null) throw SentomaruSealedException(Code.INTEGRITY)
        val length = declared.toInt()
        val inflated = inflate.inflate(deflated, length + 1)
        deflated.fill(0)
        if (inflated == null || inflated.bytes.size != length || !inflated.finished || inflated.trailing != 0) {
            inflated?.bytes?.fill(0)
            throw SentomaruSealedException(Code.INTEGRITY)
        }
        return inflated.bytes
    }

    /** `string(key)` of a sealed package: null for an absent key; not-sealed when the header names no strings file. */
    fun string(key: String): String? {
        val header = headerOrNull() ?: throw SentomaruSealedException(Code.NOT_SEALED)
        val path = header.stringsPath ?: throw SentomaruSealedException(Code.NOT_SEALED)
        return StringsJson.lookup(openEntry(header, path), key)
    }

    private fun ByteArray.startsWith(prefix: ByteArray): Boolean =
        size >= prefix.size && prefix.indices.all { this[it] == prefix[it] }
}

/**
 * The plain fallback over [SealedReader] (D-14x10): with [allowPlainFallback] and **no** `header.bin` in the package,
 * reads the plain file at its canonical path (and the strings file at [plainStringsPath]); with `header.bin` present
 * the option has no effect. Off, an unsealed package is `not-sealed`.
 */
internal class SealedAssets(private val source: SealedSource, private val reader: SealedReader) {
    fun bytes(path: String, allowPlainFallback: Boolean): ByteArray {
        if (reader.headerOrNull() != null || !allowPlainFallback) return reader.bytes(path)
        return source.readAll(path)
    }

    fun string(key: String, allowPlainFallback: Boolean, plainStringsPath: String?): String? {
        if (reader.headerOrNull() != null || !allowPlainFallback) return reader.string(key)
        val path = plainStringsPath ?: throw SentomaruSealedException(Code.NOT_SEALED)
        return StringsJson.lookup(source.readAll(path), key)
    }
}

internal fun utf8(s: String): ByteArray = s.toByteArray(Charsets.UTF_8)

/** Strict UTF-8 (a malformed or unmappable sequence throws [SentomaruSealedException] `integrity`). */
internal fun strictUtf8(bytes: ByteArray, offset: Int = 0, length: Int = bytes.size): String = try {
    Charsets.UTF_8.newDecoder()
        .onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT)
        .decode(ByteBuffer.wrap(bytes, offset, length))
        .toString()
} catch (e: CharacterCodingException) {
    throw SentomaruSealedException(Code.INTEGRITY)
}
