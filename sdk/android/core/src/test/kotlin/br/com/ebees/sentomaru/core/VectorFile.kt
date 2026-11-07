package br.com.ebees.sentomaru.core

import java.io.File
import java.util.Base64

/**
 * Test-only reader of verification/sdk/vectors/sdk-vectors-v1.jvm.txt (flat form of sdk-vectors-v1.json written by
 * gen_vectors.py; check_vectors.py proves both carry the same data). Lines: `K<TAB>pythonPublicKeySpki=<b64>` and
 * `V<TAB>name=<b64>...`; every value is base64 of UTF-8 text except `body` and `signatureBase` (raw bytes).
 */
class Vector(private val fields: Map<String, String>) {
    private fun text(name: String): String = String(raw(name), Charsets.UTF_8)
    private fun raw(name: String): ByteArray =
        Base64.getDecoder().decode(fields[name] ?: throw IllegalArgumentException("vector field $name missing"))

    val id: String get() = text("id")
    val positive: Boolean get() = text("kind") == "positive"
    val route: String get() = text("route")
    val method: String get() = text("method")
    val targetUri: String get() = text("targetUri")
    val body: ByteArray get() = raw("body")
    val created: Long get() = text("created").toLong()
    val expires: Long get() = text("expires").toLong()
    val nonce: String get() = text("nonce")
    val keyId: String get() = text("keyid")
    val contentDigest: String get() = text("contentDigest")
    val signatureBase: ByteArray get() = raw("signatureBase")
    val signatureInput: String get() = text("signatureInput")
    val pythonSignature: String get() = text("pythonSignature")
    val coreError: String get() = text("coreError")

    /** Headers in file order (keys exactly as the generator wrote them, including invalid ones in negatives). */
    val headers: Map<String, String>
        get() = LinkedHashMap<String, String>().also { map ->
            fields.keys.filter { it.startsWith("h.") }.forEach { map[it.removePrefix("h.")] = text(it) }
        }

    fun params(): SignatureParams = SignatureParams(created, expires, nonce, keyId, Profile.components(headers))
}

class VectorFile(val pythonPublicKeySpki: ByteArray, val vectors: List<Vector>) {
    val positives: List<Vector> get() = vectors.filter { it.positive }
    val negatives: List<Vector> get() = vectors.filterNot { it.positive }

    companion object {
        const val NAME = "sdk-vectors-v1.jvm.txt"

        fun dir(): File = File(
            System.getProperty("sentomaru.vectors.dir")
                ?: throw IllegalStateException("system property sentomaru.vectors.dir not set (see core/build.gradle.kts)"),
        )

        fun load(file: File = File(dir(), NAME)): VectorFile {
            var key: ByteArray? = null
            val vectors = ArrayList<Vector>()
            file.readLines(Charsets.UTF_8).filter { it.isNotEmpty() && !it.startsWith("#") }.forEach { line ->
                val parts = line.split('\t')
                val fields = LinkedHashMap<String, String>()
                for (part in parts.drop(1)) {
                    val eq = part.indexOf('=')
                    require(eq > 0) { "malformed vector field" }
                    require(fields.put(part.substring(0, eq), part.substring(eq + 1)) == null) { "duplicate field" }
                }
                when (parts[0]) {
                    "K" -> key = Base64.getDecoder().decode(fields.getValue("pythonPublicKeySpki"))
                    "V" -> vectors += Vector(fields)
                    else -> throw IllegalArgumentException("unknown record type")
                }
            }
            return VectorFile(key ?: throw IllegalArgumentException("no K record"), vectors)
        }
    }
}
