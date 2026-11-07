package br.com.ebees.sentomaru.sdk.transport

import br.com.ebees.sentomaru.sdk.*
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

/** Shared by the OkHttp and HttpURLConnection transport tests: the MockWebServer TLS identity (test-only PKCS#12,
 *  self-signed `localhost`, password `password`) and in-memory installation store and keys. */
object TestTls {
    val sslContext: SSLContext
    val trustManager: X509TrustManager
    private const val KEYSTORE_B64 =
        "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" +
        "dKL9RA6j8cGV8gICJxA="

    init {
        val bytes = Base64.getDecoder().decode(KEYSTORE_B64)
        val ks = KeyStore.getInstance("PKCS12").apply {
            load(java.io.ByteArrayInputStream(bytes), "password".toCharArray())
        }
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply {
            init(ks, "password".toCharArray())
        }
        val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply {
            init(ks)
        }
        trustManager = tmf.trustManagers.filterIsInstance<X509TrustManager>().first()
        sslContext = SSLContext.getInstance("TLS").apply {
            init(kmf.keyManagers, tmf.trustManagers, SecureRandom())
        }
    }
}

class TestStore : InstallationStore {
    var record: InstallationRecord? = null
    override fun read() = record
    override fun write(record: InstallationRecord?) { this.record = record }
}

class TestJcaKeys : InstallationKeys {
    val keys = mutableMapOf<String, KeyPair>()
    override fun exists(alias: String) = keys.containsKey(alias)
    override fun generate(alias: String, challenge: ByteArray, strongBox: Boolean): KeyMaterial {
        keys[alias] = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()
        return material(alias)
    }
    override fun material(alias: String) = KeyMaterial(keys.getValue(alias).public.encoded, emptyList())
    override fun sign(alias: String, bytes: ByteArray): ByteArray =
        Signature.getInstance("SHA256withECDSAinP1363Format").run {
            initSign(keys.getValue(alias).private)
            update(bytes)
            sign()
        }
    override fun delete(alias: String) { keys.remove(alias) }
    override fun deleteOwned(prefix: String) { keys.keys.filter { it.startsWith(prefix) }.forEach { keys.remove(it) } }
    fun verify(alias: String, base: ByteArray, sigRaw: String): Boolean =
        Signature.getInstance("SHA256withECDSAinP1363Format").run {
            initVerify(keys.getValue(alias).public)
            update(base)
            verify(Base64.getDecoder().decode(sigRaw.removePrefix("sig1=:").removeSuffix(":")))
        }
}
