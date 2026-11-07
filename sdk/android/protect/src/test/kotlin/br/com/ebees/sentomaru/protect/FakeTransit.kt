package br.com.ebees.sentomaru.protect

import com.google.gson.JsonObject
import com.google.gson.JsonParser
import com.sun.net.httpserver.HttpsConfigurator
import com.sun.net.httpserver.HttpsServer
import java.io.File
import java.net.InetSocketAddress
import java.net.URI
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.util.Base64
import java.util.concurrent.CopyOnWriteArrayList
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext

/**
 * A local stand-in for an OpenBao with JWT auth and Transit (G-03e2 tests): TLS with a server certificate generated for
 * the run ([caFile] is what `--openbao-cacert` trusts), `auth/jwt/login` accepting one role and one JWT, a Transit RSA
 * key whose private half stays in this object (signing with PKCS#1 v1.5 over the prehashed SHA-256, as Transit does),
 * and `revoke-self`. Every request is recorded (path and token header).
 */
class FakeTransit(work: File, keytool: String) : AutoCloseable {
    data class Call(val method: String, val path: String, val token: String?)

    val calls = CopyOnWriteArrayList<Call>()
    val key: KeyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(3072) }.generateKeyPair()
    val role = "protect-ci"
    val jwt = "eyJhbGciOiJSUzI1NiJ9." + Base64.getUrlEncoder().withoutPadding().encodeToString("{\"sub\":\"ci\"}".toByteArray()) + ".c2ln"
    val sessionToken = "s.session-" + java.util.UUID.randomUUID()
    @Volatile var exportable = false
    @Volatile var keyType = "rsa-3072"
    @Volatile var keyStatus: Int? = null   // forced status of the key read (404, 403…)
    @Volatile var signStatus: Int? = null  // forced status of the sign call
    @Volatile var hugeKeyAnswer = false    // a key answer far above any real one

    val caFile: File = work.resolve("bao-ca.pem")
    private val server: HttpsServer

    init {
        val storePass = java.util.UUID.randomUUID().toString()
        val p12 = work.resolve("bao-server.p12")
        p12.delete()
        exec(keytool, "-genkeypair", "-keystore", p12.path, "-storetype", "PKCS12", "-storepass", storePass, "-alias", "bao",
            "-keyalg", "EC", "-groupname", "secp256r1", "-validity", "2", "-dname", "CN=127.0.0.1", "-ext", "SAN=ip:127.0.0.1")
        exec(keytool, "-exportcert", "-rfc", "-keystore", p12.path, "-storetype", "PKCS12", "-storepass", storePass, "-alias", "bao",
            "-file", caFile.path)
        val store = KeyStore.getInstance("PKCS12").apply { p12.inputStream().use { load(it, storePass.toCharArray()) } }
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(store, storePass.toCharArray()) }
        val ssl = SSLContext.getInstance("TLS").apply { init(kmf.keyManagers, null, null) }
        server = HttpsServer.create(InetSocketAddress("127.0.0.1", 0), 0).apply {
            httpsConfigurator = HttpsConfigurator(ssl)
            createContext("/") { exchange ->
                val path = exchange.requestURI.path
                val token = exchange.requestHeaders.getFirst("X-Vault-Token")
                calls += Call(exchange.requestMethod, path, token)
                val body = runCatching { JsonParser.parseString(exchange.requestBody.readBytes().toString(Charsets.UTF_8)).asJsonObject }
                    .getOrDefault(JsonObject())
                val (status, answer) = answer(path, token, body)
                val bytes = answer.toByteArray()
                exchange.responseHeaders.add("Content-Type", "application/json")
                exchange.sendResponseHeaders(status, if (bytes.isEmpty()) -1 else bytes.size.toLong())
                if (bytes.isNotEmpty()) exchange.responseBody.use { it.write(bytes) } else exchange.close()
            }
            start()
        }
    }

    val address: URI get() = URI("https://127.0.0.1:${server.address.port}")

    private fun answer(path: String, token: String?, body: JsonObject): Pair<Int, String> = when {
        path == "/v1/auth/jwt/login" ->
            if (body.get("role")?.asString == role && body.get("jwt")?.asString == jwt)
                200 to """{"auth":{"client_token":"$sessionToken","lease_duration":600}}"""
            else 400 to """{"errors":["role or jwt rejected"]}"""
        token != sessionToken -> 403 to """{"errors":["permission denied"]}"""
        path == "/v1/auth/token/revoke-self" -> 204 to ""
        path == "/v1/transit/keys/upload" && keyStatus != null -> keyStatus!! to """{"errors":[]}"""
        path == "/v1/transit/keys/upload" && hugeKeyAnswer -> 200 to """{"data":{"padding":"${"x".repeat(1_000_000)}"}}"""
        path.startsWith("/v1/transit/sign/") && signStatus != null -> signStatus!! to """{"errors":[]}"""
        path == "/v1/transit/keys/upload" -> 200 to """{"data":{"type":"$keyType","exportable":$exportable,
            "allow_plaintext_backup":false,"latest_version":1,"keys":{"1":{"public_key":"${pem(key.public.encoded).replace("\n", "\\n")}"}}}}"""
        path == "/v1/transit/sign/upload/sha2-256" -> {
            val digest = Base64.getDecoder().decode(body.get("input").asString)
            if (body.get("prehashed")?.asBoolean != true || body.get("signature_algorithm")?.asString != "pkcs1v15" || digest.size != 32)
                400 to """{"errors":["bad request"]}"""
            else {
                // PKCS#1 v1.5 over a prehashed SHA-256: DigestInfo + raw RSA, as Transit signs.
                val digestInfo = hex("3031300d060960864801650304020105000420") + digest
                val sig = Signature.getInstance("NONEwithRSA").apply { initSign(key.private); update(digestInfo) }.sign()
                200 to """{"data":{"signature":"vault:v1:${Base64.getEncoder().encodeToString(sig)}"}}"""
            }
        }
        else -> 404 to """{"errors":[]}"""
    }

    override fun close() = server.stop(0)

    companion object {
        fun pem(der: ByteArray) = "-----BEGIN PUBLIC KEY-----\n" + Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(der) +
            "\n-----END PUBLIC KEY-----\n"
        fun hex(s: String) = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
        private fun exec(vararg cmd: String) {
            val p = ProcessBuilder(*cmd).redirectErrorStream(true).start()
            val log = p.inputStream.bufferedReader().readText()
            check(p.waitFor() == 0) { "${cmd[0]} failed: $log" }
        }
    }
}
