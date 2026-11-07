package br.com.ebees.sentomaru.protect

import com.google.gson.JsonObject
import com.google.gson.JsonParser
import java.io.ByteArrayOutputStream
import java.io.File
import java.math.BigInteger
import java.net.URI
import java.net.URLEncoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.KeyFactory
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.Provider
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Signature
import java.security.SignatureSpi
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.RSAKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.X509EncodedKeySpec
import java.time.Duration
import java.time.ZoneOffset
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import java.util.Base64
import java.util.UUID
import java.util.zip.ZipFile
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import jdk.security.jarsigner.JarSigner

/** No OpenBao answer the CLI needs is near this size (a key read is a few KiB). */
private const val ANSWER_LIMIT = 256 * 1024

/**
 * G-03e2 `--sign openbao`: the AAB's JAR signature made by a non-exportable RSA key in the client's own OpenBao Transit.
 * The key never leaves the vault: the JDK JarSigner builds the bundle signature and every RSA operation is a Transit
 * `sign` call (`sha2-256`, prehashed, PKCS#1 v1.5) through a JCA provider of this CLI. The certificate of the key is a
 * file the client keeps with the pipeline (`--openbao-key`, PEM): it must hold exactly the public key of the Transit key.
 *
 * Identity: the CI's federated token (D-02b). `SENTOMARU_OPENBAO_JWT` when set, otherwise the GitHub Actions OIDC token
 * (`ACTIONS_ID_TOKEN_REQUEST_URL`/`_TOKEN`, audience `--openbao-audience`). The JWT and the OpenBao token stay in memory:
 * never argv, log, report or file. TLS only, verified against `--openbao-cacert` when given (else the system roots); no
 * redirect. The session token is revoked at the end.
 *
 * Errors: OpenBao unreachable, login or key read refused → `signer-unavailable`; a key that is exportable, of another
 * type, or not the one of the certificate, or a signature that does not verify → `sign-failed`.
 */
class OpenBaoSigner(private val target: Target, private val env: Map<String, String>) {
    /** `--openbao-transit <mount>/<key>` and the rest of the options of `--sign openbao`. */
    data class Target(val address: URI, val role: String, val mount: String, val key: String, val certificate: X509Certificate?,
        val sslContext: SSLContext?, val audience: String) {
        companion object {
            private val ROLE = Regex("""\A[a-z0-9][a-z0-9_.-]{0,63}\z""")
            private val TRANSIT = Regex("""\A([a-z0-9][a-z0-9_-]{0,63})/([a-z0-9][a-z0-9_.-]{0,127})\z""")
            private val AUDIENCE = Regex("""\A[\x21-\x7e]{1,256}\z""")

            fun of(address: String, role: String, transit: String, certificate: String?, caCertificate: String?, audience: String?): Target {
                val uri = runCatching { URI(address) }.getOrNull()
                if (uri?.scheme != "https" || uri.host.isNullOrEmpty() || uri.userInfo != null || uri.query != null || uri.fragment != null
                    || !(uri.path.isNullOrEmpty() || uri.path == "/"))
                    throw ProtectException(ErrorCode.USAGE, "--openbao-addr must be an https URL without a path")
                if (!ROLE.matches(role)) throw ProtectException(ErrorCode.USAGE, "--openbao-role is not a role name")
                val m = TRANSIT.matchEntire(transit) ?: throw ProtectException(ErrorCode.USAGE, "--openbao-transit must be <mount>/<key>")
                val aud = audience ?: address.trimEnd('/')
                if (!AUDIENCE.matches(aud)) throw ProtectException(ErrorCode.USAGE, "--openbao-audience is not an audience")
                // Both files are arguments: a missing or unreadable one is `usage`, before any run is opened.
                val cert = certificate?.let { path ->
                    val file = File(path)
                    if (!file.isFile) throw ProtectException(ErrorCode.USAGE, "--openbao-key is not a file")
                    certificateOf(file)
                }
                val ssl = caCertificate?.let { path ->
                    val file = File(path)
                    if (!file.isFile) throw ProtectException(ErrorCode.USAGE, "--openbao-cacert is not a file")
                    trusting(file)
                }
                return Target(URI("https://" + uri.rawAuthority), role, m.groupValues[1], m.groupValues[2], cert, ssl, aud)
            }

            private fun certificateOf(file: File): X509Certificate {
                val certificate = try {
                    file.inputStream().use { CertificateFactory.getInstance("X.509").generateCertificate(it) as X509Certificate }
                } catch (e: Exception) {
                    throw ProtectException(ErrorCode.USAGE, "--openbao-key is not an X.509 certificate")
                }
                if (certificate.publicKey !is RSAPublicKey) throw ProtectException(ErrorCode.USAGE, "--openbao-key: the certificate key is not RSA")
                return certificate
            }

            private fun trusting(ca: File): SSLContext {
                val store = KeyStore.getInstance(KeyStore.getDefaultType()).apply { load(null, null) }
                val certificates = try {
                    ca.inputStream().use { CertificateFactory.getInstance("X.509").generateCertificates(it).toList() }
                } catch (e: Exception) {
                    throw ProtectException(ErrorCode.USAGE, "--openbao-cacert is not a certificate file")
                }
                if (certificates.isEmpty()) throw ProtectException(ErrorCode.USAGE, "--openbao-cacert is not a certificate file")
                certificates.forEachIndexed { i, c -> store.setCertificateEntry("ca$i", c) }
                val trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(store) }
                return SSLContext.getInstance("TLS").apply { init(null, trust.trustManagers, null) }
            }
        }
    }

    private val http: HttpClient by lazy {
        val builder = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).connectTimeout(Duration.ofSeconds(15))
        target.sslContext?.let { builder.sslContext(it) }
        builder.build()
    }
    private var token: String? = null

    /** Signs [file] in place (JAR signature, SHA-256) and returns the SHA-256 of the signer certificate. */
    fun sign(file: File): String {
        val certificate = target.certificate ?: throw ProtectException(ErrorCode.USAGE, "--openbao-key")
        try {
            val public = transitPublicKey()
            if (!public.encoded.contentEquals(certificate.publicKey.encoded))
                throw ProtectException(ErrorCode.SIGN_FAILED, "the certificate is not the one of the OpenBao key")
            val signed = File(file.parentFile, ".${file.name}.${UUID.randomUUID()}.signing")
            try {
                val chain = CertificateFactory.getInstance("X.509").generateCertPath(listOf(certificate))
                val signer = JarSigner.Builder(RemoteKey(public as RSAPublicKey), chain)
                    .signatureAlgorithm("SHA256withRSA", TransitProvider(::transitSign))
                    .digestAlgorithm("SHA-256").build()
                ZipFile(file).use { zip -> signed.outputStream().use { out -> signer.sign(zip, out) } }
                Files.move(signed.toPath(), file.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
            } catch (e: ProtectException) {
                throw e
            } catch (e: Exception) {
                // The provider wraps its own refusals; unwrap them so the contract code survives.
                generateSequence<Throwable>(e) { it.cause }.filterIsInstance<ProtectException>().firstOrNull()?.let { throw it }
                throw ProtectException(ErrorCode.SIGN_FAILED, "JAR signing (${e.javaClass.simpleName})")
            } finally {
                signed.delete()
            }
            return sha256(certificate.encoded)
        } finally {
            close()
        }
    }

    /**
     * `sentomaru protect openbao-certificate`: a self-signed X.509 v3 certificate for the Transit key (the upload
     * certificate the client registers in the Play Console), signed by the key itself in the vault. Returns the PEM.
     */
    fun selfSignedCertificate(commonName: String, years: Int): String {
        try {
            val public = transitPublicKey()
            val name = name(commonName)
            val now = ZonedDateTime.now(ZoneOffset.UTC).withNano(0)
            val serial = BigInteger(64, SecureRandom()).setBit(63)
            val algorithm = Der.seq(Der.oid("1.2.840.113549.1.1.11"), Der.NULL)
            val tbs = Der.seq(Der.explicit(0, Der.int(BigInteger.TWO)), Der.int(serial), algorithm, name,
                Der.seq(Der.time(now.minusMinutes(5)), Der.time(now.plusYears(years.toLong()))), name, public.encoded)
            val signature = transitSign(MessageDigest.getInstance("SHA-256").digest(tbs))
            val der = Der.seq(tbs, algorithm, Der.bits(signature))
            val certificate = CertificateFactory.getInstance("X.509").generateCertificate(der.inputStream()) as X509Certificate
            certificate.verify(public)
            return "-----BEGIN CERTIFICATE-----\n" + Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(der) +
                "\n-----END CERTIFICATE-----\n"
        } catch (e: ProtectException) {
            throw e
        } catch (e: Exception) {
            throw ProtectException(ErrorCode.SIGN_FAILED, "certificate (${e.javaClass.simpleName})")
        } finally {
            close()
        }
    }

    /** The Transit key: RSA, not exportable, no plaintext backup (custody), latest version's public key. */
    private fun transitPublicKey(): PublicKey {
        val data = call("GET", "/v1/${target.mount}/keys/${target.key}", null).getAsJsonObject("data")
            ?: throw ProtectException(ErrorCode.SIGN_FAILED, "unexpected key answer")
        val type = data.get("type")?.asString ?: ""
        if (!type.startsWith("rsa-")) throw ProtectException(ErrorCode.SIGN_FAILED, "the OpenBao key is not RSA ($type)")
        if (data.get("exportable")?.asBoolean != false || data.get("allow_plaintext_backup")?.asBoolean != false)
            throw ProtectException(ErrorCode.SIGN_FAILED, "the OpenBao key is exportable: refused (custody)")
        val latest = data.get("latest_version")?.asInt ?: throw ProtectException(ErrorCode.SIGN_FAILED, "unexpected key answer")
        val pem = data.getAsJsonObject("keys")?.getAsJsonObject(latest.toString())?.get("public_key")?.asString
            ?: throw ProtectException(ErrorCode.SIGN_FAILED, "unexpected key answer")
        val der = Base64.getMimeDecoder().decode(pem.lines().filter { !it.startsWith("-----") }.joinToString(""))
        return KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(der))
    }

    /** One RSA operation in the vault: PKCS#1 v1.5 over a SHA-256 [digest] computed here. */
    internal fun transitSign(digest: ByteArray): ByteArray {
        val body = JsonObject().apply {
            addProperty("input", Base64.getEncoder().encodeToString(digest))
            addProperty("prehashed", true)
            addProperty("signature_algorithm", "pkcs1v15")
        }
        val value = call("POST", "/v1/${target.mount}/sign/${target.key}/sha2-256", body)
            .getAsJsonObject("data")?.get("signature")?.asString ?: throw ProtectException(ErrorCode.SIGN_FAILED, "unexpected sign answer")
        val parts = value.split(':')
        if (parts.size != 3 || parts[0] != "vault" || !parts[1].startsWith("v")) throw ProtectException(ErrorCode.SIGN_FAILED, "unexpected sign answer")
        return try {
            Base64.getDecoder().decode(parts[2])
        } catch (e: IllegalArgumentException) {
            throw ProtectException(ErrorCode.SIGN_FAILED, "unexpected sign answer")
        }
    }

    private fun login(): String {
        token?.let { return it }
        val jwt = jwt()
        val body = JsonObject().apply { addProperty("role", target.role); addProperty("jwt", jwt) }
        val answer = try {
            call("POST", "/v1/auth/jwt/login", body, authenticated = false)
        } catch (e: ProtectException) {
            throw ProtectException(ErrorCode.SIGNER_UNAVAILABLE, "OpenBao login refused or unreachable (${e.detail})")
        }
        val value = answer.getAsJsonObject("auth")?.get("client_token")?.asString
            ?: throw ProtectException(ErrorCode.SIGNER_UNAVAILABLE, "OpenBao login gave no token")
        token = value
        return value
    }

    /** The CI identity: an explicit JWT in the environment, or the GitHub Actions OIDC token for [Target.audience]. */
    private fun jwt(): String {
        env["SENTOMARU_OPENBAO_JWT"]?.takeIf { it.isNotBlank() }?.let { return jwtShape(it.trim()) }
        val url = env["ACTIONS_ID_TOKEN_REQUEST_URL"]
        val bearer = env["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]
        if (url.isNullOrEmpty() || bearer.isNullOrEmpty())
            throw ProtectException(ErrorCode.SIGNER_UNAVAILABLE, "no CI identity: SENTOMARU_OPENBAO_JWT or GitHub OIDC (permissions: id-token: write)")
        val uri = runCatching { URI(url + (if ('?' in url) "&" else "?") + "audience=" + URLEncoder.encode(target.audience, Charsets.UTF_8)) }.getOrNull()
        if (uri?.scheme != "https") throw ProtectException(ErrorCode.SIGNER_UNAVAILABLE, "the OIDC request URL is not https")
        val response = try {
            HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).connectTimeout(Duration.ofSeconds(15)).build()
                .send(HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(30)).header("Authorization", "bearer $bearer").GET().build(),
                    HttpResponse.BodyHandlers.ofString())
        } catch (e: Exception) {
            throw ProtectException(ErrorCode.SIGNER_UNAVAILABLE, "the CI identity provider is unreachable")
        }
        if (response.statusCode() != 200) throw ProtectException(ErrorCode.SIGNER_UNAVAILABLE, "the CI identity provider refused (${response.statusCode()})")
        val value = runCatching { JsonParser.parseString(response.body()).asJsonObject.get("value").asString }.getOrNull()
            ?: throw ProtectException(ErrorCode.SIGNER_UNAVAILABLE, "unexpected CI identity answer")
        return jwtShape(value)
    }

    private fun jwtShape(value: String): String {
        if (value.length > 16384 || !Regex("""\A[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\z""").matches(value))
            throw ProtectException(ErrorCode.SIGNER_UNAVAILABLE, "the CI identity is not a JWT")
        return value
    }

    /** An OpenBao call; only the status code ever reaches an error message, never a body. */
    private fun call(method: String, path: String, body: JsonObject?, authenticated: Boolean = true): JsonObject {
        val request = HttpRequest.newBuilder(target.address.resolve(path)).timeout(Duration.ofSeconds(30))
            .header("Content-Type", "application/json")
            .method(method, if (body == null) HttpRequest.BodyPublishers.noBody() else HttpRequest.BodyPublishers.ofString(body.toString()))
        if (authenticated) request.header("X-Vault-Token", login())
        val response = try {
            http.send(request.build(), HttpResponse.BodyHandlers.ofInputStream())
        } catch (e: Exception) {
            throw ProtectException(ErrorCode.SIGNER_UNAVAILABLE, "OpenBao unreachable or TLS refused (${e.javaClass.simpleName})")
        }
        // 401/403: identity or policy (signer-unavailable); 404 and other 4xx: the key or the request (sign-failed);
        // 5xx: the vault (signer-unavailable). The body is never read past ANSWER_LIMIT.
        val status = response.statusCode()
        val bytes = try {
            response.body().use { it.readNBytes(ANSWER_LIMIT + 1) }
        } catch (e: Exception) {
            throw ProtectException(ErrorCode.SIGNER_UNAVAILABLE, "OpenBao answer interrupted")
        }
        if (status == 401 || status == 403) throw ProtectException(ErrorCode.SIGNER_UNAVAILABLE, "OpenBao refused ($status)")
        if (status !in 200..299) throw ProtectException(if (status >= 500) ErrorCode.SIGNER_UNAVAILABLE else ErrorCode.SIGN_FAILED, "OpenBao answered $status")
        if (bytes.size > ANSWER_LIMIT) throw ProtectException(ErrorCode.SIGN_FAILED, "OpenBao answer too large")
        if (bytes.isEmpty()) return JsonObject()
        return runCatching { JsonParser.parseString(bytes.toString(Charsets.UTF_8)).asJsonObject }.getOrNull()
            ?: throw ProtectException(ErrorCode.SIGN_FAILED, "unexpected OpenBao answer")
    }

    /** Revokes the session token (best effort: it also expires by its own TTL). */
    private fun close() {
        val value = token ?: return
        token = null
        runCatching {
            http.send(HttpRequest.newBuilder(target.address.resolve("/v1/auth/token/revoke-self")).timeout(Duration.ofSeconds(10))
                .header("X-Vault-Token", value).POST(HttpRequest.BodyPublishers.noBody()).build(), HttpResponse.BodyHandlers.discarding())
        }
    }

    private fun name(commonName: String): ByteArray {
        if (commonName.isEmpty() || commonName.length > 64 || commonName.any { it.isISOControl() })
            throw ProtectException(ErrorCode.USAGE, "--common-name must have 1..64 characters")
        return Der.seq(Der.set(Der.seq(Der.oid("2.5.4.3"), Der.utf8(commonName))))
    }

    /** A private key handle with no material: the operations happen in [TransitProvider]. */
    private class RemoteKey(private val public: RSAPublicKey) : PrivateKey, RSAKey {
        override fun getAlgorithm() = "RSA"
        override fun getFormat(): String? = null
        override fun getEncoded(): ByteArray? = null
        override fun getModulus(): BigInteger = public.modulus
    }

    /** JCA provider with one service, `Signature.SHA256withRSA`, whose sign step is a Transit call. */
    private class TransitProvider(private val sign: (ByteArray) -> ByteArray) :
        Provider("SentomaruOpenBaoTransit", "1.0", "OpenBao Transit RSA signing (sentomaru protect)") {
        init {
            putService(object : Service(this, "Signature", "SHA256withRSA", TransitSignature::class.java.name, null, null) {
                override fun newInstance(constructorParameter: Any?): Any = TransitSignature(sign)
            })
        }
    }

    private class TransitSignature(private val sign: (ByteArray) -> ByteArray) : SignatureSpi() {
        private val digest = MessageDigest.getInstance("SHA-256")
        override fun engineInitSign(privateKey: PrivateKey?) {
            if (privateKey !is RemoteKey) throw java.security.InvalidKeyException("not an OpenBao key")
            digest.reset()
        }
        override fun engineInitVerify(publicKey: PublicKey?) = throw java.security.InvalidKeyException("sign only")
        override fun engineUpdate(b: Byte) = digest.update(b)
        override fun engineUpdate(b: ByteArray, off: Int, len: Int) = digest.update(b, off, len)
        override fun engineSign(): ByteArray = try {
            sign(digest.digest())
        } catch (e: ProtectException) {
            throw java.security.SignatureException(e.error.code, e)
        }
        override fun engineVerify(sigBytes: ByteArray?) = throw java.security.SignatureException("sign only")
        @Deprecated("JCA legacy") override fun engineSetParameter(param: String?, value: Any?) = throw UnsupportedOperationException()
        @Deprecated("JCA legacy") override fun engineGetParameter(param: String?): Any = throw UnsupportedOperationException()
    }

    /** The few DER constructs a self-signed certificate needs. */
    private object Der {
        val NULL = byteArrayOf(0x05, 0x00)
        fun tlv(tag: Int, content: ByteArray): ByteArray = ByteArrayOutputStream().apply {
            write(tag)
            val n = content.size
            when {
                n < 0x80 -> write(n)
                n < 0x100 -> { write(0x81); write(n) }
                n < 0x10000 -> { write(0x82); write(n shr 8); write(n and 0xff) }
                else -> { write(0x83); write(n shr 16); write((n shr 8) and 0xff); write(n and 0xff) }
            }
            write(content)
        }.toByteArray()
        fun seq(vararg parts: ByteArray) = tlv(0x30, parts.fold(ByteArray(0)) { a, b -> a + b })
        fun set(vararg parts: ByteArray) = tlv(0x31, parts.fold(ByteArray(0)) { a, b -> a + b })
        fun int(value: BigInteger) = tlv(0x02, value.toByteArray())
        fun explicit(n: Int, content: ByteArray) = tlv(0xa0 + n, content)
        fun utf8(s: String) = tlv(0x0c, s.toByteArray(Charsets.UTF_8))
        fun bits(bytes: ByteArray) = tlv(0x03, byteArrayOf(0) + bytes)
        fun oid(dotted: String): ByteArray {
            val arcs = dotted.split('.').map { it.toLong() }
            val out = ByteArrayOutputStream()
            out.write((arcs[0] * 40 + arcs[1]).toInt())
            for (arc in arcs.drop(2)) {
                val chunks = generateSequence(arc) { it shr 7 }.takeWhile { it > 0 }.map { (it and 0x7f).toInt() }.toList().reversed()
                    .ifEmpty { listOf(0) }
                chunks.forEachIndexed { i, c -> out.write(if (i < chunks.size - 1) c or 0x80 else c) }
            }
            return tlv(0x06, out.toByteArray())
        }
        /** RFC 5280 §4.1.2.5: UTCTime through 2049, GeneralizedTime from 2050. */
        fun time(t: ZonedDateTime): ByteArray = if (t.year < 2050)
            tlv(0x17, t.format(DateTimeFormatter.ofPattern("yyMMddHHmmss'Z'")).toByteArray())
        else tlv(0x18, t.format(DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'")).toByteArray())
    }

    private fun sha256(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
}
