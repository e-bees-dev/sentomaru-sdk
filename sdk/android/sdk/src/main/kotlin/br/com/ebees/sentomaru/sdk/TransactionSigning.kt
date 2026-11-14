package br.com.ebees.sentomaru.sdk

import br.com.ebees.sentomaru.core.SentomaruError
import br.com.ebees.sentomaru.core.SentomaruException
import br.com.ebees.sentomaru.core.SignedMessage
import br.com.ebees.sentomaru.sdk.transport.SentomaruWire
import br.com.ebees.sentomaru.signer.EcdsaSignatureFormat
import br.com.ebees.sentomaru.signer.TransactionKeyInvalidatedException
import br.com.ebees.sentomaru.signer.TransactionKeySigner
import java.security.GeneralSecurityException
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature
import java.util.Base64

/**
 * D-25 (HU-01): why a transaction signature was not produced. [recoverable] errors leave everything as it was: the same
 * call can be made again, nothing was spent and neither the installation key nor the grant was touched.
 */
abstract class TransactionError(code: String, val recoverable: Boolean) : SentomaruError(code) {
    /** No transaction key for this installation: enroll one first. */
    class NotEnrolled : TransactionError("TxNotEnrolled", false)
    /** The platform dropped the key (new biometric enrolled, or the key is gone): enroll a new one. */
    class KeyInvalidated : TransactionError("TxKeyInvalidated", false)
    /** The person dismissed the prompt or pressed the negative button; ask again when they act again. */
    class Cancelled : TransactionError("TxCancelled", true)
    /** The sensor is locked out for a while ([permanent] false) or until the device credential is used. */
    class LockedOut(val permanent: Boolean) : TransactionError("TxLockedOut", !permanent)
    /** No biometric or device credential is enrolled on this device. */
    class NoUserAuthentication : TransactionError("TxNoUserAuthentication", false)
    /** The prompt could not run (hardware unavailable, timeout, system cancel); [platformCode] is the platform code. */
    class Unavailable(val platformCode: Int) : TransactionError("TxUnavailable", true)
    /** The signature could not be computed even after authentication. */
    class SigningFailed : TransactionError("TxSigningFailed", false)
}

/** The consumer route's answer from the private API, passed through: HTTP status and body text. */
class TransactionAnswer @JvmOverloads constructor(val status: Int, val body: String, retryAfterSeconds: Long? = null) {
    /** The server's `Retry-After` in seconds; a negative value from a proxy or CDN is not a wait, so it becomes `null` (review B, RC-07). */
    val retryAfterSeconds: Long? = retryAfterSeconds?.takeIf { it >= 0 }

    init {
        require(status in 100..599) { "Invalid HTTP status" }
    }

    /**
     * Shield #12: how long to wait before asking again after a 429 or 5xx, from the server's `Retry-After` (seconds), bounded to
     * 1 s..24 h (the largest wait the server emits, the daily limit; review B, RC-08) so a `0` cannot make a tight loop and a huge value cannot park the app. `null` = the server said nothing: the app
     * picks its own backoff.
     */
    val retryWaitSeconds: Long? get() = retryAfterSeconds?.coerceIn(MIN_RETRY_SECONDS, MAX_RETRY_SECONDS)

    companion object {
        const val MIN_RETRY_SECONDS = 1L
        const val MAX_RETRY_SECONDS = 86_400L
    }
}

/** Result of [SentomaruTransactionSigner.enroll]. */
sealed class TransactionEnrollOutcome {
    class Enrolled(val txKeyId: String, val userAuthentication: String) : TransactionEnrollOutcome()
    /** The server refused; [code] is its stable code (for example `user-auth-not-proven`), the new key was removed. */
    class Refused(val code: String, val status: Int) : TransactionEnrollOutcome()
    /** Network, 429 or 5xx: try again later; nothing was kept. [retryAfterSeconds]: the server's wait (bounded), `null` if none. */
    class Unavailable @JvmOverloads constructor(val retryAfterSeconds: Long? = null) : TransactionEnrollOutcome()
}

/** Platform port for the secondary, user-authenticated key. The private key never leaves the Keystore. */
interface TransactionKeys {
    fun exists(alias: String): Boolean
    fun generate(alias: String, challenge: ByteArray, strongBox: Boolean, strongBiometricOnly: Boolean): KeyMaterial
    /** A signature initialised for signing; it works only after the person authenticates. */
    fun initSign(alias: String): Signature
    fun delete(alias: String)
    /** When the key was made, epoch milliseconds; between two keys of one installation the larger is the newer. */
    fun createdAt(alias: String): Long = 0L
}

class AndroidTransactionKeys : TransactionKeys {
    private val signer = TransactionKeySigner()

    override fun exists(alias: String): Boolean = try { TransactionKeySigner.containsAlias(alias) }
    catch (_: GeneralSecurityException) { false }

    override fun generate(alias: String, challenge: ByteArray, strongBox: Boolean, strongBiometricOnly: Boolean): KeyMaterial {
        val chain = try { signer.generate(alias, challenge, strongBox, strongBiometricOnly) }
        catch (_: br.com.ebees.sentomaru.signer.StrongBoxUnavailableError) { fail(EnrollmentError.StrongBoxUnavailable()) }
        catch (_: GeneralSecurityException) { fail(EnrollmentError.KeyUnavailable()) }
        catch (_: java.security.ProviderException) { fail(EnrollmentError.KeyUnavailable()) }
        val leaf = java.security.cert.CertificateFactory.getInstance("X.509")
            .generateCertificate(chain[0].inputStream()).publicKey.encoded
        return KeyMaterial(leaf, chain)
    }

    override fun initSign(alias: String): Signature = try { signer.initSign(alias) }
    catch (e: TransactionKeyInvalidatedException) { throw e }

    override fun delete(alias: String) = TransactionKeySigner.deleteKey(alias)

    override fun createdAt(alias: String): Long = try { TransactionKeySigner.createdAtMillis(alias) }
    catch (_: GeneralSecurityException) { 0L }
}

/**
 * Runs the user authentication for one signature. Implementations show the system prompt with [signature] wrapped in
 * a crypto object (see [BiometricPromptAuthenticator]) and call exactly one of the two callbacks, from any thread.
 */
interface TransactionAuthenticator {
    fun authenticate(signature: Signature, onAuthenticated: (Signature) -> Unit, onError: (TransactionError) -> Unit)
}

/** Which signed format the signer emits (contract `transaction-keys-v1`, sections 2 and 2a). */
enum class TransactionSignatureVersion { V1, V2 }

/** The server challenge to sign: nonce, operation and the body, bound by [TransactionSignature.message]. */
object TransactionSignature {
    const val VERSION = "sentomaru-tx-v1"
    const val VERSION_2 = "sentomaru-tx-v2"
    const val NONCE_BYTES = 16

    /**
     * The exact bytes the transaction key signs in v1: `sentomaru-tx-v1 LF nonce LF operation-id LF body-digest`, nonce and
     * digest in base64url without padding, digest = SHA-256 of the body. It binds a signature to one operation and one
     * body. It does not show that the person read the body. No clock: the server remembers the nonce for 25 h.
     */
    fun message(nonce: ByteArray, operationId: String, body: ByteArray): ByteArray {
        require(nonce.size == NONCE_BYTES) { "nonce must be $NONCE_BYTES bytes" }
        require(OPERATION_ID.matches(operationId)) { "invalid operation id" }
        val b64 = Base64.getUrlEncoder().withoutPadding()
        val digest = b64.encodeToString(MessageDigest.getInstance("SHA-256").digest(body))
        return "$VERSION\n${b64.encodeToString(nonce)}\n$operationId\n$digest".toByteArray(Charsets.UTF_8)
    }

    /**
     * v2 bytes: `sentomaru-tx-v2 LF nonce LF issuedAt LF operation-id LF body-digest`, `issuedAt` = Unix seconds UTC in
     * decimal (10 digits). The server accepts it only within 5 minutes of its own clock and remembers the nonce for 11.
     */
    fun message(nonce: ByteArray, issuedAtSeconds: Long, operationId: String, body: ByteArray): ByteArray {
        require(nonce.size == NONCE_BYTES) { "nonce must be $NONCE_BYTES bytes" }
        require(OPERATION_ID.matches(operationId)) { "invalid operation id" }
        val issuedAt = issuedAtText(issuedAtSeconds)
        val b64 = Base64.getUrlEncoder().withoutPadding()
        val digest = b64.encodeToString(MessageDigest.getInstance("SHA-256").digest(body))
        return "$VERSION_2\n${b64.encodeToString(nonce)}\n$issuedAt\n$operationId\n$digest".toByteArray(Charsets.UTF_8)
    }

    /** `sentomaru-tx-v1.<nonce>.<signature>`, base64url without padding, signature in IEEE P1363 (r || s). */
    fun header(nonce: ByteArray, p1363: ByteArray): String {
        val b64 = Base64.getUrlEncoder().withoutPadding()
        return "$VERSION.${b64.encodeToString(nonce)}.${b64.encodeToString(p1363)}"
    }

    /** `sentomaru-tx-v2.<nonce>.<issuedAt>.<signature>`. */
    fun header(nonce: ByteArray, issuedAtSeconds: Long, p1363: ByteArray): String {
        val b64 = Base64.getUrlEncoder().withoutPadding()
        return "$VERSION_2.${b64.encodeToString(nonce)}.${issuedAtText(issuedAtSeconds)}.${b64.encodeToString(p1363)}"
    }

    /** Ten decimal digits (1_000_000_000 to 9_999_999_999): a clock that reads before 2001 is refused, not signed. */
    private fun issuedAtText(seconds: Long): String {
        require(seconds in 1_000_000_000L..9_999_999_999L) { "issuedAt out of range" }
        return seconds.toString()
    }

    private val OPERATION_ID = Regex("""\A[A-Za-z0-9-]{16,64}\z""")
}

/**
 * The answer of `POST transaction-keys/challenges` (contract `transaction-keys-v1` section 1). Unlike the installation
 * [EnrollmentChallenge], [token] is the `challengeId` as text: the SDK sends it back as is in the enrollment body, so it only
 * has to be short and free of characters that need JSON escaping. [attestationChallenge] is the 32 bytes the key attests.
 */
class TransactionKeyChallenge(val id: String, val token: String, attestationChallenge: ByteArray, val expiresAt: java.time.Instant) {
    private val attestation = attestationChallenge.copyOf()
    fun attestationChallenge(): ByteArray = attestation.copyOf()
    init {
        validateUuid(id)
        require(token.length in 1..128 && token.all { it.isLetterOrDigit() && it.code < 128 || it in "-_+/=" } &&
            attestation.size == 32) { "Invalid challenge" }
    }
}

/**
 * D-25 slice (c): enrollment body of the transaction key and the per-operation signature.
 *
 * What a signature proves: a person who can unlock this device was present at the moment of signing. It does not prove
 * the person saw or agreed to the value. The prompt runs here, in the caller's thread of control, never inside the HTTP
 * interceptor: the app calls [sign], gets the header value and sets `x-sentomaru-tx-signature` on the request.
 * Nothing here touches the installation key, the grant or the stored record; a cancelled prompt corrupts nothing.
 */
class SentomaruTransactionSigner @JvmOverloads constructor(
    private val client: SentomaruClient,
    private val keys: TransactionKeys = AndroidTransactionKeys(),
    private val random: SecureRandom = SecureRandom(),
    /** v2 is the default; pass [TransactionSignatureVersion.V1] only for a server that does not list `v2` (contract section 2a). */
    private val version: TransactionSignatureVersion = TransactionSignatureVersion.V2,
    private val nowSeconds: () -> Long = { System.currentTimeMillis() / 1000 },
    // Last, so an existing trailing-lambda call `SentomaruTransactionSigner(client, keys, random) { false }` still binds here.
    private val onMainThread: () -> Boolean = { android.os.Looper.getMainLooper()?.isCurrentThread == true },
) {
    /** The alias being generated and not yet accepted by the server, in this process only. */
    @Volatile private var pending: String? = null

    /** Whether a transaction key exists for the current installation. */
    fun isEnrolled(): Boolean = activeAlias() != null

    /**
     * Generates the transaction key (replacing an old one) for [challenge] and returns the enrollment request body for
     * `POST transaction-keys` (contract `transaction-keys-v1`). [EnrollmentError.EnrollmentRequired] without a grant.
     */
    /**
     * The installation enrollment challenge has a 32-byte Base64 token and the transaction-key server never issues one: kept
     * only so code built against rc.5 still compiles. Use the [TransactionKeyChallenge] overload.
     */
    @Deprecated("The transaction-key challenge is a TransactionKeyChallenge (token = challengeId)",
        ReplaceWith("prepareEnrollment(TransactionKeyChallenge(challenge.id, challenge.token, challenge.attestationChallenge(), challenge.expiresAt), strongBox, strongBiometricOnly)"))
    @JvmOverloads
    fun prepareEnrollment(challenge: EnrollmentChallenge, strongBox: Boolean = false, strongBiometricOnly: Boolean = true): ByteArray =
        prepareEnrollment(TransactionKeyChallenge(challenge.id, challenge.token, challenge.attestationChallenge(), challenge.expiresAt),
            strongBox, strongBiometricOnly)

    @JvmOverloads
    fun prepareEnrollment(challenge: TransactionKeyChallenge, strongBox: Boolean = false, strongBiometricOnly: Boolean = true): ByteArray {
        val base = baseAlias() ?: fail(EnrollmentError.EnrollmentRequired())
        // A key the server already holds is never touched here: the new one is made in the other slot and replaces it only in
        // [commitEnrollment], after the server accepted it. With no key yet the first slot is used and nothing is at risk.
        val live = activeAlias()
        val alias = slots(base).first { it != live }
        val material = try { keys.generate(alias, challenge.attestationChallenge(), strongBox, strongBiometricOnly) }
        catch (e: Throwable) { keys.delete(alias); throw e }
        val chain = material.chain()
        if (chain.isEmpty() || chain.size > 5 || chain.any { it.isEmpty() || it.size > 4096 }) {
            keys.delete(alias)
            fail(EnrollmentError.KeyUnavailable())
        }
        pending = alias
        val b64 = Base64.getEncoder()
        val auth = if (strongBiometricOnly) "biometric-strong" else "biometric-or-credential"
        return ("{\"challenge\":\"${challenge.token}\",\"publicKey\":\"${b64.encodeToString(material.publicKey())}\"," +
            "\"attestationChain\":[${chain.joinToString(",") { "\"${b64.encodeToString(it)}\"" }}]," +
            "\"userAuthentication\":\"$auth\"}").toByteArray(Charsets.UTF_8)
    }

    /**
     * The server accepted the key made by [prepareEnrollment]: it becomes the one in use and the previous one is deleted.
     * If the process dies before this call both keys exist and the older one keeps signing; the server then refuses that
     * signature and the app enrolls again, which is the recoverable state.
     */
    fun commitEnrollment() {
        pending = null
        val base = baseAlias() ?: return
        val both = slots(base).filter { keys.exists(it) }
        if (both.size == 2) keys.delete(both.minBy { keys.createdAt(it) })
    }

    /** The server did not accept the key made by [prepareEnrollment]: it is deleted and the previous key stays in use. */
    fun abortEnrollment() {
        val alias = pending ?: baseAlias()?.let { base ->
            slots(base).filter { keys.exists(it) }.takeIf { it.size == 2 }?.maxBy { keys.createdAt(it) }
        }
        pending = null
        alias?.let { keys.delete(it) }
    }

    /** Drops every transaction key of the installation (the server entry is removed by the app through the contract's DELETE). */
    fun discard() { pending = null; baseAlias()?.let { base -> slots(base).forEach { keys.delete(it) } } }

    /**
     * Asks the person to authenticate and, on success, calls [onSigned] with the header value. Exactly one callback
     * is called. [TransactionError.Cancelled] and the other `recoverable` errors can simply be retried.
     */
    fun sign(operationId: String, body: ByteArray, authenticator: TransactionAuthenticator,
             onSigned: (String) -> Unit, onError: (TransactionError) -> Unit) {
        val alias = activeAlias() ?: return onError(TransactionError.NotEnrolled())
        val nonce = ByteArray(TransactionSignature.NONCE_BYTES).also { random.nextBytes(it) }
        val issuedAt = nowSeconds()
        val message = try {
            if (version == TransactionSignatureVersion.V1) TransactionSignature.message(nonce, operationId, body)
            else TransactionSignature.message(nonce, issuedAt, operationId, body)
        } catch (_: IllegalArgumentException) { return onError(TransactionError.SigningFailed()) }
        val signature = try { keys.initSign(alias) }
        catch (_: TransactionKeyInvalidatedException) { return onError(TransactionError.KeyInvalidated()) }
        catch (_: GeneralSecurityException) { return onError(TransactionError.KeyInvalidated()) }
        authenticator.authenticate(signature, { authenticated ->
            val value = try {
                authenticated.update(message)
                val p1363 = EcdsaSignatureFormat.derToP1363(authenticated.sign())
                if (version == TransactionSignatureVersion.V1) TransactionSignature.header(nonce, p1363)
                else TransactionSignature.header(nonce, issuedAt, p1363)
            } catch (_: GeneralSecurityException) { return@authenticate onError(TransactionError.SigningFailed()) }
            catch (_: IllegalArgumentException) { return@authenticate onError(TransactionError.SigningFailed()) }
            onSigned(value)
        }, onError)
    }

    /**
     * Whole enrollment through the consumer's routes that forward to the private API (contract `transaction-keys-v1`
     * section 1): (1) `POST challenges` with body `{}`; (2) a new key for that challenge; (3) `POST transaction-keys`.
     * [send] returns the answer of the private API as is. Must not run on the main thread (Keystore, network). A
     * refusal removes the new key, so a key the server did not accept never stays behind.
     */
    @JvmOverloads
    fun enroll(challengeUrl: String, enrollUrl: String, strongBox: Boolean = false, strongBiometricOnly: Boolean = true,
               send: (SignedMessage) -> TransactionAnswer): TransactionEnrollOutcome {
        check(!onMainThread()) { "Transaction key enrollment must not run on the main thread" }
        client.config.checkHost(challengeUrl); client.config.checkHost(enrollUrl)
        val issued = try { send(client.sign("POST", challengeUrl, CHALLENGE_OPERATION, EMPTY_BODY.copyOf())) }
        catch (_: java.io.IOException) { return TransactionEnrollOutcome.Unavailable() }
        if (issued.status !in 200..299) return refused(issued)
        val challenge = parseChallenge(issued.body) ?: return TransactionEnrollOutcome.Refused(UNEXPECTED, issued.status)
        val body = prepareEnrollment(challenge, strongBox, strongBiometricOnly)
        val answer = try { send(client.sign("POST", enrollUrl, ENROLL_OPERATION, body)) }
        catch (_: java.io.IOException) { abortEnrollment(); return TransactionEnrollOutcome.Unavailable() }
        catch (e: RuntimeException) { abortEnrollment(); throw e }
        if (answer.status !in 200..299) { abortEnrollment(); return refused(answer) }
        val text = answer.body
        val id = if (text.length > MAX_ANSWER_CHARS) null else ReattestationJson.string(text, "txKeyId")
        val auth = if (text.length > MAX_ANSWER_CHARS) null else ReattestationJson.string(text, "userAuthentication")
        if (id == null || auth == null) { abortEnrollment(); return TransactionEnrollOutcome.Refused(UNEXPECTED, answer.status) }
        commitEnrollment()
        return TransactionEnrollOutcome.Enrolled(id, auth)
    }

    private fun refused(answer: TransactionAnswer): TransactionEnrollOutcome =
        if (answer.status == 429 || answer.status >= 500) TransactionEnrollOutcome.Unavailable(answer.retryWaitSeconds)
        else TransactionEnrollOutcome.Refused(SentomaruWire.errorCode(answer.body.take(MAX_ANSWER_CHARS)) ?: UNEXPECTED, answer.status)

    private fun parseChallenge(text: String): TransactionKeyChallenge? {
        if (text.length > MAX_ANSWER_CHARS) return null
        return try {
            val id = ReattestationJson.string(text, "challengeId") ?: return null
            val token = ReattestationJson.string(text, "token") ?: return null
            val raw = Base64.getDecoder().decode(ReattestationJson.string(text, "attestationChallenge") ?: return null)
            val expires = java.time.OffsetDateTime.parse(ReattestationJson.string(text, "expiresAt") ?: return null).toInstant()
            TransactionKeyChallenge(id, token, raw, expires)
        } catch (_: RuntimeException) { null } catch (_: SentomaruException) { null }
    }

    private fun baseAlias(): String? = client.installationAlias()

    /** The two slots of the installation: the first is the historical `<alias>.tx`. */
    private fun slots(base: String) = listOf("$base.tx", "$base.tx.next")

    /** The key in use: the only one, or the older of two (the newer is not yet accepted by the server). */
    private fun activeAlias(): String? {
        val base = baseAlias() ?: return null
        val present = slots(base).filter { keys.exists(it) }
        return if (present.size < 2) present.firstOrNull() else present.minBy { keys.createdAt(it) }
    }

    private companion object {
        const val CHALLENGE_OPERATION = "tx_key_challenge"
        const val ENROLL_OPERATION = "tx_key_enroll"
        const val UNEXPECTED = "unexpected-response"
        const val MAX_ANSWER_CHARS = 16 * 1024
        val EMPTY_BODY = "{}".toByteArray(Charsets.UTF_8)
    }
}

/**
 * Maps `androidx.biometric.BiometricPrompt.ERROR_*` codes to [TransactionError]. The SDK takes no dependency on
 * `androidx.biometric` (the app owns the prompt, the lock file and the manifest permission): the app's
 * [TransactionAuthenticator] passes `errorCode` from `onAuthenticationError` here. The numbers are the platform's
 * stable constants, locked by a test. Unknown codes are [TransactionError.Unavailable] and recoverable.
 */
object BiometricErrors {
    const val ERROR_LOCKOUT = 7
    const val ERROR_LOCKOUT_PERMANENT = 9
    const val ERROR_USER_CANCELED = 10
    const val ERROR_NO_BIOMETRICS = 11
    const val ERROR_HW_NOT_PRESENT = 12
    const val ERROR_NEGATIVE_BUTTON = 13
    const val ERROR_NO_DEVICE_CREDENTIAL = 14

    fun map(code: Int): TransactionError = when (code) {
        ERROR_USER_CANCELED, ERROR_NEGATIVE_BUTTON -> TransactionError.Cancelled()
        ERROR_LOCKOUT -> TransactionError.LockedOut(permanent = false)
        ERROR_LOCKOUT_PERMANENT -> TransactionError.LockedOut(permanent = true)
        ERROR_NO_BIOMETRICS, ERROR_NO_DEVICE_CREDENTIAL, ERROR_HW_NOT_PRESENT -> TransactionError.NoUserAuthentication()
        else -> TransactionError.Unavailable(code)
    }
}
