package br.com.ebees.sentomaru.core

import java.util.Base64

/**
 * The signing key lives outside the core (AndroidKeyStore via `KeystoreSigner`, a JDK key in tests): the core only
 * hands it the signature base and expects a 64-byte IEEE P1363 `r || s` back. Exceptions thrown by the signer
 * propagate unchanged (the Android layer maps them, e.g. to `KeyInvalidated`).
 */
fun interface SignatureFunction {
    fun sign(signatureBase: ByteArray): ByteArray
}

/**
 * A request frozen before signing (E2): the body is copied once and the same bytes are digested, signed and sent.
 * Constructing it validates the body size ([SentomaruError.BodyTooLarge]); the rest is validated when signing.
 */
class FrozenRequest(val method: String, val targetUri: String, headers: Map<String, String>, body: ByteArray) {
    val headers: Map<String, String> = LinkedHashMap(headers)
    private val frozen: ByteArray = body.copyOf()

    init {
        MessageRules.bodySize(frozen.size)
    }

    val bodySize: Int get() = frozen.size

    /** A copy of the frozen bytes (callers cannot alter what was signed). */
    fun body(): ByteArray = frozen.copyOf()
}

/**
 * Result of [MessageSigner.sign]: the headers to send, in order (`content-digest`, the caller's profile headers,
 * `signature-input`, `signature`; lowercase names) and the exact body bytes that were digested.
 */
class SignedMessage internal constructor(
    val method: String,
    val targetUri: String,
    val headers: List<Pair<String, String>>,
    private val frozen: ByteArray,
    private val base: ByteArray,
) {
    fun body(): ByteArray = frozen.copyOf()

    /** The bytes handed to the signer; exposed for vectors and diagnostics (contains no secret). */
    fun signatureBase(): ByteArray = base.copyOf()

    fun header(name: String): String? = headers.firstOrNull { it.first == name }?.second
}

object MessageSigner {
    /** `sig1=<inner list>` for [params]. */
    fun signatureInput(params: SignatureParams): String = Profile.LABEL + "=" + params.serialize()

    /** `sig1=:<base64>:` for a 64-byte P1363 signature. */
    fun signatureHeader(signature: ByteArray): String {
        if (signature.size != Profile.SIGNATURE_BYTES) {
            throw SentomaruException(SentomaruError.SignatureFormat(signature.size))
        }
        return Profile.LABEL + "=:" + Base64.getEncoder().encodeToString(signature) + ":"
    }

    fun sign(request: FrozenRequest, given: SignatureParams, signer: SignatureFunction): SignedMessage {
        val params = given.withComponents(Profile.components(request.headers))
        val body = request.body()
        val digest = ContentDigest.sha256(body)
        val base = SignatureBase.build(request.method, request.targetUri, request.headers, digest, params)
        val signature = signatureHeader(signer.sign(base.copyOf()))
        val headers = ArrayList<Pair<String, String>>(Profile.COMPONENTS.size + 1)
        headers += Profile.CONTENT_DIGEST to digest
        for (name in Profile.CALLER_HEADERS) headers += name to request.headers.getValue(name)
        for (name in Profile.OPTIONAL_HEADERS) request.headers[name]?.let { headers += name to it }
        headers += Profile.SIGNATURE_INPUT to signatureInput(params)
        headers += Profile.SIGNATURE to signature
        return SignedMessage(request.method, request.targetUri, headers, body, base)
    }
}
