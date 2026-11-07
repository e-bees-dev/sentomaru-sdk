package br.com.ebees.sentomaru.sdk

import java.security.MessageDigest
import java.util.Base64

/**
 * C-04b: optional source of a Play Integrity token for an enrollment (the Sentomaru Play Integrity API contract). Advisory:
 * an implementation answers null on ANY failure (unavailable Play services, timeout, quota, misconfiguration) and the
 * enrollment goes on without the token. Called on the SDK worker thread, at most once per frozen enrollment body.
 */
fun interface IntegrityTokenSource {
    /** Token bound to [requestHash], or null. Must honour thread interruption (cancellation). */
    fun token(requestHash: String): String?
}

/** C-04b: the binding the server checks (`IntegrityVerdict.ExpectedNonce`). */
object IntegrityRequestHash {
    /**
     * base64url without padding of SHA-256(UTF-8(challengeId ":" attestationChallenge ":" packageName)), where the two
     * challenge values are written exactly as the challenge response carries them: the lowercase UUID and the padded
     * standard base64 of the 32 attestation-challenge bytes.
     */
    fun of(challengeId: String, attestationChallenge: ByteArray, packageName: String): String {
        val text = "$challengeId:${Base64.getEncoder().encodeToString(attestationChallenge)}:$packageName"
        return Base64.getUrlEncoder().withoutPadding().encodeToString(
            MessageDigest.getInstance("SHA-256").digest(text.toByteArray(Charsets.UTF_8)))
    }

    /** Same as [of] for a validated challenge. */
    fun of(challenge: EnrollmentChallenge, packageName: String): String =
        of(challenge.id, challenge.attestationChallenge(), packageName)

    // The enrollment body is fixed JSON without escaping: only a token in the JWS/JWE alphabet (and the server's length
    // bound) may be embedded; anything else is dropped (advisory, never a reason for a 400).
    private val tokenShape = Regex("[A-Za-z0-9._-]{1,16384}")
    internal fun acceptable(token: String?): String? = token?.takeIf { tokenShape.matches(it) }
}

/**
 * C-04b review F2/F5: provider caching and retry of a Play Integrity standard request, without Google types so it is
 * testable on the JVM. The provider is prepared once and reused; a request that fails because the provider expired
 * ([providerInvalid]) prepares again and retries ONCE; any other failure keeps the provider and answers null; a failed
 * prepare answers null. Interruption is preserved (null, flag set).
 */
internal class CachedIntegrityRequester<P : Any>(private val prepare: () -> P, private val request: (P, String) -> String,
    private val providerInvalid: (Throwable) -> Boolean) {
    private var provider: P? = null

    @Synchronized fun token(requestHash: String): String? {
        for (attempt in 1..2) {
            val ready = provider ?: try { prepare().also { provider = it } } catch (e: Exception) { return failed(e) }
            try {
                return request(ready, requestHash)
            } catch (e: Exception) {
                if (e is InterruptedException || !providerInvalid(e) || attempt == 2) return failed(e)
                provider = null // expired provider: prepare again, once
            }
        }
        return null
    }

    private fun failed(e: Exception): String? {
        if (e is InterruptedException) Thread.currentThread().interrupt()
        return null
    }
}
