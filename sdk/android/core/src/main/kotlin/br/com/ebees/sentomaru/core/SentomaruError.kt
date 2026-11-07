package br.com.ebees.sentomaru.core

/**
 * Categorized, recoverable failure (decision E7). Open hierarchy on purpose: the Android layer adds
 * `NotEnrolled`, `KeyInvalidated`, `ChallengeExpired`, ... without breaking callers. [code] is stable and never
 * carries request values (no header values, URIs, keys or bodies), so it is safe to log.
 */
abstract class SentomaruError(val code: String) {
    override fun toString(): String = code

    /** Body over [Profile.MAX_BODY_BYTES]; only sizes are kept. */
    class BodyTooLarge(val size: Int, val limit: Int = Profile.MAX_BODY_BYTES) : SentomaruError("BodyTooLarge")

    /**
     * Destination host outside the allowlist (E6). Defined here so every layer shares one type; raised by the
     * transport layer (Task 3), never by the core. The host is not kept (it may identify a tenant).
     */
    class HostNotAllowed : SentomaruError("HostNotAllowed")

    /** The request cannot be signed under the profile; [reason] names the part, never its value. */
    class InvalidRequest(val reason: Reason) : SentomaruError("InvalidRequest:${reason.name}")

    /** The injected signer did not return a 64-byte P1363 signature. */
    class SignatureFormat(val size: Int) : SentomaruError("SignatureFormat")

    enum class Reason { METHOD, TARGET_URI, HEADER_NAME, HEADER_VALUE, CONTENT_DIGEST, PARAMS }
}

/** Carrier for [SentomaruError]; the message is the stable code only. */
class SentomaruException(val error: SentomaruError) : Exception(error.code)

internal fun invalid(reason: SentomaruError.Reason): Nothing =
    throw SentomaruException(SentomaruError.InvalidRequest(reason))
