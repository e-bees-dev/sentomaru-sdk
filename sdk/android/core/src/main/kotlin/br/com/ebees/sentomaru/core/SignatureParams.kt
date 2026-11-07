package br.com.ebees.sentomaru.core

import java.time.Clock

/**
 * Signature parameters of the profile. `alg` and `tag` are fixed. Validated on construction:
 * canonical lowercase UUIDs for [keyId]/[nonce], 0 <= [created] < [expires] <= [created] + 60.
 *
 * Serialized as the RFC 9421 inner list with parameters in the order of the Python reference client
 * (created, keyid, alg, expires, nonce, tag); every value is an sf-integer or an sf-string whose characters are
 * restricted by the validation above, so no escaping is needed.
 */
class SignatureParams(
    val created: Long,
    val expires: Long,
    val nonce: String,
    val keyId: String,
    /** [Profile.COMPONENTS] plus optional headers in [Profile.OPTIONAL_HEADERS] order (see [Profile.components]). */
    val components: List<String> = Profile.COMPONENTS,
) {
    init {
        if (created !in 0..MAX_SF_INTEGER || expires !in 0..MAX_SF_INTEGER || expires <= created ||
            expires - created > Profile.MAX_LIFETIME_SECONDS || !isUuid(nonce) || !isUuid(keyId) ||
            components.take(Profile.COMPONENTS.size) != Profile.COMPONENTS ||
            components.drop(Profile.COMPONENTS.size) != Profile.OPTIONAL_HEADERS.filter { it in components }
        ) invalid(SentomaruError.Reason.PARAMS)
    }

    /** The same parameters covering [list] (used by [MessageSigner] for the request's optional headers). */
    fun withComponents(list: List<String>): SignatureParams = SignatureParams(created, expires, nonce, keyId, list)

    /** `("@method" ... "x-sentomaru-operation");created=..;keyid="..";alg="..";expires=..;nonce="..";tag=".."`. */
    fun serialize(): String = components.joinToString(" ", "(", ")") { "\"$it\"" } +
        ";created=$created;keyid=\"$keyId\";alg=\"${Profile.ALGORITHM}\";expires=$expires" +
        ";nonce=\"$nonce\";tag=\"${Profile.TAG}\""

    companion object {
        private const val MAX_SF_INTEGER = 999_999_999_999_999L
        private val UUID = Regex("""\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z""")

        internal fun isUuid(value: String): Boolean = UUID.matches(value)

        /** created = now (seconds), expires = created + [lifetimeSeconds] (default: the profile maximum). */
        fun now(clock: Clock, keyId: String, nonce: String, lifetimeSeconds: Long = Profile.MAX_LIFETIME_SECONDS) =
            (clock.millis() / 1000).let { SignatureParams(it, it + lifetimeSeconds, nonce, keyId) }
    }
}
