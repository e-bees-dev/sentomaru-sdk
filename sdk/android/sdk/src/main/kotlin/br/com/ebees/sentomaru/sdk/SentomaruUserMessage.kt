package br.com.ebees.sentomaru.sdk

import br.com.ebees.sentomaru.core.SentomaruError
import br.com.ebees.sentomaru.core.SentomaruException
import java.util.Locale

/**
 * `sdk-user-message-v1` (contracts/sdk/user-message-v1.md): the default text an app shows its end user when an operation is
 * blocked. One stable key, three languages, no interpolation: the text never carries a code, a reason or a detection detail.
 * The error codes of this SDK are unchanged; this only adds the presentable message. The host can override the text per language.
 */
object SentomaruUserMessage {
    /** Stable key of the default text. */
    const val KEY = "critical_operations_blocked"

    /** The closed set of situations a blocking code maps to (all show the same text today). */
    enum class Situation { ATTESTATION_FAILED, VERIFICATION_DENIED, CHALLENGE, DEFER, UNAVAILABLE, ENROLLMENT_PENDING }

    /** Default text by resolved language (`pt-BR`, `en`, `es`). */
    val defaults: Map<String, String> = mapOf(
        "pt-BR" to "Algumas operações críticas estão bloqueadas até a aprovação. Tente novamente mais tarde ou fale com o suporte.",
        "en" to "Some critical operations are blocked until approval. Please try again later or contact support.",
        "es" to "Algunas operaciones críticas están bloqueadas hasta su aprobación. Inténtelo de nuevo más tarde o póngase en contacto con el soporte.",
    )

    /** `pt*` is `pt-BR`, `es*` is `es`, anything else, blank or null is `en`. `_` reads as `-`; case is ignored. */
    @JvmStatic
    fun resolveLocale(tag: String?): String {
        val primary = tag?.trim()?.replace('_', '-')?.lowercase(Locale.ROOT)?.substringBefore('-').orEmpty()
        return when (primary) {
            "pt" -> "pt-BR"
            "es" -> "es"
            else -> "en"
        }
    }

    /**
     * The text for [locale]. A non-blank host text in [overrides] under the resolved language replaces the default;
     * a blank one, or one for another language, is ignored.
     */
    @JvmStatic
    @JvmOverloads
    fun resolve(locale: String? = null, overrides: Map<String, String>? = null): String {
        val resolved = resolveLocale(locale)
        val own = overrides?.get(resolved)?.trim()
        return if (!own.isNullOrEmpty()) own else defaults.getValue(resolved)
    }

    @JvmStatic
    @JvmOverloads
    fun resolve(locale: Locale, overrides: Map<String, String>? = null): String = resolve(locale.toLanguageTag(), overrides)

    /** The situation a stable error [code] (`SentomaruError.code`, `ServerRejected:REVOKED`, ...) presents; null = not a block, the app decides. */
    @JvmStatic
    fun situationFor(code: String?): Situation? = when (code) {
        "KeyInvalidated", "KeyUnavailable", "StorageUnavailable", "StrongBoxUnavailable",
        "Unsupported:APP_ATTEST", "Unsupported:SECURE_ENCLAVE", "ServerRejected:INVALID" -> Situation.ATTESTATION_FAILED
        "ServerRejected:REVOKED", "ServerRejected:SUSPENDED", "ServerRejected:CONFLICT", "ServerRejected:EXPIRED",
        "ReenrollmentRefused" -> Situation.VERIFICATION_DENIED
        "NetworkUnavailable", "ServerRejected:UNAVAILABLE", "ServerRejected:RATE_LIMITED", "RenewalBackoff",
        "PinningRefused" -> Situation.UNAVAILABLE
        "NotEnrolled", "EnrollmentRequired", "ChallengeExpired" -> Situation.ENROLLMENT_PENDING
        else -> null
    }

    /** The text for a blocking [code], or null when the code is not a block. */
    @JvmStatic
    @JvmOverloads
    fun forCode(code: String?, locale: String? = null, overrides: Map<String, String>? = null): String? =
        if (situationFor(code) == null) null else resolve(locale, overrides)
}

/** sdk-user-message-v1: the end-user text for this error's code; null when the code is not a block. The code is unchanged. */
@JvmOverloads
fun SentomaruError.userMessage(locale: String? = null, overrides: Map<String, String>? = null): String? =
    SentomaruUserMessage.forCode(code, locale, overrides)

/** sdk-user-message-v1: the end-user text for the wrapped error's code; null when the code is not a block. The code and message are unchanged. */
@JvmOverloads
fun SentomaruException.userMessage(locale: String? = null, overrides: Map<String, String>? = null): String? =
    error.userMessage(locale, overrides)
