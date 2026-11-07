package br.com.ebees.sentomaru.core

/**
 * The Sentomaru message profile (contracts/p0-http-profile.md), the single source for the SDK.
 *
 * RFC 9421 (HTTP Message Signatures) + RFC 9530 (Content-Digest), `ecdsa-p256-sha256` with a 64-byte P1363
 * signature, exact component set and order, tag `sentomaru-p0`, body <= 65536 bytes, lifetime <= 60 s.
 */
object Profile {
    const val TAG: String = "sentomaru-p0"
    const val ALGORITHM: String = "ecdsa-p256-sha256"
    const val LABEL: String = "sig1"
    const val CONTENT_TYPE: String = "application/json"
    const val MAX_BODY_BYTES: Int = 65536
    const val MAX_LIFETIME_SECONDS: Long = 60
    const val SIGNATURE_BYTES: Int = 64

    const val CONTENT_DIGEST: String = "content-digest"
    const val SIGNATURE_INPUT: String = "signature-input"
    const val SIGNATURE: String = "signature"

    /** Headers the caller supplies (everything signed except `content-digest`, which the core computes). */
    val CALLER_HEADERS: List<String> = listOf(
        "content-type",
        "x-sentomaru-profile",
        "x-sentomaru-org",
        "x-sentomaru-app",
        "x-sentomaru-environment",
        "x-sentomaru-session",
        "x-sentomaru-operation",
    )

    /** Covered components, in the order the reference client (and this core) signs them. */
    val COMPONENTS: List<String> = listOf("@method", "@target-uri", CONTENT_DIGEST) + CALLER_HEADERS

    const val SIGNALS_HEADER: String = "x-sentomaru-signals"
    const val OPERATION_ID_HEADER: String = "x-sentomaru-operation-id"

    /**
     * D-25 (contracts/api/transaction-keys-v1.md): the signature of the transaction key, made after the person
     * authenticated. Covered by the request signature when sent, so it cannot be removed or swapped in transit.
     */
    const val TX_SIGNATURE_HEADER: String = "x-sentomaru-tx-signature"

    /**
     * Optional headers signed when present, after [COMPONENTS] and in this order (contracts/p0-http-profile.md
     * "Componentes opcionais"): H3 signals, the J-01f business operation id and the D-25 transaction signature.
     */
    val OPTIONAL_HEADERS: List<String> = listOf(SIGNALS_HEADER, OPERATION_ID_HEADER, TX_SIGNATURE_HEADER)

    /** The covered components for a request with these headers: [COMPONENTS] plus the optional ones present. */
    fun components(headers: Map<String, String>): List<String> = COMPONENTS + OPTIONAL_HEADERS.filter { it in headers }
}
