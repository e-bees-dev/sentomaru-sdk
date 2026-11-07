package br.com.ebees.sentomaru.core

/**
 * RFC 9421 §2.5 signature base for the profile's fixed component list. Every input is validated by
 * [MessageRules] first, so the base is pure ASCII and each line is `"<name>": <value>` joined by LF, ending with
 * the `"@signature-params"` line (no trailing LF).
 */
object SignatureBase {
    /**
     * @param method uppercase token (`POST`, ...).
     * @param targetUri the exact public https URI that will be sent (`@target-uri`), already in canonical form.
     * @param headers exactly [Profile.CALLER_HEADERS], lowercase names.
     * @param contentDigest `sha-256=:...:` of the frozen body ([ContentDigest.sha256]).
     * @throws SentomaruException with [SentomaruError.InvalidRequest] when any input is outside the profile.
     */
    fun build(
        method: String,
        targetUri: String,
        headers: Map<String, String>,
        contentDigest: String,
        params: SignatureParams,
    ): ByteArray {
        MessageRules.method(method)
        MessageRules.targetUri(targetUri)
        MessageRules.headers(headers)
        MessageRules.contentDigest(contentDigest)
        if (params.components != Profile.components(headers)) invalid(SentomaruError.Reason.PARAMS)
        val base = StringBuilder()
        line(base, "@method", method)
        line(base, "@target-uri", targetUri)
        line(base, Profile.CONTENT_DIGEST, contentDigest)
        for (name in Profile.CALLER_HEADERS) line(base, name, headers.getValue(name))
        for (name in Profile.OPTIONAL_HEADERS) headers[name]?.let { line(base, name, it) }
        base.append("\"@signature-params\": ").append(params.serialize())
        return base.toString().toByteArray(Charsets.US_ASCII)
    }

    private fun line(base: StringBuilder, name: String, value: String) {
        base.append('"').append(name).append("\": ").append(value).append('\n')
    }
}
