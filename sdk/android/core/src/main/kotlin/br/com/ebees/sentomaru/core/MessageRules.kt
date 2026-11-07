package br.com.ebees.sentomaru.core

import br.com.ebees.sentomaru.core.SentomaruError.Reason

/**
 * Input validation of the profile. Fails closed and early: every form the P1 server is KNOWN to refuse or rewrite
 * (ForwardedMessage round-trip + NSign; probed exhaustively for single percent-escapes in path and query, for the
 * listed host forms, and pinned by the SDK-VEC negative vectors) is refused here instead of being signed. The
 * accepted set is a subset proven by the positive vectors, not a claim of equivalence for every possible URI. This
 * is NOT a URI or header parser: it accepts only the exact canonical wire form and never normalizes (normalizing
 * would sign bytes other than the ones sent).
 */
internal object MessageRules {
    private val METHOD = Regex("""\A[A-Z]{1,16}\z""")
    private val SLUG = Regex("""\A[a-z0-9][a-z0-9-]{0,62}\z""")
    private const val MAX_OPERATION = 64
    private val HOST = Regex("""\A[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?\z""")
    private const val MAX_URI = 4096
    private const val MAX_HEADER_VALUE = 4096
    private val OPERATION_ID = Regex("""\A[A-Za-z0-9-]{16,64}\z""")
    // v1: version, nonce, signature. v2 (F1): version, nonce, issuedAt (10 decimal digits, Unix seconds), signature.
    private val TX_SIGNATURE = Regex("""\Asentomaru-tx-v1\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{86}\z""")
    private val TX_SIGNATURE_V2 = Regex("""\Asentomaru-tx-v2\.[A-Za-z0-9_-]{22}\.[0-9]{10}\.[A-Za-z0-9_-]{86}\z""")
    private const val HTTPS = "https://"
    private const val HEX_UPPER = "0123456789ABCDEF"

    // RFC 3986 unreserved + sub-delims + ":" "@" "/" "?" (pchar/query characters), and "%" for escapes.
    private const val URI_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~!$&'()*+,;=:@/?%"
    private const val UNRESERVED_MARKS = "-._~"

    // Octets whose escape the server decodes in the PATH (PathString) and re-emits raw, so the round-trip differs:
    // NUL (refused outright), unreserved, sub-delims and ":" "@". Other escapes (%20, %25, %2F, %3F, %7F, non-ASCII)
    // stay encoded. In the QUERY only escaped unreserved octets are rewritten (by Uri canonicalization).
    private const val PATH_DECODED_MARKS = "!$&'()*+,;=:@"

    fun method(method: String) {
        if (!METHOD.matches(method)) invalid(Reason.METHOD)
    }

    /**
     * Absolute `https` URI in the canonical form the server reproduces (`Uri.AbsoluteUri` / `GetEncodedUrl`):
     * lowercase host (DNS name, or strict dotted-quad IPv4 when the last label is numeric or hex), optional
     * non-default port, non-empty path starting with `/`, optional query; no userinfo, fragment, raw non-ASCII,
     * space, dot segment, lowercase-hex escape, escape of an unreserved octet, and in the path no `%00` nor escape of
     * a sub-delim, `:` or `@`. IPv6 literals are not supported by this profile version.
     */
    fun targetUri(uri: String) {
        if (uri.length !in 1..MAX_URI || !uri.startsWith(HTTPS)) invalid(Reason.TARGET_URI)
        val authorityEnd = uri.indexOf('/', HTTPS.length)
        if (authorityEnd < 0) invalid(Reason.TARGET_URI)
        authority(uri.substring(HTTPS.length, authorityEnd))
        val queryStart = uri.indexOf('?', authorityEnd).let { if (it < 0) uri.length else it }
        val path = uri.substring(authorityEnd, queryStart)
        var i = authorityEnd
        while (i < uri.length) {
            val c = uri[i]
            if (c !in URI_CHARS) invalid(Reason.TARGET_URI)
            if (c == '%') {
                if (i + 2 >= uri.length || uri[i + 1] !in HEX_UPPER || uri[i + 2] !in HEX_UPPER) invalid(Reason.TARGET_URI)
                val octet = uri.substring(i + 1, i + 3).toInt(16)
                if (rewritten(octet, inPath = i < queryStart)) invalid(Reason.TARGET_URI)
                i += 3
                continue
            }
            i++
        }
        if (path.split('/').any { it == "." || it == ".." }) invalid(Reason.TARGET_URI)
    }

    private fun rewritten(octet: Int, inPath: Boolean): Boolean {
        val c = octet.toChar()
        val unreserved = c in 'A'..'Z' || c in 'a'..'z' || c in '0'..'9' || c in UNRESERVED_MARKS
        return unreserved || inPath && (octet == 0 || c in PATH_DECODED_MARKS)
    }

    private fun authority(authority: String) {
        val colon = authority.lastIndexOf(':')
        val host = if (colon < 0) authority else authority.substring(0, colon)
        if (!HOST.matches(host) || host.contains("..")) invalid(Reason.TARGET_URI)
        // WHATWG/OkHttp and .NET read a host whose last label is a number (decimal or 0x-hex) as IPv4, accepting
        // short (`1.2.3`, `123`), octal (`010.0.0.1`) and hex forms that are then rewritten. Only the strict
        // dotted quad (0-255, no leading zero) is accepted; `256.0.0.1` / `a.123` are refused too.
        val labels = host.split('.')
        if (labels.last().let { it.all { c -> c in '0'..'9' } || it.startsWith("0x") }) {
            if (labels.size != 4 || labels.any { !octet(it) }) invalid(Reason.TARGET_URI)
        }
        if (colon >= 0) {
            val port = authority.substring(colon + 1)
            if (port.isEmpty() || port.length > 5 || !port.all { it in '0'..'9' } || port[0] == '0' ||
                port.toInt() !in 1..65535 || port == "443"
            ) invalid(Reason.TARGET_URI)
        }
    }

    /** Exactly [Profile.CALLER_HEADERS] (canonical lowercase names), with the profile's value rules. */
    fun headers(headers: Map<String, String>) {
        if (!headers.keys.containsAll(Profile.CALLER_HEADERS) ||
            !(Profile.CALLER_HEADERS + Profile.OPTIONAL_HEADERS).containsAll(headers.keys)
        ) {
            invalid(Reason.HEADER_NAME)
        }
        for ((name, value) in headers) {
            if (value.isEmpty() || value.length > MAX_HEADER_VALUE || value.first() == ' ' || value.last() == ' ' ||
                value.any { it !in ' '..'~' }
            ) invalid(Reason.HEADER_VALUE)
            val ok = when (name) {
                "content-type" -> value == Profile.CONTENT_TYPE
                "x-sentomaru-profile" -> value == Profile.TAG
                "x-sentomaru-org", "x-sentomaru-app", "x-sentomaru-environment" -> SLUG.matches(value)
                "x-sentomaru-session" -> SignatureParams.isUuid(value)
                // The server's rule (InputLimits.OperationMax; equality with the consumer route is checked there).
                "x-sentomaru-operation" -> value.length <= MAX_OPERATION
                // H3: compact JSON, printable ASCII (already checked above), same limit as the server.
                Profile.SIGNALS_HEADER -> true
                // J-01f: business operation id, the same on every retry of one operation.
                Profile.OPERATION_ID_HEADER -> OPERATION_ID.matches(value)
                // D-25: version, a 16-byte nonce and a 64-byte P1363 signature, all base64url without padding.
                Profile.TX_SIGNATURE_HEADER -> TX_SIGNATURE.matches(value) || TX_SIGNATURE_V2.matches(value)
                else -> false
            }
            if (!ok) invalid(Reason.HEADER_VALUE)
        }
    }

    private fun octet(label: String): Boolean =
        label.isNotEmpty() && label.length <= 3 && label.all { it in '0'..'9' } && (label == "0" || label[0] != '0') &&
            label.toInt() <= 255

    fun contentDigest(value: String) {
        if (!ContentDigest.isCanonical(value)) invalid(Reason.CONTENT_DIGEST)
    }

    fun bodySize(size: Int) {
        if (size > Profile.MAX_BODY_BYTES) throw SentomaruException(SentomaruError.BodyTooLarge(size))
    }
}
