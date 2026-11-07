package br.com.ebees.sentomaru.signals

/**
 * D-15b: an INFORMATIVE event with the closed code a consumer answered to one SIGNED request, delivered through the same
 * [SentomaruSignalEvents] as the signal events (same executors, same [sequence] counter). It is the real result of the
 * server's policy as the consumer passed it on (a challenge with its kind, a suspension, a policy refusal), never a
 * suggestion of what the app should do, and never a verdict: there is no "is compromised", score or summary. The policy
 * stage of each rule never reaches the app.
 *
 * Only the top-level `code` member of the error body (and `challengeKind` next to `challenge-required`) is read, and an
 * event exists only for a code of the closed set ([ServerResponseCodes]): anything else in the body (other members,
 * free text, a `riskEvent`, a nested `code`) is never read into an event. No installation, session, key, subject,
 * tenant, operation id, URL, header or wall-clock time.
 *
 * @property code `challenge-required`, `proof-required`, `installation-suspended`, `installation-revoked`,
 *   `session-unavailable`, `policy-denied`, or a policy reason code (`^[A-Z0-9_]{3,64}$`, only on 403).
 * @property challengeKind with `challenge-required` only: the kind token as the consumer sent it, one of
 *   [ServerResponseCodes.CHALLENGE_KINDS] (`fresh_signals`, `step_up`, `reattest`) or another token of
 *   `^[a-z][a-z0-9_]{0,31}$` from a newer server; null otherwise.
 * @property httpStatus 401 or 403.
 */
data class SentomaruServerResponseEvent(
    val code: String,
    val challengeKind: String?,
    val httpStatus: Int,
    val sequence: Long,
) {
    /**
     * D-06h: a `challenge-required` of kind `reattest`. The app may call `SentomaruReattestation.reattest` (which ignores
     * the local wait: the server decided) and repeat the operation ONCE with a new nonce; the server checks the
     * reattestation on that evaluation. The SDK never reattests nor repeats by itself, and this is not a verdict.
     */
    val isReattestChallenge: Boolean get() = code == ServerResponseCodes.CHALLENGE_REQUIRED &&
        challengeKind == ServerResponseCodes.REATTEST

    /** Always [Kind.SERVER_RESPONSE] (wire value `server_response`); its own enum, so the D-15a [SentomaruSignalEvent.Kind]
     * keeps only `SIGNAL` (review R M-1). */
    val kind: Kind get() = Kind.SERVER_RESPONSE

    enum class Kind { SERVER_RESPONSE }
}

/** D-15b: receives [SentomaruServerResponseEvent]s on the executor it was registered with. */
fun interface SentomaruServerResponseListener {
    fun onServerResponseEvent(event: SentomaruServerResponseEvent)
}

/**
 * D-15b: the closed vocabulary of server response events and the reader of an error body. Pure and bounded: the body is
 * at most [MAX_BODY_CHARS] characters (a longer one is not read; the transport peeks MAX_BODY_CHARS + 1 BYTES, so a
 * multibyte body is cut there, comes out malformed and gives no event: the effective bound is in bytes), parsed as one JSON object whose top-level members are
 * scanned without building anything but the two strings; a repeated `code`, a non-object, malformed JSON or nesting
 * deeper than [MAX_DEPTH] yields no event.
 */
object ServerResponseCodes {
    const val CHALLENGE_REQUIRED = "challenge-required"

    /** Challenge kinds of the policy (contract v1.10, adapter 4.6.0). */
    const val FRESH_SIGNALS = "fresh_signals"
    const val STEP_UP = "step_up"
    /** D-06h: the policy asks for a recent reattestation passed by the server; see [SentomaruServerResponseEvent.isReattestChallenge]. */
    const val REATTEST = "reattest"

    /**
     * The closed set of challenge kinds this SDK knows (D-06h adds `reattest`). A well-formed kind outside it still
     * passes raw in [SentomaruServerResponseEvent.challengeKind] (a newer server); a malformed one is null.
     */
    val CHALLENGE_KINDS: Set<String> = setOf(FRESH_SIGNALS, STEP_UP, REATTEST)
    const val MAX_BODY_CHARS = 4096
    const val MAX_DEPTH = 16

    /** Codes accepted on 401 or 403 (`challenge-required` and `proof-required` on 401 only). */
    internal val CLOSED: Set<String> = setOf(CHALLENGE_REQUIRED, "proof-required", "installation-suspended", "installation-revoked",
        "session-unavailable", "policy-denied")
    private val ONLY_401 = setOf(CHALLENGE_REQUIRED, "proof-required")
    /** Same pattern as the policy validator's reasonCode (the adapter answers a deny with the first reason code). */
    internal val POLICY_REASON = Regex("^[A-Z0-9_]{3,64}$")
    /** Same token as the 4.5.0/4.6.0 adapter's challengeKind (unknown kinds pass raw, malformed ones never). */
    internal val CHALLENGE_KIND = Regex("^[a-z][a-z0-9_]{0,31}$")

    /** The (code, challengeKind) of a response, or null when it is not one of the closed codes. */
    internal fun read(httpStatus: Int, body: String?): Pair<String, String?>? {
        if (httpStatus != 401 && httpStatus != 403) return null
        if (body == null || body.length > MAX_BODY_CHARS) return null
        val members = try { TopLevel(body).members() } catch (_: IllegalArgumentException) { return null } ?: return null
        val code = members["code"] ?: return null
        val known = code in CLOSED && (httpStatus == 401 || code !in ONLY_401)
        val policy = httpStatus == 403 && POLICY_REASON.matches(code)
        if (!known && !policy) return null
        val kind = if (code == CHALLENGE_REQUIRED) members["challengeKind"]?.takeIf(CHALLENGE_KIND::matches) else null
        return code to kind
    }

    /**
     * Minimal JSON reader for one object: top-level string members `code` and `challengeKind`, every other value
     * skipped (strings, numbers, literals, nested objects/arrays). Null when the text is not exactly one object or a
     * wanted member repeats; IllegalArgumentException on malformed input.
     */
    private class TopLevel(private val s: String) {
        private var i = 0

        fun members(): Map<String, String>? {
            ws()
            if (peek() != '{') return null
            i++
            val out = HashMap<String, String>()
            val seen = HashSet<String>()
            ws()
            if (peek() == '}') { i++; return end(out) }
            while (true) {
                ws()
                val name = string()
                ws(); expect(':'); ws()
                if (name == "code" || name == "challengeKind") {
                    if (!seen.add(name)) return null
                    if (peek() == '"') out[name] = string() else skipValue(1)
                } else skipValue(1)
                ws()
                when (next()) {
                    ',' -> continue
                    '}' -> return end(out)
                    else -> throw IllegalArgumentException()
                }
            }
        }

        private fun end(out: Map<String, String>): Map<String, String>? { ws(); return if (i == s.length) out else null }

        private fun skipValue(depth: Int) {
            require(depth <= MAX_DEPTH)
            when (peek()) {
                '"' -> string()
                '{' -> container('}', depth, keyed = true)
                '[' -> container(']', depth, keyed = false)
                else -> {
                    val start = i
                    while (i < s.length && (s[i].isLetterOrDigit() || s[i] in "+-.")) i++
                    val token = s.substring(start, i)
                    require(token == "true" || token == "false" || token == "null" || NUMBER.matches(token))
                }
            }
        }

        private fun container(close: Char, depth: Int, keyed: Boolean) {
            i++
            ws()
            if (peek() == close) { i++; return }
            while (true) {
                ws()
                if (keyed) { string(); ws(); expect(':'); ws() }
                skipValue(depth + 1)
                ws()
                when (next()) {
                    ',' -> continue
                    close -> return
                    else -> throw IllegalArgumentException()
                }
            }
        }

        private fun string(): String {
            expect('"')
            val sb = StringBuilder()
            while (true) {
                val c = next()
                when {
                    c == '"' -> return sb.toString()
                    c == '\\' -> when (val e = next()) {
                        '"', '\\', '/' -> sb.append(e)
                        'b' -> sb.append('\b'); 'f' -> sb.append('\u000c'); 'n' -> sb.append('\n')
                        'r' -> sb.append('\r'); 't' -> sb.append('\t')
                        'u' -> {
                            require(i + 4 <= s.length && (i until i + 4).all { s[it] in '0'..'9' || s[it] in 'a'..'f' || s[it] in 'A'..'F' })
                            sb.append(s.substring(i, i + 4).toInt(16).toChar()); i += 4
                        }
                        else -> throw IllegalArgumentException()
                    }
                    c < ' ' -> throw IllegalArgumentException()
                    else -> sb.append(c)
                }
            }
        }

        private fun ws() { while (i < s.length && s[i] in " \t\r\n") i++ }
        private fun peek(): Char = if (i < s.length) s[i] else throw IllegalArgumentException()
        private fun next(): Char = peek().also { i++ }
        private fun expect(c: Char) = require(next() == c)
    }

    private val NUMBER = Regex("^-?(0|[1-9][0-9]*)(\\.[0-9]+)?([eE][+-]?[0-9]+)?$")
}
