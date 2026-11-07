package br.com.ebees.sentomaru.signals

/**
 * Minimal strict JSON reader: integers only, no duplicate keys, nesting at most [MAX_DEPTH] (review 4/11, Shield #3: an
 * unbounded recursive descent made `[[[[...` a StackOverflowError, which `catch (e: Exception)` does not catch, before the
 * signature was ever checked). The module has no JSON library (org.json is a stub in JVM tests).
 */
internal object StrictJson {
    const val MAX_DEPTH = 32

    fun parse(text: String): Any? = Reader(text).run { value().also { skipWs(); require(pos == text.length) { "trailing data" } } }

    private class Reader(val s: String) {
        var pos = 0
        var depth = 0

        fun skipWs() {
            while (pos < s.length && s[pos] in " \t\r\n") pos++
        }

        fun value(): Any? {
            skipWs()
            return when (val c = s[pos]) {
                '{' -> nested { obj() }
                '[' -> nested { arr() }
                '"' -> str()
                't' -> literal("true", true)
                'f' -> literal("false", false)
                'n' -> literal("null", null)
                else -> if (c == '-' || c.isDigit()) num() else error("unexpected '$c' at $pos")
            }
        }

        private inline fun <T> nested(read: () -> T): T {
            require(++depth <= MAX_DEPTH) { "nesting deeper than $MAX_DEPTH" }
            try { return read() } finally { depth-- }
        }

        fun literal(word: String, v: Any?): Any? {
            require(s.startsWith(word, pos)) { "bad literal at $pos" }
            pos += word.length
            return v
        }

        fun num(): Long {
            val start = pos
            if (s[pos] == '-') pos++
            while (pos < s.length && s[pos].isDigit()) pos++
            require(pos < s.length && s[pos] !in ".eE") { "only integers expected at $start" }
            return s.substring(start, pos).toLong()
        }

        fun str(): String {
            require(s[pos++] == '"')
            val sb = StringBuilder()
            while (true) {
                val c = s[pos++]
                when (c) {
                    '"' -> return sb.toString()
                    '\\' -> when (val e = s[pos++]) {
                        '"', '\\', '/' -> sb.append(e)
                        'n' -> sb.append('\n')
                        't' -> sb.append('\t')
                        'r' -> sb.append('\r')
                        'b' -> sb.append('\b')
                        'f' -> sb.append('\u000c')
                        'u' -> sb.append(s.substring(pos, pos + 4).toInt(16).toChar()).also { pos += 4 }
                        else -> error("bad escape at $pos")
                    }
                    else -> sb.append(c)
                }
            }
        }

        fun arr(): List<Any?> {
            pos++
            val out = mutableListOf<Any?>()
            skipWs()
            if (s[pos] == ']') return out.also { pos++ }
            while (true) {
                out += value()
                skipWs()
                when (s[pos++]) {
                    ',' -> continue
                    ']' -> return out
                    else -> error("bad array at $pos")
                }
            }
        }

        fun obj(): Map<String, Any?> {
            pos++
            val out = linkedMapOf<String, Any?>()
            skipWs()
            if (s[pos] == '}') return out.also { pos++ }
            while (true) {
                skipWs()
                val key = str()
                skipWs()
                require(s[pos++] == ':') { "expected ':' at $pos" }
                require(!out.containsKey(key)) { "duplicate key $key" }
                out[key] = value()
                skipWs()
                when (s[pos++]) {
                    ',' -> continue
                    '}' -> return out
                    else -> error("bad object at $pos")
                }
            }
        }
    }
}
