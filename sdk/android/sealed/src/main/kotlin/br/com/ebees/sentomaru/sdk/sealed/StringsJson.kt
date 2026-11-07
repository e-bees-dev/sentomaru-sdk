package br.com.ebees.sentomaru.sdk.sealed

import br.com.ebees.sentomaru.sdk.sealed.SentomaruSealedException.Code

/**
 * The strings file of `asset-encryption` (`{"key": "value"}` in UTF-8, a flat object of texts). The CLI checks the
 * file's shape before sealing (keys, count, duplicates); after opening, the reader only requires UTF-8 and a JSON
 * object whose values are all strings, else `integrity` (contracts/devsecops/cli-v1.md, asset-encryption, "Leitura").
 * A small strict parser of exactly that shape (RFC 8259 grammar, no nesting), so the result does not depend on the
 * leniency of `org.json` on each Android version. A repeated key keeps the last value, as the reference reader does.
 */
internal object StringsJson {
    fun lookup(bytes: ByteArray, key: String): String? = try {
        parse(strictUtf8(bytes))[key]
    } finally {
        bytes.fill(0)
    }

    fun parse(text: String): Map<String, String> = Parser(text).run {
        val out = obj()
        ws()
        if (pos != text.length) fail()
        out
    }

    private fun fail(): Nothing = throw SentomaruSealedException(Code.INTEGRITY)

    private class Parser(val s: String) {
        var pos = 0

        fun ws() {
            while (pos < s.length && s[pos] in " \t\r\n") pos++
        }

        fun next(): Char = if (pos < s.length) s[pos++] else fail()

        fun obj(): Map<String, String> {
            ws()
            if (next() != '{') fail()
            val out = HashMap<String, String>()
            ws()
            if (pos < s.length && s[pos] == '}') return out.also { pos++ }
            while (true) {
                ws()
                val key = str()
                ws()
                if (next() != ':') fail()
                ws()
                out[key] = str()
                ws()
                when (next()) {
                    ',' -> continue
                    '}' -> return out
                    else -> fail()
                }
            }
        }

        fun str(): String {
            if (next() != '"') fail()
            val sb = StringBuilder()
            while (true) {
                val c = next()
                when {
                    c == '"' -> return sb.toString()
                    c < ' ' -> fail()
                    c == '\\' -> when (next()) {
                        '"' -> sb.append('"')
                        '\\' -> sb.append('\\')
                        '/' -> sb.append('/')
                        'b' -> sb.append('\b')
                        'f' -> sb.append('\u000c')
                        'n' -> sb.append('\n')
                        'r' -> sb.append('\r')
                        't' -> sb.append('\t')
                        'u' -> {
                            if (pos + 4 > s.length) fail()
                            val code = s.substring(pos, pos + 4).toIntOrNull(16) ?: fail()
                            if (s.substring(pos, pos + 4).any { it == '+' || it == '-' }) fail()
                            sb.append(code.toChar())
                            pos += 4
                        }
                        else -> fail()
                    }
                    else -> sb.append(c)
                }
            }
        }
    }
}
