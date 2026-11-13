package br.com.ebees.sentomaru.protect

import java.io.File

/** A refusal of `sentomaru scope`: [code] and [exit] are the stable ones of contracts/devsecops/cli-v1.md ("sentomaru scope"). */
class ScopeException(val code: String, val exit: Int, val detail: String) : Exception("$code: $detail")

/**
 * Fase C: `sentomaru-scope.yaml` v1 (contracts/platform/scope-manifest-v1.schema.json). The file is a CLOSED document: an
 * unknown key is refused, so there is nowhere to put a secret. It is read by a strict reader for the YAML subset the
 * manifest uses (block maps and lists, flow lists and maps of scalars, quoted and plain scalars, comments); anchors,
 * aliases, tags, block scalars, multiple documents and tabs are refused rather than guessed.
 */
data class ScopeManifest(
    val scope: Scope,
    val android: Android?,
    val ios: Ios?,
    val policy: PolicySpec?,
    val consumerExpected: Map<String, Boolean>,
    val appExpected: Map<String, Boolean>,
    val telegram: Boolean?,
) {
    enum class DigestSource(val id: String) {
        PLAY_APP_SIGNING("play_app_signing"), UPLOAD_KEY("upload_key"), SIDELOAD("sideload");
        companion object { fun of(id: String) = entries.firstOrNull { it.id == id } }
    }

    /** [sha256] is 64 lowercase hex characters (the form the API takes); the manifest writes it as 32 `XX:` pairs. */
    data class SigningDigest(val sha256: String, val source: DigestSource) {
        val colon: String get() = sha256.chunked(2).joinToString(":").uppercase()
    }

    data class Android(val packageName: String, val signingDigests: List<SigningDigest>, val cloudProjectNumber: Long?)

    /** The App ID is always built from the two parts ([appId]); a bundle id that already carries the team prefix is refused. */
    data class Ios(val teamId: String, val bundleId: String, val attestEnvironment: String) {
        val appId: String get() = "$teamId.$bundleId"
    }

    data class PolicySpec(val template: String, val sensitiveOperations: List<String>, val operations: List<String>, val file: String?)

    companion object {
        const val MAX_BYTES = 64 * 1024
        private val SLUG = Regex("""\A[a-z0-9][a-z0-9-]{0,62}\z""")
        private val PACKAGE = Regex("""\A[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+\z""")
        private val TEAM = Regex("""\A[A-Z0-9]{10}\z""")
        private val BUNDLE = Regex("""\A[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\z""")
        private val DIGEST = Regex("""\A[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){31}\z""")
        private val OPERATION = Regex("""\A[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}\z""")

        fun load(file: File): ScopeManifest {
            if (!file.isFile) throw bad("manifest", "not a file")
            if (file.length() > MAX_BYTES) throw bad("manifest", "larger than $MAX_BYTES bytes")
            return parse(file.readText(Charsets.UTF_8))
        }

        fun parse(text: String): ScopeManifest {
            val root = Yaml.read(text)
            val doc = Doc(root as? Map<*, *> ?: throw bad("$", "a mapping is expected"), "$")
            if (doc.int("version") != 1L) throw bad("version", "only version 1 is supported")
            val scope = scope(doc.string("scope"))
            val android = doc.optMap("android")?.let { android(it) }
            val ios = doc.optMap("ios")?.let { ios(it, scope) }
            val policy = doc.optMap("policy")?.let { policy(it) }
            val consumer = doc.optMap("consumer")?.optMap("expected")?.let { flags(it, setOf("mobileGate", "requireBinding", "fraud")) } ?: emptyMap()
            doc.optMap("consumer")?.closed(setOf("expected"))
            val app = doc.optMap("app")?.optMap("expected")?.let { flags(it, setOf("enforce", "installationResponse")) } ?: emptyMap()
            doc.optMap("app")?.closed(setOf("expected"))
            val telegram = doc.optMap("notifications")?.let { n -> n.closed(setOf("telegram")); n.optBool("telegram") }
            doc.closed(setOf("version", "scope", "android", "ios", "policy", "consumer", "app", "notifications"))
            return ScopeManifest(scope, android, ios, policy, consumer, app, telegram)
        }

        private fun scope(text: String): Scope {
            val parts = text.split("/")
            if (parts.size != 3 || parts.any { !SLUG.matches(it) }) throw bad("scope", "expected organization/app/environment, each a lowercase slug")
            return Scope(parts[0], parts[1], parts[2])
        }

        private fun android(d: Doc): Android {
            d.closed(setOf("package", "signingDigests", "playIntegrity"))
            val pkg = d.string("package")
            if (pkg.length > 255 || !PACKAGE.matches(pkg)) throw bad("android.package", "not an Android package name")
            val digests = d.list("signingDigests").mapIndexed { index, item ->
                val entry = Doc(item as? Map<*, *> ?: throw bad("android.signingDigests[$index]", "a mapping is expected"), "android.signingDigests[$index]")
                entry.closed(setOf("sha256", "source"))
                val text = entry.string("sha256")
                if (!DIGEST.matches(text)) throw bad("android.signingDigests[$index].sha256", "expected 32 hex pairs separated by ':'")
                val source = ScopeManifest.DigestSource.of(entry.string("source"))
                    ?: throw bad("android.signingDigests[$index].source", "one of play_app_signing, upload_key, sideload")
                SigningDigest(text.replace(":", "").lowercase(), source)
            }
            if (digests.isEmpty()) throw bad("android.signingDigests", "at least one digest")
            if (digests.size > 16) throw bad("android.signingDigests", "at most 16 digests")
            if (digests.map { it.sha256 }.toSet().size != digests.size) throw bad("android.signingDigests", "a digest is listed twice")
            val number = d.optMap("playIntegrity")?.let { p ->
                p.closed(setOf("cloudProjectNumber"))
                p.optInt("cloudProjectNumber")?.also { if (it !in 1..9_999_999_999_999L) throw bad("android.playIntegrity.cloudProjectNumber", "a positive number") }
            }
            return Android(pkg, digests, number)
        }

        private fun ios(d: Doc, scope: Scope): Ios {
            d.closed(setOf("teamId", "bundleId", "attestEnvironment"))
            val team = d.string("teamId")
            if (!TEAM.matches(team)) throw bad("ios.teamId", "10 uppercase letters or digits")
            val bundle = d.string("bundleId")
            if (!BUNDLE.matches(bundle) || team.length + 1 + bundle.length > 255) throw bad("ios.bundleId", "not a bundle id")
            if (bundle.startsWith("$team.")) throw bad("ios.bundleId", "the App ID is built from teamId and bundleId; do not type it whole")
            val environment = d.string("attestEnvironment")
            if (environment != "development" && environment != "production") throw bad("ios.attestEnvironment", "development or production")
            if (environment == "development" && scope.environment !in setOf("dev", "lab", "hml"))
                throw bad("ios.attestEnvironment", "development only in a dev, lab or hml scope")
            return Ios(team, bundle, environment)
        }

        private fun policy(d: Doc): PolicySpec {
            d.closed(setOf("template", "file", "sensitiveOperations", "operations"))
            val template = d.string("template")
            if (template != "study" && template != "file") throw bad("policy.template", "study or file")
            val file = d.optString("file")
            if (template == "file" && file == null) throw bad("policy.file", "required for template file")
            if (template == "study" && file != null) throw bad("policy.file", "a study policy is generated, not read from a file")
            return PolicySpec(template, operations(d, "sensitiveOperations"), operations(d, "operations"), file)
        }

        private fun operations(d: Doc, key: String): List<String> {
            val values = d.optList(key).orEmpty().mapIndexed { index, item ->
                (item as? String)?.takeIf { OPERATION.matches(it) } ?: throw bad("policy.$key[$index]", "an operation name")
            }
            if (values.size > 64) throw bad("policy.$key", "at most 64 operations")
            if (values.toSet().size != values.size) throw bad("policy.$key", "an operation is listed twice")
            return values
        }

        private fun flags(d: Doc, allowed: Set<String>): Map<String, Boolean> {
            d.closed(allowed)
            return allowed.mapNotNull { key -> d.optBool(key)?.let { key to it } }.toMap()
        }

        internal fun bad(path: String, detail: String) = ScopeException("manifest-format", 4, "$path: $detail")
    }

    /** A mapping with typed, path-named reads. */
    internal class Doc(private val map: Map<*, *>, private val path: String) {
        private fun at(key: String) = if (path == "$") key else "$path.$key"
        private fun raw(key: String): Any? = map[key]
        fun closed(allowed: Set<String>) {
            val extra = map.keys.firstOrNull { it !in allowed }
            if (extra != null) throw bad(at(extra.toString().take(40)), "unknown key")
        }
        fun string(key: String): String = optString(key) ?: throw bad(at(key), "required text")
        fun optString(key: String): String? = when (val v = raw(key)) { null -> null; is String -> v.takeIf { it.isNotEmpty() && it.length <= 512 }
            ?: throw bad(at(key), "text of 1 to 512 characters"); else -> throw bad(at(key), "text is expected") }
        fun int(key: String): Long = optInt(key) ?: throw bad(at(key), "required number")
        fun optInt(key: String): Long? = when (val v = raw(key)) { null -> null; is Long -> v; else -> throw bad(at(key), "a number is expected") }
        fun optBool(key: String): Boolean? = when (val v = raw(key)) { null -> null; is Boolean -> v; else -> throw bad(at(key), "true or false is expected") }
        fun optMap(key: String): Doc? = when (val v = raw(key)) { null -> null; is Map<*, *> -> Doc(v, at(key)); else -> throw bad(at(key), "a mapping is expected") }
        fun optList(key: String): List<*>? = when (val v = raw(key)) { null -> null; is List<*> -> v; else -> throw bad(at(key), "a list is expected") }
        fun list(key: String): List<*> = optList(key) ?: throw bad(at(key), "required list")
    }
}

/**
 * The strict reader of the YAML subset above. Output: `Map<String, Any?>`, `List<Any?>`, `String`, `Long`, `Boolean`, `null`.
 * Two-space (or any consistent) indentation, no tabs, no duplicate keys, depth at most 8.
 */
internal object Yaml {
    private class Line(val indent: Int, val text: String, val number: Int)

    fun read(text: String): Any? {
        val lines = ArrayList<Line>()
        text.removePrefix("﻿").split("\n").forEachIndexed { index, rawLine ->
            val withoutCr = rawLine.removeSuffix("\r")
            if (withoutCr.takeWhile { it == ' ' || it == '\t' }.contains('\t')) throw fail(index + 1, "tab in indentation")
            val body = stripComment(withoutCr, index + 1).trimEnd()
            if (body.isBlank()) return@forEachIndexed
            if (body == "---" && lines.isEmpty()) return@forEachIndexed
            if (body == "---" || body == "...") throw fail(index + 1, "only one document is supported")
            lines.add(Line(body.length - body.trimStart().length, body.trimStart(), index + 1))
        }
        if (lines.isEmpty()) throw fail(1, "empty document")
        val cursor = intArrayOf(0)
        val value = block(lines, cursor, lines[0].indent, 0)
        if (cursor[0] != lines.size) throw fail(lines[cursor[0]].number, "unexpected indentation")
        return value
    }

    private fun fail(line: Int, detail: String) = ScopeManifest.bad("line $line", detail)

    private fun block(lines: MutableList<Line>, cursor: IntArray, indent: Int, depth: Int): Any? {
        if (depth > 8) throw fail(lines[cursor[0]].number, "nesting deeper than 8")
        val first = lines[cursor[0]]
        return if (first.text == "-" || first.text.startsWith("- ")) list(lines, cursor, indent, depth) else map(lines, cursor, indent, depth)
    }

    private fun map(lines: MutableList<Line>, cursor: IntArray, indent: Int, depth: Int): Map<String, Any?> {
        val out = LinkedHashMap<String, Any?>()
        while (cursor[0] < lines.size && lines[cursor[0]].indent == indent) {
            val line = lines[cursor[0]]
            if (line.text == "-" || line.text.startsWith("- ")) throw fail(line.number, "a list item inside a mapping")
            val colon = line.text.indexOf(':')
            val key = if (colon > 0) line.text.substring(0, colon) else ""
            if (!Regex("""[A-Za-z_][A-Za-z0-9_]*""").matches(key)) throw fail(line.number, "a plain key followed by ':' is expected")
            val rest = line.text.substring(colon + 1)
            if (rest.isNotEmpty() && !rest.startsWith(" ")) throw fail(line.number, "a space is expected after ':'")
            if (key in out) throw fail(line.number, "duplicate key '$key'")
            cursor[0]++
            val inline = rest.trim()
            out[key] = if (inline.isEmpty()) {
                if (cursor[0] < lines.size && lines[cursor[0]].indent > indent) block(lines, cursor, lines[cursor[0]].indent, depth + 1) else null
            } else inlineValue(inline, line.number)
        }
        if (cursor[0] < lines.size && lines[cursor[0]].indent > indent) throw fail(lines[cursor[0]].number, "unexpected indentation")
        return out
    }

    private fun list(lines: MutableList<Line>, cursor: IntArray, indent: Int, depth: Int): List<Any?> {
        val out = ArrayList<Any?>()
        while (cursor[0] < lines.size && lines[cursor[0]].indent == indent && (lines[cursor[0]].text == "-" || lines[cursor[0]].text.startsWith("- "))) {
            val line = lines[cursor[0]]
            val rest = line.text.removePrefix("-").trimStart()
            val offset = line.text.length - rest.length
            if (rest.isEmpty()) {
                cursor[0]++
                if (cursor[0] < lines.size && lines[cursor[0]].indent > indent) out.add(block(lines, cursor, lines[cursor[0]].indent, depth + 1)) else out.add(null)
            } else if (Regex("""[A-Za-z_][A-Za-z0-9_]*:( .*)?""").matches(rest)) {
                // "- key: value": the rest of the line becomes the first line of an item mapping that sits at the key's column.
                lines[cursor[0]] = Line(indent + offset, rest, line.number)
                out.add(map(lines, cursor, indent + offset, depth + 1))
            } else {
                cursor[0]++
                out.add(inlineValue(rest, line.number))
            }
        }
        if (cursor[0] < lines.size && lines[cursor[0]].indent > indent) throw fail(lines[cursor[0]].number, "unexpected indentation")
        return out
    }

    private fun inlineValue(text: String, line: Int): Any? {
        val reader = Flow(text, line)
        val value = reader.value()
        reader.end()
        return value
    }

    /** Cuts a trailing comment: `#` at the start or after a space, outside quotes. */
    private fun stripComment(text: String, line: Int): String {
        var quote = 0.toChar()
        var index = 0
        while (index < text.length) {
            val c = text[index]
            if (quote != 0.toChar()) {
                if (quote == '"' && c == '\\') index++ else if (c == quote) quote = 0.toChar()
            } else if ((c == '"' || c == '\'') && (index == 0 || text[index - 1] in " [{,:-")) quote = c
            else if (c == '#' && (index == 0 || text[index - 1] == ' ')) return text.substring(0, index)
            index++
        }
        if (quote != 0.toChar()) throw fail(line, "unterminated quote")
        return text
    }

    /** A value on one line: a scalar, `[a, b]` or `{k: v, k: v}` (scalars inside). */
    private class Flow(private val s: String, private val line: Int) {
        private var i = 0
        private fun skip() { while (i < s.length && s[i] == ' ') i++ }
        fun end() { skip(); if (i != s.length) throw fail(line, "unexpected text after the value") }
        fun value(depth: Int = 0): Any? {
            if (depth > 4) throw fail(line, "nesting deeper than 4 in a one-line value")
            skip()
            if (i >= s.length) throw fail(line, "a value is expected")
            return when (s[i]) {
                '[' -> { i++; seq(depth) }
                '{' -> { i++; mapping(depth) }
                '"' -> quoted('"')
                '\'' -> quoted('\'')
                '&', '*', '!', '|', '>', '%', '@', '`' -> throw fail(line, "anchors, aliases, tags and block scalars are not supported")
                else -> scalar()
            }
        }
        private fun seq(depth: Int): List<Any?> {
            val out = ArrayList<Any?>()
            skip()
            if (i < s.length && s[i] == ']') { i++; return out }
            while (true) {
                out.add(value(depth + 1)); skip()
                if (i >= s.length) throw fail(line, "unterminated list")
                if (s[i] == ',') { i++; continue }
                if (s[i] == ']') { i++; return out }
                throw fail(line, "',' or ']' is expected")
            }
        }
        private fun mapping(depth: Int): Map<String, Any?> {
            val out = LinkedHashMap<String, Any?>()
            skip()
            if (i < s.length && s[i] == '}') { i++; return out }
            while (true) {
                skip()
                val start = i
                while (i < s.length && (s[i].isLetterOrDigit() || s[i] == '_')) i++
                val key = s.substring(start, i)
                if (key.isEmpty() || i >= s.length || s[i] != ':') throw fail(line, "a key followed by ':' is expected")
                i++
                if (key in out) throw fail(line, "duplicate key '$key'")
                out[key] = value(depth + 1); skip()
                if (i >= s.length) throw fail(line, "unterminated mapping")
                if (s[i] == ',') { i++; continue }
                if (s[i] == '}') { i++; return out }
                throw fail(line, "',' or '}' is expected")
            }
        }
        private fun quoted(q: Char): String {
            i++
            val b = StringBuilder()
            while (i < s.length) {
                val c = s[i]
                if (q == '"' && c == '\\') {
                    if (i + 1 >= s.length || s[i + 1] !in "\"\\") throw fail(line, "only \\\" and \\\\ are supported in a double-quoted text")
                    b.append(s[i + 1]); i += 2
                } else if (c == q) {
                    if (q == '\'' && i + 1 < s.length && s[i + 1] == '\'') { b.append('\''); i += 2; continue }
                    i++; return b.toString()
                } else { b.append(c); i++ }
            }
            throw fail(line, "unterminated quote")
        }
        private fun scalar(): Any? {
            val start = i
            while (i < s.length && s[i] !in ",]}") i++
            val text = s.substring(start, i).trim()
            if (text.isEmpty()) throw fail(line, "a value is expected")
            return when {
                text == "null" || text == "~" -> null
                text == "true" -> true
                text == "false" -> false
                Regex("""-?[0-9]{1,15}""").matches(text) -> text.toLong()
                text.contains(": ") || text.endsWith(":") -> throw fail(line, "a nested mapping on one line must use { }")
                else -> text
            }
        }
    }
}
