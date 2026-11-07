package br.com.ebees.sentomaru.protect

import com.google.gson.JsonElement
import com.google.gson.JsonObject
import java.io.File
import java.security.MessageDigest

/** One control section of the profile: its declared version and the raw fields (validated by the control). */
data class ControlSection(val id: String, val version: String, val fields: JsonObject)

data class Scope(val organization: String, val app: String, val environment: String) {
    override fun toString() = "$organization/$app/$environment"
}

/**
 * `protect-profile` v1 (contracts/devsecops/protect-profile-v1.schema.json). This reads the envelope and the scope only
 * (the contract's precedence puts the scope before the credential and the input); each control validates its own
 * section later, in [Controls.resolve] (closed: an unknown field is a refusal). An unknown control id with a numeric
 * version is kept so the registry can answer `control-not-available`.
 */
class Profile private constructor(val id: String, val scope: Scope, val controls: List<ControlSection>, val sha256: String) {
    companion object {
        const val MAX_BYTES = 1024 * 1024
        private val SLUG = Regex("""\A[a-z0-9_-]{2,32}\z""")
        private val PROFILE_ID = Regex("""\A[a-z0-9][a-z0-9-]{1,62}\z""")
        private val CONTROL_ID = Regex("""\A[a-z][a-z0-9-]{2,40}\z""")
        private val VERSION = Regex("""\A[0-9]+\z""")
        private val TOP = setOf("schemaVersion", "kind", "profileId", "scope", "controls")

        fun read(file: File): Profile {
            if (file.length() > MAX_BYTES) fail("above 1 MiB")
            val bytes = file.inputStream().use { it.readNBytes(MAX_BYTES + 1) }
            if (bytes.size > MAX_BYTES) fail("above 1 MiB")
            return parse(bytes)
        }

        fun parse(bytes: ByteArray): Profile {
            val root = StrictJson.parse(bytes)
            if (!root.isJsonObject) fail("not an object")
            val o = root.asJsonObject
            if (o.keySet() != TOP) fail("top-level members")
            if (text(o, "schemaVersion") != "1") fail("schemaVersion")
            if (text(o, "kind") != "protect") fail("kind")
            val id = text(o, "profileId").takeIf(PROFILE_ID::matches) ?: fail("profileId")
            val s = o.get("scope").takeIf(JsonElement::isJsonObject)?.asJsonObject ?: fail("scope")
            if (s.keySet() != setOf("organization", "app", "environment")) fail("scope members")
            val scope = Scope(slug(s, "organization"), slug(s, "app"), slug(s, "environment"))
            val c = o.get("controls").takeIf(JsonElement::isJsonObject)?.asJsonObject ?: fail("controls")
            if (c.size() == 0) fail("no controls")
            val controls = c.entrySet().map { (name, value) ->
                if (!CONTROL_ID.matches(name) || !value.isJsonObject) fail("control $name")
                val section = value.asJsonObject
                val version = text(section, "version").takeIf(VERSION::matches) ?: fail("control $name version")
                ControlSection(name, version, section)
            }
            val sha = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
            return Profile(id, scope, controls, sha)
        }

        private fun text(o: JsonObject, name: String): String {
            val e = o.get(name) ?: fail("$name missing")
            if (!e.isJsonPrimitive || !e.asJsonPrimitive.isString) fail("$name not text")
            return e.asString
        }

        private fun slug(o: JsonObject, name: String) = text(o, name).takeIf(SLUG::matches) ?: fail("scope $name")

        private fun fail(detail: String): Nothing = throw ProtectException(ErrorCode.PROFILE_FORMAT, detail)
    }
}
