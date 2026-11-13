package br.com.ebees.sentomaru.protect

import com.google.gson.GsonBuilder
import com.google.gson.JsonArray
import com.google.gson.JsonElement
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import com.google.gson.JsonPrimitive
import java.io.File

/**
 * `sentomaru policy study`: ativação de módulos em cliente novo, Fase D (spec de 10/11/2026 §8). Monta a política
 * shadow que cobre o catálogo de sinais e as operações declaradas, no modelo de
 * `contracts/policy/templates/study-v1.json` (o mesmo que a classe de teste C#
 * `Integrity.Tests.Policy.StudyPolicyTemplate` lê, para que as duas nunca divirjam em silêncio) — nunca um JSON
 * escrito à mão. "Pronto" (spec §8): com as listas do ExampleApp prod, o resultado é estruturalmente igual a
 * docs/api/examples/policy-exampleapp-prod-estudo-1.0.0.json, a menos de id, versão e descrição.
 */
object Policy {
    const val USAGE = "usage: sentomaru policy study (--scope <org>/<app>/<env> --operations <op,op,...> " +
        "--sensitive-operations <op,op,...> | --manifest <sentomaru-scope.yaml>) " +
        "[--presence-operations <op,op,...>] [--location-sensitive-operations <op,op,...>] " +
        "[--version <v>] [--description <text>] [--out <path>]"
    private val SLUG = Regex("[a-z0-9][a-z0-9-]{0,62}")
    /** An operation id as consumers name them (`concluir_demanda`, `start-job`): underscore and hyphen both allowed. */
    private val OPERATION_ID = Regex("[a-z0-9][a-z0-9_-]{0,62}")
    private val gson = GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create()

    fun run(args: List<String>, out: (String) -> Unit, err: (String) -> Unit): Int {
        if (args.firstOrNull() != "study") {
            err(USAGE)
            return 2
        }
        val flags = try {
            parseFlags(args.drop(1))
        } catch (e: UsageError) {
            err("sentomaru policy study: ${e.message}. $USAGE")
            return 2
        } catch (e: ScopeException) {
            err("sentomaru policy study: ${e.code}: ${e.detail}")
            return e.exit
        }
        val json = try {
            generate(flags)
        } catch (e: UsageError) {
            err("sentomaru policy study: ${e.message}")
            return 2
        }
        val text = gson.toJson(JsonParser.parseString(json))
        val outPath = flags.out
        if (outPath != null) java.io.File(outPath).writeText(text + "\n") else out(text)
        return 0
    }

    private class UsageError(message: String) : Exception(message)

    internal data class Flags(val organization: String, val app: String, val environment: String,
        val operations: List<String>, val sensitiveOperations: List<String>, val presenceOperations: List<String>?,
        val locationSensitiveOperations: List<String>?, val version: String, val description: String?, val out: String?)

    private fun parseFlags(args: List<String>): Flags {
        val map = mutableMapOf<String, String>()
        var i = 0
        while (i < args.size) {
            val flag = args[i]
            if (!flag.startsWith("--")) throw UsageError("unexpected argument '$flag'")
            val value = args.getOrNull(i + 1) ?: throw UsageError("$flag needs a value")
            map[flag.removePrefix("--")] = value
            i += 2
        }
        if (map["scope"] != null && map["manifest"] != null) throw UsageError("--scope and --manifest are mutually exclusive")
        val presence = map["presence-operations"]?.let { csv(it, "--presence-operations") }
        val location = map["location-sensitive-operations"]?.let { csv(it, "--location-sensitive-operations") }

        val manifestPath = map["manifest"]
        val scopeAndOperations = if (manifestPath != null) {
            val manifest = ScopeManifest.load(File(manifestPath))
            val spec = manifest.policy ?: throw UsageError("the manifest declares no policy; policy study needs policy.template: study")
            if (spec.template != "study")
                throw UsageError("the manifest's policy.template is '${spec.template}', not 'study'")
            if (spec.sensitiveOperations.isEmpty())
                throw UsageError("the manifest's policy.sensitiveOperations must not be empty")
            // policy.operations is optional in the manifest (unlike --operations); absent or empty means
            // "no operation beyond the sensitive ones".
            val operations = spec.operations.ifEmpty { spec.sensitiveOperations }
            ScopeAndOperations(manifest.scope.organization, manifest.scope.app, manifest.scope.environment,
                operations, spec.sensitiveOperations)
        } else {
            val scope = map["scope"] ?: throw UsageError("--scope or --manifest is required")
            val parts = scope.split("/")
            if (parts.size != 3 || parts.any { it.isBlank() }) throw UsageError("--scope must be <org>/<app>/<env>")
            val operations = csv(map["operations"] ?: throw UsageError("--operations is required"), "--operations")
            val sensitive = csv(map["sensitive-operations"] ?: throw UsageError("--sensitive-operations is required"), "--sensitive-operations")
            ScopeAndOperations(parts[0], parts[1], parts[2], operations, sensitive)
        }
        for ((name, group) in listOf("--sensitive-operations (or the manifest's policy.sensitiveOperations)" to scopeAndOperations.sensitiveOperations,
            "--presence-operations" to presence, "--location-sensitive-operations" to location)) {
            group?.forEach { op -> if (op !in scopeAndOperations.operations) throw UsageError("$name names '$op', which is not in the operations") }
        }
        return Flags(scopeAndOperations.organization, scopeAndOperations.app, scopeAndOperations.environment,
            scopeAndOperations.operations, scopeAndOperations.sensitiveOperations, presence, location,
            map["version"] ?: "1.0.0", map["description"], map["out"])
    }

    private data class ScopeAndOperations(val organization: String, val app: String, val environment: String,
        val operations: List<String>, val sensitiveOperations: List<String>)

    private fun csv(value: String, flag: String): List<String> {
        val items = value.split(",").map { it.trim() }.filter { it.isNotEmpty() }
        if (items.isEmpty()) throw UsageError("$flag must not be empty")
        for (op in items) if (!OPERATION_ID.matches(op)) throw UsageError("$flag has an invalid operation id '$op'")
        return items
    }

    /** Exposed for tests: the same substitution a real run does, without argument parsing or I/O. */
    internal fun generate(flags: Flags): String {
        for ((name, slug) in listOf("organization" to flags.organization, "app" to flags.app, "environment" to flags.environment))
            if (!SLUG.matches(slug)) throw UsageError("--scope's $name '$slug' is not a valid slug")
        val scalars = mapOf(
            "__POLICY_ID__" to "pol_${flags.organization}_${flags.app}_${flags.environment}_estudo",
            "__VERSION__" to flags.version, "__ORGANIZATION__" to flags.organization, "__APP__" to flags.app,
            "__ENVIRONMENT__" to flags.environment,
            "__DESCRIPTION__" to (flags.description ?: ("Estudo de ${flags.organization}/${flags.app}/${flags.environment}: shadow, " +
                "toda regra em observe; mede o que cada sinal e cada combinação recomendaria nas operações declaradas, sem efeito no app.")),
        )
        val arrays = mapOf(
            "__SENSITIVE_OPERATIONS__" to flags.sensitiveOperations,
            "__PRESENCE_OPERATIONS__" to (flags.presenceOperations ?: flags.sensitiveOperations),
            "__LOCATION_SENSITIVE_OPERATIONS__" to (flags.locationSensitiveOperations ?: flags.sensitiveOperations),
        )
        val template = javaClass.getResourceAsStream("/study-v1.json")?.bufferedReader()?.readText()
            ?: throw IllegalStateException("contracts/policy/templates/study-v1.json is not bundled in this build")
        val root = JsonParser.parseString(template).asJsonObject
        root.remove("_comment")
        root.remove("_placeholders")
        return substitute(root, scalars, arrays).toString()
    }

    private fun substitute(node: JsonElement, scalars: Map<String, String>, arrays: Map<String, List<String>>): JsonElement = when {
        node.isJsonObject -> JsonObject().also { out ->
            for ((key, value) in node.asJsonObject.entrySet()) out.add(key, substitute(value, scalars, arrays))
        }
        node.isJsonArray -> {
            val arr = node.asJsonArray
            val sentinel = arr.singleGroupSentinel()
            if (sentinel != null && arrays.containsKey(sentinel))
                JsonArray().also { out -> arrays.getValue(sentinel).forEach { out.add(it) } }
            else JsonArray().also { out -> arr.forEach { out.add(substitute(it, scalars, arrays)) } }
        }
        node.isJsonPrimitive && node.asJsonPrimitive.isString && scalars.containsKey(node.asString) ->
            JsonPrimitive(scalars.getValue(node.asString))
        else -> node.deepCopy()
    }

    /** A single-element array naming a group placeholder, e.g. `["__SENSITIVE_OPERATIONS__"]`; null otherwise
     * (the signalRules arrays, which hold objects, never match). */
    private fun JsonArray.singleGroupSentinel(): String? {
        if (size() != 1) return null
        val only = get(0)
        return if (only.isJsonPrimitive && only.asJsonPrimitive.isString) only.asString else null
    }
}
