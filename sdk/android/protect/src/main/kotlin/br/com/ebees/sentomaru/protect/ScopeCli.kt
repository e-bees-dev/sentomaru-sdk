package br.com.ebees.sentomaru.protect

import com.google.gson.GsonBuilder
import com.google.gson.JsonElement
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import java.io.File
import java.io.InputStream
import java.net.URI
import java.net.URLEncoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.security.MessageDigest
import java.time.Duration

/**
 * Fase C: `sentomaru scope plan|apply` (contracts/devsecops/cli-v1.md, "sentomaru scope"). `plan` reads the scope through
 * the admin API and prints the difference to `sentomaru-scope.yaml`; it changes nothing. `apply` makes the changes through the
 * admin routes that already exist (scope creation, signing digests, Apple app, policy DRAFT) and stops there: it never
 * approves a policy, so the approval stays with another operator in the Console (SoD). Nothing in it removes or retires
 * anything. Both commands are idempotent.
 *
 * The session token comes from `SENTOMARU_ADMIN_TOKEN` or the first line of stdin (`--admin-token-stdin`), never from an
 * argument; it is sent only in the session cookie and the derived CSRF header, and no output, error or file carries it.
 */
object ScopeCommand {
    private val gson = GsonBuilder().setPrettyPrinting().disableHtmlEscaping().serializeNulls().create()
    private val TOKEN = Regex("""\A[0-9a-f]{64}\z""")

    /** One line of a plan: [action] is `add`, `change`, `keep`, `conflict`, `blocked` or `info`. */
    data class Item(val kind: String, val action: String, val detail: String)

    private class Options(val sub: String, val manifest: File, val api: String?, val policy: File?, val json: Boolean,
        val tokenStdin: Boolean, val console: String?, val expect: Set<String> = emptySet(), val allowUnknown: Boolean = false)

    fun run(args: List<String>, env: Map<String, String>, out: (String) -> Unit, err: (String) -> Unit,
        stdin: InputStream = System.`in`): Int {
        return try {
            val options = parse(args)
            val manifest = ScopeManifest.load(options.manifest)
            val api = AdminApi.open(options.api ?: env["SENTOMARU_API"], token(options, env, stdin), manifest.scope)
            if (options.sub == "check") return check(options, manifest, api, out)
            val policy = policy(options, manifest)
            val state = State.read(api, manifest)
            val plan = plan(manifest, state, policy)
            if (options.sub == "plan") { print(options, manifest, plan, applied = false, out); return 0 }
            if (plan.any { it.action == "conflict" }) {
                print(options, manifest, plan, applied = false, out)
                throw ScopeException("scope-conflict", 4, plan.first { it.action == "conflict" }.detail)
            }
            if (plan.any { it.action == "blocked" }) {
                print(options, manifest, plan, applied = false, out)
                throw ScopeException("policy-not-generated", 2, plan.first { it.action == "blocked" }.detail)
            }
            val draft = applyPlan(api, manifest, state, plan, policy)
            print(options, manifest, plan, applied = true, out, draft, options.console ?: env["SENTOMARU_CONSOLE_URL"])
            0
        } catch (e: ScopeException) {
            err(gson.toJson(mapOf("code" to e.code, "detail" to e.detail)))
            e.exit
        } catch (e: ProtectException) {
            err(gson.toJson(mapOf("code" to e.error.code, "detail" to e.detail)))
            e.error.exit
        }
    }

    // ---- arguments ----------------------------------------------------------------------------------------------

    private fun usage(detail: String) = ScopeException("usage", 2, detail)

    private fun parse(args: List<String>): Options {
        val sub = args.firstOrNull()
        if (sub != "plan" && sub != "apply" && sub != "check") throw usage("scope plan|apply|check --manifest <sentomaru-scope.yaml> [--api <url>] [--policy <policy.json>] [--expect <module,...>] [--allow-unknown] [--json] [--admin-token-stdin]")
        var manifest: String? = null; var api: String? = null; var policy: String? = null; var console: String? = null
        var json = false; var stdin = false; var allowUnknown = false; var expect = emptySet<String>()
        var i = 1
        fun value(name: String): String = args.getOrNull(++i)?.takeIf { !it.startsWith("--") } ?: throw usage("$name needs a value")
        while (i < args.size) {
            when (val a = args[i]) {
                "--manifest" -> manifest = value(a)
                "--api" -> api = value(a)
                "--policy" -> policy = value(a)
                "--console" -> console = value(a)
                "--json" -> json = true
                "--allow-unknown" -> allowUnknown = true
                "--expect" -> expect = value(a).split(",").map { it.trim() }.filter { it.isNotEmpty() }.toSet()
                "--admin-token-stdin" -> stdin = true
                else -> throw usage("unknown option $a")
            }
            i++
        }
        return Options(sub, File(manifest ?: throw usage("--manifest is required")), api, policy?.let(::File), json, stdin, console, expect, allowUnknown)
    }

    private fun token(options: Options, env: Map<String, String>, stdin: InputStream): String {
        val raw = if (options.tokenStdin) stdin.bufferedReader().readLine() else env["SENTOMARU_ADMIN_TOKEN"]
        val token = raw?.trim().orEmpty()
        if (token.isEmpty()) throw ScopeException("credential-missing", 8, "SENTOMARU_ADMIN_TOKEN (or --admin-token-stdin) is required")
        if (!TOKEN.matches(token)) throw ScopeException("credential-missing", 8, "the session token is not in the expected form")
        return token
    }

    // ---- policy file ---------------------------------------------------------------------------------------------

    /** The policy to draft, already checked against the manifest; null when the manifest declares none. */
    private class PolicyFile(val json: JsonObject, val policyId: String, val version: String)

    private fun policy(options: Options, manifest: ScopeManifest): PolicyFile? {
        val spec = manifest.policy ?: return null
        val path = options.policy ?: spec.file?.let { File(options.manifest.absoluteFile.parentFile, it) } ?: return null
        if (!path.isFile || path.length() > 512 * 1024) throw usage("--policy is not a policy file (at most 512 KiB)")
        val json = try { JsonParser.parseString(path.readText(Charsets.UTF_8)).asJsonObject }
            catch (e: Exception) { throw ScopeException("policy-format", 4, "the policy file is not a JSON object") }
        fun text(key: String) = json.get(key)?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isString }?.asString
        val scope = manifest.scope
        if (text("organization") != scope.organization || text("app") != scope.app || text("environment") != scope.environment)
            throw ScopeException("policy-format", 4, "the policy file is for another scope")
        val id = text("policyId") ?: throw ScopeException("policy-format", 4, "policyId is missing")
        val version = text("version") ?: throw ScopeException("policy-format", 4, "version is missing")
        if (spec.template == "study") {
            // A study policy never enforces and carries the operations the manifest declares.
            if (text("enforcementMode") != "shadow") throw ScopeException("policy-format", 4, "a study policy is shadow")
            val declared = json.getAsJsonArray("sensitiveOperations")?.map { it.asString }?.toSet().orEmpty()
            if (declared != spec.sensitiveOperations.toSet())
                throw ScopeException("policy-format", 4, "sensitiveOperations differ from the manifest")
        }
        return PolicyFile(json, id, version)
    }

    // ---- server state --------------------------------------------------------------------------------------------

    private class State(val visible: Boolean, val scopeId: String?, val packageName: String?, val digests: Map<String, String>,
        val appleAppId: String?, val appleEnvironment: String?, val policies: Set<Pair<String, String>>) {
        companion object {
            fun read(api: AdminApi, manifest: ScopeManifest): State {
                val scopes = api.get("/v1/auth/scopes").asJsonArray
                val s = manifest.scope
                val held = scopes.any { e -> e.asJsonObject.let { it.str("organization") == s.organization && it.str("app") == s.app && it.str("environment") == s.environment } }
                if (!held) return State(false, null, null, emptyMap(), null, null, emptySet())
                val detail = api.get("${api.adminPath}/scope").asJsonObject
                val digests = detail.getAsJsonArray("signingDigests").associate { it.asJsonObject.let { d -> d.str("sha256")!! to d.str("state")!! } }
                val policies = if (manifest.policy == null) emptySet()
                    else api.get("${api.adminPath}/policies").asJsonArray.map { it.asJsonObject.let { p -> p.str("policyId")!! to p.str("version")!! } }.toSet()
                return State(true, detail.str("id"), detail.str("packageName"), digests, detail.str("appleAppId"),
                    detail.str("appleAttestEnvironment"), policies)
            }
        }
    }

    // ---- plan ----------------------------------------------------------------------------------------------------

    private fun plan(m: ScopeManifest, state: State, policy: PolicyFile?): List<Item> {
        val items = ArrayList<Item>()
        val label = "${m.scope.organization}/${m.scope.app}/${m.scope.environment}"
        val packageName = m.android?.packageName
        if (!state.visible) {
            if (packageName == null) items.add(Item("scope", "conflict", "$label is not visible to this operator and the manifest has no android.package to create it with"))
            else items.add(Item("scope", "add", "create $label (package $packageName); an existing scope of the same package is reused"))
        } else if (packageName != null && state.packageName != packageName) {
            items.add(Item("scope", "conflict", "$label has package ${state.packageName}, the manifest says $packageName; the package of a scope is not changed by this command"))
        } else items.add(Item("scope", "keep", label))

        m.android?.signingDigests?.forEach { d ->
            val text = "${d.colon.take(8)}… (${d.source.id})"
            when (state.digests[d.sha256]) {
                "active" -> items.add(Item("digest", "keep", text))
                "retired" -> items.add(Item("digest", "change", "activate $text, retired on the server"))
                else -> items.add(Item("digest", "add", "add $text"))
            }
        }
        val wanted = m.android?.signingDigests?.map { it.sha256 }?.toSet().orEmpty()
        state.digests.filter { it.value == "active" && it.key !in wanted }.keys.sorted().forEach {
            items.add(Item("digest", "info", "the server has active digest ${it.chunked(2).joinToString(":").uppercase().take(8)}… that the manifest does not list; it is not removed"))
        }

        m.ios?.let { ios ->
            when {
                state.appleAppId == ios.appId && state.appleEnvironment == ios.attestEnvironment -> items.add(Item("apple", "keep", "${ios.appId} (${ios.attestEnvironment})"))
                state.appleAppId == null -> items.add(Item("apple", "add", "set the Apple app ${ios.appId} (${ios.attestEnvironment})"))
                else -> items.add(Item("apple", "change", "replace the Apple app ${state.appleAppId} (${state.appleEnvironment}) with ${ios.appId} (${ios.attestEnvironment})"))
            }
        }

        m.policy?.let { spec ->
            when {
                policy == null -> items.add(Item("policy", "blocked", if (spec.template == "study")
                    "template study: generate the policy (sentomaru policy study) and pass it with --policy" else "template file: --policy or policy.file is missing"))
                (policy.policyId to policy.version) in state.policies -> items.add(Item("policy", "keep", "${policy.policyId} ${policy.version} already exists on the server"))
                else -> items.add(Item("policy", "add", "draft ${policy.policyId} ${policy.version} (${spec.template}); another operator approves it"))
            }
        }

        // Declared, but with no admin route this command can call: read by the Prontidão (spec section 7) and `scope check`.
        m.android?.cloudProjectNumber?.let { items.add(Item("playIntegrity", "info", "cloudProjectNumber declared; not stored by this command")) }
        if (m.consumerExpected.isNotEmpty()) items.add(Item("consumer", "info", "expected ${m.consumerExpected.toSortedMap()} declared; not applied"))
        if (m.appExpected.isNotEmpty()) items.add(Item("app", "info", "expected ${m.appExpected.toSortedMap()} declared; not applied"))
        m.telegram?.let { items.add(Item("notifications", "info", "telegram=$it declared; not applied")) }
        return items
    }

    // ---- apply ---------------------------------------------------------------------------------------------------

    private fun applyPlan(api: AdminApi, m: ScopeManifest, state: State, plan: List<Item>, policy: PolicyFile?): JsonObject? {
        if (plan.any { it.kind == "scope" && it.action == "add" }) {
            val body = mapOf("app" to m.scope.app, "environment" to m.scope.environment, "packageName" to m.android!!.packageName)
            api.send("POST", "/v1/${enc(m.scope.organization)}/platform/scopes", gson.toJson(body))
            val held = api.get("/v1/auth/scopes").asJsonArray.any { e -> e.asJsonObject.let {
                it.str("organization") == m.scope.organization && it.str("app") == m.scope.app && it.str("environment") == m.scope.environment } }
            if (!held) throw ScopeException("scope-not-visible", 5, "the scope exists but this operator does not hold it; assign it in the Console and run apply again")
        }
        val server = if (state.visible) state.digests else emptyMap()
        m.android?.signingDigests?.forEach { d ->
            if (server[d.sha256] != "active")
                api.send("POST", "${api.adminPath}/scope/signing-digests", gson.toJson(mapOf("sha256" to d.sha256, "state" to "active")))
        }
        m.ios?.let { ios ->
            if (state.appleAppId != ios.appId || state.appleEnvironment != ios.attestEnvironment)
                api.send("PUT", "${api.adminPath}/scope/apple-app", gson.toJson(mapOf("teamId" to ios.teamId, "bundleId" to ios.bundleId, "environment" to ios.attestEnvironment)))
        }
        if (policy != null && plan.any { it.kind == "policy" && it.action == "add" })
            return api.send("POST", "${api.adminPath}/policies", gson.toJson(policy.json)).takeIf { it.isJsonObject }?.asJsonObject
        return null
    }


    // ---- check ---------------------------------------------------------------------------------------------------

    private val STATES = setOf("ready", "partial", "off", "misconfigured", "unknown")
    private val MODULE_ID = Regex("""\A[a-z][a-z0-9_.]{0,48}\z""")

    /** The modules the manifest says must be ready, with the reason each one is expected (the ids are the catalog's: contracts/platform/readiness-modules-v1.json). */
    internal fun expectedModules(m: ScopeManifest, extra: Set<String>): Map<String, String> {
        val out = LinkedHashMap<String, String>()
        if (m.android != null) out["attestation.android"] = "android in the manifest"
        if (m.ios != null) out["attestation.ios"] = "ios in the manifest"
        if (m.android?.cloudProjectNumber != null) out["play_integrity"] = "playIntegrity.cloudProjectNumber in the manifest"
        if (m.policy != null) out["policy"] = "policy in the manifest"
        if (m.consumerExpected["mobileGate"] == true) out["consumer.gate"] = "consumer.expected.mobileGate"
        if (m.consumerExpected["fraud"] == true) out["fraud"] = "consumer.expected.fraud"
        if (m.appExpected["installationResponse"] == true) out["response"] = "app.expected.installationResponse"
        if (m.telegram == true) out["notifications"] = "notifications.telegram"
        extra.forEach { out.putIfAbsent(it, "--expect") }
        return out
    }

    /**
     * `scope check`: reads `GET …/admin/readiness` (contracts/platform/readiness-v1.md) and compares it with what the manifest expects.
     * Read only. Exit 0 when every expected module is `ready` (an `unknown` one counts as not ready unless `--allow-unknown`: the
     * server cannot see it, and CI should not pass on something nobody saw); exit 4 `readiness-not-ready` otherwise. The answer is
     * data, never an instruction: only the closed code shapes are printed.
     */
    private fun check(options: Options, m: ScopeManifest, api: AdminApi, out: (String) -> Unit): Int {
        val body = try { api.get("${api.adminPath}/readiness") } catch (e: ScopeException) {
            if (e.code == "apply-refused" && Regex("""scope-unknown|not-found|http-404""").containsMatchIn(e.detail))
                throw ScopeException("scope-unknown", 4, "the scope is unknown to the server, or the server predates the readiness route")
            throw e
        }
        val root = body as? JsonObject ?: throw ScopeException("readiness-format", 8, "the readiness answer is not an object")
        val rows = (root.get("modules") as? com.google.gson.JsonArray ?: throw ScopeException("readiness-format", 8, "modules is missing")).map { e ->
            val o = e as? JsonObject ?: throw ScopeException("readiness-format", 8, "a module is not an object")
            val id = o.str("id")?.takeIf { MODULE_ID.matches(it) } ?: throw ScopeException("readiness-format", 8, "a module has no valid id")
            val state = o.str("state")?.takeIf { it in STATES } ?: throw ScopeException("readiness-format", 8, "module $id has an unknown state")
            fun codes(array: String, field: String?) = o.get(array).items().mapNotNull { c ->
                (if (field == null) c else (c as? JsonObject)?.get(field))?.takeIf { it.isJsonPrimitive }?.asString?.takeIf { MODULE_ID.matches(it) }
            }
            val steps = o.get("nextSteps").items().mapNotNull { c ->
                (c as? JsonObject)?.let { n -> n.str("actor")?.takeIf { MODULE_ID.matches(it) }?.let { a -> n.str("code")?.takeIf { MODULE_ID.matches(it) }?.let { code -> "$a:$code" } } }
            }
            Row(id, state, codes("reasons", null), steps)
        }
        val byId = rows.associateBy { it.id }
        val expected = expectedModules(m, options.expect)
        val missing = expected.keys.filter { it !in byId }
        val failing = expected.keys.filter { id -> byId[id]?.let { it.state != "ready" && !(it.state == "unknown" && options.allowUnknown) } == true }
        val label = "${m.scope.organization}/${m.scope.app}/${m.scope.environment}"
        val stale = root.get("stale")?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isBoolean }?.asBoolean == true
        val ok = missing.isEmpty() && failing.isEmpty()
        if (options.json) {
            out(gson.toJson(mapOf("scope" to label, "mode" to "check", "ok" to ok, "stale" to stale,
                "expected" to expected.keys.toList(), "failing" to failing, "missing" to missing,
                "modules" to rows.map { mapOf("id" to it.id, "state" to it.state, "reasons" to it.reasons, "nextSteps" to it.steps, "expected" to (it.id in expected)) })))
        } else {
            out("scope $label readiness${if (stale) " (cached report)" else ""}")
            rows.forEach { r ->
                val bad = r.id in failing
                val line = StringBuilder("  ${if (bad) "!" else if (r.id in expected) "=" else " "} ${r.id}: ${r.state}")
                if (r.reasons.isNotEmpty()) line.append(" [").append(r.reasons.joinToString(", ")).append("]")
                if (r.steps.isNotEmpty() && r.state != "ready") line.append(" -> ").append(r.steps.joinToString(", "))
                out(line.toString())
            }
            missing.forEach { out("  ! $it: not in the server catalog (expected by ${expected[it]})") }
            out(if (ok) "expected modules: all ready" else "expected modules not ready: ${(failing + missing).joinToString(", ")}")
        }
        if (!ok) throw ScopeException("readiness-not-ready", 4, (failing + missing).joinToString(","))
        return 0
    }

    private class Row(val id: String, val state: String, val reasons: List<String>, val steps: List<String>)

    // ---- output --------------------------------------------------------------------------------------------------

    private fun print(options: Options, m: ScopeManifest, plan: List<Item>, applied: Boolean, out: (String) -> Unit,
        draft: JsonObject? = null, console: String? = null) {
        val label = "${m.scope.organization}/${m.scope.app}/${m.scope.environment}"
        val link = draft?.let { d ->
            console?.trimEnd('/')?.let { "$it/#/policy/${enc(m.scope.organization)}/${enc(m.scope.app)}/${enc(m.scope.environment)}" }
                ?: "#/policy/${enc(m.scope.organization)}/${enc(m.scope.app)}/${enc(m.scope.environment)} in the Console"
        }
        if (options.json) {
            out(gson.toJson(mapOf("scope" to label, "mode" to if (applied) "apply" else "plan", "items" to plan,
                "draftPolicyId" to draft?.str("id"), "draftLocation" to link,
                "approval" to "another operator approves the draft in the Console; this command never approves")))
            return
        }
        val mark = mapOf("add" to "+", "change" to "~", "keep" to "=", "conflict" to "!", "blocked" to "!", "info" to "i")
        out("scope $label (${if (applied) "applied" else "plan, nothing changed"})")
        plan.forEach { out("  ${mark[it.action]} ${it.kind}: ${it.detail}") }
        if (draft != null) out("draft policy created (id ${draft.str("id")}): approve it in the Console as another operator, $link; this command never approves")
    }

    private fun enc(s: String) = URLEncoder.encode(s, Charsets.UTF_8)
    private fun JsonElement?.items(): List<JsonElement> = (this as? com.google.gson.JsonArray)?.toList() ?: emptyList()
    private fun JsonObject.str(key: String): String? = get(key)?.takeIf { it.isJsonPrimitive }?.asString

    // ---- admin API -----------------------------------------------------------------------------------------------

    internal class AdminApi private constructor(private val base: URI, private val token: String, scope: Scope, private val client: HttpClient) {
        val adminPath = "/v1/${enc(scope.organization)}/${enc(scope.app)}/${enc(scope.environment)}/admin"
        private val csrf = MessageDigest.getInstance("SHA-256").digest("sentomaru-csrf:$token".toByteArray()).joinToString("") { "%02x".format(it) }

        companion object {
            fun open(api: String?, token: String, scope: Scope): AdminApi {
                val uri = try { Registry.address(api) } catch (e: ProtectException) {
                    throw ScopeException("usage", 2, "--api (or SENTOMARU_API) must be an https URL")
                }
                val client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).followRedirects(HttpClient.Redirect.NEVER).build()
                return AdminApi(uri, token, scope, client)
            }
        }

        fun get(path: String): JsonElement = send("GET", path, null)

        /** Sends one request; the answer is the parsed JSON body (JsonNull-like empty object when there is none). */
        fun send(method: String, path: String, body: String?): JsonElement {
            val builder = HttpRequest.newBuilder(URI(base.toString().trimEnd('/') + path)).timeout(Duration.ofSeconds(20))
                .header("Cookie", "__Host-sentomaru_session=$token").header("Accept", "application/json")
            if (method != "GET") builder.header("X-Sentomaru-Csrf", csrf).header("Content-Type", "application/json")
            builder.method(method, if (body == null) HttpRequest.BodyPublishers.noBody() else HttpRequest.BodyPublishers.ofString(body))
            val response = try { client.send(builder.build(), HttpResponse.BodyHandlers.ofString()) }
                catch (e: InterruptedException) { Thread.currentThread().interrupt(); throw ScopeException("api-unavailable", 8, "interrupted") }
                catch (e: Exception) { throw ScopeException("api-unavailable", 8, "API unreachable (${e.javaClass.simpleName})") }
            val json = runCatching { JsonParser.parseString(response.body()) }.getOrNull()
            val status = response.statusCode()
            if (status in 200..299) return json ?: JsonObject()
            val raw = (json as? JsonObject)?.get("code")?.takeIf { it.isJsonPrimitive }?.asString
            val code = raw?.takeIf { Regex("""\A[a-z0-9-]{1,48}\z""").matches(it) } ?: "http-$status"
            throw when {
                status == 401 -> ScopeException("credential-missing", 8, "session refused ($code)")
                status == 403 -> ScopeException("permission-missing", 5, "refused ($code); apply needs a SuperAdmin session, plan needs a role that can read the scope")
                status == 429 || status >= 500 -> ScopeException("api-unavailable", 8, code)
                else -> ScopeException("apply-refused", 8, "$method ${path.substringAfter("/admin")} refused ($code)")
            }
        }
    }
}
