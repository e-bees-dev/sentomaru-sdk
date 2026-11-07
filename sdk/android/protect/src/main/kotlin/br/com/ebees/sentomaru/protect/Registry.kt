package br.com.ebees.sentomaru.protect

import com.google.gson.Gson
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration

/**
 * G-03e: the Sentomaru API side of a real run (contract "Invocação", "Medição"). Opening the run is the entitlement
 * check (the route is gated by the devsecops module) and opens the usage event; closing it registers the result in the
 * Shield registry and closes the event. Only metadata and digests are sent; the credential goes in the Authorization
 * header and never into an error, a report or a log.
 *
 * [api] must be https; plain http is accepted only for a loopback address (local tests), never for a remote host.
 */
class Registry(private val api: URI, private val token: String, private val client: HttpClient = default) {
    companion object {
        private val default: HttpClient = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10))
            .followRedirects(HttpClient.Redirect.NEVER).build()
        private val gson = Gson()

        /** The API address from `SENTOMARU_API`, or `usage` when it is not an https URL (loopback http for tests). */
        fun address(value: String?): URI {
            val uri = value?.let { runCatching { URI(it) }.getOrNull() }
            val loopback = uri?.host in setOf("127.0.0.1", "localhost", "[::1]")
            if (uri == null || uri.host.isNullOrEmpty() || uri.userInfo != null || uri.query != null || uri.fragment != null ||
                !(uri.scheme == "https" || uri.scheme == "http" && loopback))
                throw ProtectException(ErrorCode.USAGE, "SENTOMARU_API must be an https URL")
            return uri
        }
    }

    data class Registered(val buildId: String)

    private fun runs(scope: Scope) =
        api.resolve("${api.path.trimEnd('/')}/v1/${scope.organization}/${scope.app}/${scope.environment}/devsecops/runs")

    /** Entitlement check and opening of the usage event, before the input is read. */
    fun open(scope: Scope, runId: String, profile: Profile, cliVersion: String) {
        val body = mapOf("runId" to runId, "profileId" to profile.id, "profileSha256" to profile.sha256, "cliVersion" to cliVersion)
        val (status, answer) = post(runs(scope), body)
        if (status == 201 || status == 200) return
        throw refusal(status, answer, opening = true)
    }

    /** Closes the run with its result: the registration of a protected run, or the failure code. */
    fun close(scope: Scope, runId: String, closing: Map<String, Any?>): Registered {
        val (status, answer) = post(URI("${runs(scope)}/$runId/close"), closing)
        if (status == 200) return Registered(answer?.get("buildId")?.takeIf { it.isJsonPrimitive }?.asString ?: runId)
        throw refusal(status, answer, opening = false)
    }

    private fun refusal(status: Int, answer: JsonObject?, opening: Boolean): ProtectException {
        val code = answer?.get("code")?.takeIf { it.isJsonPrimitive }?.asString ?: "http-$status"
        val safe = if (Regex("""\A[a-z0-9-]{1,48}\z""").matches(code)) code else "http-$status"
        // Close (registration): the run was admitted, so any refusal is a registration failure; the artifact stays.
        if (!opening) return if (status >= 500 || status == 429) ProtectException(ErrorCode.REGISTRY_UNAVAILABLE, safe)
            else ProtectException(ErrorCode.REGISTER_FAILED, safe)
        return when {
            status == 401 -> ProtectException(ErrorCode.CREDENTIAL_MISSING, "credential refused ($safe)")
            status == 403 && safe.startsWith("module-") -> ProtectException(ErrorCode.ENTITLEMENT_DENIED, safe)
            status == 403 && safe == "workload-scope" -> ProtectException(ErrorCode.SCOPE_MISMATCH, "the credential is not of the profile scope")
            status == 403 -> ProtectException(ErrorCode.CREDENTIAL_MISSING, "not a shield-builder credential of this scope ($safe)")
            status >= 500 || status == 429 -> ProtectException(ErrorCode.REGISTRY_UNAVAILABLE, safe)
            else -> ProtectException(ErrorCode.REGISTER_FAILED, "run not opened ($safe)")
        }
    }

    private fun post(uri: URI, body: Map<String, Any?>): Pair<Int, JsonObject?> {
        val request = HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(20))
            .header("Authorization", "Bearer $token").header("Content-Type", "application/json").header("Accept", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(gson.toJson(body))).build()
        val response = try {
            client.send(request, HttpResponse.BodyHandlers.ofString())
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            throw ProtectException(ErrorCode.REGISTRY_UNAVAILABLE, "interrupted")
        } catch (e: Exception) {
            throw ProtectException(ErrorCode.REGISTRY_UNAVAILABLE, "API unreachable (${e.javaClass.simpleName})")
        }
        val json = runCatching { JsonParser.parseString(response.body()).takeIf { it.isJsonObject }?.asJsonObject }.getOrNull()
        return response.statusCode() to json
    }
}
