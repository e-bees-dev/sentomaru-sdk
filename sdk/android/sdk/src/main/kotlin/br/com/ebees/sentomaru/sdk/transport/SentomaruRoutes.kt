package br.com.ebees.sentomaru.sdk.transport

import okhttp3.HttpUrl

/**
 * G-03c: the profile's `network-signing` section (contracts/devsecops/cli-v1.md) in the app. A request with no
 * declared operation whose host is in [hosts] and whose path matches a route is signed as that route's operation,
 * so the app protects its calls by installing the transport once (`addSentomaru(client, routes)`) instead of tagging
 * each request. A declared operation (header or [SentomaruOperation] tag) always wins over the table.
 *
 * Same rules as the CLI profile: hosts lowercase `[a-z0-9.-]{1,253}`, unique, at least one; routes at least one, path
 * starting with `/`, operation `[a-z0-9_]{1,64}`. A path segment `*` matches exactly one non-empty segment; other
 * segments compare case-insensitively (servers such as ASP.NET route that way, so a case variant is still signed);
 * one trailing slash is ignored; no query or fragment in a route. Routes are tried **in order and the first match wins**
 * (put a literal route before a `*` route that would also match it); a repeated path is refused. Paths are compared
 * percent-decoded (OkHttp's `pathSegments`, the same view the server routes on); the port is ignored; a request host with
 * one trailing dot (`api.example.`) is the same host, so it is covered too and then refused by the allowlist check
 * (`HostNotAllowed`), never sent unsigned. [hosts] must be within the client's allowed hosts: `addSentomaru(client,
 * routes)` refuses the installation otherwise.
 */
class SentomaruRoutes private constructor(val hosts: Set<String>, val routes: List<Route>) {

    class Route(val path: String, val operation: String) {
        internal val segments: List<String> = segmentsOf(path)
    }

    /** The operation for [url] by this table, or null when its host or path is not covered. */
    fun operationFor(url: HttpUrl): String? {
        if (url.host.removeSuffix(".") !in hosts) return null
        val actual = url.pathSegments.let { if (it.size > 1 && it.last().isEmpty()) it.dropLast(1) else it }
        return routes.firstOrNull { matches(it.segments, actual) }?.operation
    }

    companion object {
        private val HOST = Regex("""\A[a-z0-9.-]{1,253}\z""")
        private val OPERATION = Regex("""\A[a-z0-9_]{1,64}\z""")

        /** Validates and builds the table; throws [IllegalArgumentException] naming the first offending field. */
        @JvmStatic
        fun of(hosts: List<String>, routes: List<Route>): SentomaruRoutes {
            require(hosts.isNotEmpty() && hosts.all { HOST.matches(it) } && hosts.toSet().size == hosts.size) { "network-signing.hosts" }
            require(routes.isNotEmpty()) { "network-signing.routes" }
            for (r in routes) require(OPERATION.matches(r.operation)) { "network-signing.routes.operation" }
            require(routes.map { it.segments.joinToString("/") { s -> s.lowercase() } }.toSet().size == routes.size) {
                "network-signing.routes: repeated path"
            }
            return SentomaruRoutes(hosts.toSet(), routes.toList())
        }

        /** Path → segments (`*` stays a segment); refuses what the contract does not allow (no leading slash, query, fragment, partial `*`). */
        private fun segmentsOf(path: String): List<String> {
            require(path.startsWith("/") && '?' !in path && '#' !in path && path.none { it <= ' ' || it == '\u007f' }) {
                "network-signing.routes.path"
            }
            val parts = path.substring(1).split('/').let { if (it.size > 1 && it.last().isEmpty()) it.dropLast(1) else it }
            require(parts.none { it.isEmpty() } || parts == listOf("")) { "network-signing.routes.path" }
            require(parts.none { '*' in it && it != "*" }) { "network-signing.routes.path" }
            return parts
        }

        private fun matches(pattern: List<String>, actual: List<String>): Boolean =
            pattern.size == actual.size && pattern.indices.all { i ->
                if (pattern[i] == "*") actual[i].isNotEmpty() else pattern[i].equals(actual[i], ignoreCase = true)
            }
    }
}
