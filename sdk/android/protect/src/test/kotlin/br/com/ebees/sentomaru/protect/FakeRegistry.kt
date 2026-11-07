package br.com.ebees.sentomaru.protect

import com.google.gson.JsonObject
import com.google.gson.JsonParser
import com.sun.net.httpserver.HttpServer
import java.net.InetSocketAddress
import java.net.URI
import java.util.concurrent.CopyOnWriteArrayList

/**
 * A local stand-in for the Sentomaru API side of a real run (G-03e): it answers the open and close routes with the
 * configured status and records every request (path, Authorization header, JSON body). Loopback http only.
 */
class FakeRegistry : AutoCloseable {
    data class Call(val path: String, val authorization: String?, val body: JsonObject)

    val calls = CopyOnWriteArrayList<Call>()
    @Volatile var open: Pair<Int, String> = 201 to """{"runId":"x"}"""
    @Volatile var close: Pair<Int, String>? = null // null: 200 with the build id = the run id of the path

    private val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0).apply {
        createContext("/") { exchange ->
            val body = exchange.requestBody.readBytes().toString(Charsets.UTF_8)
            val json = runCatching { JsonParser.parseString(body).asJsonObject }.getOrDefault(JsonObject())
            val path = exchange.requestURI.path
            calls += Call(path, exchange.requestHeaders.getFirst("Authorization"), json)
            val (status, answer) = if (path.endsWith("/close")) close ?: (200 to """{"buildId":"${path.split('/').let { it[it.size - 2] }}"}""") else open
            val bytes = answer.toByteArray()
            exchange.responseHeaders.add("Content-Type", "application/json")
            exchange.sendResponseHeaders(status, bytes.size.toLong())
            exchange.responseBody.use { it.write(bytes) }
        }
        start()
    }

    val address: URI get() = URI("http://127.0.0.1:${server.address.port}")

    override fun close() = server.stop(0)
}
