package br.com.ebees.sentomaru.sdk.transport

import okhttp3.HttpUrl.Companion.toHttpUrl
import org.junit.Assert.*
import org.junit.Test

class SentomaruRoutesTest {
    private val table = SentomaruRoutes.of(listOf("api.example"), listOf(
        SentomaruRoutes.Route("/v1/demandas/*/concluir", "concluir_demanda"),
        SentomaruRoutes.Route("/v1/demandas", "criar_demanda"),
        SentomaruRoutes.Route("/v1/demandas/*", "ler_demanda"),
    ))

    private fun op(url: String) = table.operationFor(url.toHttpUrl())

    @Test fun matchesBySegmentWithOneStarPerSegment() {
        assertEquals("concluir_demanda", op("https://api.example/v1/demandas/7/concluir"))
        assertEquals("criar_demanda", op("https://api.example/v1/demandas"))
        assertEquals("criar_demanda", op("https://api.example/v1/demandas/"))
        assertEquals("ler_demanda", op("https://api.example/v1/demandas/7?x=1"))
        assertEquals("concluir_demanda", op("https://api.example/V1/Demandas/7/CONCLUIR"))
        assertNull(op("https://api.example/v1/demandas/7/concluir/x"))
        assertNull(op("https://api.example/v1/demandas//concluir"))
        assertNull(op("https://api.example/v1"))
        assertNull(op("https://other.example/v1/demandas"))
        // Port ignored; percent-encoding compared decoded; one trailing dot on the host is the same host.
        assertEquals("criar_demanda", op("https://api.example:8443/v1/demandas"))
        assertEquals("concluir_demanda", op("https://api.example/v1/%64emandas/7/concluir"))
        assertEquals("criar_demanda", op("https://api.example./v1/demandas"))
    }

    @Test fun theFirstMatchingRouteWins() {
        val ordered = SentomaruRoutes.of(listOf("api.example"), listOf(
            SentomaruRoutes.Route("/v1/demandas/novo", "criar_demanda"), SentomaruRoutes.Route("/v1/demandas/*", "ler_demanda")))
        assertEquals("criar_demanda", ordered.operationFor("https://api.example/v1/demandas/novo".toHttpUrl()))
        val reversed = SentomaruRoutes.of(listOf("api.example"), listOf(
            SentomaruRoutes.Route("/v1/demandas/*", "ler_demanda"), SentomaruRoutes.Route("/v1/demandas/novo", "criar_demanda")))
        assertEquals("ler_demanda", reversed.operationFor("https://api.example/v1/demandas/novo".toHttpUrl()))
    }

    @Test fun refusesWhatTheProfileRefuses() {
        fun refused(hosts: List<String>, vararg routes: Pair<String, String>) = assertThrows(IllegalArgumentException::class.java) {
            SentomaruRoutes.of(hosts, routes.map { SentomaruRoutes.Route(it.first, it.second) })
        }
        refused(emptyList(), "/a" to "op")
        refused(listOf("API.example"), "/a" to "op")
        refused(listOf("a.example", "a.example"), "/a" to "op")
        refused(listOf("a.example"))
        refused(listOf("a.example"), "a" to "op")
        refused(listOf("a.example"), "/a?x=1" to "op")
        refused(listOf("a.example"), "/a#f" to "op")
        refused(listOf("a.example"), "/a*" to "op")
        refused(listOf("a.example"), "/a//b" to "op")
        refused(listOf("a.example"), "/a b" to "op")
        refused(listOf("a.example"), "/a" to "Op")
        refused(listOf("a.example"), "/a" to "x".repeat(65))
        refused(listOf("a.example"), "/a" to "one", "/A/" to "two")
    }
}
