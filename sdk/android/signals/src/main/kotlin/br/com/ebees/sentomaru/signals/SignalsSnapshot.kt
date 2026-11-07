package br.com.ebees.sentomaru.signals

/**
 * Snapshot of observed signals collected within an execution budget.
 * Client-observed provenance only; never an authority or server authorization.
 */
data class SignalsSnapshot(
    val catalogVersion: String,
    val collectedAt: String,
    val durationMs: Long,
    val observations: List<SignalObservation>,
) {
    init {
        // One observation per capability: a duplicate (in any case) would make the server outcome ambiguous.
        val ids = observations.map { it.capabilityId.lowercase() }
        require(ids.size == ids.toSet().size) { "Duplicate capabilityId in signals snapshot" }
    }

    fun toJson(): String = buildString {
        append("{\"catalogVersion\":\"").append(escape(catalogVersion))
        append("\",\"collectedAt\":\"").append(escape(collectedAt))
        append("\",\"durationMs\":").append(durationMs)
        append(",\"observations\":[")
        observations.forEachIndexed { i, obs ->
            if (i > 0) append(",")
            append("{\"capabilityId\":\"").append(escape(obs.capabilityId))
            append("\",\"version\":\"").append(escape(obs.version))
            append("\",\"state\":\"").append(obs.state.name)
            append("\",\"source\":\"").append(escape(obs.source))
            append("\",\"observedAt\":\"").append(escape(obs.observedAt))
            append("\",\"detail\":{")
            obs.detail.entries.forEachIndexed { di, (k, v) ->
                if (di > 0) append(",")
                append("\"").append(escape(k)).append("\":\"").append(escape(v)).append("\"")
            }
            append("}}")
        }
        append("]}")
    }

    private companion object {
        fun escape(s: String): String =
            s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    }
}
