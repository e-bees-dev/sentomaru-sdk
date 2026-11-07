package br.com.ebees.sentomaru.signals

/**
 * Single signal observation as defined in decision E5.
 * Observation only; client_observed provenance; never an authorization.
 */
data class SignalObservation(
    val capabilityId: String,
    val version: String,
    val state: SignalState,
    val source: String = "client_observed",
    val observedAt: String,
    val detail: Map<String, String> = emptyMap(),
)
