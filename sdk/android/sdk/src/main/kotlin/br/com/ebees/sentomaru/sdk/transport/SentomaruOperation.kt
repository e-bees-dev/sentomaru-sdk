package br.com.ebees.sentomaru.sdk.transport

import br.com.ebees.sentomaru.signals.SignalsSnapshot

/** Request tag to declare a Sentomaru-protected operation name and optional signals on an OkHttp Request. */
class SentomaruOperation(
    val name: String,
    val signals: SignalsSnapshot? = null,
    val signalsJson: String? = null
) {
    init {
        require(name.isNotBlank()) { "Operation name must not be blank" }
    }

    /** Resolves the signals JSON string if either snapshot or raw JSON was provided. */
    fun resolvedSignalsJson(): String? = signals?.toJson() ?: signalsJson
}
