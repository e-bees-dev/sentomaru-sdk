package br.com.ebees.sentomaru.signals.rasp

/**
 * Marker of the D-05 opt-in artifact `signals-rasp`, whose manifest carries the `<queries>` of the root-manager
 * packages. `RootArtifactsDetector` looks it up by name: when absent, those packages are invisible to the app, so the
 * package check did not run.
 */
object RootManagerQueries {
    const val VERSION = "1.0.0"
}
