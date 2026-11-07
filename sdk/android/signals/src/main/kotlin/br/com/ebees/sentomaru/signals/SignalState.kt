package br.com.ebees.sentomaru.signals

/** Observation states from decision E5. Local observation only; never an authorization. */
enum class SignalState { DETECTED, NOT_DETECTED, UNKNOWN, UNSUPPORTED, ERROR, STALE }
