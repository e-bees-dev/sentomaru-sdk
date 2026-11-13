package br.com.ebees.sentomaru.hybrid

import br.com.ebees.sentomaru.sdk.SentomaruConfig

/**
 * Revisor A, rodada 2 (médio A): `initialize` takes `allowedHosts`/`enrollmentUrl`/`renewalUrl` from the channel
 * (contracts/sdk/hybrid-bridge-v1.json), i.e. from the JavaScript side. On Capacitor/Cordova that JavaScript is a
 * WebView page, not the app's own code; without this lock, injected or compromised page content could call
 * `initialize` again with `allowedHosts` pointing at an attacker host and have the next `enroll`/`sign`/
 * `renewSession` attest, sign and renew against it (the previous behaviour, "of two `initialize` calls the later one
 * wins", applied with no check of who is calling).
 *
 * The first accepted `initialize` locks these three fields for the life of the bridge. A later `initialize` is
 * allowed only when its `allowedHosts` is a subset of the locked set (the list may only shrink, never grow) and its
 * `enrollmentUrl`/`renewalUrl` are byte-identical to the locked ones; anything else is refused before a client is
 * built, same as a malformed argument (`ConfigurationError`). This is stricter than `SentomaruConfig`/
 * `SentomaruClient`'s own per-scope-identity reuse check: that one only guards against reconfiguring the *same*
 * organization/app/environment differently, not against a second call choosing a different identity altogether to
 * avoid the collision and get a fresh, attacker-controlled client installed as the bridge's `native`.
 */
class InitializeSecurityLock(config: SentomaruConfig) {
    private val allowedHosts: Set<String> = config.allowedHosts
    private val enrollmentUrl: String = config.enrollmentUrl
    private val renewalUrl: String? = config.renewalUrl

    fun allows(candidate: SentomaruConfig): Boolean =
        allowedHosts.containsAll(candidate.allowedHosts) &&
            enrollmentUrl == candidate.enrollmentUrl &&
            renewalUrl == candidate.renewalUrl
}
