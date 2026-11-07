package br.com.ebees.sentomaru.sdk.transport

import br.com.ebees.sentomaru.sdk.SentomaruClient
import br.com.ebees.sentomaru.signals.SentomaruSignalEvents
import okhttp3.OkHttpClient

/**
 * The only way to install Sentomaru on OkHttp: disables OkHttp redirects (the interceptor follows them under the
 * SDK rules), adds the signing interceptor and a network guard that refuses a signed hop to a non-allowlisted or
 * non-https target even if redirects are re-enabled later on the builder.
 */
fun OkHttpClient.Builder.addSentomaru(client: SentomaruClient): OkHttpClient.Builder = addSentomaru(client, null)

/**
 * G-03c, the one line that turns on network signing: as [addSentomaru], and a request with no declared operation whose
 * host and path match [routes] (the profile's `network-signing` section) is signed as that route's operation.
 */
fun OkHttpClient.Builder.addSentomaru(client: SentomaruClient, routes: SentomaruRoutes?): OkHttpClient.Builder =
    addSentomaru(client, routes, null)

/**
 * D-15b, opt-in: as [addSentomaru], and the closed code a consumer answers to a SIGNED request (401/403 with
 * `challenge-required` and its `challengeKind`, `proof-required`, `installation-suspended`, `installation-revoked`,
 * `session-unavailable`, `policy-denied` or a policy reason code) becomes an informative
 * `SentomaruServerResponseEvent` on [events] (`addServerResponseListener`). The response the app receives is unchanged
 * (the body is peeked, at most 4096 characters, only when a listener exists); nothing else of the body is read.
 *
 * D-07d, same [events]: a TLS failure of any exchange of the interceptor (signed or not, redirect hop, renewal) to a
 * host of the app's pinning meta-data (`sentomaru protect`, `network-pinning`) becomes a local
 * `SentomaruTransportEvent` (`addTransportListener`): `pin_failure` with `pin_mismatch`, `tls_untrusted` or `tls_other`
 * and the pinned host only. The exception reaches the app unchanged; nothing is retried, stored or sent.
 */
fun OkHttpClient.Builder.addSentomaru(client: SentomaruClient, routes: SentomaruRoutes?, events: SentomaruSignalEvents?):
    OkHttpClient.Builder = apply {
    SentomaruWire.requireRoutesWithin(client, routes)
    followRedirects(false)
    followSslRedirects(false)
    addInterceptor(SentomaruInterceptor.create(client, routes, events))
    addNetworkInterceptor(SentomaruRedirectGuard(client))
}
