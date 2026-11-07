package br.com.ebees.sentomaru.sdk.transport

import br.com.ebees.sentomaru.core.Profile
import br.com.ebees.sentomaru.core.SentomaruError
import br.com.ebees.sentomaru.core.SentomaruException
import br.com.ebees.sentomaru.sdk.SentomaruClient
import okhttp3.Interceptor
import okhttp3.Response

/**
 * Network interceptor installed by [addSentomaru] (I1). It sees every hop that actually goes on the wire, including
 * follow-ups OkHttp generates itself if a consumer re-enabled redirects after [addSentomaru]. A hop that still
 * carries signature or Sentomaru headers is refused before sending unless it targets an allowlisted https host.
 */
internal class SentomaruRedirectGuard(private val client: SentomaruClient) : Interceptor {
    override fun intercept(chain: Interceptor.Chain): Response {
        val request = chain.request()
        val carriesProof = request.header(Profile.SIGNATURE) != null || request.header(Profile.SIGNATURE_INPUT) != null ||
            request.headers.names().any { it.startsWith("x-sentomaru-") }
        if (carriesProof && (request.url.scheme != "https" || request.url.host !in client.config.allowedHosts)) {
            throw SentomaruException(SentomaruError.HostNotAllowed())
        }
        return chain.proceed(request)
    }
}
