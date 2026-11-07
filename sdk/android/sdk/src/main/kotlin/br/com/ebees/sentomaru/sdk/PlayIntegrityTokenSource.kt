package br.com.ebees.sentomaru.sdk

import android.content.Context
import com.google.android.gms.tasks.Tasks
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.StandardIntegrityException
import com.google.android.play.core.integrity.StandardIntegrityManager.PrepareIntegrityTokenRequest
import com.google.android.play.core.integrity.StandardIntegrityManager.StandardIntegrityTokenProvider
import com.google.android.play.core.integrity.StandardIntegrityManager.StandardIntegrityTokenRequest
import com.google.android.play.core.integrity.model.StandardIntegrityErrorCode
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit

/**
 * C-04b: Play Integrity STANDARD request (Google Play services). The token provider is prepared once per process with
 * the Google Cloud project number linked to the app (or to the Sentomaru SDK in the Play SDK Console) and reused; an
 * expired provider is prepared again once. Every failure, including no Play services, an emulator without Play or a
 * call on the main thread (Tasks.await refuses it), answers null within [timeoutMillis] per step. Interruption is
 * preserved. Caching and retry: [CachedIntegrityRequester].
 */
class PlayIntegrityTokenSource(context: Context, private val cloudProjectNumber: Long,
    private val timeoutMillis: Long = 4_000) : IntegrityTokenSource {
    private val context = context.applicationContext

    init {
        require(cloudProjectNumber > 0) { "Invalid cloud project number" }
        require(timeoutMillis in 500..10_000) { "Invalid timeout" }
    }

    private val requester = CachedIntegrityRequester<StandardIntegrityTokenProvider>(
        prepare = {
            Tasks.await(IntegrityManagerFactory.createStandard(context).prepareIntegrityToken(
                PrepareIntegrityTokenRequest.builder().setCloudProjectNumber(cloudProjectNumber).build()),
                timeoutMillis, TimeUnit.MILLISECONDS)
        },
        request = { provider, hash ->
            Tasks.await(provider.request(StandardIntegrityTokenRequest.builder().setRequestHash(hash).build()),
                timeoutMillis, TimeUnit.MILLISECONDS).token()
        },
        providerInvalid = { error ->
            ((error as? ExecutionException)?.cause as? StandardIntegrityException)?.errorCode ==
                StandardIntegrityErrorCode.INTEGRITY_TOKEN_PROVIDER_INVALID
        })

    override fun token(requestHash: String): String? = requester.token(requestHash)
}
