package br.com.ebees.sentomaru.sentomaru_flutter

import androidx.fragment.app.FragmentActivity
import br.com.ebees.sentomaru.core.SentomaruException
import br.com.ebees.sentomaru.sdk.TransactionKeyChallenge
import br.com.ebees.sentomaru.sdk.SentomaruClient
import br.com.ebees.sentomaru.sdk.SentomaruTransactionSigner
import br.com.ebees.sentomaru.sdk.TransactionError
import java.time.Instant
import java.time.OffsetDateTime
import java.time.format.DateTimeParseException

/** The real [SentomaruFlutterTransaction.Port]: the SDK signer plus the system prompt on the foreground activity. */
internal class AndroidTransactionPort(
    private val client: SentomaruClient,
    private val activity: () -> FragmentActivity?,
    private val signer: SentomaruTransactionSigner = SentomaruTransactionSigner(client),
) : SentomaruFlutterTransaction.Port {
    override fun isEnrolled(): Boolean = signer.isEnrolled()

    override fun discard() = signer.discard()

    override fun commitKey() = signer.commitEnrollment()

    override fun abortKey() = signer.abortEnrollment()

    override fun createKey(challenge: SentomaruFlutterTransaction.Challenge, biometricOnly: Boolean, strongBox: Boolean): ByteArray {
        val expires: Instant = try { OffsetDateTime.parse(challenge.expiresAt).toInstant() }
        catch (_: DateTimeParseException) { throw IllegalArgumentException("expiresAt") }
        val sdkChallenge = TransactionKeyChallenge(challenge.id, challenge.token, challenge.attestationChallenge, expires)
        return signer.prepareEnrollment(sdkChallenge, strongBox, biometricOnly)
    }

    override fun sign(operationId: String, body: ByteArray, reason: String, cancelLabel: String, biometricOnly: Boolean,
                      onSigned: (String) -> Unit, onError: (String) -> Unit) {
        val authenticator = BiometricPromptAuthenticator(activity, reason, cancelLabel, biometricOnly)
        try {
            signer.sign(operationId, body, authenticator, onSigned) { onError(SentomaruFlutterTransaction.transactionCode(it.code)) }
        } catch (e: IllegalArgumentException) {
            onError(SentomaruFlutterTransaction.INVALID_PARAMS)
        }
    }
}
