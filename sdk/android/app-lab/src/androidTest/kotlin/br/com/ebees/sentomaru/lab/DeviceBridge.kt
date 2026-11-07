package br.com.ebees.sentomaru.lab

import android.os.Build
import android.os.Bundle
import android.security.keystore.KeyInfo
import android.util.Base64
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import br.com.ebees.sentomaru.signer.KeystoreSigner
import java.security.KeyFactory
import java.security.KeyStore
import java.security.PrivateKey
import org.junit.Test
import org.junit.runner.RunWith

/**
 * LAB ONLY. Step-wise bridge for the real-device interop run (`the vendor's run p0 check --device`).
 * Driven by `am instrument -w -r -e class br.com.ebees.sentomaru.lab.DeviceBridge -e sentomaruOp <op> ...`:
 *
 * - `generate` (`sentomaruAlias`, `sentomaruChallenge` = 32 bytes base64url): generates the key with
 *   [KeystoreSigner.generate]; reports `sentomaru.chainCount`, `sentomaru.chain.<i>` (DER, base64, leaf
 *   first), `sentomaru.spki` (leaf SPKI DER, base64) and `sentomaru.securityLevel` (KeyInfo).
 * - `sign` (`sentomaruAlias`, `sentomaruBase` = signature-base bytes base64url): [KeystoreSigner.useExisting]
 *   + [KeystoreSigner.sign]; reports `sentomaru.signature` (64-byte P1363, base64).
 * - `delete` (`sentomaruAlias`): deletes the alias; reports `sentomaru.present=false`.
 *
 * Results go through `Instrumentation.sendStatus(STATUS_CODE, bundle)`. Only aliases with the lab
 * prefix are accepted. Without `sentomaruOp` (normal `connectedDebugAndroidTest`) the test returns
 * immediately (guard clause, no Assume) and reports as passed. Never reports device identifiers.
 */
@RunWith(AndroidJUnit4::class)
class DeviceBridge {

    @Test
    fun bridge() {
        val args = InstrumentationRegistry.getArguments()
        val op = args.getString("sentomaruOp") ?: return // not a bridge invocation
        val alias = args.getString("sentomaruAlias").orEmpty()
        require(ALIAS.matches(alias)) { "alias must match ${ALIAS.pattern}" }
        val out = Bundle()
        when (op) {
            "generate" -> {
                val challenge = decode(args.getString("sentomaruChallenge"))
                val chain = KeystoreSigner().generate(alias, challenge, strongBox = false)
                out.putString("sentomaru.chainCount", chain.size.toString())
                chain.forEachIndexed { i, der -> out.putString("sentomaru.chain.$i", encode(der)) }
                val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
                out.putString("sentomaru.spki", encode(keyStore.getCertificate(alias).publicKey.encoded))
                out.putString("sentomaru.securityLevel", securityLevel(keyStore.getKey(alias, null) as PrivateKey))
            }
            "sign" -> {
                val signer = KeystoreSigner()
                signer.useExisting(alias)
                out.putString("sentomaru.signature", encode(signer.sign(decode(args.getString("sentomaruBase")))))
            }
            "delete" -> {
                KeystoreSigner.deleteKey(alias)
                out.putString("sentomaru.present", KeystoreSigner.containsAlias(alias).toString())
            }
            else -> throw IllegalArgumentException("unknown sentomaruOp")
        }
        InstrumentationRegistry.getInstrumentation().sendStatus(STATUS_CODE, out)
    }

    private fun securityLevel(key: PrivateKey): String {
        val info = KeyFactory.getInstance(key.algorithm, "AndroidKeyStore").getKeySpec(key, KeyInfo::class.java)
        if (Build.VERSION.SDK_INT < 31) return if (@Suppress("DEPRECATION") info.isInsideSecureHardware) "secureHardware" else "software"
        return when (info.securityLevel) {
            android.security.keystore.KeyProperties.SECURITY_LEVEL_SOFTWARE -> "software"
            android.security.keystore.KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "trustedEnvironment"
            android.security.keystore.KeyProperties.SECURITY_LEVEL_STRONGBOX -> "strongBox"
            android.security.keystore.KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE -> "unknownSecure"
            else -> "unknown"
        }
    }

    private fun decode(value: String?): ByteArray =
        Base64.decode(requireNotNull(value) { "missing argument" }, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)

    private fun encode(bytes: ByteArray): String = Base64.encodeToString(bytes, Base64.NO_WRAP)

    private companion object {
        const val STATUS_CODE = 7 // must match BRIDGE_STATUS_CODE in verification/android/run_device.py
        val ALIAS = Regex("sentomaru-lab-device-[a-z]")
    }
}
