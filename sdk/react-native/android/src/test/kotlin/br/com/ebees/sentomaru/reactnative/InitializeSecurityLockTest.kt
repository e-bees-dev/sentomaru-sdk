package br.com.ebees.sentomaru.reactnative

import br.com.ebees.sentomaru.hybrid.InitializeSecurityLock
import br.com.ebees.sentomaru.sdk.SentomaruConfig
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Revisor A, rodada 2 (médio A): the pure decision [InitializeSecurityLock] takes before `SentomaruBridge` ever
 * builds a client for a second `initialize`. Not `SentomaruBridge.onMethodCall` itself: that posts its reply
 * through a real `android.os.Handler(Looper.getMainLooper())`, which the Android unit-test stub jar no-ops, same
 * limitation `SealedReaderTest` already works around the same way for this package's other pure logic.
 */
class InitializeSecurityLockTest {
    private fun config(hosts: Set<String> = setOf("api.example.test"), enrollmentUrl: String = "https://api.example.test/v1/acme/shop/hml/installations",
                        renewalUrl: String? = "https://api.example.test/v1/acme/shop/hml/sessions") =
        SentomaruConfig("acme", "shop", "hml", hosts, enrollmentUrl, renewalUrl = renewalUrl)

    @Test fun aSecondInitializeIdenticalToTheFirstIsAllowed() {
        val lock = InitializeSecurityLock(config())
        assertTrue(lock.allows(config()))
    }

    @Test fun aSecondInitializeThatShrinksTheAllowlistIsAllowed() {
        val lock = InitializeSecurityLock(config(hosts = setOf("api.example.test", "other.example.test")))
        assertTrue(lock.allows(config(hosts = setOf("api.example.test"))))
    }

    @Test fun aSecondInitializeThatAddsAHostIsRefused() {
        // the attack this closes: a WebView page calling `initialize` again to widen the allowlist to a host it controls.
        val lock = InitializeSecurityLock(config(hosts = setOf("api.example.test")))
        assertFalse(lock.allows(config(hosts = setOf("api.example.test", "attacker.evil.test"))))
    }

    @Test fun aSecondInitializeWithADifferentEnrollmentUrlIsRefused() {
        val lock = InitializeSecurityLock(config())
        assertFalse(lock.allows(config(hosts = setOf("api.example.test", "attacker.evil.test"),
            enrollmentUrl = "https://attacker.evil.test/v1/acme/shop/hml/installations")))
    }

    @Test fun aSecondInitializeWithADifferentRenewalUrlIsRefused() {
        val lock = InitializeSecurityLock(config())
        assertFalse(lock.allows(config(renewalUrl = "https://api.example.test/v1/acme/shop/hml/sessions-2")))
    }

    @Test fun droppingAPreviouslySetRenewalUrlIsRefused() {
        // null is still a change from the locked value, not "no opinion": a page cannot disarm renewal either.
        val lock = InitializeSecurityLock(config())
        assertFalse(lock.allows(config(renewalUrl = null)))
    }
}
