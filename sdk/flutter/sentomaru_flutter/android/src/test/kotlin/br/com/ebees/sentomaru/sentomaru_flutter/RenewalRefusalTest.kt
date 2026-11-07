package br.com.ebees.sentomaru.sentomaru_flutter

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** `renewSession` precheck: a backoff refusal has its own code, apart from "cannot renew" (PARAMS). */
class RenewalRefusalTest {
    @Test fun insideTheBackoffTheRefusalIsRenewalBackoff() {
        assertEquals("RenewalBackoff", SentomaruFlutterPlugin.renewalRefusal(backingOff = true, canRenewNow = false)!!.code)
    }

    @Test fun unableToRenewOutsideTheBackoffStaysParams() {
        assertEquals("InvalidRequest:PARAMS",
            SentomaruFlutterPlugin.renewalRefusal(backingOff = false, canRenewNow = false)!!.code)
    }

    // 0.9.2: a backoff refusal carries the code of the failure that started it, in the serverRejected string format.
    @Test fun aBackoffRefusalCarriesTheLastFailureInDetails() {
        val refusal = SentomaruFlutterPlugin.renewalRefusal(backingOff = true, canRenewNow = false)!!
        assertEquals("ServerRejected:SUSPENDED", SentomaruFlutterPlugin.refusalDetails(refusal, "ServerRejected:SUSPENDED"))
        assertEquals("NetworkUnavailable", SentomaruFlutterPlugin.refusalDetails(refusal, "NetworkUnavailable"))
        assertNull(SentomaruFlutterPlugin.refusalDetails(refusal, null))
    }

    @Test fun aParamsRefusalHasNoDetails() {
        val refusal = SentomaruFlutterPlugin.renewalRefusal(backingOff = false, canRenewNow = false)!!
        assertNull(SentomaruFlutterPlugin.refusalDetails(refusal, "ServerRejected:SUSPENDED"))
    }

    @Test fun allowedRenewalHasNoRefusal() {
        assertNull(SentomaruFlutterPlugin.renewalRefusal(backingOff = false, canRenewNow = true))
    }
}
