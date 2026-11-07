package br.com.ebees.sentomaru.rasplab

import br.com.ebees.sentomaru.rasplab.RaspLabReattestChallenge.Outcome
import br.com.ebees.sentomaru.rasplab.RaspLabReattestChallenge.Step
import org.junit.Assert.assertEquals
import org.junit.Test

class RaspLabReattestChallengeTest {
    @Test
    fun `only a challenge of kind reattest asks for a reattestation`() {
        assertEquals(Step.REATTEST, RaspLabReattestChallenge.afterAnswer("challenge", "reattest"))
        for ((action, kind) in listOf("challenge" to null, "challenge" to "fresh_signals", "challenge" to "step_up",
            "challenge" to "Reattest", "challenge" to "reattest ", "deny" to "reattest", "allow" to "reattest",
            null to "reattest", "allow" to null)) {
            assertEquals("$action/$kind", Step.FINAL, RaspLabReattestChallenge.afterAnswer(action, kind))
        }
    }

    @Test
    fun `a completed reattestation repeats once, a not-now or a refusal never repeats`() {
        assertEquals(Step.REPEAT_ONCE, RaspLabReattestChallenge.afterReattest(Outcome.COMPLETED))
        assertEquals(Step.TRY_LATER, RaspLabReattestChallenge.afterReattest(Outcome.NOT_NOW))
        assertEquals(Step.SHOW_REFUSAL, RaspLabReattestChallenge.afterReattest(Outcome.REFUSED))
    }
}
