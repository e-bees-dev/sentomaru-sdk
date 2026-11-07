package br.com.ebees.sentomaru.rasplab

import br.com.ebees.sentomaru.rasplab.RaspLabCandidateSequence.Kind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class RaspLabCandidateSequenceTest {
    @Test
    fun `the option is a strict flag that defaults to off`() {
        assertEquals("candidateSequence", RaspLabCandidateSequence.ARGUMENT)
        assertEquals(false, RaspLabCandidateSequence.parse(null))
        assertEquals(false, RaspLabCandidateSequence.parse("false"))
        assertEquals(true, RaspLabCandidateSequence.parse("true"))
        for (bad in listOf("", "TRUE", "True", "1", "0", "yes", " true", "true ", "false\n", "on")) {
            assertNull("'$bad'", RaspLabCandidateSequence.parse(bad))
        }
    }

    @Test
    fun `without the option the run is the collected operations only, as before`() {
        for (n in listOf(1, 3, 20)) {
            assertEquals(List(n) { Kind.COLLECTED }, RaspLabCandidateSequence.plan(n, false))
        }
    }

    @Test
    fun `with the option an allow-shaped bare operation comes before and after the collected ones`() {
        assertEquals(listOf(Kind.BARE_BEFORE, Kind.COLLECTED, Kind.COLLECTED, Kind.COLLECTED, Kind.BARE_AFTER),
            RaspLabCandidateSequence.plan(3, true))
        val one = RaspLabCandidateSequence.plan(1, true)
        assertEquals(listOf(Kind.BARE_BEFORE, Kind.COLLECTED, Kind.BARE_AFTER), one)
        assertEquals(22, RaspLabCandidateSequence.plan(20, true).size)
    }

    @Test
    fun `a plan with no collected operation is refused`() {
        assertThrows(IllegalArgumentException::class.java) { RaspLabCandidateSequence.plan(0, true) }
        assertThrows(IllegalArgumentException::class.java) { RaspLabCandidateSequence.plan(0, false) }
    }

    @Test
    fun `case ids are distinct and in the token format of the report`() {
        val ids = Kind.values().map { RaspLabCandidateSequence.caseId(it) }
        assertEquals(3, ids.toSet().size)
        assertEquals("collected", RaspLabCandidateSequence.caseId(Kind.COLLECTED))
        assertTrue(ids.all { Regex("[a-zA-Z][a-zA-Z0-9_-]{0,47}").matches(it) })
        assertTrue("unsigned-snapshot" !in ids)
    }
}
