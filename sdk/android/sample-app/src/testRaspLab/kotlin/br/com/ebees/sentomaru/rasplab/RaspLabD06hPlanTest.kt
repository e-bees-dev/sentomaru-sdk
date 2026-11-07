package br.com.ebees.sentomaru.rasplab

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class RaspLabD06hPlanTest {
    @Test
    fun `the operations are distinct, in the policy operation format, and the plan uses only them`() {
        val ops = listOf(RaspLabD06hPlan.ENFORCE, RaspLabD06hPlan.OBSERVE, RaspLabD06hPlan.PLAIN)
        assertEquals(3, ops.toSet().size)
        // PolicyValidator.OperationList: 1..64 characters, no control character; the lab keeps them to [a-z0-9_].
        assertTrue(ops.all { Regex("[a-z0-9_]{1,64}").matches(it) })
        val plan = RaspLabD06hPlan.BEFORE + RaspLabD06hPlan.ENFORCED + RaspLabD06hPlan.RETRY + RaspLabD06hPlan.AFTER +
            RaspLabD06hPlan.measurement(RaspLabD06hPlan.MAX_MEASURE)
        assertTrue(plan.all { it.operation in ops })
        assertEquals(listOf("plain", "observe"), RaspLabD06hPlan.BEFORE.map { it.id })
        assertEquals(RaspLabD06hPlan.ENFORCE, RaspLabD06hPlan.ENFORCED.operation)
        assertEquals(RaspLabD06hPlan.ENFORCE, RaspLabD06hPlan.RETRY.operation)
        assertEquals(RaspLabD06hPlan.OBSERVE, RaspLabD06hPlan.AFTER.operation)
    }

    @Test
    fun `measure is bounded, defaults to 10 and alternates plain and enforced`() {
        assertEquals(10, RaspLabD06hPlan.measure(null))
        assertEquals(0, RaspLabD06hPlan.measure("0"))
        assertEquals(30, RaspLabD06hPlan.measure("30"))
        for (bad in listOf("31", "-1", "", "ten", "1.5", " 3")) assertNull(bad, RaspLabD06hPlan.measure(bad))
        val pairs = RaspLabD06hPlan.measurement(3)
        assertEquals(6, pairs.size)
        assertEquals(List(3) { listOf("measure-plain", "measure-enforce") }.flatten(), pairs.map { it.id })
        assertEquals(List(3) { listOf(RaspLabD06hPlan.PLAIN, RaspLabD06hPlan.ENFORCE) }.flatten(), pairs.map { it.operation })
        assertTrue(RaspLabD06hPlan.measurement(0).isEmpty())
        // Review R M-3: 5 + 2M evaluations per run (the roteiro's 45 with M = 20): before, enforce, retry, after, pairs.
        val evaluations = RaspLabD06hPlan.BEFORE.size + 3 + RaspLabD06hPlan.measurement(20).size
        assertEquals(45, evaluations)
    }
}
