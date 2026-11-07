package br.com.ebees.sentomaru.rasplab

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class RaspLabPolicyFieldsTest {
    @Test
    fun `rule ids in the 0054 format pass in order without repeats`() {
        assertEquals(listOf("rule_emulator_observe", "rule_root_ladder"),
            RaspLabPolicyFields.observedRules(listOf("rule_emulator_observe", "rule_root_ladder", "rule_emulator_observe")))
        assertEquals(emptyList<String>(), RaspLabPolicyFields.observedRules(emptyList()))
    }

    @Test
    fun `a rule id outside the format is dropped and never echoed`() {
        val kept = RaspLabPolicyFields.observedRules(listOf("ok_rule", "Rule_Upper", "ab", "a".repeat(33), "rule-dash",
            "/data/local/tmp/frida", "someone@example.invalid", "rule id", null, 7, "ok_rule2"))
        assertEquals(listOf("ok_rule", "ok_rule2"), kept)
    }

    @Test
    fun `at most the validator limit of rules is reported`() {
        val many = (0 until 200).map { "rule_%03d".format(it) }
        assertEquals(RaspLabPolicyFields.MAX_RULES, RaspLabPolicyFields.observedRules(many).size)
    }

    @Test
    fun `policy version only in the semver format`() {
        assertEquals("1.1.0", RaspLabPolicyFields.policyVersion("1.1.0"))
        assertEquals("10.20.300", RaspLabPolicyFields.policyVersion("10.20.300"))
        for (bad in listOf("1.0", "v1.0.0", "1.0.0-rc1", "1.0.0 ", "", "1".repeat(10) + ".0.0", null, 1)) {
            assertNull("$bad", RaspLabPolicyFields.policyVersion(bad))
        }
    }
}
