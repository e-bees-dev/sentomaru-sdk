package br.com.ebees.sentomaru.protect

import com.google.gson.JsonParser
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * `sentomaru policy study` (Fase D, ativação de módulos em cliente novo). The substitution itself is proved against
 * the published ExampleApp file by the C# test (Integrity.Tests.Policy.StudyPolicyTemplateTests, same model file);
 * these tests cover the CLI's own surface: argument parsing, usage errors, output shape and the exit codes.
 */
class PolicyTest {
    private fun run(vararg args: String): Triple<Int, String, String> {
        val out = StringBuilder(); val err = StringBuilder()
        val code = Policy.run(args.toList(), { out.append(it).append('\n') }, { err.append(it).append('\n') })
        return Triple(code, out.toString(), err.toString())
    }

    @Test fun unknownSubcommandIsUsage() {
        val (code, _, err) = run("promote")
        assertEquals(2, code)
        assertTrue(err, err.contains("usage: sentomaru policy study"))
    }

    @Test fun missingRequiredFlagsIsUsage() {
        assertEquals(2, run("study").first)
        assertEquals(2, run("study", "--scope", "org/app/env").first)
        assertEquals(2, run("study", "--scope", "org/app/env", "--operations", "op1").first)
    }

    @Test fun malformedScopeIsUsage() {
        val (code, _, err) = run("study", "--scope", "org/app", "--operations", "op1", "--sensitive-operations", "op1")
        assertEquals(2, code)
        assertTrue(err, err.contains("<org>/<app>/<env>"))
    }

    @Test fun aSensitiveOperationNotInOperationsIsUsage() {
        val (code, _, err) = run("study", "--scope", "org/app/env", "--operations", "op1,op2",
            "--sensitive-operations", "op1,op3")
        assertEquals(2, code)
        assertTrue(err, err.contains("op3"))
    }

    @Test fun generatesAValidShadowPolicyCoveringTheDeclaredOperations() {
        val (code, out, err) = run("study", "--scope", "acme/fieldapp/hml", "--operations", "start_job,finish_job,upload_photo",
            "--sensitive-operations", "finish_job")
        assertEquals(err, 0, code)
        val policy = JsonParser.parseString(out).asJsonObject
        assertEquals("acme", policy["organization"].asString)
        assertEquals("fieldapp", policy["app"].asString)
        assertEquals("hml", policy["environment"].asString)
        assertEquals("pol_acme_fieldapp_hml_estudo", policy["policyId"].asString)
        assertEquals("shadow", policy["enforcementMode"].asString)
        assertEquals(listOf("finish_job"), policy["sensitiveOperations"].asJsonArray.map { it.asString })
        assertTrue(policy["rules"].asJsonArray.all { it.asJsonObject["stage"].asString == "observe" })
        assertTrue(policy["responseRules"].asJsonArray.all { it.asJsonObject["mode"].asString == "alert" })
        // hw_sensitive takes the sensitive operations (finish_job); user_presence defaults to the same, since no
        // --presence-operations was given.
        val byId = policy["rules"].asJsonArray.associateBy { it.asJsonObject["ruleId"].asString }
        assertEquals(listOf("finish_job"), byId.getValue("hw_sensitive").asJsonObject["conditions"].asJsonObject["operations"].asJsonArray.map { it.asString })
        assertEquals(listOf("finish_job"), byId.getValue("user_presence").asJsonObject["conditions"].asJsonObject["operations"].asJsonArray.map { it.asString })
    }

    @Test fun presenceAndLocationGroupsOverrideTheSensitiveDefault() {
        val (code, out, err) = run("study", "--scope", "ebees/exampleapp/prod",
            "--operations", "criar_demanda,concluir_demanda,aceitar_demanda,enviar_proposta,atualizar_perfil,trocar_tenant,exampleapp_api,bind_session",
            "--sensitive-operations", "criar_demanda,concluir_demanda,aceitar_demanda,enviar_proposta",
            "--presence-operations", "concluir_demanda,enviar_proposta",
            "--location-sensitive-operations", "aceitar_demanda,concluir_demanda,enviar_proposta")
        assertEquals(err, 0, code)
        val byId = JsonParser.parseString(out).asJsonObject["rules"].asJsonArray.associateBy { it.asJsonObject["ruleId"].asString }
        assertEquals(setOf("concluir_demanda", "enviar_proposta"),
            byId.getValue("user_presence").asJsonObject["conditions"].asJsonObject["operations"].asJsonArray.map { it.asString }.toSet())
        assertEquals(setOf("aceitar_demanda", "concluir_demanda", "enviar_proposta"),
            byId.getValue("fraud_location_mock").asJsonObject["conditions"].asJsonObject["operations"].asJsonArray.map { it.asString }.toSet())
    }

    @Test fun regeneratingWithExampleAppsOwnListsMatchesThePublishedFile() {
        val (code, out, err) = run("study", "--scope", "ebees/exampleapp/prod",
            "--operations", "criar_demanda,concluir_demanda,aceitar_demanda,enviar_proposta,atualizar_perfil,trocar_tenant,exampleapp_api,bind_session",
            "--sensitive-operations", "criar_demanda,concluir_demanda,aceitar_demanda,enviar_proposta",
            "--presence-operations", "concluir_demanda,enviar_proposta",
            "--location-sensitive-operations", "aceitar_demanda,concluir_demanda,enviar_proposta",
            "--description", "Estudo do ExampleApp prod: shadow, toda regra em observe; mede o que cada sinal e cada " +
                "combinação recomendaria nas operações do ExampleBackend, sem efeito no app.")
        assertEquals(err, 0, code)
        val generated = JsonParser.parseString(out).asJsonObject
        val publishedFile = java.io.File("../../../docs/api/examples/policy-exampleapp-prod-estudo-1.0.0.json")
        assertTrue("published example not found at ${publishedFile.canonicalPath}", publishedFile.isFile)
        val published = JsonParser.parseString(publishedFile.readText()).asJsonObject
        assertEquals(published, generated)
    }

    @Test fun outWritesToAFileInsteadOfStdout() {
        val dir = kotlin.io.path.createTempDirectory("sentomaru-policy-study-").toFile()
        try {
            val target = dir.resolve("policy.json")
            val (code, out, err) = run("study", "--scope", "org/app/env", "--operations", "op1",
                "--sensitive-operations", "op1", "--out", target.path)
            assertEquals(err, 0, code)
            assertEquals("", out)
            assertNotNull(JsonParser.parseString(target.readText()))
        } finally {
            dir.deleteRecursively()
        }
    }

    // ---- --manifest (sentomaru-scope.yaml, Fase C) --------------------------------------------------------------

    private fun manifestFile(dir: java.io.File, policy: String = "policy:\n  template: study\n  sensitiveOperations: [finish_job]\n" +
        "  operations: [start_job, finish_job, upload_photo]\n", scope: String = "acme/fieldapp/hml"): java.io.File =
        dir.resolve("sentomaru-scope.yaml").apply { writeText("version: 1\nscope: $scope\n$policy") }

    @Test fun scopeAndManifestTogetherIsUsage() {
        val dir = kotlin.io.path.createTempDirectory("sentomaru-policy-study-").toFile()
        try {
            val manifest = manifestFile(dir)
            val (code, _, err) = run("study", "--scope", "acme/fieldapp/hml", "--manifest", manifest.path)
            assertEquals(2, code)
            assertTrue(err, err.contains("mutually exclusive"))
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test fun aManifestWithoutAPolicySectionIsUsage() {
        val dir = kotlin.io.path.createTempDirectory("sentomaru-policy-study-").toFile()
        try {
            val manifest = dir.resolve("sentomaru-scope.yaml").apply { writeText("version: 1\nscope: acme/fieldapp/hml\n") }
            val (code, _, err) = run("study", "--manifest", manifest.path)
            assertEquals(2, code)
            assertTrue(err, err.contains("declares no policy"))
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test fun aManifestWithPolicyTemplateFileIsUsage() {
        val dir = kotlin.io.path.createTempDirectory("sentomaru-policy-study-").toFile()
        try {
            val manifest = manifestFile(dir, policy = "policy:\n  template: file\n  file: policy.json\n  sensitiveOperations: [finish_job]\n")
            val (code, _, err) = run("study", "--manifest", manifest.path)
            assertEquals(2, code)
            assertTrue(err, err.contains("'file', not 'study'"))
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test fun aMalformedManifestIsManifestFormatExit4() {
        val dir = kotlin.io.path.createTempDirectory("sentomaru-policy-study-").toFile()
        try {
            val manifest = dir.resolve("sentomaru-scope.yaml").apply { writeText("version: 2\n") }
            val (code, _, err) = run("study", "--manifest", manifest.path)
            assertEquals(4, code)
            assertTrue(err, err.contains("manifest-format"))
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test fun generatesFromAManifestWithoutAnExplicitOperationsList() {
        val dir = kotlin.io.path.createTempDirectory("sentomaru-policy-study-").toFile()
        try {
            val manifest = manifestFile(dir, policy = "policy:\n  template: study\n  sensitiveOperations: [finish_job]\n")
            val (code, out, err) = run("study", "--manifest", manifest.path)
            assertEquals(err, 0, code)
            val policy = JsonParser.parseString(out).asJsonObject
            // policy.operations absent in the manifest: defaults to the sensitive operations alone.
            assertEquals(listOf("finish_job"), policy["sensitiveOperations"].asJsonArray.map { it.asString })
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test fun generatesFromAManifestAndStillAcceptsPresenceAndLocationFlags() {
        val dir = kotlin.io.path.createTempDirectory("sentomaru-policy-study-").toFile()
        try {
            val manifest = manifestFile(dir)
            val (code, out, err) = run("study", "--manifest", manifest.path, "--presence-operations", "finish_job")
            assertEquals(err, 0, code)
            val policy = JsonParser.parseString(out).asJsonObject
            assertEquals("acme", policy["organization"].asString)
            assertEquals("fieldapp", policy["app"].asString)
            assertEquals("hml", policy["environment"].asString)
            assertEquals(listOf("finish_job"), policy["sensitiveOperations"].asJsonArray.map { it.asString })
            val byId = policy["rules"].asJsonArray.associateBy { it.asJsonObject["ruleId"].asString }
            assertEquals(listOf("finish_job"),
                byId.getValue("user_presence").asJsonObject["conditions"].asJsonObject["operations"].asJsonArray.map { it.asString })
        } finally {
            dir.deleteRecursively()
        }
    }

    /** The exact contract ScopeCli's `scope apply --policy` checks on a study policy file (ScopeCli.policy()). */
    @Test fun theGeneratedPolicySatisfiesScopeApplysStudyContract() {
        val dir = kotlin.io.path.createTempDirectory("sentomaru-policy-study-").toFile()
        try {
            val manifest = manifestFile(dir)
            val (code, out, err) = run("study", "--manifest", manifest.path)
            assertEquals(err, 0, code)
            val policy = JsonParser.parseString(out).asJsonObject
            assertEquals("acme", policy["organization"].asString)
            assertEquals("fieldapp", policy["app"].asString)
            assertEquals("hml", policy["environment"].asString)
            assertNotNull(policy["policyId"])
            assertNotNull(policy["version"])
            assertEquals("shadow", policy["enforcementMode"].asString)
            assertEquals(setOf("finish_job"), policy["sensitiveOperations"].asJsonArray.map { it.asString }.toSet())
        } finally {
            dir.deleteRecursively()
        }
    }
}
