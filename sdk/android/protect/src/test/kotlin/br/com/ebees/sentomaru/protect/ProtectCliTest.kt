package br.com.ebees.sentomaru.protect

import com.android.apksig.ApkSigner
import com.android.apksig.KeyConfig
import com.google.gson.JsonParser
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.BeforeClass
import org.junit.Test
import java.io.File
import java.nio.file.Files
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.util.Random
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

/**
 * G-03b1: the CLI skeleton against real artifacts built at test time by the SDK's aapt2 (a binary-manifest APK and a
 * protobuf-manifest AAB), signed with a key generated for the run (apksig for the APK, the JDK's jarsigner for the
 * AAB), so the readers are checked against the formats Android actually produces.
 */
class ProtectCliTest {
    companion object {
        private lateinit var work: File
        private lateinit var apk: File
        private lateinit var aab: File
        private lateinit var signedAab: File
        private lateinit var noInternetApk: File
        private lateinit var oldApk: File
        private lateinit var unsignedApk: File
        private lateinit var apkManifest: ByteArray
        private lateinit var keystore: File
        private const val STORE_PASS = "fixture-only" // a key generated for this run and deleted with it

        internal fun sdkToolPublic() = sdkTool()

        private fun sdkTool(): Pair<File, File> {
            val home = File(System.getProperty("android.home").ifEmpty { System.getenv("ANDROID_HOME") ?: "" })
            val aapt2 = home.resolve("build-tools").listFiles()!!.filter { it.resolve("aapt2").isFile }
                .maxByOrNull { it.name }!!.resolve("aapt2")
            val platform = home.resolve("platforms").listFiles()!!.filter { it.resolve("android.jar").isFile }
                .maxByOrNull { it.name.removePrefix("android-").toIntOrNull() ?: 0 }!!.resolve("android.jar")
            return aapt2 to platform
        }

        private fun exec(vararg cmd: String) {
            val p = ProcessBuilder(*cmd).redirectErrorStream(true).start()
            val log = p.inputStream.bufferedReader().readText()
            check(p.waitFor() == 0) { "${cmd[0]} failed: $log" }
        }

        private fun jdkTool(name: String) = File(System.getProperty("java.home"), "bin/$name").path

        private fun manifest(minSdk: Int, internet: Boolean, application: String = "", queries: String = "") = """
            <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="br.com.example.fixture"
                android:versionCode="42" android:versionName="1.2">
              <uses-sdk android:minSdkVersion="$minSdk" android:targetSdkVersion="35"/>
              ${if (internet) """<uses-permission android:name="android.permission.INTERNET"/>""" else ""}
              <uses-permission android:name="android.permission.CAMERA"/>
              ${if (queries.isEmpty()) "" else "<queries>$queries</queries>"}
              <application android:label="fixture">$application</application>
            </manifest>
        """.trimIndent()

        private fun link(name: String, minSdk: Int, internet: Boolean, proto: Boolean, application: String = "",
            queries: String = ""): File {
            val (aapt2, platform) = sdkTool()
            val dir = work.resolve(name).apply { mkdirs() }
            val m = dir.resolve("AndroidManifest.xml").apply { writeText(manifest(minSdk, internet, application, queries)) }
            val out = dir.resolve("linked.zip")
            val cmd = mutableListOf(aapt2.path, "link", "-o", out.path, "-I", platform.path, "--manifest", m.path)
            if (proto) cmd += "--proto-format"
            exec(*cmd.toTypedArray())
            return out
        }

        internal fun zip(target: File, entries: List<Pair<String, ByteArray>>) {
            ZipOutputStream(target.outputStream()).use { z ->
                for ((n, bytes) in entries) { z.putNextEntry(ZipEntry(n)); z.write(bytes); z.closeEntry() }
            }
        }

        private fun entries(file: File) = ZipFile(file).use { z -> z.entries().toList().map { it.name to z.getInputStream(it).readBytes() } }

        private fun sign(unsigned: File, target: File): File {
            val ks = KeyStore.getInstance("PKCS12").apply { keystore.inputStream().use { load(it, STORE_PASS.toCharArray()) } }
            val key = ks.getKey("fixture", STORE_PASS.toCharArray()) as PrivateKey
            val cert = ks.getCertificate("fixture") as X509Certificate
            ApkSigner.Builder(listOf(ApkSigner.SignerConfig.Builder("fixture", KeyConfig.Jca(key), listOf(cert)).build()))
                .setInputApk(unsigned).setOutputApk(target).build().sign()
            return target
        }

        /**
         * A minimal DEX for the read-only G-03c check: header, string table, one type per string and a `class_def_item`
         * for each of [classes] (the other [strings] are only strings). Nothing else of a DEX is needed by DexScan.
         */
        internal fun dexWith(classes: List<String>, strings: List<String> = emptyList()): ByteArray {
            val all = classes + strings
            val data = all.map { byteArrayOf(it.length.toByte()) + it.toByteArray(Charsets.US_ASCII) + 0 }
            val stringIds = 0x70
            val typeIds = stringIds + 4 * all.size
            val classDefs = typeIds + 4 * all.size
            val stringData = classDefs + 32 * classes.size
            val b = java.nio.ByteBuffer.allocate(stringData + data.sumOf { it.size }).order(java.nio.ByteOrder.LITTLE_ENDIAN)
            b.put("dex\n035\u0000".toByteArray(Charsets.US_ASCII))
            b.putInt(0x20, b.capacity()).putInt(0x24, 0x70).putInt(0x28, 0x12345678)
            b.putInt(0x38, all.size).putInt(0x3C, stringIds).putInt(0x40, all.size).putInt(0x44, typeIds)
            b.putInt(0x60, classes.size).putInt(0x64, classDefs)
            var at = stringData
            all.forEachIndexed { i, _ -> b.putInt(stringIds + 4 * i, at); b.putInt(typeIds + 4 * i, i); at += data[i].size }
            classes.indices.forEach { i -> b.putInt(classDefs + 32 * i, i) }
            b.position(stringData); data.forEach { b.put(it) }
            return b.array()
        }

        /** The fixtures' app code: it embeds the SDK signing transport, so a profile with network-signing passes. */
        internal val appDex: ByteArray get() = dexWith(listOf("Lbr/com/example/fixture/App;", NetworkSigning.ANDROID_TRANSPORT))

        private fun apkWithDex(name: String, minSdk: Int, internet: Boolean, signed: Boolean = true, application: String = "",
            queries: String = ""): File {
            val linked = link(name, minSdk, internet, proto = false, application = application, queries = queries)
            val manifestBytes = ZipFile(linked).use { it.getInputStream(it.getEntry("AndroidManifest.xml")).readBytes() }
            val unsigned = work.resolve("$name-unsigned.apk").also {
                zip(it, listOf("AndroidManifest.xml" to manifestBytes, "classes.dex" to appDex))
            }
            return if (signed) sign(unsigned, work.resolve("$name.apk")) else unsigned
        }

        @BeforeClass @JvmStatic fun fixtures() {
            work = Files.createTempDirectory("protect-test").toFile()
            keystore = work.resolve("fixture.p12")
            exec(jdkTool("keytool"), "-genkeypair", "-keystore", keystore.path, "-storetype", "PKCS12", "-storepass", STORE_PASS,
                "-alias", "fixture", "-keyalg", "EC", "-groupname", "secp256r1", "-validity", "2", "-dname", "CN=fixture")
            apk = apkWithDex("app", 28, internet = true)
            apkManifest = ZipFile(apk).use { it.getInputStream(it.getEntry("AndroidManifest.xml")).readBytes() }
            noInternetApk = apkWithDex("nointernet", 28, internet = false)
            oldApk = apkWithDex("old", 21, internet = true)
            unsignedApk = apkWithDex("unsigned", 28, internet = true, signed = false)
            val proto = link("bundle", 29, internet = true, proto = true)
            val protoManifest = ZipFile(proto).use { it.getInputStream(it.getEntry("AndroidManifest.xml")).readBytes() }
            val bundle = listOf("BundleConfig.pb" to ByteArray(0), "base/manifest/AndroidManifest.xml" to protoManifest,
                "base/dex/classes.dex" to appDex)
            aab = work.resolve("app.aab").also { zip(it, bundle) }
            signedAab = work.resolve("signed.aab").also { zip(it, bundle) }
            exec(jdkTool("jarsigner"), "-keystore", keystore.path, "-storetype", "PKCS12", "-storepass", STORE_PASS, signedAab.path, "fixture")
        }
    }

    private fun profile(controls: String) = work.resolve("profile-${controls.hashCode()}.json").apply {
        writeText("""{"schemaVersion":"1","kind":"protect","profileId":"fixture-protect",
            "scope":{"organization":"ebees","app":"exampleapp","environment":"hml"},"controls":{$controls}}""")
    }

    private fun rawProfile(text: String) = work.resolve("raw-${text.hashCode()}.json").apply { writeText(text) }

    private val both = """"runtime-injection":{"version":"1","enrollmentUrl":"https://api.example/enroll"},
        "network-signing":{"version":"1","hosts":["api.example"],"routes":[{"path":"/v1/x","operation":"concluir_demanda"}]}"""

    private fun run(vararg args: String, env: Map<String, String> = emptyMap()): Triple<Int, String, String> {
        val out = StringBuilder(); val err = StringBuilder()
        val code = Cli.run(args.toList(), env, { out.append(it) }, { err.append(it) })
        return Triple(code, out.toString(), err.toString())
    }

    private fun refused(expectedExit: Int, expectedCode: String, vararg args: String, env: Map<String, String> = emptyMap()) {
        val (code, _, err) = run(*args, env = env)
        assertEquals(err, expectedExit, code)
        assertEquals(err, expectedCode, JsonParser.parseString(err).asJsonObject.get("code").asString)
    }

    private fun dry(input: File, p: File, out: String = work.resolve("out-dry").path) =
        arrayOf("--input", input.path, "--profile", p.path, "--out", out, "--dry-run", "--sign", "none")

    private fun inputFormat(bytes: ByteArray) {
        try {
            ArtifactReader.binaryManifest(bytes)
        } catch (e: ProtectException) {
            assertEquals(e.detail, ErrorCode.INPUT_FORMAT, e.error)
        }
    }

    private fun patched(bytes: ByteArray, at: Int, value: Int) = bytes.copyOf().also {
        java.nio.ByteBuffer.wrap(it).order(java.nio.ByteOrder.LITTLE_ENDIAN).putInt(at, value)
    }

    @Test fun dryRunRefusesAnApkThatAlreadyDeclaresTheProvider() {
        // G-06: the binary-manifest reader sees the provider only as a child of <application>, like the AAB reader.
        val provider = """<provider android:name="${RuntimeInjection.PROVIDER}" android:authorities="br.com.example.fixture.sentomaru-init"/>"""
        val protectedApk = apkWithDex("protected", 28, internet = true, application = provider)
        val (code, _, err) = run(*dry(protectedApk, profile(both)))
        assertEquals(err, 5, code)
        assertEquals("app-incompatible", JsonParser.parseString(err).asJsonObject.get("code").asString)
        assertTrue(err, err.contains("already declares the Sentomaru provider"))
        // The same name under <queries> is not a declaration: the dry run still plans.
        val queried = apkWithDex("queried", 28, internet = true, queries = provider)
        assertTrue(!ArtifactReader.read(queried).manifest.declaresSentomaruProvider)
        val planned = run(*dry(queried, profile(both)))
        assertEquals(planned.third, 0, planned.first)
        assertTrue(!ArtifactReader.read(apk).manifest.declaresSentomaruProvider)
        assertTrue(ArtifactReader.read(protectedApk).manifest.declaresSentomaruProvider)
    }

    /**
     * The contract order compatibility → controls in a real run: an APK the control cannot take (the provider is
     * already declared) answers 5 (app-incompatible), not 6 (control-failed, the APK rule until G-03b3). D-16-lab-gate
     * keeps this order covered for the released controls; for asset-encryption (released in D-14e) it is
     * AssetEncryptionTest.aRegisteredRunAppliesItWithoutTheGateAndTheLabRunAppliesItAsTheDryRunPlans.
     */
    @Test fun aRealRunRefusesAnIncompatibleApkBeforeTheApkRule() {
        val provider = """<provider android:name="${RuntimeInjection.PROVIDER}" android:authorities="br.com.example.fixture.sentomaru-init"/>"""
        val protectedApk = apkWithDex("protected-real", 28, internet = true, application = provider)
        FakeRegistry().use { registry ->
            val env = mapOf("SENTOMARU_BUILDER_TOKEN" to "builder-token-fixture", "SENTOMARU_API" to registry.address.toString())
            refused(5, "app-incompatible", "--input", protectedApk.path, "--profile", profile(both).path,
                "--out", work.resolve("out-real-incompatible").path, "--sign", "none", env = env)
            refused(6, "control-failed", "--input", apk.path, "--profile", profile(both).path,
                "--out", work.resolve("out-real-apk").path, "--sign", "none", env = env)
        }
    }

    @Test fun apkAndAabManifestsAreRead() {
        for ((file, kind) in listOf(apk to ArtifactKind.APK, aab to ArtifactKind.AAB, signedAab to ArtifactKind.AAB)) {
            val a = ArtifactReader.read(file)
            assertEquals(kind, a.kind)
            assertEquals("br.com.example.fixture", a.manifest.packageName)
            assertEquals(42L, a.manifest.versionCode)
            assertEquals(35, a.manifest.targetSdk)
            assertEquals(setOf("android.permission.INTERNET", "android.permission.CAMERA"), a.manifest.permissions)
            assertTrue(a.manifest.hasApplication)
        }
        assertEquals(28, ArtifactReader.read(apk).manifest.minSdk)
        assertEquals(29, ArtifactReader.read(aab).manifest.minSdk)
        assertNull(ArtifactReader.read(aab).signingCertSha256)
        assertEquals(ArtifactReader.read(apk).signingCertSha256, ArtifactReader.read(signedAab).signingCertSha256)
        assertNotNull(ArtifactReader.read(apk).signingCertSha256)
    }

    @Test fun dryRunReportsTheControlsInOrderAndWritesTheFullReport() {
        for (input in listOf(apk, aab)) {
            val out = work.resolve("out-${input.name}")
            val (code, stdout, _) = run(*dry(input, profile(both), out.path))
            assertEquals(stdout, 0, code)
            val report = JsonParser.parseString(out.resolve("report.json").readText()).asJsonObject
            assertEquals(listOf("reportVersion", "runId", "startedAt", "dryRun", "cli", "profile", "input", "output", "controls",
                "signing", "registration", "warnings", "errors"), report.keySet().toList())
            assertTrue(report.get("dryRun").asBoolean)
            val controls = report.getAsJsonArray("controls").map { it.asJsonObject }
            assertEquals(listOf("runtime-injection", "network-signing"), controls.map { it.get("id").asString })
            assertEquals(listOf("planned", "checked"), controls.map { it.get("status").asString })
            assertTrue(report.getAsJsonObject("output").get("sha256").isJsonNull)
            assertEquals("fixture-protect", report.getAsJsonObject("profile").get("id").asString)
            assertEquals("none", report.getAsJsonObject("signing").get("mode").asString)
            assertTrue(report.getAsJsonObject("registration").get("status").isJsonNull)
            val warnings = report.getAsJsonArray("warnings").map { it.asJsonObject.get("code").asString }
            assertEquals((if (input == apk) listOf("output-unsigned") else emptyList()) + "network-signing-install-line", warnings)
            assertTrue(out.listFiles()!!.map { it.name } == listOf("report.json")) // dry-run writes no artifact
        }
    }

    @Test fun aRefusalStillWritesTheFullReport() {
        val out = work.resolve("out-refused-report")
        refused(5, "permission-missing", *dry(noInternetApk, profile(both), out.path))
        val report = JsonParser.parseString(out.resolve("report.json").readText()).asJsonObject
        assertEquals(13, report.size())
        assertEquals("permission-missing", report.getAsJsonArray("errors")[0].asJsonObject.get("code").asString)
        assertEquals("apk", report.getAsJsonObject("input").get("kind").asString)
    }

    @Test fun profileRefusalsHaveStableCodes() {
        refused(4, "control-not-available", *dry(apk, profile(""""integrity-manifest":{"version":"1"}""")))
        refused(4, "control-version-unsupported", *dry(apk, profile(""""runtime-injection":{"version":"2","enrollmentUrl":"https://a"}""")))
        refused(4, "control-prerequisite", *dry(apk, profile(""""network-signing":{"version":"1","hosts":["a.b"],"routes":[{"path":"/x","operation":"op"}]}""")))
        refused(4, "profile-format", *dry(apk, profile(""""runtime-injection":{"version":"1","enrollmentUrl":"https://a","extra":1}""")))
        refused(4, "profile-format", *dry(apk, profile(""""runtime-injection":{"enrollmentUrl":"https://a"}""")))
        refused(4, "profile-format", *dry(apk, profile(""""runtime-injection":{"version":"1"}""")))
        val withHosts = { hosts: String -> profile(""""runtime-injection":{"version":"1","enrollmentUrl":"https://a"},
            "network-signing":{"version":"1","hosts":$hosts,"routes":[{"path":"/x","operation":"op"}]}""") }
        refused(4, "profile-format", *dry(apk, withHosts("""[123]""")))
        refused(4, "profile-format", *dry(apk, withHosts("""["a.b","a.b"]""")))
        refused(4, "profile-format", *dry(apk, withHosts("""[]""")))
    }

    /**
     * D-07b: network-pinning was behind the laboratory gate (SENTOMARU_LAB=1, not contractual) until D-07f. D-07f
     * released it: with and without the gate the section is validated and the app checked (this AAB has no
     * resources.pb: 5), an APK is planned in the dry-run (the real run of an APK stays control-failed; with the gate,
     * D-16-lab-gate refuses the registered run first: usage) and `controls` lists it.
     */
    @Test fun networkPinningIsReleasedWithOrWithoutTheGate() {
        val section = """"network-pinning":{"version":"1","expiration":"2027-03-31","domains":[{"host":"lab-pin.sentomaru.com.br",
            "includeSubdomains":false,"pins":["sha256/wiHsTSryBCSSgeMtp2iGevQhCi4C1T6dp5yPxEgMS5s="],
            "backupPins":["sha256/jl0tsLo4WkI1z7aBKcSTL/z72E7fhJsNkpqjetYrShI="]}]}"""
        val previous = Cli.today
        try {
            Cli.today = { java.time.LocalDate.of(2026, 10, 26) }
            for ((i, env) in listOf(emptyMap(), mapOf("SENTOMARU_LAB" to "0"), mapOf("SENTOMARU_LAB" to "true"),
                    mapOf("SENTOMARU_LAB" to "1")).withIndex()) {
                refused(5, "app-incompatible", *dry(aab, profile(section)), env = env)
                refused(4, "profile-format", *dry(aab, profile(section.replace("2027-03-31", "2027-04-25"))), env = env)
                refused(4, "control-version-unsupported", *dry(aab, profile(section.replace(""""version":"1",""", """"version":"2","""))), env = env)
                val out = work.resolve("out-pinning-apk-$i")
                val (code, _, err) = run(*dry(apk, profile("$both,$section"), out.path), env = env)
                assertEquals(err, 0, code)
                val report = JsonParser.parseString(out.resolve("report.json").readText()).asJsonObject
                val controls = report.getAsJsonArray("controls").map { it.asJsonObject }
                assertEquals(listOf("runtime-injection", "network-signing", "network-pinning"), controls.map { it.get("id").asString })
                assertEquals(listOf("res.xml.added", "resources.entry.added", "manifest.network-security-config.set", "manifest.meta-data.added"),
                    controls[2].getAsJsonArray("changes").map { it.asJsonObject.get("id").asString })
                // The real run of an APK stays control-failed (AAB only, until G-03b3). D-16-lab-gate: with
                // SENTOMARU_LAB=1 the registered run is refused first (usage, before the run is opened).
                FakeRegistry().use { registry ->
                    val gate = env["SENTOMARU_LAB"] == "1"
                    refused(if (gate) 2 else 6, if (gate) "usage" else "control-failed", "--input", apk.path, "--profile", profile(section).path,
                        "--out", work.resolve("out-pin-apk-real-$i").path, "--sign", "none",
                        env = env + mapOf("SENTOMARU_BUILDER_TOKEN" to "builder-token-fixture", "SENTOMARU_API" to registry.address.toString()))
                    assertEquals(gate, registry.calls.isEmpty())
                }
                assertTrue(run("controls", "--json", env = env).second.contains("network-pinning"))
            }
        } finally {
            Cli.today = previous
        }
    }

    /**
     * D-16-lab-gate: SENTOMARU_LAB=1 (exact value) is refused in a registered run with exit 2, `usage` and the stable
     * detail, after the profile is read and before the credential, the entitlement (no request reaches the registry)
     * and the input. The dry-run (never registered) and `--lab-unregistered` (AabInjectionTest) keep the gate.
     */
    @Test fun theLaboratoryGateIsRefusedInARegisteredRun() {
        val gate = mapOf("SENTOMARU_LAB" to "1")
        val out = work.resolve("out-lab-gate")
        val (code, _, err) = run("--input", File(work, "missing.aab").path, "--profile", profile(both).path, "--out", out.path, env = gate)
        assertEquals(err, 2, code)
        val error = JsonParser.parseString(err).asJsonObject
        assertEquals("usage", error.get("code").asString)
        assertEquals(Cli.LAB_GATE_REGISTERED, error.get("detail").asString)
        val report = JsonParser.parseString(out.resolve("report.json").readText()).asJsonObject
        assertEquals(error, report.getAsJsonArray("errors")[0].asJsonObject)
        // The profile comes first (contract precedence).
        refused(4, "profile-format", "--input", aab.path, "--profile", rawProfile("""{"schemaVersion":"2"}""").path,
            "--out", work.resolve("out-lab-gate-profile").path, env = gate)
        FakeRegistry().use { registry ->
            val api = mapOf("SENTOMARU_BUILDER_TOKEN" to "builder-token-fixture", "SENTOMARU_API" to registry.address.toString())
            val real = work.resolve("out-lab-gate-real")
            refused(2, "usage", "--input", aab.path, "--profile", profile(both).path, "--out", real.path, env = gate + api)
            assertTrue(registry.calls.isEmpty())
            // Contract: nothing in <out> but the refusal's report (review R M4).
            assertEquals(setOf("report.json"), real.list()!!.toSet())
            // The gate comes before the keystore check: a missing keystore is not what answers (review R M4).
            val keystore = work.resolve("out-lab-gate-keystore")
            val (kcode, _, kerr) = run("--input", aab.path, "--profile", profile(both).path, "--out", keystore.path,
                "--sign", "keystore", "--keystore", File(work, "missing.p12").path, "--key-alias", "x", env = gate + api)
            assertEquals(kerr, 2, kcode)
            assertEquals(Cli.LAB_GATE_REGISTERED, JsonParser.parseString(kerr).asJsonObject.get("detail").asString)
            assertTrue(registry.calls.isEmpty())
        }
        assertEquals(0, run(*dry(aab, profile(both)), env = gate).first)
    }

    /**
     * D-08a and D-14a: the contract has the build-obfuscation and asset-encryption sections. D-08d brought
     * build-obfuscation and D-14c asset-encryption behind SENTOMARU_LAB=1 (the checks are BuildObfuscationTest and
     * AssetEncryptionTest). D-08f released build-obfuscation and D-14e asset-encryption: both answer the same with and
     * without the gate in the dry run (this AAB and this APK have no sealed reader: app-incompatible) and `controls`
     * lists both. The gate only changes the asset-encryption per-file limit (AssetEncryptionTest).
     */
    @Test fun buildObfuscationAndAssetEncryptionAreReleased() {
        val obfuscation = """"build-obfuscation":{"version":"1"}"""
        val sealed = """"asset-encryption":{"version":"1","assets":["assets/regras/tabela.json"],
            "strings":"assets/sentomaru-strings.json"}"""
        val lab = mapOf("SENTOMARU_LAB" to "1")
        for (input in listOf(aab, apk)) {
            for (env in listOf(emptyMap(), mapOf("SENTOMARU_LAB" to "0"), mapOf("SENTOMARU_LAB" to "true"), lab)) {
                assertEquals(0, run(*dry(input, profile(obfuscation)), env = env).first)
                assertEquals(0, run(*dry(input, profile("$both,$obfuscation")), env = env).first)
                refused(4, "control-version-unsupported", *dry(input, profile(""""build-obfuscation":{"version":"2"}""")), env = env)
                refused(5, "app-incompatible", *dry(input, profile(sealed)), env = env)
                refused(5, "app-incompatible", *dry(input, profile("$obfuscation,$sealed")), env = env)
                refused(5, "app-incompatible", *dry(input, profile("$both,$obfuscation,$sealed")), env = env)
                refused(4, "control-version-unsupported", *dry(input, profile(sealed.replace("\"1\"", "\"2\""))), env = env)
            }
        }
        // G-10c: no control is behind the laboratory gate (ui-shield was released in build 0.6.0, UiShieldTest).
        assertEquals(listOf<Control>(), Controls.laboratory)
        for (env in listOf(emptyMap(), lab)) {
            val listed = run("controls", "--json", env = env).second
            assertTrue(listed, listed.contains("build-obfuscation") && listed.contains("asset-encryption"))
        }
    }

    @Test fun profileJsonIsStrict() {
        val ok = """{"schemaVersion":"1","kind":"protect","profileId":"fixture-protect",
            "scope":{"organization":"ebees","app":"exampleapp","environment":"hml"},
            "controls":{"runtime-injection":{"version":"1","enrollmentUrl":"https://a"}}}"""
        assertEquals(0, run(*dry(apk, rawProfile(ok))).first)
        for (bad in listOf(
            ok.replaceFirst("{", "{\"kind\":\"protect\","),            // duplicate member (Gson keeps the last one)
            ok.replace("\"https://a\"}", "\"https://a\",\"version\":\"2\"}"), // duplicate member inside a section
            "$ok // comment",
            "$ok {}",
            ok.replace("\"schemaVersion\"", "schemaVersion"),          // lenient unquoted name
            "\uFEFF$ok",
        )) refused(4, "profile-format", *dry(apk, rawProfile(bad)))
        val notUtf8 = work.resolve("latin1.json").apply { writeBytes(ok.toByteArray() + byteArrayOf(0xC3.toByte())) }
        refused(4, "profile-format", *dry(apk, notUtf8))
        val big = work.resolve("big.json").apply { writeText(" ".repeat(Profile.MAX_BYTES) + ok) }
        refused(4, "profile-format", *dry(apk, big))
    }

    @Test fun precedenceFollowsTheContract() {
        // Envelope (profile read) comes before the input …
        refused(4, "profile-format", *dry(File(work, "missing.apk"), rawProfile("""{"schemaVersion":"2"}""")))
        // … the input before the full validation of the controls …
        refused(3, "min-sdk-unsupported", *dry(oldApk, profile(""""integrity-manifest":{"version":"1"}""")))
        refused(3, "input-format", *dry(File(work, "missing.apk"), profile(""""integrity-manifest":{"version":"1"}""")))
        // … and the validation before compatibility.
        refused(4, "profile-format", *dry(noInternetApk, profile(""""runtime-injection":{"version":"1","enrollmentUrl":"http://a"}""")))
    }

    @Test fun appRefusalsHaveStableCodes() {
        refused(5, "permission-missing", *dry(noInternetApk, profile(both)))
        refused(3, "min-sdk-unsupported", *dry(oldApk, profile(both)))
        val notZip = work.resolve("not.apk").apply { writeText("x") }
        refused(3, "input-format", *dry(notZip, profile(both)))
    }

    @Test fun inputSignaturesAreVerified() {
        refused(3, "input-signature", *dry(unsignedApk, profile(both)))
        val tamperedApk = work.resolve("tampered.apk").also { t ->
            zip(t, entries(apk).map { (n, b) -> n to if (n == "classes.dex") ByteArray(112) { 1 } else b })
        }
        refused(3, "input-signature", *dry(tamperedApk, profile(both)))
        val tamperedAab = work.resolve("tampered.aab").also { t ->
            zip(t, entries(signedAab).map { (n, b) -> n to if (n == "base/dex/classes.dex") ByteArray(112) { 1 } else b })
        }
        refused(3, "input-signature", *dry(tamperedAab, profile(both)))
        val extraEntryAab = work.resolve("extra.aab").also { t -> zip(t, entries(signedAab) + ("base/dex/classes2.dex" to ByteArray(8))) }
        refused(3, "input-signature", *dry(extraEntryAab, profile(both)))
    }

    @Test fun hostileArchivesAreInputFormat() {
        // Duplicate entry names: the zip writer refuses them, so rename one entry in the raw bytes.
        val twin = work.resolve("twin.apk").also { zip(it, listOf("AndroidManifest.xml" to apkManifest, "AndroidManifest.xmm" to apkManifest,
            "classes.dex" to ByteArray(112))) }
        val raw = String(twin.readBytes(), Charsets.ISO_8859_1).replace("AndroidManifest.xmm", "AndroidManifest.xml")
        twin.writeBytes(raw.toByteArray(Charsets.ISO_8859_1))
        refused(3, "input-format", *dry(twin, profile(both)))
        // A manifest entry that inflates past the limit is refused before it is read whole.
        val bomb = work.resolve("bomb.apk").also { zip(it, listOf("AndroidManifest.xml" to ByteArray(ArtifactReader.MAX_MANIFEST_BYTES + 1),
            "classes.dex" to ByteArray(112))) }
        refused(3, "input-format", *dry(bomb, profile(both)))
    }

    @Test fun hostileBinaryManifestsAreInputFormat() {
        for (n in apkManifest.indices) inputFormat(apkManifest.copyOf(n))           // every truncation
        inputFormat(patched(apkManifest, 4, Int.MAX_VALUE))                         // declared file size
        val pool = 8
        inputFormat(patched(apkManifest, pool + 4, Int.MAX_VALUE))                  // string pool chunk size
        inputFormat(patched(apkManifest, pool + 8, Int.MAX_VALUE))                  // string count
        inputFormat(patched(apkManifest, pool + 8, -1))
        inputFormat(patched(apkManifest, pool + 20, Int.MAX_VALUE))                 // strings start
        inputFormat(patched(apkManifest, pool + 28, Int.MAX_VALUE))                 // first string offset
        val random = Random(9421)
        repeat(3000) {
            val mutated = apkManifest.copyOf()
            repeat(1 + random.nextInt(8)) { mutated[random.nextInt(mutated.size)] = random.nextInt(256).toByte() }
            inputFormat(mutated)
        }
    }

    @Test fun invocationRefusals() {
        val out = work.resolve("out-usage").path
        refused(2, "usage", "--input", apk.path, "--profile", profile(both).path)
        refused(2, "usage", "--input", apk.path, "--profile", profile(both).path, "--out", out, "--keystore", "k.jks")
        refused(2, "usage", "--input", apk.path, "--profile", profile(both).path, "--out", "--dry-run")
        refused(2, "usage", "--input", apk.path, "--profile", profile(both).path, "--out", out, "--dry-run", "--sign", "keystore")
        refused(2, "usage", "--input", apk.path, "--profile", profile(both).path, "--out", out, "--dry-run", "--sign", "none", "--key-alias", "a")
        refused(2, "usage", "--input", apk.path, "--profile", profile(both).path, "--out", out, "--dry-run", "--dry-run")
        // An APK needs an explicit signing mode (contract); an AAB defaults to unsigned.
        refused(2, "usage", "--input", apk.path, "--profile", profile(both).path, "--out", out, "--dry-run")
        assertEquals(0, run("--input", aab.path, "--profile", profile(both).path, "--out", out, "--dry-run").first)
        refused(8, "credential-missing", "--input", apk.path, "--profile", profile(both).path, "--out", out)
        refused(2, "usage", "--input", apk.path, "--profile", profile(both).path, "--out", out,
            env = mapOf("SENTOMARU_BUILDER_TOKEN" to "t", "SENTOMARU_API" to "http://plain"))
        // A real run checks the entitlement first: an unreachable API stops it before the input is read.
        refused(8, "registry-unavailable", "--input", apk.path, "--profile", profile(both).path, "--out", out, "--sign", "none",
            env = mapOf("SENTOMARU_BUILDER_TOKEN" to "t", "SENTOMARU_API" to "https://127.0.0.1:1"))
    }

    @Test fun outputAndReportPathsAreArguments() {
        val blocker = work.resolve("blocker").apply { writeText("x") }
        // `<out>` unusable wins over a bad profile: arguments come first.
        refused(2, "output-unwritable", "--input", apk.path, "--profile", rawProfile("{}").path, "--out", blocker.resolve("sub").path,
            "--dry-run", "--sign", "none")
        refused(2, "usage", "--input", apk.path, "--profile", profile(both).path, "--out", work.resolve("o").path, "--dry-run",
            "--sign", "none", "--report", apk.path)
        refused(2, "usage", "--input", apk.path, "--profile", profile(both).path, "--out", work.resolve("o").path, "--dry-run",
            "--sign", "none", "--json", "--json")
        val (_, _, err) = run("--input", apk.path, "--profile", profile(both).path, "--out", work.resolve("o").path, "/secret/path")
        assertTrue(err, !err.contains("/secret/path"))
        val custom = work.resolve("custom/report.json")
        assertEquals(0, run(*dry(apk, profile(both)), "--report", custom.path).first)
        assertTrue(custom.isFile)
    }

    @Test fun manifestFieldsOutOfRangeAreInputFormat() {
        fun linked(xml: String): ByteArray {
            val (aapt2, platform) = sdkToolPublic()
            val dir = Files.createTempDirectory(work.toPath(), "m").toFile()
            val m = dir.resolve("AndroidManifest.xml").apply { writeText(xml) }
            val out = dir.resolve("l.zip")
            val p = ProcessBuilder(aapt2.path, "link", "-o", out.path, "-I", platform.path, "--manifest", m.path).redirectErrorStream(true).start()
            p.inputStream.readBytes(); check(p.waitFor() == 0)
            return ZipFile(out).use { it.getInputStream(it.getEntry("AndroidManifest.xml")).readBytes() }
        }
        val head = """<manifest xmlns:android="http://schemas.android.com/apk/res/android" xmlns:fake="http://example.test/fake" package="p.q""""
        val outOfRange = linked("$head><uses-sdk android:minSdkVersion=\"99999\"/><application/></manifest>")
        try { ArtifactReader.binaryManifest(outOfRange); fail() } catch (e: ProtectException) { assertEquals(ErrorCode.INPUT_FORMAT, e.error) }
        // An attribute named like the android one in another namespace is not the android attribute.
        val fake = ArtifactReader.binaryManifest(linked("$head><uses-sdk fake:minSdkVersion=\"30\"/><application/></manifest>"))
        assertNull(fake.minSdk)
        val split = linked("$head split=\"config.xxhdpi\"><application android:hasCode=\"false\"/></manifest>")
        try { ArtifactReader.binaryManifest(split); fail() } catch (e: ProtectException) { assertEquals(ErrorCode.INPUT_FORMAT, e.error) }
    }

    @Test fun controlsAndVersionAreMachineReadable() {
        val (code, json, _) = run("controls", "--json")
        assertEquals(0, code)
        // D-08f: build-obfuscation joined the distributed CLI; D-07f: network-pinning too; D-14e: asset-encryption (stage order); G-10c: ui-shield.
        assertEquals(listOf("runtime-injection", "network-signing", "build-obfuscation", "asset-encryption", "network-pinning", "ui-shield"),
            JsonParser.parseString(json).asJsonArray.map { it.asJsonObject.get("id").asString })
        assertEquals("1", JsonParser.parseString(run("--version", "--json").second).asJsonObject.get("version").asString)
        refused(2, "usage", "controls", "--bogus")
    }

    @Test fun theDexScanCountsOnlyAClassDefinedInAWellFormedDex() {
        val both = setOf(NetworkSigning.ANDROID_TRANSPORT, NetworkSigning.FLUTTER_TRANSPORT)
        val dex = dexWith(listOf("La;", NetworkSigning.ANDROID_TRANSPORT, "Lz;"))
        assertEquals(setOf(NetworkSigning.ANDROID_TRANSPORT), DexScan.classes(dex, both))
        // The descriptor only as a string (a literal or a type reference) is not a class; neither is a longer name.
        assertEquals(emptySet<String>(), DexScan.classes(dexWith(listOf("La;"), listOf(NetworkSigning.ANDROID_TRANSPORT)), both))
        assertEquals(emptySet<String>(), DexScan.classes(dexWith(listOf(NetworkSigning.ANDROID_TRANSPORT.dropLast(1) + "x;")), both))
        // Anything malformed contributes nothing (never presence).
        assertEquals(emptySet<String>(), DexScan.classes(ByteArray(112), both))
        assertEquals(emptySet<String>(), DexScan.classes(dex.copyOf(0x70), both))
        for (field in listOf(0x3C, 0x44, 0x64)) assertEquals("$field", emptySet<String>(), DexScan.classes(patched(dex, field, Int.MAX_VALUE), both))
        for (field in listOf(0x38, 0x40, 0x60)) assertEquals("$field", emptySet<String>(), DexScan.classes(patched(dex, field, -1), both))
        val classDefs = java.nio.ByteBuffer.wrap(dex).order(java.nio.ByteOrder.LITTLE_ENDIAN).getInt(0x64)
        assertEquals(emptySet<String>(), DexScan.classes(patched(patched(patched(dex, classDefs, 99), classDefs + 32, -1), classDefs + 64, 7), both))
    }

    // S2: the HttpURLConnection transport is found by the same rule (a class_def), next to the OkHttp one.
    @Test fun theDexScanFindsTheUrlConnectionTransportByItsClassDef() {
        val all = setOf(NetworkSigning.ANDROID_TRANSPORT, NetworkSigning.ANDROID_URLCONNECTION_TRANSPORT, NetworkSigning.FLUTTER_TRANSPORT)
        assertEquals("Lbr/com/ebees/sentomaru/sdk/transport/SentomaruUrlConnection;", NetworkSigning.ANDROID_URLCONNECTION_TRANSPORT)
        assertEquals(setOf(NetworkSigning.ANDROID_TRANSPORT, NetworkSigning.ANDROID_URLCONNECTION_TRANSPORT),
            DexScan.classes(dexWith(listOf("La;", NetworkSigning.ANDROID_TRANSPORT, NetworkSigning.ANDROID_URLCONNECTION_TRANSPORT)), all))
        assertEquals(emptySet<String>(),
            DexScan.classes(dexWith(listOf("La;"), listOf(NetworkSigning.ANDROID_URLCONNECTION_TRANSPORT)), all))
    }

}
