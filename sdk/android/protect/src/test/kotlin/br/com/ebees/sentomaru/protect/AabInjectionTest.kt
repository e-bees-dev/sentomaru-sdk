package br.com.ebees.sentomaru.protect

import com.google.gson.JsonObject
import com.google.gson.JsonParser
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test
import java.io.File
import java.nio.file.Files
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

/**
 * G-03b2: runtime injection into a real AAB. The fixture is a bundle built at test time (aapt2 proto link, a DEX from
 * d8, bundletool build-bundle); the output is checked by bundletool itself (validate, build-apks signed with a key
 * generated for the run, dump manifest) and by dexdump (the runtime classes are in the added DEX).
 */
class AabInjectionTest {
    companion object {
        private lateinit var work: File
        private lateinit var aab: File
        private lateinit var featureAab: File
        private lateinit var threeDexAab: File
        private lateinit var gapDexAab: File
        private lateinit var sdkAab: File
        private lateinit var flutterAab: File
        private lateinit var urlConnectionAab: File
        private lateinit var urlConnectionOnlyAab: File
        private lateinit var signedAab: File
        private lateinit var keystore: File
        private lateinit var buildTools: File
        private lateinit var androidJar: File
        private const val STORE_PASS = "fixture-only" // a key generated for this run and deleted with it
        private const val URL = "https://api.example/v1/ebees/exampleapp/prod/installations"

        private fun exec(vararg cmd: String, dir: File? = null): String {
            val p = ProcessBuilder(*cmd).redirectErrorStream(true).apply { if (dir != null) directory(dir) }.start()
            val log = p.inputStream.bufferedReader().readText()
            check(p.waitFor() == 0) { "${cmd.take(4)} failed: $log" }
            return log
        }

        private fun java(): String = File(System.getProperty("java.home"), "bin/java").path
        private fun jdk(tool: String): String = File(System.getProperty("java.home"), "bin/$tool").path

        /** bundletool from the test classpath (the CLI's own dependency, pinned and checksum-verified by Gradle). */
        fun bundletool(vararg args: String): String =
            exec(java(), "-cp", System.getProperty("java.class.path"), "com.android.tools.build.bundletool.BundleToolMain", *args)

        private fun zip(target: File, entries: List<Pair<String, ByteArray>>) {
            ZipOutputStream(target.outputStream()).use { z ->
                for ((n, bytes) in entries) { z.putNextEntry(ZipEntry(n)); z.write(bytes); z.closeEntry() }
            }
        }

        @BeforeClass @JvmStatic fun fixtures() {
            work = Files.createTempDirectory("protect-aab").toFile()
            val home = File(System.getProperty("android.home").ifEmpty { System.getenv("ANDROID_HOME") ?: "" })
            buildTools = home.resolve("build-tools").listFiles()!!.filter { it.resolve("lib/d8.jar").isFile && it.resolve("aapt2").isFile }
                .maxByOrNull { it.name }!!
            androidJar = home.resolve("platforms").listFiles()!!.filter { it.resolve("android.jar").isFile }
                .maxByOrNull { it.name.removePrefix("android-").toIntOrNull() ?: 0 }!!.resolve("android.jar")
            keystore = work.resolve("fixture.p12")
            exec(jdk("keytool"), "-genkeypair", "-keystore", keystore.path, "-storetype", "PKCS12", "-storepass", STORE_PASS,
                "-alias", "fixture", "-keyalg", "EC", "-groupname", "secp256r1", "-validity", "2", "-dname", "CN=fixture")
            // App code: one class, compiled and dexed like a real build.
            val src = work.resolve("src/br/com/example/fixture").apply { mkdirs() }.resolve("App.java")
            src.writeText("package br.com.example.fixture; public class App extends android.app.Application {}")
            val classes = work.resolve("classes").apply { mkdirs() }
            exec(jdk("javac"), "--release", "11", "-cp", androidJar.path, "-d", classes.path, src.path)
            val dexOut = work.resolve("dex").apply { mkdirs() }
            exec(java(), "-cp", buildTools.resolve("lib/d8.jar").path, "com.android.tools.r8.D8", "--min-api", "28",
                "--lib", androidJar.path, "--output", dexOut.path, classes.resolve("br/com/example/fixture/App.class").path)
            val manifest = work.resolve("AndroidManifest.xml").apply { writeText("""
                <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="br.com.example.fixture"
                    android:versionCode="42" android:versionName="1.2">
                  <uses-sdk android:minSdkVersion="28" android:targetSdkVersion="35"/>
                  <uses-permission android:name="android.permission.INTERNET"/>
                  <uses-permission android:name="android.permission.CAMERA"/>
                  <application android:label="fixture" android:name="br.com.example.fixture.App"/>
                </manifest>""".trimIndent()) }
            val linked = work.resolve("linked.zip")
            exec(buildTools.resolve("aapt2").path, "link", "-o", linked.path, "-I", androidJar.path, "--manifest", manifest.path, "--proto-format")
            val module = ZipFile(linked).use { z -> z.entries().toList().filter { !it.isDirectory }.map { e ->
                val name = if (e.name == "AndroidManifest.xml") "manifest/AndroidManifest.xml" else e.name
                name to z.getInputStream(e).readBytes() } } + ("dex/classes.dex" to dexOut.resolve("classes.dex").readBytes())
            val base = work.resolve("base.zip").also { zip(it, module) }
            aab = work.resolve("app.aab")
            bundletool("build-bundle", "--modules=${base.path}", "--output=${aab.path}")
            // G-03c: the same app also carrying the Android SDK transport, or the Flutter plugin (stub classes of those names).
            fun withClass(file: String, vararg fqcns: String): File {
                val simple = file.substringBeforeLast('.')
                val stubSrcs = fqcns.map { fqcn ->
                    work.resolve("stub-$simple/src/${fqcn.substringBeforeLast('.').replace('.', '/')}").apply { mkdirs() }
                        .resolve("${fqcn.substringAfterLast('.')}.java")
                        .apply { writeText("package ${fqcn.substringBeforeLast('.')}; public final class ${fqcn.substringAfterLast('.')} {}") }
                }
                val stubClasses = work.resolve("stub-$simple/classes").apply { mkdirs() }
                exec(jdk("javac"), "--release", "11", "-d", stubClasses.path, *stubSrcs.map { it.path }.toTypedArray())
                val stubDex = work.resolve("stub-$simple/dex").apply { mkdirs() }
                exec(java(), "-cp", buildTools.resolve("lib/d8.jar").path, "com.android.tools.r8.D8", "--min-api", "28",
                    "--lib", androidJar.path, "--output", stubDex.path, classes.resolve("br/com/example/fixture/App.class").path,
                    *fqcns.map { stubClasses.resolve("${it.replace('.', '/')}.class").path }.toTypedArray())
                val withStub = module.filter { it.first != "dex/classes.dex" } + ("dex/classes.dex" to stubDex.resolve("classes.dex").readBytes())
                val zipped = work.resolve("base-$simple.zip").also { zip(it, withStub) }
                return work.resolve(file).also { bundletool("build-bundle", "--modules=${zipped.path}", "--output=${it.path}") }
            }
            sdkAab = withClass("sdk-app.aab", "br.com.ebees.sentomaru.sdk.transport.SentomaruRoutes")
            flutterAab = withClass("flutter-app.aab", "br.com.ebees.sentomaru.sentomaru_flutter.SentomaruFlutterPlugin")
            // S2: an app that calls the HttpURLConnection transport (R8 keeps that name only then) also has SentomaruRoutes.
            urlConnectionAab = withClass("urlconnection-app.aab", "br.com.ebees.sentomaru.sdk.transport.SentomaruRoutes",
                "br.com.ebees.sentomaru.sdk.transport.SentomaruUrlConnection")
            urlConnectionOnlyAab = withClass("urlconnection-only-app.aab", "br.com.ebees.sentomaru.sdk.transport.SentomaruUrlConnection")
            // A dynamic feature module (install-time), which the injection must leave untouched.
            val featureManifest = work.resolve("feature/AndroidManifest.xml").apply { parentFile.mkdirs(); writeText("""
                <manifest xmlns:android="http://schemas.android.com/apk/res/android"
                    xmlns:dist="http://schemas.android.com/apk/distribution" package="br.com.example.fixture" split="feature" android:versionCode="42"
                    android:isFeatureSplit="true">
                  <uses-sdk android:minSdkVersion="28" android:targetSdkVersion="35"/>
                  <dist:module><dist:delivery><dist:install-time/></dist:delivery><dist:fusing dist:include="true"/></dist:module>
                  <application android:hasCode="false"/>
                </manifest>""".trimIndent()) }
            val featureLinked = work.resolve("feature-linked.zip")
            exec(buildTools.resolve("aapt2").path, "link", "-o", featureLinked.path, "-I", androidJar.path, "--manifest",
                featureManifest.path, "--proto-format")
            val featureModule = ZipFile(featureLinked).use { z -> z.entries().toList().filter { !it.isDirectory }.map { e ->
                (if (e.name == "AndroidManifest.xml") "manifest/AndroidManifest.xml" else e.name) to z.getInputStream(e).readBytes() } }
            val feature = work.resolve("feature.zip").also { zip(it, featureModule) }
            featureAab = work.resolve("feature-app.aab")
            bundletool("build-bundle", "--modules=${base.path},${feature.path}", "--output=${featureAab.path}")
            val dex = dexOut.resolve("classes.dex").readBytes()
            threeDexAab = work.resolve("three-dex.aab")
            bundletool("build-bundle", "--modules=${work.resolve("base3.zip").also { zip(it, module + listOf("dex/classes2.dex" to dex,
                "dex/classes3.dex" to dex)) }.path}", "--output=${threeDexAab.path}")
            // bundletool itself refuses a DEX gap, so the gap bundle is the three-DEX one without classes2.dex.
            gapDexAab = work.resolve("gap-dex.aab").also { gap ->
                zip(gap, ZipFile(threeDexAab).use { z -> z.entries().toList().filter { !it.isDirectory && it.name != "base/dex/classes2.dex" }
                    .map { it.name to z.getInputStream(it).readBytes() } })
            }
            signedAab = work.resolve("signed.aab")
            aab.copyTo(signedAab)
            exec(jdk("jarsigner"), "-keystore", keystore.path, "-storetype", "PKCS12", "-storepass", STORE_PASS, signedAab.path, "fixture")
        }
    }

    private fun profile(controls: String) = work.resolve("profile-${controls.hashCode()}.json").apply {
        writeText("""{"schemaVersion":"1","kind":"protect","profileId":"fixture-protect",
            "scope":{"organization":"ebees","app":"exampleapp","environment":"prod"},"controls":{$controls}}""")
    }

    private val runtimeOnly = """"runtime-injection":{"version":"1","enrollmentUrl":"$URL"}"""
    private val withNetwork = """$runtimeOnly, "network-signing":{"version":"1","hosts":["api.example"],"routes":[{"path":"/v1/x","operation":"op"}]}"""

    private fun run(vararg args: String, env: Map<String, String> = mapOf("SENTOMARU_LAB" to "1")): Triple<Int, String, String> {
        val out = StringBuilder(); val err = StringBuilder()
        val code = Cli.run(args.toList(), env, { out.append(it) }, { err.append(it) })
        return Triple(code, out.toString(), err.toString())
    }

    private fun lab(input: File, out: File, controls: String = runtimeOnly, vararg extra: String) =
        run("--input", input.path, "--profile", profile(controls).path, "--out", out.path, "--lab-unregistered", *extra)

    private fun report(out: File): JsonObject = JsonParser.parseString(out.resolve("report.json").readText()).asJsonObject

    @Test fun injectsTheRuntimeAndBundletoolAcceptsTheResult() {
        val out = work.resolve("out-ok")
        val (code, _, err) = lab(aab, out)
        assertEquals(err, 0, code)
        val protected = out.resolve("app.lab.aab")
        assertTrue(protected.isFile)
        assertEquals(setOf("app.lab.aab", "report.json"), out.list()!!.toSet()) // no temporary file left
        val r = report(out)
        val control = r.getAsJsonArray("controls").single().asJsonObject
        assertEquals("applied", control.get("status").asString)
        assertEquals(listOf("dex.added:base/dex/classes2.dex", "manifest.provider.added:${RuntimeInjection.PROVIDER}"),
            control.getAsJsonArray("changes").map { it.asJsonObject.let { c -> c.get("id").asString + ":" + c.get("target").asString } })
        assertEquals(AabInjector.runtimeDexSha256, control.getAsJsonObject("evidence").get("runtimeDexSha256").asString)
        assertFalse(r.get("dryRun").asBoolean)
        assertTrue(r.get("lab").asBoolean)
        assertFalse(r.getAsJsonArray("warnings").any { it.asJsonObject.get("code").asString == "input-signature-removed" })
        assertFalse(r.getAsJsonObject("output").get("signed").asBoolean)
        assertEquals(64, r.getAsJsonObject("output").get("sha256").asString.length)
        assertEquals("not-registered", r.getAsJsonObject("registration").get("status").asString)
        assertTrue(r.getAsJsonArray("warnings").any { it.asJsonObject.get("code").asString == "lab-unregistered" })

        // Every original entry is kept byte for byte, except the manifest; the DEX added is the CLI's runtime.
        val before = ZipFile(aab).use { z -> z.entries().toList().associate { it.name to z.getInputStream(it).readBytes() } }
        val after = ZipFile(protected).use { z -> z.entries().toList().associate { it.name to z.getInputStream(it).readBytes() } }
        assertEquals(before.keys + "base/dex/classes2.dex", after.keys)
        for ((name, bytes) in before) if (name != "base/manifest/AndroidManifest.xml") assertArrayEquals(name, bytes, after[name])
        assertArrayEquals(AabInjector.runtimeDex, after["base/dex/classes2.dex"])

        // Structurally, the manifest differs only by the provider appended to <application>.
        val original = com.android.aapt.Resources.XmlNode.parseFrom(before.getValue("base/manifest/AndroidManifest.xml"))
        val changed = com.android.aapt.Resources.XmlNode.parseFrom(after.getValue("base/manifest/AndroidManifest.xml"))
        val appIndex = changed.element.childList.indexOfFirst { it.hasElement() && it.element.name == "application" }
        val application = changed.element.getChild(appIndex).element
        val added = application.childList.last()
        assertEquals("provider", added.element.name)
        val stripped = changed.toBuilder().setElement(changed.element.toBuilder().setChild(appIndex,
            changed.element.getChild(appIndex).toBuilder().setElement(application.toBuilder().removeChild(application.childCount - 1)))).build()
        assertEquals(original, stripped)
        assertEquals(listOf(0x01010003, 0x01010010, 0x01010018), added.element.attributeList.map { it.resourceId })

        // Reproducible: the same input and profile give the same bytes.
        val again = work.resolve("out-again")
        assertEquals(0, lab(aab, again).first)
        assertEquals(r.getAsJsonObject("output").get("sha256").asString, report(again).getAsJsonObject("output").get("sha256").asString)

        bundletool("validate", "--bundle=${protected.path}")
        val manifest = bundletool("dump", "manifest", "--bundle=${protected.path}", "--module=base")
        for (expected in listOf("android:versionCode=\"42\"", "android:versionName=\"1.2\"", "android:targetSdkVersion=\"35\"",
            "android.permission.INTERNET", "android.permission.CAMERA", "android:name=\"br.com.example.fixture.App\"",
            "android:name=\"${RuntimeInjection.PROVIDER}\"", "android:authorities=\"br.com.example.fixture.sentomaru-init\"",
            "android:exported=\"false\"", "android:name=\"${AabInjector.ENROLLMENT_URL_KEY}\"", "android:value=\"$URL\""))
            assertTrue("$expected in\n$manifest", manifest.contains(expected))
        assertFalse(manifest, manifest.contains("android:process"))

        // APKs generated from the protected bundle, signed with a test key, carry the runtime classes.
        val apks = work.resolve("out.apks")
        bundletool("build-apks", "--bundle=${protected.path}", "--output=${apks.path}", "--mode=universal",
            "--ks=${keystore.path}", "--ks-key-alias=fixture", "--ks-pass=pass:$STORE_PASS",
            "--aapt2=${buildTools.resolve("aapt2").path}") // the Maven bundletool jar ships without aapt2
        val universal = work.resolve("universal.apk")
        ZipFile(apks).use { z -> z.getInputStream(z.getEntry("universal.apk")).use { universal.writeBytes(it.readBytes()) } }
        val dexes = ZipFile(universal).use { z -> z.entries().toList().filter { it.name.matches(Regex("""classes\d*\.dex""")) }.map { e ->
            work.resolve("u-" + e.name).also { f -> f.writeBytes(z.getInputStream(e).readBytes()) } } }
        val dump = dexes.joinToString("\n") { exec(buildTools.resolve("dexdump").path, it.path) }
        assertTrue(dump.contains("Lbr/com/ebees/sentomaru/runtime/InitProvider;"))
        assertTrue(dump.contains("Lbr/com/ebees/sentomaru/runtime/SentomaruRuntime;"))
        assertTrue(dump.contains("Lbr/com/example/fixture/App;"))
    }

    @Test fun aSignedBundleLosesTheStaleSignature() {
        val out = work.resolve("out-signed")
        val (code, _, err) = lab(signedAab, out)
        assertEquals(err, 0, code)
        val names = ZipFile(out.resolve("signed.lab.aab")).use { z -> z.entries().toList().map { it.name } }
        assertFalse(names.toString(), names.any { it.startsWith("META-INF/") })
        assertTrue(report(out).getAsJsonArray("warnings").any { it.asJsonObject.get("code").asString == "input-signature-removed" })
    }

    @Test fun dynamicModulesStayIntactAndDexIsNumberedAfterTheLast() {
        val out = work.resolve("out-feature")
        assertEquals(0, lab(featureAab, out).first)
        val before = ZipFile(featureAab).use { z -> z.entries().toList().filter { it.name.startsWith("feature/") }
            .associate { it.name to z.getInputStream(it).readBytes() } }
        val after = ZipFile(out.resolve("feature-app.lab.aab")).use { z -> z.entries().toList().filter { it.name.startsWith("feature/") }
            .associate { it.name to z.getInputStream(it).readBytes() } }
        assertEquals(before.keys, after.keys)
        for ((n, b) in before) assertArrayEquals(n, b, after[n])
        bundletool("validate", "--bundle=${out.resolve("feature-app.lab.aab").path}")

        val three = work.resolve("out-three")
        assertEquals(0, lab(threeDexAab, three).first)
        assertEquals("base/dex/classes4.dex", report(three).getAsJsonArray("controls")[0].asJsonObject.getAsJsonArray("changes")[0]
            .asJsonObject.get("target").asString)
        val gap = work.resolve("out-gap")
        val (code, _, err) = lab(gapDexAab, gap)
        assertEquals(err, 5, code)
        assertEquals("app-incompatible", JsonParser.parseString(err).asJsonObject.get("code").asString)
    }

    @Test fun aFailureAfterWritingStartedLeavesNothingInOut() {
        fun clean(out: File) = assertEquals(out.list()!!.toList().toString(), listOf("report.json"), out.list()!!.toList())
        try {
            AabInjector.validate = { throw IllegalStateException("forced") }
            val out = work.resolve("out-validate-fails")
            assertEquals(6, lab(aab, out).first)
            clean(out)
        } finally {
            AabInjector.validate = { p -> com.android.tools.build.bundletool.commands.ValidateBundleCommand.builder().setBundlePath(p)
                .setPrintOutput(false).build().execute() }
        }
        try {
            AabInjector.afterEntry = { name -> if (name.startsWith("base/dex/")) throw java.io.IOException("disk full") }
            val out = work.resolve("out-write-fails")
            assertEquals(1, lab(aab, out).first)
            clean(out)
        } finally {
            AabInjector.afterEntry = {}
        }
    }

    @Test fun theLabRunIsExplicit() {
        val out = work.resolve("out-no-env")
        val (code, _, err) = run("--input", aab.path, "--profile", profile(runtimeOnly).path, "--out", out.path, "--lab-unregistered",
            env = emptyMap())
        assertEquals(err, 2, code)
        assertTrue(err.contains("SENTOMARU_LAB"))
        for (bad in listOf("http://api.example/x", "https:///x", "https://u@api.example/x", "https://api.example/a b", "https://api.example/" + "a".repeat(2048))) {
            val o = work.resolve("out-url-${bad.hashCode()}")
            assertEquals(bad, 4, lab(aab, o, """"runtime-injection":{"version":"1","enrollmentUrl":"$bad"}""").first)
        }
    }

    @Test fun refusalsLeaveNoArtifact() {
        fun refused(exit: Int, code: String, out: File, result: Triple<Int, String, String>) {
            assertEquals(result.third, exit, result.first)
            assertEquals(code, JsonParser.parseString(result.third).asJsonObject.get("code").asString)
            assertFalse(out.list().orEmpty().toList().toString(), out.list().orEmpty().any { it.endsWith(".aab") || it.endsWith(".tmp") })
        }
        // The lab run stays runtime-injection only, even for an app that carries the transport.
        work.resolve("out-ns").let { refused(6, "control-failed", it, lab(sdkAab, it, withNetwork)) }
        work.resolve("out-dry").let { refused(2, "usage", it, lab(aab, it, runtimeOnly, "--dry-run")) }
        work.resolve("out-sign").let { refused(2, "usage", it, lab(aab, it, runtimeOnly, "--sign", "keystore", "--keystore", "k", "--key-alias", "a")) }
        // A bundle that already carries the provider (protected twice) is refused, not doubled.
        val first = work.resolve("out-first").also { assertEquals(0, lab(aab, it).first) }
        work.resolve("out-twice").let { refused(5, "app-incompatible", it, lab(first.resolve("app.lab.aab"), it)) }
        // G-06: --dry-run plans with the same refusal, so a dry run never answers "ok" for an already-protected bundle.
        val dry = work.resolve("out-twice-dry")
        val (code, _, err) = run("--input", first.resolve("app.lab.aab").path, "--profile", profile(runtimeOnly).path,
            "--out", dry.path, "--dry-run", "--sign", "none", env = emptyMap())
        assertEquals(err, 5, code)
        assertEquals("app-incompatible", JsonParser.parseString(err).asJsonObject.get("code").asString)
        assertTrue(err, err.contains("already declares the Sentomaru provider"))
        // And an unprotected bundle still plans.
        assertEquals(0, run("--input", aab.path, "--profile", profile(runtimeOnly).path, "--out", work.resolve("out-dry-ok").path,
            "--dry-run", "--sign", "none", env = emptyMap()).first)
    }

    /** D-07b: without network-pinning, the per-control pipeline writes the bytes the previous single-pass writer wrote. */
    @Test fun theRefactoredPipelineWritesThePreviousBytes() {
        for (input in listOf(aab, featureAab, threeDexAab, signedAab, sdkAab)) {
            val out = work.resolve("out-regression-${input.nameWithoutExtension}")
            assertEquals(input.name, 0, lab(input, out).first)
            val reference = work.resolve("reference-${input.name}")
            PreviousInjector.write(input, "br.com.example.fixture", URL, reference)
            assertArrayEquals(input.name, reference.readBytes(), out.resolve(input.name.removeSuffix(".aab") + ".lab.aab").readBytes())
        }
    }

    @Test fun theReportedRuntimeIsTheEmbeddedDex() {
        val version = JsonParser.parseString(run("--version", "--json").second).asJsonObject.getAsJsonObject("runtime")
        assertEquals(AabInjector.runtimeDexSha256, version.get("dexSha256").asString)
        assertTrue(AabInjector.runtimeDex.copyOfRange(0, 4).contentEquals("dex\n".toByteArray()))
    }

    // ---- G-03e: real run (entitlement, injection, signing, registration) against a local fake registry

    private val token = "builder-token-" + java.util.UUID.randomUUID()

    private fun real(registry: FakeRegistry, input: File, out: File, vararg sign: String, env: Map<String, String> = emptyMap()) =
        run("--input", input.path, "--profile", profile(runtimeOnly).path, "--out", out.path, *sign,
            env = mapOf("SENTOMARU_BUILDER_TOKEN" to token, "SENTOMARU_API" to registry.address.toString()) + env)

    private fun noArtifact(out: File) = assertFalse(out.list().orEmpty().toList().toString(),
        out.list().orEmpty().any { it.endsWith(".aab") || it.endsWith(".tmp") || it.endsWith(".signing") })

    @Test fun aRealRunOpensSignsAndRegisters() {
        FakeRegistry().use { registry ->
            val out = work.resolve("out-real")
            val (code, stdout, err) = real(registry, aab, out, "--sign", "keystore", "--keystore", keystore.path, "--key-alias", "fixture",
                env = mapOf("SENTOMARU_KEYSTORE_PASSWORD" to STORE_PASS))
            assertEquals(err, 0, code)
            assertFalse(stdout.contains(token))
            val protected = out.resolve("app.protected.aab")
            assertTrue(protected.isFile)
            // The JDK verifies the JAR signature, and the CLI's own reader agrees on the certificate.
            assertTrue(exec(jdk("jarsigner"), "-verify", protected.path).contains("jar verified."))
            val r = report(out)
            val output = r.getAsJsonObject("output")
            assertTrue(output.get("signed").asBoolean)
            assertEquals(ArtifactReader.read(protected).signingCertSha256, output.get("signingCertSha256").asString)
            assertEquals(("applied" to "keystore"), r.getAsJsonObject("signing").let { it.get("status").asString to it.get("mode").asString })
            val runId = r.get("runId").asString
            assertEquals(("registered" to runId), r.getAsJsonObject("registration").let { it.get("status").asString to it.get("buildId").asString })
            assertFalse(r.has("lab"))
            // Open (entitlement) first, close (registration) last; only metadata and digests; the credential in the header.
            assertEquals(listOf("/v1/ebees/exampleapp/prod/devsecops/runs", "/v1/ebees/exampleapp/prod/devsecops/runs/$runId/close"), registry.calls.map { it.path })
            assertTrue(registry.calls.all { it.authorization == "Bearer $token" })
            val (opened, closed) = registry.calls
            assertEquals(setOf("runId", "profileId", "profileSha256", "cliVersion"), opened.body.keySet())
            assertEquals("protected", closed.body.get("result").asString)
            assertEquals(r.getAsJsonObject("input").get("sha256").asString, closed.body.get("inputSha256").asString)
            assertEquals(output.get("sha256").asString, closed.body.get("outputSha256").asString)
            assertEquals(java.security.MessageDigest.getInstance("SHA-256").digest(protected.readBytes()).joinToString("") { "%02x".format(it) },
                output.get("sha256").asString)
            // bundletool accepts the signed output.
            bundletool("validate", "--bundle=${protected.path}")
        }
    }

    @Test fun anUnsignedRealRunOfAnAab() {
        FakeRegistry().use { registry ->
            val out = work.resolve("out-real-none")
            val (code, _, err) = real(registry, aab, out)
            assertEquals(err, 0, code)
            val r = report(out)
            assertFalse(r.getAsJsonObject("output").get("signed").asBoolean)
            assertEquals("skipped", r.getAsJsonObject("signing").get("status").asString)
            assertEquals(false, registry.calls.last().body.get("signed").asBoolean)
        }
    }

    @Test fun notEntitledStopsBeforeTheInputIsRead() {
        FakeRegistry().use { registry ->
            registry.open = 403 to """{"code":"module-not-entitled"}"""
            val out = work.resolve("out-denied")
            val missing = work.resolve("missing.aab") // never read: the entitlement comes first (contract precedence)
            val (code, _, err) = real(registry, missing, out)
            assertEquals(err, 8, code)
            assertEquals("entitlement-denied", JsonParser.parseString(err).asJsonObject.get("code").asString)
            assertEquals(1, registry.calls.size)          // nothing to close: the run was never opened
            noArtifact(out)
            registry.open = 403 to """{"code":"workload-scope"}"""
            assertEquals(4, real(registry, missing, work.resolve("out-scope")).first)
            registry.open = 401 to """{"code":"workload-required"}"""
            assertEquals(8, real(registry, missing, work.resolve("out-401")).first)
        }
    }

    @Test fun aFailureAfterTheOpenIsRecordedAsFailed() {
        FakeRegistry().use { registry ->
            val out = work.resolve("out-fail-after-open")
            // network-signing on an app without the SDK transport: refused after the open (G-03c), recorded as failed.
            val (code, _, err) = run("--input", aab.path, "--profile", profile(withNetwork).path, "--out", out.path,
                env = mapOf("SENTOMARU_BUILDER_TOKEN" to token, "SENTOMARU_API" to registry.address.toString()))
            assertEquals(err, 5, code)
            noArtifact(out)
            val closed = registry.calls.last()
            assertTrue(closed.path.endsWith("/close"))
            assertEquals(("failed" to "app-incompatible"), closed.body.get("result").asString to closed.body.get("errorCode").asString)
            assertTrue(closed.body.has("inputSha256"))
            // A bad keystore password fails the signature after the open: sign-failed, nothing left, recorded as failed.
            val badSign = work.resolve("out-bad-sign")
            val signed = real(registry, aab, badSign, "--sign", "keystore", "--keystore", keystore.path, "--key-alias", "fixture",
                env = mapOf("SENTOMARU_KEYSTORE_PASSWORD" to "wrong"))
            assertEquals(signed.third, 7, signed.first)
            noArtifact(badSign)
            assertEquals("sign-failed", registry.calls.last().body.get("errorCode").asString)
        }
    }

    @Test fun aRegistrationFailureKeepsTheArtifact() {
        FakeRegistry().use { registry ->
            registry.close = 409 to """{"code":"run-closed"}"""
            val out = work.resolve("out-register-failed")
            val (code, _, err) = real(registry, aab, out)
            assertEquals(err, 8, code)
            assertEquals("register-failed", JsonParser.parseString(err).asJsonObject.get("code").asString)
            assertTrue(out.resolve("app.protected.aab").isFile)                    // contract: the artifact stays
            assertEquals("not-registered", report(out).getAsJsonObject("registration").get("status").asString)
            registry.close = 503 to """{"code":"store-unavailable"}"""
            val unavailable = work.resolve("out-registry-down")
            val down = real(registry, aab, unavailable)
            assertEquals(8, down.first)
            assertEquals("registry-unavailable", JsonParser.parseString(down.third).asJsonObject.get("code").asString)
            assertTrue(unavailable.resolve("app.protected.aab").isFile)
        }
    }

    @Test fun aRefusedCloseKeepsTheArtifactAndRegisterRetriesIt() {
        FakeRegistry().use { registry ->
            // The module disabled between open and close: the close is a registration failure, the artifact stays.
            registry.close = 403 to """{"code":"module-not-entitled"}"""
            val out = work.resolve("out-close-refused")
            val (code, _, err) = real(registry, aab, out)
            assertEquals(err, 8, code)
            assertEquals("register-failed", JsonParser.parseString(err).asJsonObject.get("code").asString)
            assertTrue(out.resolve("app.protected.aab").isFile)
            // `protect register` re-sends the same close from the report (idempotent on the server) and updates it.
            registry.close = null
            val before = registry.calls.last().body
            val reg = run("register", "--report", out.resolve("report.json").path,
                env = mapOf("SENTOMARU_BUILDER_TOKEN" to token, "SENTOMARU_API" to registry.address.toString()))
            assertEquals(reg.third, 0, reg.first)
            assertEquals(before, registry.calls.last().body)
            val r = report(out)
            assertEquals("registered", r.getAsJsonObject("registration").get("status").asString)
            assertFalse(r.has("closing"))
            assertEquals(0, r.getAsJsonArray("errors").size())
            // Nothing left to register: usage.
            assertEquals(2, run("register", "--report", out.resolve("report.json").path,
                env = mapOf("SENTOMARU_BUILDER_TOKEN" to token, "SENTOMARU_API" to registry.address.toString())).first)
        }
    }

    @Test fun registerChecksTheReportBeforeSending() {
        FakeRegistry().use { registry ->
            registry.close = 503 to """{"code":"down"}"""
            val out = work.resolve("out-register-checks")
            assertEquals(8, real(registry, aab, out).first)
            registry.close = null
            val reportFile = out.resolve("report.json")
            val pristine = reportFile.readText()
            val env = mapOf("SENTOMARU_BUILDER_TOKEN" to token, "SENTOMARU_API" to registry.address.toString())
            fun register(edit: (JsonObject) -> Unit): Int {
                val r = JsonParser.parseString(pristine).asJsonObject.also(edit)
                reportFile.writeText(r.toString())
                return run("register", "--report", reportFile.path, env = env).first
            }
            val sent = registry.calls.size
            assertEquals(2, register { it.getAsJsonObject("profile").getAsJsonObject("scope").addProperty("app", "../x") })
            assertEquals(2, register { it.addProperty("runId", "not-a-uuid") })
            assertEquals(2, register { it.getAsJsonObject("closing").addProperty("extra", "x") })
            assertEquals(2, register { it.getAsJsonObject("closing").addProperty("result", "failed") })
            val artifact = out.resolve("app.protected.aab")
            val original = artifact.readBytes()
            artifact.writeBytes(original + byteArrayOf(0))                       // not the artifact the report declares
            assertEquals(2, register { })
            artifact.writeBytes(original)
            assertEquals(sent, registry.calls.size)                             // none of the refusals reached the API
            // Only the registration failure is resolved; another error of the report stays.
            assertEquals(0, register { r ->
                r.getAsJsonArray("errors").add(JsonParser.parseString("""{"code":"output-unwritable","detail":"x"}""")) })
            val codes = report(out).getAsJsonArray("errors").map { it.asJsonObject.get("code").asString }
            assertEquals(listOf("output-unwritable"), codes)
        }
    }

    @Test fun aSignatureThatDoesNotVerifyIsSignFailed() {
        FakeRegistry().use { registry ->
            val saved = Cli.verifySigned
            Cli.verifySigned = { throw ProtectException(ErrorCode.INPUT_SIGNATURE, "bundle entries with different signers") }
            try {
                val out = work.resolve("out-sign-verify")
                val (code, _, err) = real(registry, aab, out, "--sign", "keystore", "--keystore", keystore.path, "--key-alias", "fixture",
                    env = mapOf("SENTOMARU_KEYSTORE_PASSWORD" to STORE_PASS))
                assertEquals(err, 7, code)
                assertEquals("sign-failed", JsonParser.parseString(err).asJsonObject.get("code").asString)
                noArtifact(out)
            } finally {
                Cli.verifySigned = saved
            }
        }
    }

    @Test fun anInvalidTlsCertificateIsRegistryUnavailable() {
        // A local HTTPS server with a self-signed certificate the JVM does not trust: never accepted, nothing opened.
        val ks = java.security.KeyStore.getInstance("PKCS12").apply { keystore.inputStream().use { load(it, STORE_PASS.toCharArray()) } }
        val kmf = javax.net.ssl.KeyManagerFactory.getInstance(javax.net.ssl.KeyManagerFactory.getDefaultAlgorithm()).apply { init(ks, STORE_PASS.toCharArray()) }
        val ssl = javax.net.ssl.SSLContext.getInstance("TLS").apply { init(kmf.keyManagers, null, null) }
        val server = com.sun.net.httpserver.HttpsServer.create(java.net.InetSocketAddress("127.0.0.1", 0), 0).apply {
            httpsConfigurator = com.sun.net.httpserver.HttpsConfigurator(ssl)
            createContext("/") { it.sendResponseHeaders(201, -1); it.close() }
            start()
        }
        try {
            val out = work.resolve("out-tls")
            val (code, _, err) = run("--input", aab.path, "--profile", profile(runtimeOnly).path, "--out", out.path,
                env = mapOf("SENTOMARU_BUILDER_TOKEN" to token, "SENTOMARU_API" to "https://127.0.0.1:${server.address.port}"))
            assertEquals(err, 8, code)
            assertEquals("registry-unavailable", JsonParser.parseString(err).asJsonObject.get("code").asString)
            noArtifact(out)
        } finally {
            server.stop(0)
        }
    }

    @Test fun theCredentialNeverLeaks() {
        FakeRegistry().use { registry ->
            for ((name, setup) in listOf<Pair<String, (FakeRegistry) -> Unit>>(
                "ok" to { _ -> }, "denied" to { r -> r.open = 403 to """{"code":"module-not-entitled"}""" },
                "close" to { r -> r.open = 201 to "{}"; r.close = 500 to """{"code":"x"}""" })) {
                setup(registry)
                val out = work.resolve("out-leak-$name")
                val (_, stdout, stderr) = real(registry, aab, out)
                assertFalse(name, (stdout + stderr).contains(token))
                if (out.resolve("report.json").isFile) assertFalse(name, out.resolve("report.json").readText().contains(token))
            }
            for (bad in listOf("a b", "x\u0000y", "t".repeat(600)))
                assertEquals(bad.take(8), 8, run("--input", aab.path, "--profile", profile(runtimeOnly).path, "--out", work.resolve("o-bad").path,
                    env = mapOf("SENTOMARU_BUILDER_TOKEN" to bad, "SENTOMARU_API" to registry.address.toString())).first)
        }
    }

    // ---- G-03e2: OpenBao Transit signing against a local fake OpenBao (TLS, JWT login, Transit RSA)

    private fun bao(transit: FakeTransit, vararg extra: String) = arrayOf("--sign", "openbao", "--openbao-addr", transit.address.toString(),
        "--openbao-role", transit.role, "--openbao-transit", "transit/upload", "--openbao-cacert", transit.caFile.path, *extra)

    @Test fun aRealRunSignsWithTheOpenBaoKey() {
        FakeTransit(work, jdk("keytool")).use { transit ->
            FakeRegistry().use { registry ->
                val jwtEnv = mapOf("SENTOMARU_OPENBAO_JWT" to transit.jwt)
                // The certificate of the Transit key, signed in the vault by the CLI's own subcommand.
                val cert = work.resolve("upload-${java.util.UUID.randomUUID()}.pem")
                val made = run("openbao-certificate", "--openbao-addr", transit.address.toString(), "--openbao-role", transit.role,
                    "--openbao-transit", "transit/upload", "--openbao-cacert", transit.caFile.path, "--common-name", "e-bees upload",
                    "--out", cert.path, env = jwtEnv)
                assertEquals(made.third, 0, made.first)
                val x509 = cert.inputStream().use { java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(it) }
                x509.verify(transit.key.public)
                assertEquals(2, run("openbao-certificate", "--openbao-addr", transit.address.toString(), "--openbao-role", transit.role,
                    "--openbao-transit", "transit/upload", "--common-name", "x", "--out", cert.path, env = jwtEnv).first) // never overwrites
                val blocker = work.resolve("blocker-${java.util.UUID.randomUUID()}").apply { writeText("x") }
                val unwritable = run("openbao-certificate", "--openbao-addr", transit.address.toString(), "--openbao-role", transit.role,
                    "--openbao-transit", "transit/upload", "--openbao-cacert", transit.caFile.path, "--common-name", "x",
                    "--out", blocker.resolve("cert.pem").path, env = jwtEnv)
                assertEquals(unwritable.third, 2, unwritable.first)
                assertEquals("output-unwritable", JsonParser.parseString(unwritable.third).asJsonObject.get("code").asString)
                val out = work.resolve("out-bao")
                val (code, stdout, err) = real(registry, aab, out, *bao(transit, "--openbao-key", cert.path), env = jwtEnv)
                assertEquals(err, 0, code)
                val protected = out.listFiles()!!.single { it.name.endsWith(".protected.aab") }
                assertTrue(exec(jdk("jarsigner"), "-verify", protected.path).contains("jar verified."))
                val report = JsonParser.parseString(out.resolve("report.json").readText()).asJsonObject
                val digest = java.security.MessageDigest.getInstance("SHA-256").digest(x509.encoded).joinToString("") { "%02x".format(it) }
                assertEquals(digest, report.getAsJsonObject("output").get("signingCertSha256").asString)
                assertEquals("openbao", report.getAsJsonObject("signing").get("mode").asString)
                assertEquals("applied", report.getAsJsonObject("signing").get("status").asString)
                for (text in listOf(stdout, err, out.resolve("report.json").readText())) {
                    assertFalse(text.contains(transit.jwt)); assertFalse(text.contains(transit.sessionToken)); assertFalse(text.contains(token))
                }
                // The session token is revoked at the end; every Transit call carried it.
                assertEquals("/v1/auth/token/revoke-self", transit.calls.last().path)
                assertTrue(transit.calls.filter { it.path.startsWith("/v1/transit/") }.all { it.token == transit.sessionToken })

                fun refused(expectedExit: Int, expectedCode: String, args: Array<String>, env: Map<String, String> = jwtEnv) {
                    registry.calls.clear()
                    val o = work.resolve("out-bao-refused-${java.util.UUID.randomUUID()}")
                    val r = real(registry, aab, o, *args, env = env)
                    assertEquals(r.third, expectedExit, r.first)
                    assertEquals(r.third, expectedCode, JsonParser.parseString(r.third).asJsonObject.get("code").asString)
                    // The run was opened (entitlement) and closed as failed with the signer's code; nothing left behind.
                    assertEquals(listOf(false, true), registry.calls.map { it.path.endsWith("/close") })
                    assertEquals(expectedCode, registry.calls.last().body.get("errorCode").asString)
                    noArtifact(o)
                    for (text in listOf(r.second, r.third)) { assertFalse(text.contains(transit.jwt)); assertFalse(text.contains(transit.sessionToken)) }
                }
                // Wrong role, no CI identity, a CA that is not the server's, an unreachable OpenBao: signer-unavailable.
                refused(7, "signer-unavailable", bao(transit, "--openbao-key", cert.path).map { if (it == transit.role) "other-role" else it }.toTypedArray())
                refused(7, "signer-unavailable", bao(transit, "--openbao-key", cert.path), env = emptyMap())
                refused(7, "signer-unavailable", bao(transit, "--openbao-key", cert.path).map { if (it == transit.caFile.path) keystoreCa().path else it }.toTypedArray())
                refused(7, "signer-unavailable", arrayOf("--sign", "openbao", "--openbao-addr", "https://127.0.0.1:1", "--openbao-role", transit.role,
                    "--openbao-transit", "transit/upload", "--openbao-key", cert.path, "--openbao-cacert", transit.caFile.path))
                // A certificate of another key, or an exportable key: sign-failed.
                val other = rsaCertificate("other-key")
                refused(7, "sign-failed", bao(transit, "--openbao-key", other.path))
                transit.exportable = true
                refused(7, "sign-failed", bao(transit, "--openbao-key", cert.path))
                transit.exportable = false
                // Every failure after the login revokes the session token too (the last call, with that token).
                fun revoked() {
                    assertEquals("/v1/auth/token/revoke-self", transit.calls.last().path)
                    assertEquals(transit.sessionToken, transit.calls.last().token)
                }
                // A missing key (404) is the key's fault; a policy that forbids signing (403) is the identity's; a vault
                // error (5xx) is the signer being unavailable; an answer far above any real one is refused unread.
                transit.keyStatus = 404
                refused(7, "sign-failed", bao(transit, "--openbao-key", cert.path)); revoked()
                transit.keyStatus = 503
                refused(7, "signer-unavailable", bao(transit, "--openbao-key", cert.path)); revoked()
                transit.keyStatus = null
                transit.signStatus = 403
                refused(7, "signer-unavailable", bao(transit, "--openbao-key", cert.path)); revoked()
                transit.signStatus = 500
                refused(7, "signer-unavailable", bao(transit, "--openbao-key", cert.path)); revoked()
                transit.signStatus = null
                transit.hugeKeyAnswer = true
                refused(7, "sign-failed", bao(transit, "--openbao-key", cert.path)); revoked()
                transit.hugeKeyAnswer = false
                // On every failure after the login the session token is revoked too.
                transit.calls.clear()
                refused(7, "sign-failed", bao(transit, "--openbao-key", other.path))
                assertEquals("/v1/auth/token/revoke-self", transit.calls.last().path)
                assertEquals(transit.sessionToken, transit.calls.last().token)
            }
        }
    }

    /** An RSA certificate of a key generated for this run (not the Transit key). */
    private fun rsaCertificate(name: String): File = work.resolve("$name.pem").apply {
        if (isFile) return@apply
        val p12 = work.resolve("$name.p12")
        exec(jdk("keytool"), "-genkeypair", "-keystore", p12.path, "-storetype", "PKCS12", "-storepass", STORE_PASS, "-alias", name,
            "-keyalg", "RSA", "-keysize", "2048", "-validity", "2", "-dname", "CN=$name")
        writeText(exec(jdk("keytool"), "-exportcert", "-rfc", "-keystore", p12.path, "-storetype", "PKCS12", "-storepass", STORE_PASS, "-alias", name))
    }

    /** A CA file that is not the fake OpenBao's (the fixture keystore's certificate). */
    private fun keystoreCa(): File = work.resolve("not-the-bao-ca.pem").apply {
        if (!isFile) writeText(exec(jdk("keytool"), "-exportcert", "-rfc", "-keystore", keystore.path, "-storetype", "PKCS12",
            "-storepass", STORE_PASS, "-alias", "fixture"))
    }

    /** For the API E2E of the shield suite (verification/shield/test_devsecops_cli_e2e.py): the fixture bundle. */
    // ---- G-03c: network-signing is the SDK transport the app installs; the CLI checks it, read-only

    @Test fun networkSigningChecksTheEmbeddedTransportAndChangesNothingForTheNetwork() {
        for ((input, transport) in listOf(sdkAab to "android-sdk", flutterAab to "flutter-plugin",
                urlConnectionAab to "android-sdk,android-sdk-urlconnection", urlConnectionOnlyAab to "android-sdk-urlconnection")) {
            val out = work.resolve("out-ns-dry-${input.nameWithoutExtension}")
            val (code, _, err) = run("--input", input.path, "--profile", profile(withNetwork).path, "--out", out.path,
                "--dry-run", "--sign", "none", env = emptyMap())
            assertEquals(err, 0, code)
            val r = report(out)
            val ns = r.getAsJsonArray("controls").map { it.asJsonObject }.single { it.get("id").asString == "network-signing" }
            assertEquals("checked", ns.get("status").asString)
            assertEquals(0, ns.getAsJsonArray("changes").size())
            assertEquals(transport, ns.getAsJsonObject("evidence").get("transport").asString)
            assertEquals("dex-class-defined", ns.getAsJsonObject("evidence").get("check").asString)
            assertTrue(r.getAsJsonArray("warnings").any { it.asJsonObject.get("code").asString == "network-signing-install-line" })
        }
        val out = work.resolve("out-ns-absent")
        val (code, _, err) = run("--input", aab.path, "--profile", profile(withNetwork).path, "--out", out.path,
            "--dry-run", "--sign", "none", env = emptyMap())
        assertEquals(err, 5, code)
        assertEquals("app-incompatible", com.google.gson.JsonParser.parseString(err).asJsonObject.get("code").asString)
    }

    @Test fun aRealRunWithNetworkSigningInjectsTheRuntimeAndRecordsTheTransport() {
        FakeRegistry().use { registry ->
            val out = work.resolve("out-real-ns")
            val (code, _, err) = run("--input", sdkAab.path, "--profile", profile(withNetwork).path, "--out", out.path,
                env = mapOf("SENTOMARU_BUILDER_TOKEN" to token, "SENTOMARU_API" to registry.address.toString()))
            assertEquals(err, 0, code)
            val controls = report(out).getAsJsonArray("controls").map { it.asJsonObject }
            assertEquals(listOf("runtime-injection" to "applied", "network-signing" to "checked"),
                controls.map { it.get("id").asString to it.get("status").asString })
            assertEquals("android-sdk", controls[1].getAsJsonObject("evidence").get("transport").asString)
            assertEquals(0, controls[1].getAsJsonArray("changes").size())
            bundletool("validate", "--bundle=${out.resolve("sdk-app.protected.aab").path}")
            assertEquals("protected", registry.calls.last().body.get("result").asString)
        }
    }

    @Test fun exportFixtureForApiE2e() {
        val dir = System.getenv("SENTOMARU_E2E_FIXTURE_DIR") ?: return
        aab.copyTo(File(dir).apply { mkdirs() }.resolve("app.aab"), overwrite = true)
    }

    @Test fun signerChoicesOfThisBuild() {
        FakeRegistry().use { registry ->
            // Contract precedence: the entitlement (open) comes before the signer, so a tenant without the module gets 8
            // even with an OpenBao that does not exist.
            val certPem = rsaCertificate("signer-choices")
            val obArgs = arrayOf("--sign", "openbao", "--openbao-addr", "https://127.0.0.1:1", "--openbao-role", "r",
                "--openbao-transit", "transit/upload", "--openbao-key", certPem.path)
            registry.open = 403 to """{"code":"module-not-entitled"}"""
            assertEquals(8, real(registry, aab, work.resolve("out-openbao-denied"), *obArgs).first)
            registry.open = 201 to """{"runId":"x"}"""
            registry.calls.clear()
            // Missing or unknown OpenBao options are usage, before anything is opened.
            for (bad in listOf(arrayOf("--sign", "openbao", "--openbao-addr", "https://b", "--openbao-role", "r", "--openbao-key", certPem.path),
                    obArgs.map { if (it == "https://127.0.0.1:1") "http://127.0.0.1:1" else it }.toTypedArray(),
                    obArgs.map { if (it == "transit/upload") "upload" else it }.toTypedArray()))
                assertEquals(bad.joinToString(" "), 2, real(registry, aab, work.resolve("out-ob-usage"), *bad).first)
            // A CA or a certificate that is not a certificate file: usage, before the run is opened.
            val notACert = work.resolve("not-a-cert.pem").apply { writeText("not a certificate\n") }
            for (bad in listOf(obArgs + arrayOf("--openbao-cacert", notACert.path),
                    obArgs.map { if (it == certPem.path) notACert.path else it }.toTypedArray()))
                assertEquals(bad.joinToString(" "), 2, real(registry, aab, work.resolve("out-ob-usage2"), *bad).first)
            assertTrue(registry.calls.isEmpty())
            val missingStore = real(registry, aab, work.resolve("out-no-store"), "--sign", "keystore", "--keystore", work.resolve("none.p12").path,
                "--key-alias", "fixture")
            assertEquals(2, missingStore.first)
            assertTrue(registry.calls.isEmpty())
            // Only https (loopback http for tests).
            assertEquals(2, run("--input", aab.path, "--profile", profile(runtimeOnly).path, "--out", work.resolve("o-http").path,
                env = mapOf("SENTOMARU_BUILDER_TOKEN" to token, "SENTOMARU_API" to "http://api.example")).first)
        }
    }
}
