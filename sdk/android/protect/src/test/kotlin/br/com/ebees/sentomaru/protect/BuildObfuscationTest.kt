package br.com.ebees.sentomaru.protect

import com.android.apksig.ApkSigner
import com.android.apksig.KeyConfig
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.File
import java.io.InputStream
import java.nio.file.Files
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

/**
 * D-08d: `build-obfuscation` on APKs and AABs built at test time, with and without R8 and with and without
 * `--obfuscate`. The DEX is real: javac, then D8 (no R8) or R8 with the SDK's and the plugin's own consumer rules
 * (sdk/android/sdk/consumer-rules.pro, sdk/flutter/sentomaru_flutter/android/consumer-rules.pro). The `libapp.so` is a
 * stand-in (bytes with or without the plugin's Dart identifiers): the real `--obfuscate` builds are checked in the
 * flutter-plugin-android CI job, by check_dart_obfuscation.py and by this CLI on the APKs. No binary is committed.
 */
class BuildObfuscationTest {
    companion object {
        private lateinit var work: File
        private lateinit var buildTools: File
        private lateinit var androidJar: File
        private lateinit var keystore: File
        private val apk = HashMap<String, File>()
        private val aab = HashMap<String, File>()
        private const val STORE_PASS = "fixture-only" // a key generated for this run and deleted with it
        private const val URL = "https://api.example/v1/ebees/exampleapp/hml/installations"
        private const val SDK_STORE = "br.com.ebees.sentomaru.sdk.AndroidInstallationStore"
        private const val SDK_ROUTES = "br.com.ebees.sentomaru.sdk.transport.SentomaruRoutes"
        private const val PLUGIN = "br.com.ebees.sentomaru.sentomaru_flutter.SentomaruFlutterPlugin"

        private fun exec(vararg cmd: String): String {
            val p = ProcessBuilder(*cmd).redirectErrorStream(true).start()
            val log = p.inputStream.bufferedReader().readText()
            check(p.waitFor() == 0) { "${cmd.take(4)} failed: $log" }
            return log
        }

        private fun java(): String = File(System.getProperty("java.home"), "bin/java").path
        private fun jdk(tool: String): String = File(System.getProperty("java.home"), "bin/$tool").path
        private fun aapt2(vararg args: String) = exec(buildTools.resolve("aapt2").path, *args)

        private fun zip(target: File, entries: List<Pair<String, ByteArray>>) = ZipOutputStream(target.outputStream()).use { z ->
            for ((n, bytes) in entries) { z.putNextEntry(ZipEntry(n)); z.write(bytes); z.closeEntry() }
        }

        private fun entries(file: File) = ZipFile(file).use { z -> z.entries().toList().filter { !it.isDirectory }
            .map { it.name to z.getInputStream(it).readBytes() } }

        /**
         * The app's classes.dex: an `Application` that holds an instance of each of [classes] in a public static field
         * (so neither R8's shrinker nor its class inliner removes them), compiled by D8 ([rules] null) or R8 with
         * [rules] (ProGuard configuration text) and the app's own `-keep`.
         */
        private fun dex(name: String, classes: List<String>, rules: String?): ByteArray {
            val dir = work.resolve("dex-$name")
            val out = dir.resolve("classes").apply { mkdirs() }
            val sources = classes.map { fqcn ->
                val pkg = fqcn.substringBeforeLast('.'); val simple = fqcn.substringAfterLast('.')
                dir.resolve("src/${pkg.replace('.', '/')}").apply { mkdirs() }.resolve("$simple.java").apply {
                    writeText("package $pkg; public final class $simple { public long at() { return System.nanoTime(); } }")
                }
            } + dir.resolve("src/br/com/example/fixture").apply { mkdirs() }.resolve("App.java").apply {
                writeText("package br.com.example.fixture; public class App extends android.app.Application {\n" +
                    classes.withIndex().joinToString("\n") { (i, c) -> "  public static Object f$i = new $c();" } + "\n}")
            }
            exec(jdk("javac"), "--release", "11", "-cp", androidJar.path, "-d", out.path, *sources.map { it.path }.toTypedArray())
            val classFiles = out.walkTopDown().filter { it.isFile }.map { it.path }.toList().toTypedArray()
            val dexOut = dir.resolve("out").apply { mkdirs() }
            if (rules == null) exec(java(), "-cp", buildTools.resolve("lib/d8.jar").path, "com.android.tools.r8.D8", "--release",
                "--min-api", "28", "--lib", androidJar.path, "--output", dexOut.path, *classFiles)
            else {
                val conf = dir.resolve("rules.pro").apply { writeText("-keep class br.com.example.fixture.App { *; }\n$rules") }
                exec(java(), "-cp", buildTools.resolve("lib/d8.jar").path, "com.android.tools.r8.R8", "--release",
                    "--min-api", "28", "--lib", androidJar.path, "--pg-conf", conf.path, "--output", dexOut.path, *classFiles)
            }
            return dexOut.resolve("classes.dex").readBytes()
        }

        private fun manifest(name: String, debuggable: String?): File = work.resolve("manifest-$name.xml").apply { writeText("""
            <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="br.com.example.fixture"
                android:versionCode="42" android:versionName="1.2">
              <uses-sdk android:minSdkVersion="28" android:targetSdkVersion="35"/>
              <uses-permission android:name="android.permission.INTERNET"/>
              <application android:name="br.com.example.fixture.App" android:label="fixture"
                  ${debuggable?.let { "android:debuggable=\"$it\"" } ?: ""}/>
            </manifest>""".trimIndent()) }

        /**
         * A `libapp.so` stand-in: a little-endian ELF64 (header, body, one section header at the end, as `gen_snapshot`
         * writes it) whose body has the snapshot symbol ([snapshot]), the plugin's Dart identifiers [only] when [plain],
         * and the framework marker ([marker]). [elf] false gives the body alone.
         */
        fun libapp(plain: Boolean, only: List<String> = BuildObfuscation.DART_IDENTIFIERS, marker: Boolean = plain,
            snapshot: Boolean = true, elf: Boolean = true): ByteArray {
            val filler = ByteArray(70_000) { (it % 251 + 1).toByte() }
            val names = (if (snapshot) BuildObfuscation.SNAPSHOT_SYMBOL + "\u0000" else "") +
                (if (plain) only.joinToString("\u0000", postfix = "\u0000") else "sentomaru_flutter\u0000a1\u0000b2\u0000") +
                (if (marker) BuildObfuscation.PLAIN_MARKER + "\u0000" else "")
            val body = filler + names.toByteArray() + filler
            if (!elf) return body
            val header = java.nio.ByteBuffer.allocate(64).order(java.nio.ByteOrder.LITTLE_ENDIAN)
            header.put(byteArrayOf(0x7f, 'E'.code.toByte(), 'L'.code.toByte(), 'F'.code.toByte(), 2, 1, 1))
            header.putLong(0x28, 64L + body.size).putShort(0x3A, 64).putShort(0x3C, 1)
            return header.array() + body + ByteArray(64)
        }

        private fun sign(unsigned: File, target: File): File {
            val ks = KeyStore.getInstance("PKCS12").apply { keystore.inputStream().use { load(it, STORE_PASS.toCharArray()) } }
            val key = ks.getKey("fixture", STORE_PASS.toCharArray()) as PrivateKey
            val cert = ks.getCertificate("fixture") as X509Certificate
            ApkSigner.Builder(listOf(ApkSigner.SignerConfig.Builder("fixture", KeyConfig.Jca(key), listOf(cert)).build()))
                .setInputApk(unsigned).setOutputApk(target).build().sign()
            return target
        }

        /** The same app as a signed APK and as an AAB (bundletool build-bundle): [libs] maps an ABI to its libapp.so. */
        private fun app(name: String, dex: ByteArray, libs: Map<String, ByteArray> = emptyMap(), debuggable: String? = null,
            dex2: ByteArray? = null) {
            val m = manifest(name, debuggable)
            val binary = work.resolve("linked-$name.apk")
            aapt2("link", "-o", binary.path, "-I", androidJar.path, "--manifest", m.path)
            val unsigned = work.resolve("$name-unsigned.apk")
            zip(unsigned, entries(binary) + ("classes.dex" to dex) + listOfNotNull(dex2?.let { "classes2.dex" to it }) +
                libs.map { (abi, b) -> "lib/$abi/libapp.so" to b })
            apk[name] = sign(unsigned, work.resolve("$name.apk"))
            val proto = work.resolve("linked-$name.zip")
            aapt2("link", "--proto-format", "-o", proto.path, "-I", androidJar.path, "--manifest", m.path)
            val module = entries(proto).map { (n, b) -> (if (n == "AndroidManifest.xml") "manifest/AndroidManifest.xml" else n) to b } +
                ("dex/classes.dex" to dex) + listOfNotNull(dex2?.let { "dex/classes2.dex" to it }) +
                libs.map { (abi, b) -> "lib/$abi/libapp.so" to b }
            val base = work.resolve("base-$name.zip").also { zip(it, module) }
            aab[name] = work.resolve("$name.aab").also { AabInjectionTest.bundletool("build-bundle", "--modules=${base.path}", "--output=${it.path}") }
        }

        @BeforeClass @JvmStatic fun fixtures() {
            work = Files.createTempDirectory("protect-obfuscation").toFile()
            val home = File(System.getProperty("android.home").ifEmpty { System.getenv("ANDROID_HOME") ?: "" })
            buildTools = home.resolve("build-tools").listFiles()!!.filter { it.resolve("lib/d8.jar").isFile && it.resolve("aapt2").isFile }
                .maxByOrNull { it.name }!!
            androidJar = home.resolve("platforms").listFiles()!!.filter { it.resolve("android.jar").isFile }
                .maxByOrNull { it.name.removePrefix("android-").toIntOrNull() ?: 0 }!!.resolve("android.jar")
            keystore = work.resolve("fixture.p12")
            exec(jdk("keytool"), "-genkeypair", "-keystore", keystore.path, "-storetype", "PKCS12", "-storepass", STORE_PASS,
                "-alias", "fixture", "-keyalg", "EC", "-groupname", "secp256r1", "-validity", "2", "-dname", "CN=fixture")
            // The consumer rules the AARs ship: the test runs from sdk/android/protect.
            val sdkRules = File("../sdk/consumer-rules.pro").readText()
            val pluginRules = File("../../flutter/sentomaru_flutter/android/consumer-rules.pro").readText()
            val android = listOf(SDK_STORE, SDK_ROUTES)
            val flutter = android + PLUGIN
            app("d8-debug", dex("d8", android, null), debuggable = "true")
            app("r8", dex("r8", android, sdkRules))
            app("r8-broad-keep", dex("r8-broad", android, "$sdkRules\n-keep class br.com.ebees.sentomaru.** { *; }"))
            app("no-sdk", dex("no-sdk", emptyList(), null), debuggable = "false")
            val flutterDex = dex("r8-flutter", flutter, "$sdkRules\n$pluginRules")
            app("flutter-plain", flutterDex, mapOf("arm64-v8a" to libapp(true), "x86_64" to libapp(true)))
            app("flutter-obfuscated", flutterDex, mapOf("arm64-v8a" to libapp(false), "x86_64" to libapp(false)))
            app("flutter-mixed", flutterDex, mapOf("arm64-v8a" to libapp(false), "x86_64" to libapp(true)))
            app("flutter-partial", flutterDex, mapOf("arm64-v8a" to libapp(true, listOf("SentomaruClient"), marker = false)))
            app("flutter-plugin-unused", flutterDex, mapOf("arm64-v8a" to libapp(false, marker = true)))
            app("flutter-no-snapshot-symbol", flutterDex, mapOf("arm64-v8a" to libapp(false, snapshot = false)))
            app("flutter-not-elf", flutterDex, mapOf("arm64-v8a" to libapp(false, elf = false)))
            app("flutter-empty", flutterDex, mapOf("arm64-v8a" to ByteArray(0)))
            app("flutter-truncated", flutterDex, mapOf("arm64-v8a" to libapp(false).let { it.copyOf(it.size - 32) }))
            // A malformed DEX next to the R8 one: an absence no longer proves a rename.
            app("r8-bad-dex", dex("r8", android, sdkRules), dex2 = "dex\n035\u0000".toByteArray() + ByteArray(200) { 0x7f })
            app("flutter-no-plugin", dex("r8-no-plugin", android, sdkRules), mapOf("arm64-v8a" to libapp(false)))
            app("flutter-debug", dex("d8-flutter", flutter, null), debuggable = "true")
        }
    }

    private val lab = mapOf("SENTOMARU_LAB" to "1")
    private val section = """"build-obfuscation":{"version":"1"}"""
    private val runtime = """"runtime-injection":{"version":"1","enrollmentUrl":"$URL"}"""

    private fun profile(controls: String) = work.resolve("profile-${controls.hashCode()}.json").apply {
        writeText("""{"schemaVersion":"1","kind":"protect","profileId":"fixture-protect",
            "scope":{"organization":"ebees","app":"obf-lab","environment":"hml"},"controls":{$controls}}""")
    }

    private fun run(vararg args: String, env: Map<String, String> = lab): Triple<Int, String, String> {
        val out = StringBuilder(); val err = StringBuilder()
        val code = Cli.run(args.toList(), env, { out.append(it) }, { err.append(it) })
        return Triple(code, out.toString(), err.toString())
    }

    private fun dry(input: File, out: File, controls: String = section, env: Map<String, String> = lab) =
        run("--input", input.path, "--profile", profile(controls).path, "--out", out.path, "--dry-run", "--sign", "none", env = env)

    private fun report(out: File): JsonObject = JsonParser.parseString(out.resolve("report.json").readText()).asJsonObject
    private fun warnings(out: File) = report(out).getAsJsonArray("warnings").map { it.asJsonObject.get("code").asString }
    private fun control(out: File) =
        report(out).getAsJsonArray("controls").map { it.asJsonObject }.single { it.get("id").asString == BuildObfuscation.id }
    private fun evidence(out: File) = control(out).getAsJsonObject("evidence").entrySet().associate { it.key to it.value.asString }

    private fun refused(exit: Int, code: String, detail: String?, result: Triple<Int, String, String>) {
        assertEquals(result.third, exit, result.first)
        val e = JsonParser.parseString(result.third).asJsonObject
        assertEquals(result.third, code, e.get("code").asString)
        if (detail != null) assertEquals(result.third, detail, e.get("detail").asString)
    }

    // ---- the gate and the section

    /** D-08f: the control is in the distributed CLI; the gate changes nothing (same exit, same report entry). */
    @Test fun theControlIsInTheDistributedCliWithOrWithoutTheGate() {
        for (input in listOf(apk.getValue("r8"), aab.getValue("r8"))) {
            val gated = work.resolve("gate-lab-${input.name}")
            assertEquals(0, dry(input, gated).first)
            for ((i, env) in listOf(emptyMap(), mapOf("SENTOMARU_LAB" to "0"), mapOf("SENTOMARU_LAB" to "true")).withIndex()) {
                val out = work.resolve("gate-$i-${input.name}")
                val (code, _, err) = dry(input, out, env = env)
                assertEquals(err, 0, code)
                assertEquals(control(gated), control(out))
                assertEquals(warnings(gated), warnings(out))
            }
        }
        assertTrue(Controls.all.contains(BuildObfuscation) && !Controls.laboratory.contains(BuildObfuscation))
        for (env in listOf(emptyMap(), lab)) assertTrue(run("controls", "--json", env = env).second.contains(BuildObfuscation.id))
    }

    @Test fun theSectionIsClosed() {
        val input = aab.getValue("r8")
        refused(4, "profile-format", "build-obfuscation.mode", dry(input, work.resolve("closed-1"), """"build-obfuscation":{"version":"1","mode":"x"}"""))
        refused(4, "profile-format", "build-obfuscation.unknown-field",
            dry(input, work.resolve("closed-2"), """"build-obfuscation":{"version":"1","a b":1}"""))
        refused(4, "control-version-unsupported", "build-obfuscation 2", dry(input, work.resolve("closed-3"), """"build-obfuscation":{"version":"2"}"""))
        // The contract's example is accepted.
        val example = File("../../../contracts/devsecops/examples/protect-profile-build-obfuscation-v1.example.json")
        val (code, _, err) = run("--input", input.path, "--profile", example.path, "--out", work.resolve("closed-example").path,
            "--dry-run", "--sign", "none")
        assertEquals(err, 0, code)
    }

    // ---- the evidence (D-08 item 2), the same on the APK and the AAB

    private fun expect(name: String, renamed: String, kept: String, dart: String, debuggable: String, warned: List<String>) {
        for ((kind, input) in listOf("apk" to apk.getValue(name), "aab" to aab.getValue(name))) {
            val out = work.resolve("evidence-$kind-$name")
            val (code, _, err) = dry(input, out)
            assertEquals(err, 0, code)
            val c = control(out)
            assertEquals("$kind $name", "checked", c.get("status").asString)
            assertEquals(0, c.getAsJsonArray("changes").size())
            assertEquals("$kind $name", linkedMapOf("sdkProbeRenamed" to renamed, "sdkNamesKept" to kept, "dartObfuscated" to dart,
                "debuggable" to debuggable).toList(), evidence(out).toList())
            assertEquals("$kind $name", warned, warnings(out).filter { it.startsWith("build-obfuscation-") })
        }
    }

    @Test fun withoutR8TheSdkIsNotRenamedAndTheDebugBuildIsWarned() =
        expect("d8-debug", "false", "true", "unknown", "true", listOf("build-obfuscation-sdk-not-renamed", "build-obfuscation-debuggable"))

    @Test fun withR8TheSdkIsRenamedAndItsNamesKept() = expect("r8", "true", "true", "unknown", "false", emptyList())

    @Test fun aBroadKeepRuleOverTheSdkReadsAsNotRenamed() =
        expect("r8-broad-keep", "false", "true", "unknown", "false", listOf("build-obfuscation-sdk-not-renamed"))

    @Test fun anAppWithoutTheSdkIsUnknown() = expect("no-sdk", "unknown", "unknown", "unknown", "false", emptyList())

    @Test fun flutterWithoutObfuscateIsWarned() =
        expect("flutter-plain", "true", "true", "false", "false", listOf("build-obfuscation-dart-not-obfuscated"))

    @Test fun flutterWithObfuscate() = expect("flutter-obfuscated", "true", "true", "true", "false", emptyList())

    @Test fun theHeuristicDoesNotDecideOnMixedOrPartialSnapshotsOrWithoutThePlugin() {
        expect("flutter-mixed", "true", "true", "unknown", "false", emptyList())
        expect("flutter-partial", "true", "true", "unknown", "false", emptyList())
        expect("flutter-no-plugin", "true", "true", "unknown", "false", emptyList())
    }

    /** The plugin linked but its Dart types unused: the framework marker still says the snapshot is not obfuscated. */
    @Test fun theFrameworkMarkerAloneReadsAsNotObfuscated() =
        expect("flutter-plugin-unused", "true", "true", "false", "false", listOf("build-obfuscation-dart-not-obfuscated"))

    /** I-1: no name and no marker is `true` only on a readable Dart snapshot; not ELF, empty, truncated: unknown. */
    @Test fun withoutAReadableSnapshotTheAbsenceOfNamesIsUnknown() {
        for (name in listOf("flutter-no-snapshot-symbol", "flutter-not-elf", "flutter-empty", "flutter-truncated"))
            expect(name, "true", "true", "unknown", "false", emptyList())
    }

    /** I-3: a base DEX skipped (here malformed) next to a valid one: renamed and kept are unknown. */
    @Test fun aSkippedDexMakesTheSdkEvidenceUnknown() = expect("r8-bad-dex", "unknown", "unknown", "unknown", "false", emptyList())

    @Test fun aFlutterDebugBuildHasNoSnapshotToRead() =
        expect("flutter-debug", "false", "true", "unknown", "true", listOf("build-obfuscation-sdk-not-renamed", "build-obfuscation-debuggable"))

    @Test fun withTheWaveOneControlsInStageOrder() {
        val out = work.resolve("order")
        val signing = """"network-signing":{"version":"1","hosts":["api.example"],"routes":[{"path":"/v1/x","operation":"concluir_demanda"}]}"""
        assertEquals(0, dry(aab.getValue("r8"), out, "$section,$signing,$runtime").first)
        assertEquals(listOf("runtime-injection", "network-signing", "build-obfuscation"),
            report(out).getAsJsonArray("controls").map { it.asJsonObject.get("id").asString })
    }

    /** The reader marker joins `sdkNamesKept` only when the profile has asset-encryption (D-14c makes it reachable). */
    @Test fun theReaderMarkerCountsOnlyWithAssetEncryption() {
        val artifact = ArtifactReader.read(aab.getValue("r8"))
        val sealed = ControlSection("asset-encryption", "1", JsonObject())
        fun kept(sections: List<ControlSection>) = BuildObfuscation.plan(JsonObject(), artifact,
            ControlContext(Cli.today(), lab = true, sections = sections)).evidence.getValue("sdkNamesKept")
        assertEquals("true", kept(emptyList()))
        assertEquals("false", kept(listOf(sealed)))
    }

    // ---- the real run: nothing changes in the binary

    /** D-16-lab-gate: a registered run refuses SENTOMARU_LAB=1, so it runs without the gate (released since D-08f). */
    @Test fun aRegisteredRunKeepsTheCheckAndTheOutputIsByteForByteTheSame() {
        FakeRegistry().use { registry ->
            val env = mapOf("SENTOMARU_BUILDER_TOKEN" to "builder-token-fixture", "SENTOMARU_API" to registry.address.toString())
            val input = aab.getValue("d8-debug")
            val with = work.resolve("real-with"); val without = work.resolve("real-without")
            assertEquals(0, run("--input", input.path, "--profile", profile("$runtime,$section").path, "--out", with.path, env = env).first)
            assertEquals(0, run("--input", input.path, "--profile", profile(runtime).path, "--out", without.path, env = env).first)
            assertEquals("checked", control(with).get("status").asString)
            assertArrayEquals(with.resolve("d8-debug.protected.aab").readBytes(), without.resolve("d8-debug.protected.aab").readBytes())
            // The section adds its control entry and its warnings, nothing else.
            fun drop(array: com.google.gson.JsonArray, key: String, match: (String) -> Boolean) =
                (array.size() - 1 downTo 0).filter { match(array[it].asJsonObject.get(key).asString) }.forEach { array.remove(it) }
            fun normalized(out: File) = report(out).apply {
                listOf("runId", "startedAt", "profile", "registration").forEach { remove(it) }
                drop(getAsJsonArray("controls"), "id") { it == BuildObfuscation.id }
                drop(getAsJsonArray("warnings"), "code") { it.startsWith("build-obfuscation-") }
            }
            assertEquals(normalized(without), normalized(with))
            assertEquals(listOf("build-obfuscation-sdk-not-renamed", "build-obfuscation-debuggable"),
                warnings(with).filter { it.startsWith("build-obfuscation-") })
            // Nothing to apply alone; the lab run takes no check-only control. G-03b3: an APK is protected now, and the
            // check-only control keeps its `checked` status next to the runtime injection.
            refused(6, "control-failed", "nothing to apply",
                run("--input", input.path, "--profile", profile(section).path, "--out", work.resolve("real-alone").path, env = env))
            val apkOut = work.resolve("real-apk")
            val apkRun = run("--input", apk.getValue("r8").path, "--profile", profile("$runtime,$section").path, "--out", apkOut.path, "--sign", "none", env = env)
            assertEquals(apkRun.third, 0, apkRun.first)
            assertTrue(apkOut.resolve("r8.protected.apk").isFile)
            assertEquals("checked", control(apkOut).get("status").asString)
        }
        refused(6, "control-failed", "build-obfuscation: not applicable by this build", run("--input", aab.getValue("r8").path,
            "--profile", profile("$runtime,$section").path, "--out", work.resolve("lab-run").path, "--lab-unregistered"))
    }

    // ---- the readers

    @Test fun theDartNamesAreTheValidatedOnes() {
        val script = File("../../../verification/devsecops/check_dart_obfuscation.py").readText()
        val tuple = Regex("""DART_IDENTIFIERS = \(([^)]*)\)""").find(script)!!.groupValues[1]
        assertEquals(BuildObfuscation.DART_IDENTIFIERS, Regex(""""([^"]+)"""").findAll(tuple).map { it.groupValues[1] }.toList())
        assertTrue(script.contains("SNAPSHOT_SYMBOL = \"${BuildObfuscation.SNAPSHOT_SYMBOL}\""))
        assertTrue(script.contains("PLAIN_MARKER = \"${BuildObfuscation.PLAIN_MARKER}\""))
    }

    private val needles = BuildObfuscation.DART_IDENTIFIERS + BuildObfuscation.SNAPSHOT_SYMBOL + BuildObfuscation.PLAIN_MARKER

    @Test fun theSnapshotSearchFindsANeedleAcrossReadsAndStopsAtTheLimit() {
        // A stream that returns at most 7 bytes per read: every needle crosses a read boundary somewhere.
        fun trickle(b: ByteArray): InputStream = object : InputStream() {
            val inner = ByteArrayInputStream(b)
            override fun read() = inner.read()
            override fun read(buf: ByteArray, off: Int, len: Int) = inner.read(buf, off, minOf(len, 7))
        }
        val plain = LibApp.read(trickle(libapp(true)), needles, Long.MAX_VALUE)!!
        assertEquals(needles.toSet(), plain.found)
        assertTrue(LibApp.elf(plain.header, plain.total))
        assertEquals(setOf(BuildObfuscation.SNAPSHOT_SYMBOL), LibApp.read(trickle(libapp(false)), needles, Long.MAX_VALUE)!!.found)
        assertNull(LibApp.read(ByteArrayInputStream(libapp(false)), needles, 1000))
        val cut = libapp(false).let { it.copyOf(it.size - 1) }
        assertTrue(!LibApp.read(ByteArrayInputStream(cut), needles, Long.MAX_VALUE)!!.let { LibApp.elf(it.header, it.total) })
    }

    @Test fun theDecisionNeedsAReadableSnapshotOnEveryFile() {
        val s = BuildObfuscation.SNAPSHOT_SYMBOL; val m = BuildObfuscation.PLAIN_MARKER
        val ids = BuildObfuscation.DART_IDENTIFIERS.toSet()
        fun snap(vararg found: String, elf: Boolean = true) = LibApp.Snapshot(found.toSet(), elf)
        assertEquals("unknown", BuildObfuscation.dartObfuscated(null, plugin = true))
        assertEquals("unknown", BuildObfuscation.dartObfuscated(emptyList(), plugin = true))
        assertEquals("true", BuildObfuscation.dartObfuscated(listOf(snap(s), snap(s)), plugin = true))
        assertEquals("unknown", BuildObfuscation.dartObfuscated(listOf(snap(s)), plugin = false))
        assertEquals("unknown", BuildObfuscation.dartObfuscated(listOf(snap()), plugin = true))           // no snapshot symbol
        assertEquals("unknown", BuildObfuscation.dartObfuscated(listOf(snap(s, elf = false)), plugin = true)) // not a whole ELF
        assertEquals("unknown", BuildObfuscation.dartObfuscated(listOf(snap(s), snap(s, elf = false)), plugin = true))
        assertEquals("false", BuildObfuscation.dartObfuscated(listOf(snap(s, *ids.toTypedArray())), plugin = false))
        assertEquals("false", BuildObfuscation.dartObfuscated(listOf(snap(s, m), snap(s, m)), plugin = true))
        assertEquals("unknown", BuildObfuscation.dartObfuscated(listOf(snap(s, m), snap(s)), plugin = true))
        assertEquals("unknown", BuildObfuscation.dartObfuscated(listOf(snap(s, "SentomaruClient")), plugin = true))
    }

    // ---- I-2: the limits of the snapshot reader, on synthetic zips

    private fun apkOf(name: String, libs: List<Pair<String, ByteArray>>) = work.resolve("limits-$name.apk").also { zip(it, libs) }

    @Test fun theSnapshotReaderLimits() {
        val one = libapp(true)
        // 17 files: above MAX_FILES.
        assertNull(LibApp.scan(apkOf("17", (1..17).map { "lib/abi$it/libapp.so" to one }), ArtifactKind.APK, needles))
        assertEquals(16, LibApp.scan(apkOf("16", (1..16).map { "lib/abi$it/libapp.so" to one }), ArtifactKind.APK, needles)!!.size)
        // A declared size above the per-file limit.
        val big = apkOf("big", listOf("lib/arm64-v8a/libapp.so" to one))
        assertNull(LibApp.scan(big, ArtifactKind.APK, needles, maxBytes = 1000))
        // The total budget counts the bytes read across files.
        val two = apkOf("two", listOf("lib/a/libapp.so" to one, "lib/b/libapp.so" to one))
        assertNull(LibApp.scan(two, ArtifactKind.APK, needles, maxTotal = one.size + 10L))
        assertEquals(2, LibApp.scan(two, ArtifactKind.APK, needles, maxTotal = 2L * one.size)!!.size)
        // A central directory that lies about the uncompressed size: the bytes read are what counts.
        val lying = apkOf("lying", listOf("lib/arm64-v8a/libapp.so" to one)).also { patchCentralSize(it, 10) }
        assertEquals(10L, ZipFile(lying).use { it.getEntry("lib/arm64-v8a/libapp.so").size })
        assertNull(LibApp.scan(lying, ArtifactKind.APK, needles, maxBytes = 1000))
        // A deflate stream that does not inflate (IOException): null, never a failure of the control.
        val broken = apkOf("broken", listOf("lib/arm64-v8a/libapp.so" to one)).also { corruptData(it) }
        assertNull(LibApp.scan(broken, ArtifactKind.APK, needles))
    }

    /** Sets the uncompressed size of the only central directory record of [file]. */
    private fun patchCentralSize(file: File, size: Int) {
        val b = file.readBytes()
        val at = (b.size - 4 downTo 0).first { b[it] == 0x50.toByte() && b[it + 1] == 0x4b.toByte() && b[it + 2] == 1.toByte() && b[it + 3] == 2.toByte() }
        java.nio.ByteBuffer.wrap(b).order(java.nio.ByteOrder.LITTLE_ENDIAN).putInt(at + 24, size)
        file.writeBytes(b)
    }

    /** Overwrites the compressed data of the only entry with 0xff (deflate block type 3: invalid). */
    private fun corruptData(file: File) {
        val b = file.readBytes()
        val bb = java.nio.ByteBuffer.wrap(b).order(java.nio.ByteOrder.LITTLE_ENDIAN)
        val start = 30 + (bb.getShort(26).toInt() and 0xffff) + (bb.getShort(28).toInt() and 0xffff)
        for (i in start until start + 64) b[i] = 0xff.toByte()
        file.writeBytes(b)
    }

    @Test fun theDexScanMatchesAPackagePrefixOnlyOnADefinedClass() {
        val prefix = BuildObfuscation.SDK_PACKAGE
        val defined = ProtectCliTest.dexWith(listOf("Lbr/com/ebees/sentomaru/sdk/a;"))
        val referenced = ProtectCliTest.dexWith(listOf("La/b;"), strings = listOf("Lbr/com/ebees/sentomaru/sdk/a;"))
        assertEquals(setOf(prefix), DexScan.classes(defined, emptySet(), setOf(prefix)))
        assertEquals(emptySet<String>(), DexScan.classes(referenced, emptySet(), setOf(prefix)))
        assertEquals(emptySet<String>(), DexScan.classes(ProtectCliTest.dexWith(listOf("Lbr/com/ebees/sentomaru/sdkx;")), emptySet(), setOf(prefix)))
    }

    @Test fun theDexScanReportsASkippedDex() {
        val good = ProtectCliTest.dexWith(listOf("Lbr/com/ebees/sentomaru/sdk/a;"))
        assertTrue(DexScan.wellFormed(good))
        assertTrue(!DexScan.wellFormed("dex\n035\u0000".toByteArray() + ByteArray(200) { 0x7f }))
        val both = work.resolve("skip.apk").also { zip(it, listOf("classes.dex" to good, "classes2.dex" to ByteArray(10))) }
        val scan = DexScan.scan(both, ArtifactKind.APK, setOf(BuildObfuscation.SDK_PROBE), setOf(BuildObfuscation.SDK_PACKAGE))
        assertEquals(setOf(BuildObfuscation.SDK_PACKAGE), scan.found)
        assertTrue(scan.skipped)
        val one = work.resolve("noskip.apk").also { zip(it, listOf("classes.dex" to good)) }
        assertTrue(!DexScan.scan(one, ArtifactKind.APK, setOf(BuildObfuscation.SDK_PROBE), setOf(BuildObfuscation.SDK_PACKAGE)).skipped)
    }

    /** M-1: int types (0x10, 0x11) of the binary manifest, and every occurrence of the attribute in the proto one. */
    @Test fun debuggableReadsIntTypesAndEveryOccurrence() {
        val out = work.resolve("dbg-int.zip")
        aapt2("link", "-o", out.path, "-I", androidJar.path, "--manifest", manifest("dbg-int", "true").path)
        val bytes = ZipFile(out).use { it.getInputStream(it.getEntry("AndroidManifest.xml")).readBytes() }
        // Res_value of the boolean: size 8, res0 0, type 0x12, data 0xffffffff.
        val value = byteArrayOf(8, 0, 0, 0x12, -1, -1, -1, -1)
        val at = (0..bytes.size - value.size).single { i -> value.indices.all { bytes[i + it] == value[it] } }
        for ((type, data, expected) in listOf(Triple(0x10, 1, true), Triple(0x10, 0, false), Triple(0x11, 2, true), Triple(0x11, 0, false))) {
            val patched = bytes.copyOf()
            patched[at + 3] = type.toByte()
            java.nio.ByteBuffer.wrap(patched).order(java.nio.ByteOrder.LITTLE_ENDIAN).putInt(at + 4, data)
            assertEquals("type $type data $data", expected, ArtifactReader.binaryManifest(patched).debuggable)
        }
        val proto = work.resolve("dbg-proto.zip")
        aapt2("link", "--proto-format", "-o", proto.path, "-I", androidJar.path, "--manifest", manifest("dbg-proto", "false").path)
        val node = com.android.aapt.Resources.XmlNode.parseFrom(ZipFile(proto).use { it.getInputStream(it.getEntry("AndroidManifest.xml")).readBytes() })
        assertEquals(false, ArtifactReader.protoManifest(node.toByteArray()).debuggable)
        val index = node.element.childList.indexOfFirst { it.hasElement() && it.element.name == "application" }
        val app = node.element.getChild(index).element
        val falseAttr = app.attributeList.single { it.name == "debuggable" }
        val trueAttr = falseAttr.toBuilder().setValue("true").setCompiledItem(falseAttr.compiledItem.toBuilder()
            .setPrim(falseAttr.compiledItem.prim.toBuilder().setBooleanValue(true))).build()
        // The attribute repeated on the same <application>, then a second <application> with it.
        val repeated = node.toBuilder().apply { elementBuilder.getChildBuilder(index).elementBuilder.addAttribute(trueAttr) }.build()
        assertEquals(true, ArtifactReader.protoManifest(repeated.toByteArray()).debuggable)
        val second = app.toBuilder().clearAttribute().addAttribute(trueAttr).clearChild().build()
        val twoApps = node.toBuilder().apply { elementBuilder.addChild(com.android.aapt.Resources.XmlNode.newBuilder().setElement(second)) }.build()
        assertEquals(true, ArtifactReader.protoManifest(twoApps.toByteArray()).debuggable)
    }

    @Test fun debuggableIsReadFromBothManifestFormats() {
        for ((value, expected) in listOf(null to false, "false" to false, "true" to true, "@bool/dbg" to true)) {
            val m = manifest("dbg-${value.hashCode()}", value)
            val res = work.resolve("res-dbg").apply { resolve("values").mkdirs(); resolve("values/b.xml").writeText(
                """<resources><bool name="dbg">false</bool></resources>""") }
            val compiled = work.resolve("dbg-compiled.zip").also { aapt2("compile", "-o", it.path, "--dir", res.path) }
            for (proto in listOf(false, true)) {
                val out = work.resolve("dbg-${value.hashCode()}-$proto.zip")
                aapt2(*(listOf("link", "-o", out.path, "-I", androidJar.path, "--manifest", m.path, compiled.path) +
                    if (proto) listOf("--proto-format") else emptyList()).toTypedArray())
                val bytes = ZipFile(out).use { it.getInputStream(it.getEntry("AndroidManifest.xml")).readBytes() }
                val facts = if (proto) ArtifactReader.protoManifest(bytes) else ArtifactReader.binaryManifest(bytes)
                assertEquals("$value proto=$proto", expected, facts.debuggable)
            }
        }
    }
}
