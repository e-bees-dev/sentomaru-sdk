package br.com.ebees.sentomaru.protect

import com.android.aapt.Resources
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test
import java.io.File
import java.nio.file.Files
import java.time.LocalDate
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

/**
 * G-10 `ui-shield` (UIS-02, the CLI side): on bundles built at test time (aapt2 link, d8, bundletool build-bundle), the control
 * plans and applies manifest changes only, refuses an activity the manifest does not declare, writes exactly the
 * meta-data the runtime reads (`UiShield.java`) and declares `HIDE_OVERLAY_WINDOWS` only when asked and missing. UIS-01
 * (what the runtime does per screen) is `UiShieldPolicyTest` in :protect-runtime. The control is behind the laboratory gate.
 */
class UiShieldTest {
    companion object {
        private lateinit var work: File
        private lateinit var plain: File        // activities .Main, pay.PayActivity (relative to the package) and an alias
        private lateinit var overlayDeclared: File
        private const val URL = "https://api.example/v1/ebees/exampleapp/hml/installations"
        private const val PKG = "br.com.example.fixture"

        private fun exec(vararg cmd: String): String {
            val p = ProcessBuilder(*cmd).redirectErrorStream(true).start()
            val log = p.inputStream.bufferedReader().readText()
            check(p.waitFor() == 0) { "${cmd.take(4)} failed: $log" }
            return log
        }

        private fun jdk(tool: String) = File(System.getProperty("java.home"), "bin/$tool").path

        private fun zip(target: File, entries: List<Pair<String, ByteArray>>) {
            ZipOutputStream(target.outputStream()).use { z -> for ((n, b) in entries) { z.putNextEntry(ZipEntry(n)); z.write(b); z.closeEntry() } }
        }

        @BeforeClass @JvmStatic fun fixtures() {
            work = Files.createTempDirectory("protect-uishield").toFile()
            val home = File(System.getProperty("android.home").ifEmpty { System.getenv("ANDROID_HOME") ?: "" })
            val buildTools = home.resolve("build-tools").listFiles()!!.filter { it.resolve("lib/d8.jar").isFile && it.resolve("aapt2").isFile }.maxByOrNull { it.name }!!
            val androidJar = home.resolve("platforms").listFiles()!!.filter { it.resolve("android.jar").isFile }
                .maxByOrNull { it.name.removePrefix("android-").toIntOrNull() ?: 0 }!!.resolve("android.jar")
            val src = work.resolve("src/br/com/example/fixture").apply { mkdirs() }.resolve("App.java")
            src.writeText("package $PKG; public class App extends android.app.Application {}")
            val classes = work.resolve("classes").apply { mkdirs() }
            exec(jdk("javac"), "--release", "11", "-cp", androidJar.path, "-d", classes.path, src.path)
            val dexOut = work.resolve("dex").apply { mkdirs() }
            exec(jdk("java"), "-cp", buildTools.resolve("lib/d8.jar").path, "com.android.tools.r8.D8", "--min-api", "28", "--lib", androidJar.path,
                "--output", dexOut.path, classes.resolve("br/com/example/fixture/App.class").path)
            fun bundle(name: String, extraPermission: String): File {
                val manifest = work.resolve("$name.xml").apply { writeText("""
                    <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="$PKG" android:versionCode="42">
                      <uses-sdk android:minSdkVersion="28" android:targetSdkVersion="35"/>
                      <uses-permission android:name="android.permission.INTERNET"/>
                      $extraPermission
                      <application android:label="fixture" android:name="$PKG.App">
                        <activity android:name=".Main" android:exported="true"/>
                        <activity android:name="$PKG.pay.PayActivity"/>
                        <activity-alias android:name="Alias" android:targetActivity=".Main"/>
                      </application>
                    </manifest>""".trimIndent()) }
                val linked = work.resolve("$name-linked.zip")
                exec(buildTools.resolve("aapt2").path, "link", "-o", linked.path, "-I", androidJar.path, "--manifest", manifest.path, "--proto-format")
                val module = ZipFile(linked).use { z -> z.entries().toList().filter { !it.isDirectory }.map { e ->
                    (if (e.name == "AndroidManifest.xml") "manifest/AndroidManifest.xml" else e.name) to z.getInputStream(e).readBytes() } } +
                    ("dex/classes.dex" to dexOut.resolve("classes.dex").readBytes())
                val base = work.resolve("$name-base.zip").also { zip(it, module) }
                return work.resolve("$name.aab").also { AabInjectionTest.bundletool("build-bundle", "--modules=${base.path}", "--output=${it.path}") }
            }
            plain = bundle("plain", "")
            overlayDeclared = bundle("overlay", """<uses-permission android:name="android.permission.HIDE_OVERLAY_WINDOWS"/>""")
        }
    }

    private val runtime = """"runtime-injection":{"version":"1","enrollmentUrl":"$URL"}"""
    private fun shield(mode: String = "listed_only", activities: String = """["$PKG.Main","$PKG.pay.PayActivity"]""", hide: String = "true") =
        """"ui-shield":{"version":"1","mode":"$mode","activities":$activities,"hideOverlayWindows":$hide}"""

    private fun profile(controls: String) = work.resolve("profile-${controls.hashCode()}.json").apply {
        writeText("""{"schemaVersion":"1","kind":"protect","profileId":"fixture-protect","scope":{"organization":"ebees","app":"exampleapp","environment":"hml"},"controls":{$controls}}""")
    }

    private fun run(vararg args: String, env: Map<String, String> = mapOf("SENTOMARU_LAB" to "1")): Triple<Int, String, String> {
        val out = StringBuilder(); val err = StringBuilder()
        val code = Cli.run(args.toList(), env, { out.append(it) }, { err.append(it) })
        return Triple(code, out.toString(), err.toString())
    }

    private fun lab(input: File, out: File, controls: String, vararg extra: String) =
        run("--input", input.path, "--profile", profile(controls).path, "--out", out.path, "--lab-unregistered", *extra)

    private fun report(out: File): JsonObject = JsonParser.parseString(out.resolve("report.json").readText()).asJsonObject

    private fun manifestOf(aab: File): Resources.XmlNode = ZipFile(aab).use { z ->
        Resources.XmlNode.parseFrom(z.getInputStream(z.getEntry("base/manifest/AndroidManifest.xml")).readBytes()) }

    private fun metaData(node: Resources.XmlNode): Map<String, String> {
        val application = node.element.childList.first { it.hasElement() && it.element.name == "application" }.element
        val provider = application.childList.first { it.hasElement() && it.element.name == "provider" }.element
        return provider.childList.filter { it.hasElement() && it.element.name == "meta-data" }.associate { c ->
            c.element.attributeList.first { it.name == "name" }.value to c.element.attributeList.first { it.name == "value" }.value }
    }

    // G-10c: released in build 0.6.0. The gate changes nothing for it, and `controls --json` lists it last.
    @Test fun theControlIsReleasedAndListedByControlsWithOrWithoutTheGate() {
        assertTrue(Controls.all.contains(UiShieldControl) && !Controls.laboratory.contains(UiShieldControl))
        assertTrue(Controls.byId("ui-shield") === UiShieldControl)
        assertTrue(Controls.byId("ui-shield", lab = true) === UiShieldControl)
        for (env in listOf(emptyMap(), mapOf("SENTOMARU_LAB" to "1"))) {
            val ids = JsonParser.parseString(run("controls", "--json", env = env).second).asJsonArray.map { it.asJsonObject.get("id").asString }
            assertEquals("ui-shield", ids.last())
        }
        val profile = Profile.parse(profile("$runtime, ${shield()}").readBytes())
        assertEquals(listOf("runtime-injection", "ui-shield"), Controls.resolve(profile, ControlContext(LocalDate.of(2026, 11, 4))).map { it.first.id })
    }

    @Test fun theManifestFactsListTheActivitiesAsBinaryClassNames() {
        val facts = ArtifactReader.read(plain) { _, _ -> }.manifest
        assertEquals(setOf("$PKG.Main", "$PKG.pay.PayActivity", "$PKG.Alias"), facts.activities)
        assertEquals("$PKG.Main", ArtifactReader.activityClass(PKG, ".Main"))
        assertEquals("$PKG.Main", ArtifactReader.activityClass(PKG, "Main"))
        assertEquals("other.pkg.Main", ArtifactReader.activityClass(PKG, "other.pkg.Main"))
    }

    @Test fun theDryRunPlansTheManifestChangesAndTheWarningForAllActivities() {
        val (code, out, err) = run("--input", plain.path, "--profile", profile("$runtime, ${shield()}").path, "--out", work.resolve("out-dry").path, "--dry-run", "--sign", "none")
        assertEquals(err, 0, code)
        val control = JsonParser.parseString(out).asJsonObject.getAsJsonArray("controls").first { it.asJsonObject.get("id").asString == "ui-shield" }.asJsonObject
        assertEquals("planned", control.get("status").asString)
        assertEquals(listOf("manifest.meta-data.added:ui-shield", "manifest.permission.added:${UiShieldControl.OVERLAY_PERMISSION}"),
            control.getAsJsonArray("changes").map { it.asJsonObject.let { c -> c.get("id").asString + ":" + c.get("target").asString } })
        val evidence = control.getAsJsonObject("evidence")
        assertEquals(listOf("listed_only", "2", "true", "activity-lifecycle"),
            listOf("mode", "activities", "hideOverlayWindows", "applies").map { evidence.get(it).asString })
        // The permission is already declared: no permission change. All activities: the warning.
        val all = run("--input", overlayDeclared.path, "--profile", profile("$runtime, ${shield("all_activities", "[]")}").path,
            "--out", work.resolve("out-dry-all").path, "--dry-run", "--sign", "none")
        assertEquals(all.third, 0, all.first)
        val r = JsonParser.parseString(all.second).asJsonObject
        assertEquals(listOf("manifest.meta-data.added:ui-shield"), r.getAsJsonArray("controls").first { it.asJsonObject.get("id").asString == "ui-shield" }
            .asJsonObject.getAsJsonArray("changes").map { it.asJsonObject.let { c -> c.get("id").asString + ":" + c.get("target").asString } })
        assertTrue(r.getAsJsonArray("warnings").any { it.asJsonObject.get("code").asString == "ui-shield-all-activities" })
    }

    @Test fun appliesTheMetaDataTheRuntimeReadsAndTheOverlayPermissionOnlyWhenAskedAndMissing() {
        val out = work.resolve("out-apply")
        val (code, _, err) = lab(plain, out, "$runtime, ${shield()}")
        assertEquals(err, 0, code)
        val protected = out.resolve("plain.lab.aab")
        AabInjectionTest.bundletool("validate", "--bundle=${protected.path}")
        val node = manifestOf(protected)
        assertEquals(mapOf(
            AabInjector.ENROLLMENT_URL_KEY to URL, UiShieldControl.MODE_KEY to "listed_only",
            UiShieldControl.ACTIVITIES_KEY to "$PKG.Main,$PKG.pay.PayActivity", UiShieldControl.HIDE_OVERLAY_KEY to "true"), metaData(node))
        val children = node.element.childList.filter { it.hasElement() }.map { it.element }
        val permission = children.indexOfFirst { it.name == "uses-permission" && it.attributeList.any { a -> a.value == UiShieldControl.OVERLAY_PERMISSION } }
        assertTrue(permission in 0 until children.indexOfFirst { it.name == "application" })
        val dump = AabInjectionTest.bundletool("dump", "manifest", "--bundle=${protected.path}", "--module=base")
        assertTrue(dump, dump.contains("android.permission.HIDE_OVERLAY_WINDOWS"))
        val applied = report(out).getAsJsonArray("controls").first { it.asJsonObject.get("id").asString == "ui-shield" }.asJsonObject
        assertEquals("applied", applied.get("status").asString)
        // Nothing but the manifest and the runtime DEX changed: the app's own code is not rewritten.
        val before = ZipFile(plain).use { z -> z.entries().toList().associate { it.name to z.getInputStream(it).readBytes().toList() } }
        val after = ZipFile(protected).use { z -> z.entries().toList().associate { it.name to z.getInputStream(it).readBytes().toList() } }
        assertEquals(before.keys + "base/dex/classes2.dex", after.keys)
        for ((name, bytes) in before) if (name != "base/manifest/AndroidManifest.xml") assertEquals(name, bytes, after[name])

        // Permission already declared: not added twice. hideOverlayWindows=false: never added.
        val declared = work.resolve("out-declared")
        assertEquals(0, lab(overlayDeclared, declared, "$runtime, ${shield()}").first)
        assertEquals(1, manifestOf(declared.resolve("overlay.lab.aab")).element.childList.count { it.hasElement() && it.element.name == "uses-permission" &&
            it.element.attributeList.any { a -> a.value == UiShieldControl.OVERLAY_PERMISSION } })
        val no = work.resolve("out-nohide")
        assertEquals(0, lab(plain, no, "$runtime, ${shield(hide = "false")}").first)
        assertFalse(AabInjectionTest.bundletool("dump", "manifest", "--bundle=${no.resolve("plain.lab.aab").path}", "--module=base").contains("HIDE_OVERLAY_WINDOWS"))
        assertEquals("false", metaData(manifestOf(no.resolve("plain.lab.aab")))[UiShieldControl.HIDE_OVERLAY_KEY])

        // all_activities writes an empty list.
        val all = work.resolve("out-all")
        assertEquals(0, lab(plain, all, "$runtime, ${shield("all_activities", "[]", "false")}").first)
        val meta = metaData(manifestOf(all.resolve("plain.lab.aab")))
        assertEquals(listOf("all_activities", ""), listOf(meta[UiShieldControl.MODE_KEY], meta[UiShieldControl.ACTIVITIES_KEY]))
    }

    /**
     * G10-2: the runtime reads `UI_SHIELD_HIDE_OVERLAY` with `Bundle.getString`, which returns null for a boolean-typed value.
     * The CLI writes the value without a compiled item, so aapt2/bundletool store it as a string. This builds the universal APK
     * from the protected bundle and has aapt2 dump the installed (binary) manifest: the value must be the quoted string.
     * Skipped when ANDROID_HOME has no aapt2.
     */
    @Test fun hideOverlayIsStoredAsAStringInTheInstalledManifestBecauseTheRuntimeUsesGetString() {
        val aapt2 = listOfNotNull(System.getenv("ANDROID_HOME"), System.getenv("ANDROID_SDK_ROOT"), "/opt/android-sdk")
            .flatMap { sdk -> File(sdk, "build-tools").listFiles().orEmpty().sortedDescending().map { File(it, "aapt2") } }.firstOrNull { it.canExecute() }
        org.junit.Assume.assumeTrue("aapt2 not found", aapt2 != null)
        val out = work.resolve("out-g102")
        assertEquals(0, lab(plain, out, "$runtime, ${shield(hide = "true")}").first)
        val apks = work.resolve("g102.apks")
        AabInjectionTest.bundletool("build-apks", "--bundle=${out.resolve("plain.lab.aab").path}", "--output=${apks.path}",
            "--mode=universal", "--aapt2=${aapt2!!.path}", "--overwrite")
        val apk = work.resolve("g102-universal.apk")
        ZipFile(apks).use { z -> apk.writeBytes(z.getInputStream(z.getEntry("universal.apk")).readBytes()) }
        val tree = exec(aapt2.path, "dump", "xmltree", "--file", "AndroidManifest.xml", apk.path)
        val at = tree.lines().indexOfFirst { it.contains(UiShieldControl.HIDE_OVERLAY_KEY) }
        assertTrue(tree, at >= 0)
        val value = tree.lines().drop(at).first { it.contains("value") }
        assertTrue(value, Regex("""value\(0x01010024\)="true"""").containsMatchIn(value))
    }

    @Test fun refusalsAreStableAndLeaveNoArtifact() {
        fun code(result: Triple<Int, String, String>) = JsonParser.parseString(result.third).asJsonObject.get("code").asString
        // An activity the manifest does not declare: app-incompatible, in the dry run and the real run.
        val ghost = shield(activities = """["$PKG.Missing"]""")
        val real = lab(plain, work.resolve("out-ghost"), "$runtime, $ghost")
        assertEquals(real.third, 5, real.first); assertEquals("app-incompatible", code(real))
        assertTrue(real.third, real.third.contains("$PKG.Missing"))
        assertFalse(work.resolve("out-ghost").list().orEmpty().any { it.endsWith(".aab") })
        val dry = run("--input", plain.path, "--profile", profile("$runtime, $ghost").path, "--out", work.resolve("out-ghost-dry").path, "--dry-run", "--sign", "none")
        assertEquals(dry.third, 5, dry.first)
        // Without runtime-injection the provider is not there.
        val alone = lab(plain, work.resolve("out-alone"), shield())
        assertEquals(alone.third, 4, alone.first); assertEquals("control-prerequisite", code(alone))
        // Profile rules.
        for ((name, section) in mapOf(
            "unknown mode" to shield(mode = "everything"), "listed without activities" to shield(activities = "[]"),
            "all with activities" to shield("all_activities", """["$PKG.Main"]"""), "repeated" to shield(activities = """["$PKG.Main","$PKG.Main"]"""),
            "not a class name" to shield(activities = """["Main"]"""), "not text" to shield(activities = "[1]"),
            "hide not boolean" to shield(hide = "\"yes\""), "too many" to shield(activities = (0..64).joinToString(",", "[", "]") { "\"a.A$it\"" }),
            "unknown field" to """"ui-shield":{"version":"1","mode":"all_activities","activities":[],"hideOverlayWindows":false,"extra":1}""",
            "missing field" to """"ui-shield":{"version":"1","mode":"all_activities","activities":[]}""")) {
            val r = lab(plain, work.resolve("out-bad-${name.hashCode()}"), "$runtime, $section")
            assertEquals("$name: ${r.third}", 4, r.first); assertEquals(name, "profile-format", code(r))
        }
        // A bundle that already carries the shield configuration (protected twice) is refused, not doubled.
        val first = work.resolve("out-first").also { assertEquals(0, lab(plain, it, "$runtime, ${shield()}").first) }
        val twice = lab(first.resolve("plain.lab.aab"), work.resolve("out-twice"), "$runtime, ${shield()}")
        assertEquals(twice.third, 5, twice.first)
    }

    @Test fun theMetaDataKeysAreTheOnesTheRuntimeReads() {
        val source = File("../protect-runtime/src/main/java/br/com/ebees/sentomaru/runtime/UiShield.java").takeIf { it.isFile }
            ?: File("sdk/android/protect-runtime/src/main/java/br/com/ebees/sentomaru/runtime/UiShield.java")
        val text = source.readText()
        for (key in listOf(UiShieldControl.MODE_KEY, UiShieldControl.ACTIVITIES_KEY, UiShieldControl.HIDE_OVERLAY_KEY))
            assertTrue(key, text.contains("\"$key\""))
        val policy = File(source.parentFile, "UiShieldPolicy.java").readText()
        assertTrue(policy.contains("\"${UiShieldControl.MODE_LISTED_ONLY}\"") && policy.contains("\"${UiShieldControl.MODE_ALL}\""))
        assertTrue(policy.contains("MAX_ACTIVITIES = ${UiShieldControl.MAX_ACTIVITIES}"))
    }
}
