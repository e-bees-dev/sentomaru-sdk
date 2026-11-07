package br.com.ebees.sentomaru.protect

import com.android.aapt.Resources
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import org.junit.AfterClass
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
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
 * D-07b: `network-pinning` on real bundles built at test time (aapt2 compile + link in proto format, d8, bundletool
 * build-bundle), checked against aapt2's own output (golden XML and manifest reference), bundletool (validate,
 * build-apks) and `aapt2 dump` on the generated APK. No binary is committed: every fixture is built here.
 */
class NetworkPinningTest {
    companion object {
        private lateinit var work: File
        private lateinit var buildTools: File
        private lateinit var androidJar: File
        private lateinit var keystore: File
        private lateinit var resAab: File        // a string resource only: the xml type is new
        private lateinit var xmlAab: File        // already has an xml resource: the type is reused
        private lateinit var sdkAab: File        // the Android SDK transport in the DEX: the hosts meta-data
        private lateinit var flutterAab: File    // the Flutter plugin class: the dart-line warning
        private lateinit var nscAab: File        // declares its own networkSecurityConfig
        private lateinit var cleartextAab: File  // usesCleartextTraffic="true"
        private lateinit var noTableAab: File    // without base/resources.pb
        private lateinit var referenceAab: File  // usesCleartextTraffic="@bool/…"
        private lateinit var metaDataAab: File   // the hosts meta-data without a configuration
        private lateinit var garbageTableAab: File
        private lateinit var takenPathAab: File  // already has base/res/xml/sentomaru_network_security_config.xml
        private const val STORE_PASS = "fixture-only" // a key generated for this run and deleted with it
        val TODAY: LocalDate = LocalDate.of(2026, 10, 26)
        const val PIN_A = "sha256/wiHsTSryBCSSgeMtp2iGevQhCi4C1T6dp5yPxEgMS5s="
        const val PIN_B = "sha256/jl0tsLo4WkI1z7aBKcSTL/z72E7fhJsNkpqjetYrShI="
        const val PIN_C = "sha256/47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
        private const val URL = "https://api.example/v1/ebees/exampleapp/hml/installations"

        private fun exec(vararg cmd: String): String {
            val p = ProcessBuilder(*cmd).redirectErrorStream(true).start()
            val log = p.inputStream.bufferedReader().readText()
            check(p.waitFor() == 0) { "${cmd.take(4)} failed: $log" }
            return log
        }

        private fun java(): String = File(System.getProperty("java.home"), "bin/java").path
        private fun jdk(tool: String): String = File(System.getProperty("java.home"), "bin/$tool").path
        fun bundletool(vararg args: String): String = AabInjectionTest.bundletool(*args)
        private fun aapt2(vararg args: String) = exec(buildTools.resolve("aapt2").path, *args)

        private fun zip(target: File, entries: List<Pair<String, ByteArray>>) = ZipOutputStream(target.outputStream()).use { z ->
            for ((n, bytes) in entries) { z.putNextEntry(ZipEntry(n)); z.write(bytes); z.closeEntry() }
        }

        private fun entries(file: File) = ZipFile(file).use { z -> z.entries().toList().filter { !it.isDirectory }
            .map { it.name to z.getInputStream(it).readBytes() } }

        private fun dex(name: String, vararg fqcns: String): ByteArray {
            val dir = work.resolve("dex-$name")
            val classes = dir.resolve("classes").apply { mkdirs() }
            val srcs = (listOf("br.com.example.fixture.App") + fqcns).map { fqcn ->
                val pkg = fqcn.substringBeforeLast('.'); val simple = fqcn.substringAfterLast('.')
                dir.resolve("src/${pkg.replace('.', '/')}").apply { mkdirs() }.resolve("$simple.java").apply {
                    writeText(if (simple == "App") "package $pkg; public class App extends android.app.Application {}"
                        else "package $pkg; public final class $simple {}")
                }
            }
            exec(jdk("javac"), "--release", "11", "-cp", androidJar.path, "-d", classes.path, *srcs.map { it.path }.toTypedArray())
            val out = dir.resolve("out").apply { mkdirs() }
            val classFiles = classes.walkTopDown().filter { it.isFile }.map { it.path }.toList()
            exec(java(), "-cp", buildTools.resolve("lib/d8.jar").path, "com.android.tools.r8.D8", "--min-api", "28",
                "--lib", androidJar.path, "--output", out.path, *classFiles.toTypedArray())
            return out.resolve("classes.dex").readBytes()
        }

        /** A linked module (proto format) from [application] attributes and [resources] (path under res/ to content). */
        fun linked(name: String, application: String, resources: Map<String, String>, children: String = ""): List<Pair<String, ByteArray>> {
            val dir = work.resolve("mod-$name").apply { mkdirs() }
            val res = dir.resolve("res")
            for ((path, content) in resources) res.resolve(path).apply { parentFile.mkdirs(); writeText(content) }
            val manifest = dir.resolve("AndroidManifest.xml").apply { writeText("""
                <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="br.com.example.fixture"
                    android:versionCode="42" android:versionName="1.2">
                  <uses-sdk android:minSdkVersion="28" android:targetSdkVersion="35"/>
                  <uses-permission android:name="android.permission.INTERNET"/>
                  <application android:name="br.com.example.fixture.App" $application>$children</application>
                </manifest>""".trimIndent()) }
            val compiled = dir.resolve("compiled.zip")
            val out = dir.resolve("linked.zip")
            if (resources.isEmpty()) aapt2("link", "--proto-format", "-o", out.path, "-I", androidJar.path, "--manifest", manifest.path)
            else {
                aapt2("compile", "-o", compiled.path, "--dir", res.path)
                aapt2("link", "--proto-format", "-o", out.path, "-I", androidJar.path, "--manifest", manifest.path, compiled.path)
            }
            return entries(out).map { (n, b) -> (if (n == "AndroidManifest.xml") "manifest/AndroidManifest.xml" else n) to b }
        }

        private val STRINGS = mapOf("values/strings.xml" to """<resources><string name="app_name">fixture</string></resources>""")

        private fun bundle(name: String, application: String = "android:label=\"@string/app_name\"",
            resources: Map<String, String> = STRINGS, dex: ByteArray, children: String = ""): File {
            val module = linked(name, application, resources, children) + ("dex/classes.dex" to dex)
            val base = work.resolve("base-$name.zip").also { zip(it, module) }
            return work.resolve("$name.aab").also { bundletool("build-bundle", "--modules=${base.path}", "--output=${it.path}") }
        }

        @BeforeClass @JvmStatic fun fixtures() {
            work = Files.createTempDirectory("protect-pinning").toFile()
            val home = File(System.getProperty("android.home").ifEmpty { System.getenv("ANDROID_HOME") ?: "" })
            buildTools = home.resolve("build-tools").listFiles()!!.filter { it.resolve("lib/d8.jar").isFile && it.resolve("aapt2").isFile }
                .maxByOrNull { it.name }!!
            androidJar = home.resolve("platforms").listFiles()!!.filter { it.resolve("android.jar").isFile }
                .maxByOrNull { it.name.removePrefix("android-").toIntOrNull() ?: 0 }!!.resolve("android.jar")
            keystore = work.resolve("fixture.p12")
            exec(jdk("keytool"), "-genkeypair", "-keystore", keystore.path, "-storetype", "PKCS12", "-storepass", STORE_PASS,
                "-alias", "fixture", "-keyalg", "EC", "-groupname", "secp256r1", "-validity", "2", "-dname", "CN=fixture")
            val appDex = dex("app")
            resAab = bundle("res-app", dex = appDex)
            xmlAab = bundle("xml-app", resources = STRINGS + mapOf(
                "xml/prefs.xml" to """<PreferenceScreen xmlns:android="http://schemas.android.com/apk/res/android"/>""",
                "xml/backup.xml" to """<full-backup-content/>"""), dex = appDex)
            sdkAab = bundle("sdk-app", dex = dex("sdk", "br.com.ebees.sentomaru.sdk.transport.SentomaruRoutes"))
            flutterAab = bundle("flutter-app", dex = dex("flutter", "br.com.ebees.sentomaru.sentomaru_flutter.SentomaruFlutterPlugin"))
            nscAab = bundle("nsc-app", application = "android:label=\"@string/app_name\" android:networkSecurityConfig=\"@xml/own\"",
                resources = STRINGS + mapOf("xml/own.xml" to "<network-security-config/>"), dex = appDex)
            cleartextAab = bundle("cleartext-app", application = "android:label=\"@string/app_name\" android:usesCleartextTraffic=\"true\"",
                dex = appDex)
            noTableAab = work.resolve("no-table.aab").also { zip(it, entries(resAab).filter { it.first != "base/resources.pb" }) }
            referenceAab = bundle("reference-app", application = "android:label=\"@string/app_name\" android:usesCleartextTraffic=\"@bool/cleartext\"",
                resources = STRINGS + mapOf("values/bools.xml" to """<resources><bool name="cleartext">true</bool></resources>"""), dex = appDex)
            metaDataAab = bundle("metadata-app", dex = appDex,
                children = """<meta-data android:name="${NetworkPinning.HOSTS_META_DATA}" android:value="a.example.com"/>""")
            garbageTableAab = work.resolve("garbage-table.aab").also { zip(it, entries(resAab).map { (n, b) ->
                n to if (n == "base/resources.pb") byteArrayOf(0x0a, 0x7f, 0x01) else b }) }
            takenPathAab = work.resolve("taken-path.aab").also { zip(it, entries(resAab) + ("base/${NetworkPinning.RESOURCE_PATH}" to ByteArray(1))) }
            Cli.today = { TODAY }
        }

        @AfterClass @JvmStatic fun clock() {
            Cli.today = { LocalDate.now(java.time.ZoneOffset.UTC) }
        }
    }

    private fun domain(host: String = "lab-pin.sentomaru.com.br", sub: Boolean = false, pins: String = "\"$PIN_A\"",
        backups: String = "\"$PIN_B\"") = """{"host":"$host","includeSubdomains":$sub,"pins":[$pins],"backupPins":[$backups]}"""

    private fun pinning(expiration: String = "2027-03-31", domains: String = domain()) =
        """"network-pinning":{"version":"1","expiration":"$expiration","domains":[$domains]}"""

    private fun profile(controls: String) = work.resolve("profile-${controls.hashCode()}.json").apply {
        writeText("""{"schemaVersion":"1","kind":"protect","profileId":"fixture-protect",
            "scope":{"organization":"ebees","app":"pin-lab","environment":"hml"},"controls":{$controls}}""")
    }

    private val lab = mapOf("SENTOMARU_LAB" to "1")

    private fun run(vararg args: String, env: Map<String, String> = lab): Triple<Int, String, String> {
        val out = StringBuilder(); val err = StringBuilder()
        val code = Cli.run(args.toList(), env, { out.append(it) }, { err.append(it) })
        return Triple(code, out.toString(), err.toString())
    }

    private fun apply(input: File, out: File, controls: String = pinning(), env: Map<String, String> = lab) =
        run("--input", input.path, "--profile", profile(controls).path, "--out", out.path, "--lab-unregistered", env = env)

    private fun dry(input: File, out: File, controls: String = pinning(), env: Map<String, String> = lab) =
        run("--input", input.path, "--profile", profile(controls).path, "--out", out.path, "--dry-run", "--sign", "none", env = env)

    private fun report(out: File): JsonObject = JsonParser.parseString(out.resolve("report.json").readText()).asJsonObject
    private fun warnings(out: File) = report(out).getAsJsonArray("warnings").map { it.asJsonObject.get("code").asString }
    private fun control(out: File, id: String = "network-pinning") =
        report(out).getAsJsonArray("controls").map { it.asJsonObject }.single { it.get("id").asString == id }
    private fun changes(c: JsonObject) = c.getAsJsonArray("changes").map { it.asJsonObject.let { x -> x.get("id").asString + ":" + x.get("target").asString } }

    private fun refused(exit: Int, code: String, detail: String?, result: Triple<Int, String, String>) {
        assertEquals(result.third, exit, result.first)
        val e = JsonParser.parseString(result.third).asJsonObject
        assertEquals(result.third, code, e.get("code").asString)
        if (detail != null) assertEquals(result.third, detail, e.get("detail").asString)
    }

    private fun strip(n: Resources.XmlNode): Resources.XmlNode {
        val b = n.toBuilder().clearSource()
        if (n.hasElement()) {
            val e = n.element.toBuilder().clearChild()
            e.clearAttribute()
            n.element.attributeList.forEach { e.addAttribute(it.toBuilder().clearSource()) }
            n.element.namespaceDeclarationList.forEachIndexed { i, d -> e.setNamespaceDeclaration(i, d.toBuilder().clearSource()) }
            n.element.childList.filter { !(it.hasText() && it.text.isBlank()) }.forEach { e.addChild(strip(it)) }
            b.setElement(e)
        }
        return b.build()
    }

    private fun bundleEntry(file: File, name: String) = ZipFile(file).use { z -> z.getInputStream(z.getEntry(name)).readBytes() }

    // ---- the gate (D-07x10) and the release (D-07f)

    /**
     * D-07f: the control is in the distributed CLI. The laboratory gate changes nothing: same exit, same report entry
     * and the same warnings in the dry-run (D-16: a control whose behaviour depends on `context.lab` could not be
     * released before D-16-lab-gate; this one does not read it). D-16-lab-gate: a registered run refuses the gate
     * (exit 2, `usage`) before opening the run; a value other than `1` is no gate, so the same bytes are generated.
     */
    @Test fun theControlIsInTheDistributedCliWithOrWithoutTheGate() {
        for (input in listOf(resAab, sdkAab, cleartextAab)) {
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
        assertTrue(Controls.all.contains(NetworkPinning) && !Controls.laboratory.contains(NetworkPinning))
        for (env in listOf(emptyMap(), lab)) {
            val list = run("controls", "--json", env = env).second
            assertTrue(list, list.contains("network-pinning"))
        }
        FakeRegistry().use { registry ->
            val api = mapOf("SENTOMARU_BUILDER_TOKEN" to "builder-token-fixture", "SENTOMARU_API" to registry.address.toString())
            val bare = work.resolve("gate-real-bare"); val other = work.resolve("gate-real-zero"); val gated = work.resolve("gate-real-lab")
            val (code, _, err) = run("--input", sdkAab.path, "--profile", profile(pinning()).path, "--out", bare.path, env = api)
            assertEquals(err, 0, code)
            assertEquals(0, run("--input", sdkAab.path, "--profile", profile(pinning()).path, "--out", other.path,
                env = mapOf("SENTOMARU_LAB" to "0") + api).first)
            assertEquals(control(other), control(bare))
            assertEquals(warnings(other), warnings(bare))
            // Review R M4 of D-16-lab-gate: any value but the exact "1" is not the gate ("true" too).
            val truthy = work.resolve("gate-real-true")
            assertEquals(0, run("--input", sdkAab.path, "--profile", profile(pinning()).path, "--out", truthy.path,
                env = mapOf("SENTOMARU_LAB" to "true") + api).first)
            assertEquals(control(truthy), control(bare))
            val (a, b) = listOf(bare, other).map { ZipFile(it.resolve("sdk-app.protected.aab")).use { z ->
                z.entries().asSequence().map { e -> e.name to z.getInputStream(e).readBytes().toList() }.toList() } }
            assertEquals(a, b)
            val calls = registry.calls.size
            refused(2, "usage", Cli.LAB_GATE_REGISTERED,
                run("--input", sdkAab.path, "--profile", profile(pinning()).path, "--out", gated.path, env = lab + api))
            assertEquals(calls, registry.calls.size)
            assertFalse(gated.resolve("sdk-app.protected.aab").exists())
        }
    }

    // ---- the section's rules (exit 4, contract table)

    @Test fun sectionRulesAreProfileFormatWithTheContractDetail() {
        val d = "network-pinning.domains"
        val pin43 = "sha256/" + "A".repeat(42) + "B=" // non-canonical: the last digit leaves a non-zero bit
        val cases = listOf(
            """"network-pinning":{"version":"1","expiration":"2027-03-31","domains":[${domain()}],"extra":1}""" to "network-pinning.extra",
            """"network-pinning":{"version":"1","expiration":"2027-03-31","domains":[${domain()}],"a b\u0001":1}""" to "network-pinning.unknown-field",
            """"network-pinning":{"version":"1","domains":[${domain()}]}""" to "network-pinning.expiration",
            """"network-pinning":{"version":"1","expiration":"2027-03-31"}""" to "network-pinning.domains",
            pinning("2026-10-25") to "network-pinning.expiration",              // today - 1
            pinning("2027-04-25") to "network-pinning.expiration",              // today + 181
            pinning("2027-02-30") to "network-pinning.expiration",              // not a calendar day
            pinning("2027-3-31") to "network-pinning.expiration",
            pinning("2027-03-31\\n") to "network-pinning.expiration",
            pinning(domains = "") to d,
            pinning(domains = (1..17).joinToString(",") { domain("h$it.example.com") }) to d,
            pinning(domains = domain() + "," + domain()) to d,
            pinning(domains = """{"host":"a.example.com","includeSubdomains":false,"pins":["$PIN_A"],"backupPins":["$PIN_B"],"x":1}""") to "$d.x",
            pinning(domains = """{"host":"a.example.com","pins":["$PIN_A"],"backupPins":["$PIN_B"]}""") to "$d.includeSubdomains",
            pinning(domains = """{"host":"a.example.com","includeSubdomains":"false","pins":["$PIN_A"],"backupPins":["$PIN_B"]}""") to "$d.includeSubdomains",
            pinning(domains = """{"host":"a.example.com","includeSubdomains":false,"pins":["$PIN_A"]}""") to "$d.backupPins",
            pinning(domains = domain("*.example.com")) to "$d.host",
            pinning(domains = domain("example.com:443")) to "$d.host",
            pinning(domains = domain("example.com.")) to "$d.host",
            pinning(domains = domain("10.0.0.1")) to "$d.host",
            pinning(domains = domain("Example.com")) to "$d.host",
            pinning(domains = domain("localhost")) to "$d.host",
            pinning(domains = domain(("a".repeat(63) + ".").repeat(4) + "com")) to "$d.host", // 259 characters
            pinning(domains = domain(pins = "")) to "$d.pins",
            pinning(domains = domain(pins = "\"$PIN_A\",\"$PIN_A\"")) to "$d.pins",
            pinning(domains = domain(pins = "\"sha256/abc=\"")) to "$d.pins",
            pinning(domains = domain(pins = "\"$pin43\"")) to "$d.pins",
            pinning(domains = domain(pins = "\"${PIN_A.replace('/', '_')}\"")) to "$d.pins",
            pinning(domains = domain(pins = (1..15).joinToString(",") { "\"${pin(it)}\"" }, backups = "\"$PIN_B\",\"$PIN_C\"")) to "$d.pins",
            pinning(domains = domain(backups = "")) to "$d.backupPins",
            pinning(domains = domain(backups = "\"$PIN_A\"")) to "$d.backupPins",
            pinning(domains = domain(backups = "\"$PIN_B\",\"$PIN_B\"")) to "$d.backupPins",
        )
        for ((i, case) in cases.withIndex()) refused(4, "profile-format", case.second, dry(resAab, work.resolve("rule-$i"), case.first))
        refused(4, "control-version-unsupported", "network-pinning 2",
            dry(resAab, work.resolve("rule-v2"), """"network-pinning":{"version":"2"}"""))
        // Boundaries accepted: today, today + 180, 16 pins in one domain, a 253-character host.
        for ((i, ok) in listOf(pinning("2026-10-26"), pinning("2027-04-24"),
                pinning(domains = domain(pins = (1..15).joinToString(",") { "\"${pin(it)}\"" })),
                pinning(domains = domain(("a".repeat(63) + ".").repeat(3) + "a".repeat(57) + ".com"))).withIndex())
            assertEquals(ok, 0, dry(resAab, work.resolve("ok-$i"), ok).first)
    }

    /** A canonical pin from a number (SHA-256 of it). */
    private fun pin(n: Int) = "sha256/" + java.util.Base64.getEncoder().encodeToString(
        java.security.MessageDigest.getInstance("SHA-256").digest(byteArrayOf(n.toByte())))

    @Test fun expirationNearAndHostWarnings() {
        val near = work.resolve("warn-near")
        assertEquals(0, dry(resAab, near, pinning("2026-11-24")).first) // today + 29
        assertTrue(warnings(near).contains("network-pinning-expiration-near"))
        val far = work.resolve("warn-far")
        assertEquals(0, dry(resAab, far, pinning("2026-11-25")).first)  // today + 30
        assertFalse(warnings(far).contains("network-pinning-expiration-near"))
        assertTrue(warnings(far).contains("network-pinning-host-unsigned")) // no network-signing section
        val signed = work.resolve("warn-signed")
        val withSigning = """"runtime-injection":{"version":"1","enrollmentUrl":"$URL"},
            "network-signing":{"version":"1","hosts":["lab-pin.sentomaru.com.br"],"routes":[{"path":"/x","operation":"op"}]},${pinning()}"""
        assertEquals(0, dry(sdkAab, signed, withSigning).first)
        assertFalse(warnings(signed).contains("network-pinning-host-unsigned"))
        assertEquals(listOf("runtime-injection", "network-signing", "network-pinning"),
            report(signed).getAsJsonArray("controls").map { it.asJsonObject.get("id").asString })
        val flutter = work.resolve("warn-flutter")
        assertEquals(0, dry(flutterAab, flutter).first)
        assertTrue(warnings(flutter).contains("network-pinning-dart-line"))
        assertFalse(warnings(far).contains("network-pinning-dart-line"))
        assertFalse(warnings(far).contains("network-pinning-cleartext-blocked"))
    }

    // ---- generation

    @Test fun theGeneratedXmlIsWhatAapt2CompilesFromTheSameSource() {
        val two = PinningSection(LocalDate.of(2027, 3, 31), listOf(
            PinnedDomain("lab-pin.sentomaru.com.br", false, listOf(PIN_A, PIN_C), listOf(PIN_B)),
            PinnedDomain("api.example.com", true, listOf(PIN_B), listOf(PIN_A))))
        for ((i, cleartext) in listOf(null, true, false).withIndex()) {
            val source = buildString {
                append("<network-security-config>\n")
                if (cleartext != null) append("  <base-config cleartextTrafficPermitted=\"$cleartext\"/>\n")
                for (d in two.domains) {
                    append("  <domain-config cleartextTrafficPermitted=\"false\">\n")
                    append("    <domain includeSubdomains=\"${d.includeSubdomains}\">${d.host}</domain>\n")
                    append("    <pin-set expiration=\"2027-03-31\">\n")
                    for (p in d.pins + d.backupPins) append("      <pin digest=\"SHA-256\">${p.removePrefix("sha256/")}</pin>\n")
                    append("    </pin-set>\n    <trust-anchors>\n      <certificates src=\"system\"/>\n    </trust-anchors>\n")
                    append("  </domain-config>\n")
                }
                append("</network-security-config>\n")
            }
            val module = linked("golden-$i", "", STRINGS + mapOf("xml/${NetworkPinning.RESOURCE_NAME}.xml" to source)).toMap()
            val expected = strip(Resources.XmlNode.parseFrom(module.getValue(NetworkPinning.RESOURCE_PATH)))
            assertEquals("cleartext $cleartext", expected, NetworkSecurityConfigXml.build(two, cleartext))
        }
    }

    @Test fun appliesToAnAabWithANewXmlTypeAndBundletoolAcceptsIt() {
        val out = work.resolve("apply-new-type")
        val (code, _, err) = apply(resAab, out)
        assertEquals(err, 0, code)
        val output = out.resolve("res-app.lab.aab")
        val c = control(out)
        assertEquals("applied", c.get("status").asString)
        assertEquals(listOf("res.xml.added:base/${NetworkPinning.RESOURCE_PATH}", "resources.entry.added:xml/${NetworkPinning.RESOURCE_NAME}",
            "manifest.network-security-config.set:@xml/${NetworkPinning.RESOURCE_NAME}"), changes(c))
        val evidence = c.getAsJsonObject("evidence")
        assertEquals(setOf("domains", "expiration", "sectionSha256", "cleartextBase"), evidence.keySet())
        assertEquals("1", evidence.get("domains").asString)
        assertEquals("2027-03-31", evidence.get("expiration").asString)
        assertEquals("absent", evidence.get("cleartextBase").asString)
        // JCS of the section (members sorted, no whitespace), the same bytes as Python's sorted compact json.dumps.
        val jcs = """{"domains":[{"backupPins":["$PIN_B"],"host":"lab-pin.sentomaru.com.br","includeSubdomains":false,"pins":["$PIN_A"]}],"expiration":"2027-03-31","version":"1"}"""
        assertEquals(java.security.MessageDigest.getInstance("SHA-256").digest(jcs.toByteArray()).joinToString("") { "%02x".format(it) },
            evidence.get("sectionSha256").asString)
        assertFalse(warnings(out).contains("network-pinning-cleartext-blocked"))

        // Every source entry is kept byte for byte, except the manifest and resources.pb; one entry is added.
        val before = entries(resAab).toMap()
        val after = entries(output).toMap()
        assertEquals(before.keys + "base/${NetworkPinning.RESOURCE_PATH}", after.keys)
        for ((n, b) in before) if (n != AabInjector.MANIFEST && n != AabInjector.RESOURCES) assertArrayEquals(n, b, after[n])

        // Resource table: the existing types and entries are unchanged; a new xml type with the first free id.
        val t0 = Resources.ResourceTable.parseFrom(before.getValue(AabInjector.RESOURCES))
        val t1 = Resources.ResourceTable.parseFrom(after.getValue(AabInjector.RESOURCES))
        val p0 = t0.getPackage(0); val p1 = t1.getPackage(0)
        assertEquals(p0.typeCount + 1, p1.typeCount)
        for (type in p0.typeList) assertEquals(type, p1.typeList.single { it.typeId.id == type.typeId.id })
        val xml = p1.typeList.single { it.name == "xml" }
        val freeType = (1..255).first { id -> p0.typeList.none { it.typeId.id == id } }
        assertEquals(freeType, xml.typeId.id)
        assertEquals(0, xml.getEntry(0).entryId.id)
        assertEquals(NetworkPinning.RESOURCE_PATH, xml.getEntry(0).getConfigValue(0).value.item.file.path)
        assertEquals(t0.toBuilder().clearPackage().build(), t1.toBuilder().clearPackage().build()) // pool, fingerprint
        val resourceId = (0x7f shl 24) or (freeType shl 16)

        // Manifest: only the attribute, in resource-id order, and shaped as aapt2 links it.
        val m0 = Resources.XmlNode.parseFrom(before.getValue(AabInjector.MANIFEST))
        val m1 = Resources.XmlNode.parseFrom(after.getValue(AabInjector.MANIFEST))
        val app1 = m1.element.childList.single { it.hasElement() && it.element.name == "application" }.element
        val attr = app1.attributeList.single { it.name == "networkSecurityConfig" }
        val ids = app1.attributeList.map { it.resourceId }
        assertEquals(ids.sortedWith { a, b -> Integer.compareUnsigned(a, b) }, ids)
        assertEquals(m0.element.childCount, m1.element.childCount)
        assertEquals(app1.childCount, m0.element.childList.single { it.hasElement() && it.element.name == "application" }.element.childCount)
        val linkedApp = Resources.XmlNode.parseFrom(linked("golden-manifest", "android:networkSecurityConfig=\"@xml/${NetworkPinning.RESOURCE_NAME}\"",
            STRINGS + mapOf("xml/${NetworkPinning.RESOURCE_NAME}.xml" to "<network-security-config/>")).toMap()
            .getValue("manifest/AndroidManifest.xml")).element.childList.single { it.hasElement() && it.element.name == "application" }.element
        val aapt2Attr = linkedApp.attributeList.single { it.name == "networkSecurityConfig" }.toBuilder().clearSource()
        aapt2Attr.compiledItemBuilder.refBuilder.id = resourceId
        assertEquals(aapt2Attr.build(), attr)

        // Reproducible.
        val again = work.resolve("apply-new-type-again")
        assertEquals(0, apply(resAab, again).first)
        assertEquals(report(out).getAsJsonObject("output").get("sha256"), report(again).getAsJsonObject("output").get("sha256"))

        // bundletool and aapt2 on the APK built from it.
        bundletool("validate", "--bundle=${output.path}")
        val apk = universal(output, "new-type")
        val tree = aapt2("dump", "xmltree", "--file", NetworkPinning.RESOURCE_PATH, apk.path)
        for (expected in listOf("E: network-security-config", "E: domain-config", "A: cleartextTrafficPermitted=false",
                "A: includeSubdomains=false", "T: 'lab-pin.sentomaru.com.br'", "A: expiration=\"2027-03-31\"", "A: digest=\"SHA-256\"",
                "T: '${PIN_A.removePrefix("sha256/")}'", "T: '${PIN_B.removePrefix("sha256/")}'", "A: src=\"system\""))
            assertTrue("$expected in\n$tree", tree.contains(expected))
        assertFalse(tree, tree.contains("base-config") || tree.contains("debug-overrides") || tree.contains("user"))
        val manifest = aapt2("dump", "xmltree", "--file", "AndroidManifest.xml", apk.path)
        assertTrue(manifest, manifest.contains("networkSecurityConfig") && manifest.contains("@0x%08x".format(resourceId)))
        val resources = aapt2("dump", "resources", apk.path)
        assertTrue(resources, resources.contains("resource 0x%08x xml/${NetworkPinning.RESOURCE_NAME}".format(resourceId)))
        assertTrue(resources, resources.contains(NetworkPinning.RESOURCE_PATH))
    }

    private fun universal(aab: File, name: String): File {
        val apks = work.resolve("$name.apks")
        bundletool("build-apks", "--bundle=${aab.path}", "--output=${apks.path}", "--mode=universal",
            "--ks=${keystore.path}", "--ks-key-alias=fixture", "--ks-pass=pass:$STORE_PASS", "--aapt2=${buildTools.resolve("aapt2").path}")
        return work.resolve("$name.apk").also { f -> ZipFile(apks).use { z -> z.getInputStream(z.getEntry("universal.apk")).use { f.writeBytes(it.readBytes()) } } }
    }

    @Test fun anExistingXmlTypeGetsTheFirstFreeEntryAndTwoDomainsWithSubdomains() {
        val out = work.resolve("apply-xml-type")
        val section = pinning(domains = domain() + "," + domain("api.example.com", sub = true, pins = "\"$PIN_C\""))
        assertEquals(0, apply(xmlAab, out, section).first)
        val output = out.resolve("xml-app.lab.aab")
        val t0 = Resources.ResourceTable.parseFrom(bundleEntry(xmlAab, AabInjector.RESOURCES)).getPackage(0)
        val t1 = Resources.ResourceTable.parseFrom(bundleEntry(output, AabInjector.RESOURCES)).getPackage(0)
        assertEquals(t0.typeCount, t1.typeCount)
        val x0 = t0.typeList.single { it.name == "xml" }; val x1 = t1.typeList.single { it.name == "xml" }
        assertEquals(x0.typeId, x1.typeId)
        assertEquals(x0.entryList, x1.entryList.filter { it.name != NetworkPinning.RESOURCE_NAME })
        assertEquals(2, x1.entryList.single { it.name == NetworkPinning.RESOURCE_NAME }.entryId.id)
        assertEquals("2", control(out).getAsJsonObject("evidence").get("domains").asString)
        bundletool("validate", "--bundle=${output.path}")
        val apk = universal(output, "xml-type")
        val tree = aapt2("dump", "xmltree", "--file", NetworkPinning.RESOURCE_PATH, apk.path)
        assertTrue(tree, tree.contains("T: 'api.example.com'") && tree.contains("A: includeSubdomains=true"))
        val resources = aapt2("dump", "resources", apk.path)
        for (name in listOf("xml/prefs", "xml/backup", "xml/${NetworkPinning.RESOURCE_NAME}")) assertTrue(resources, resources.contains(name))
    }

    @Test fun cleartextIsCopiedToTheBaseConfigAndWarned() {
        val out = work.resolve("apply-cleartext")
        assertEquals(0, apply(cleartextAab, out).first)
        assertTrue(warnings(out).contains("network-pinning-cleartext-blocked"))
        assertEquals("true", control(out).getAsJsonObject("evidence").get("cleartextBase").asString)
        val xml = Resources.XmlNode.parseFrom(bundleEntry(out.resolve("cleartext-app.lab.aab"), "base/${NetworkPinning.RESOURCE_PATH}"))
        val first = xml.element.getChild(0).element
        assertEquals("base-config", first.name)
        assertEquals("true", first.getAttribute(0).value)
        assertTrue(first.getAttribute(0).compiledItem.prim.booleanValue)
        assertEquals("domain-config", xml.element.getChild(1).element.name)
        // usesCleartextTraffic stays in the manifest (the platform ignores it when a configuration is present).
        bundletool("validate", "--bundle=${out.resolve("cleartext-app.lab.aab").path}")
    }

    @Test fun theHostsMetaDataOnlyWithTheSdkAndTogetherWithTheRuntime() {
        val out = work.resolve("apply-sdk")
        val section = """"runtime-injection":{"version":"1","enrollmentUrl":"$URL"},""" +
            pinning(domains = domain() + "," + domain("api.example.com", pins = "\"$PIN_C\""))
        val (code, _, err) = apply(sdkAab, out, section)
        assertEquals(err, 0, code)
        val controls = report(out).getAsJsonArray("controls").map { it.asJsonObject }
        assertEquals(listOf("runtime-injection" to "applied", "network-pinning" to "applied"),
            controls.map { it.get("id").asString to it.get("status").asString })
        assertTrue(changes(controls[1]).contains("manifest.meta-data.added:${NetworkPinning.HOSTS_META_DATA}"))
        val output = out.resolve("sdk-app.lab.aab")
        bundletool("validate", "--bundle=${output.path}")
        val dump = bundletool("dump", "manifest", "--bundle=${output.path}", "--module=base")
        assertTrue(dump, dump.contains("android:name=\"${NetworkPinning.HOSTS_META_DATA}\""))
        assertTrue(dump, dump.contains("android:value=\"lab-pin.sentomaru.com.br,api.example.com\""))
        assertTrue(dump, dump.contains("android:name=\"${RuntimeInjection.PROVIDER}\""))
        assertTrue(dump, dump.contains("android:networkSecurityConfig=\"@xml/${NetworkPinning.RESOURCE_NAME}\""))
        assertTrue(ZipFile(output).use { it.getEntry("base/dex/classes2.dex") != null })
        // Without the SDK: no meta-data.
        val plain = work.resolve("apply-plain")
        assertEquals(0, apply(resAab, plain).first)
        assertFalse(bundletool("dump", "manifest", "--bundle=${plain.resolve("res-app.lab.aab").path}", "--module=base")
            .contains(NetworkPinning.HOSTS_META_DATA))
    }

    @Test fun aRegisteredRunAppliesItWithoutTheGate() {
        FakeRegistry().use { registry ->
            val out = work.resolve("apply-real")
            val (code, _, err) = run("--input", resAab.path, "--profile", profile(pinning()).path, "--out", out.path,
                env = mapOf("SENTOMARU_BUILDER_TOKEN" to "builder-token-fixture", "SENTOMARU_API" to registry.address.toString()))
            assertEquals(err, 0, code)
            assertEquals("applied", control(out).get("status").asString)
            assertEquals("protected", registry.calls.last().body.get("result").asString)
            bundletool("validate", "--bundle=${out.resolve("res-app.protected.aab").path}")
        }
    }

    @Test fun theDryRunPlansTheSameChangesAndEvidence() {
        for (input in listOf(resAab, sdkAab, cleartextAab)) {
            val d = work.resolve("same-dry-${input.name}"); val a = work.resolve("same-apply-${input.name}")
            assertEquals(0, dry(input, d).first)
            assertEquals(0, apply(input, a).first)
            assertEquals("planned", control(d).get("status").asString)
            assertEquals(changes(control(d)), changes(control(a)))
            assertEquals(control(d).get("evidence"), control(a).get("evidence"))
            assertEquals(warnings(d), warnings(a).filter { it != "lab-unregistered" })
        }
    }

    // ---- refusals (exit 5) and the already-protected bundle

    @Test fun refusalsAreAppIncompatibleInTheDryRunAndTheRealRun() {
        for ((input, detail) in listOf(nscAab to NetworkPinning.NSC_PRESENT, noTableAab to NetworkPinning.RESOURCE_TABLE_UNSUPPORTED)) {
            refused(5, "app-incompatible", detail, dry(input, work.resolve("refuse-dry-${input.name}")))
            val out = work.resolve("refuse-lab-${input.name}")
            refused(5, "app-incompatible", detail, apply(input, out))
            assertEquals(listOf("report.json"), out.list()!!.toList())
        }
        for ((input, detail) in listOf(metaDataAab to NetworkPinning.NSC_PRESENT, referenceAab to NetworkPinning.CLEARTEXT_UNSUPPORTED,
                takenPathAab to NetworkPinning.RESOURCE_TABLE_UNSUPPORTED)) {
            refused(5, "app-incompatible", detail, dry(input, work.resolve("refuse2-dry-${input.name}")))
            refused(5, "app-incompatible", detail, apply(input, work.resolve("refuse2-lab-${input.name}")))
        }
        refused(3, "input-format", "unreadable resource table", dry(garbageTableAab, work.resolve("refuse-garbage")))
        // A bundletool failure after the edit leaves nothing in <out>.
        try {
            AabInjector.validate = { throw IllegalStateException("forced") }
            val out = work.resolve("refuse-validate")
            refused(6, "control-failed", "network-pinning: bundletool validation (IllegalStateException)", apply(resAab, out))
            assertEquals(listOf("report.json"), out.list()!!.toList())
        } finally {
            AabInjector.validate = { p -> com.android.tools.build.bundletool.commands.ValidateBundleCommand.builder().setBundlePath(p)
                .setPrintOutput(false).build().execute() }
        }
        // Already protected: the output again is refused, not pinned twice (also with the runtime, which is refused first).
        val first = work.resolve("protected-once").also { assertEquals(0, apply(resAab, it).first) }
        val protected = first.resolve("res-app.lab.aab")
        refused(5, "app-incompatible", NetworkPinning.NSC_PRESENT, apply(protected, work.resolve("protected-twice")))
        refused(5, "app-incompatible", NetworkPinning.NSC_PRESENT, dry(protected, work.resolve("protected-twice-dry")))
        // The profile is checked before the app (precedence): a bad section on an incompatible app is 4.
        refused(4, "profile-format", "network-pinning.expiration", dry(nscAab, work.resolve("refuse-order"), pinning("2020-01-01")))
    }

    @Test fun resourceTablesOutsideThePatternAreRefused() {
        val table = Resources.ResourceTable.parseFrom(bundleEntry(resAab, AabInjector.RESOURCES))
        fun refusedSlot(t: Resources.ResourceTable) = try {
            ResourceTables.slot(t); false
        } catch (e: ProtectException) {
            e.error == ErrorCode.APP_INCOMPATIBLE && e.detail == NetworkPinning.RESOURCE_TABLE_UNSUPPORTED
        }
        val pkg = table.getPackage(0)
        assertTrue(refusedSlot(table.toBuilder().clearPackage().build()))
        assertTrue(refusedSlot(table.toBuilder().addPackage(pkg).build()))
        assertTrue(refusedSlot(table.toBuilder().setPackage(0, pkg.toBuilder().setPackageId(Resources.PackageId.newBuilder().setId(0x7e))).build()))
        val xmlType = Resources.Type.newBuilder().setTypeId(Resources.TypeId.newBuilder().setId(9)).setName("xml")
        for (name in listOf(NetworkPinning.RESOURCE_NAME, NetworkPinning.RESOURCE_NAME + "_debug"))
            assertTrue(refusedSlot(table.toBuilder().setPackage(0, pkg.toBuilder().addType(xmlType.clone()
                .addEntry(Resources.Entry.newBuilder().setEntryId(Resources.EntryId.newBuilder().setId(0)).setName(name)))).build()))
        val full = pkg.toBuilder().clearType()
        for (id in 1..255) full.addType(Resources.Type.newBuilder().setTypeId(Resources.TypeId.newBuilder().setId(id)).setName("t$id"))
        assertTrue(refusedSlot(table.toBuilder().setPackage(0, full).build()))
        assertFalse(refusedSlot(table))
        // Above the byte limit: refused before parsing.
        val big = work.resolve("big-table.zip").also { zip(it, listOf("base/resources.pb" to ByteArray(ResourceTables.MAX_BYTES + 1))) }
        ZipFile(big).use { z ->
            val e = try { ResourceTables.read(z, z.getEntry("base/resources.pb")); null } catch (x: ProtectException) { x }
            assertEquals(NetworkPinning.RESOURCE_TABLE_UNSUPPORTED, e?.detail)
        }
    }

    @Test fun theProfileExampleOfTheContractIsAcceptedWithAFixedClock() {
        val example = File(System.getProperty("user.dir")).resolve("../../../contracts/devsecops/examples/protect-profile-network-pinning-v1.example.json")
        val out = work.resolve("example")
        val (code, _, err) = run("--input", resAab.path, "--profile", example.canonicalPath, "--out", out.path, "--dry-run", "--sign", "none")
        assertEquals(err, 0, code)
        assertEquals("planned", control(out).get("status").asString)
    }

    @Test fun jcsEscapesLikeJsonStringify() {
        val o = JsonParser.parseString("""{"b":"\u0001\n\"\\é\u2028","a":[true,false,{"z":"","é":"x","e":"y"}]}""")
        assertEquals("{\"a\":[true,false,{\"e\":\"y\",\"z\":\"\",\"é\":\"x\"}],\"b\":\"\\u0001\\n\\\"\\\\é\u2028\"}", Jcs.canonical(o))
        assertTrue(NetworkPinning.canonical(PIN_A))
        assertFalse(NetworkPinning.canonical("sha256/" + "A".repeat(42) + "B="))
    }
}
