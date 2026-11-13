package br.com.ebees.sentomaru.protect

import com.android.apksig.ApkVerifier
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.BeforeClass
import org.junit.Test
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Files
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

/**
 * G-03b3: a real run on an APK. The fixtures are built at test time with the SDK's aapt2 (a binary-manifest APK with
 * activities, a stored `resources.arsc` and a stored native library) and signed with apksig and a key generated for the
 * run. The output is checked three ways: the CLI's own reader, apksig, and `aapt2 dump` (the platform tool that reads the
 * binary manifest the way the installer does). Installing it on a device is NOT done here.
 */
class ApkInjectionTest {
    companion object {
        private lateinit var work: File
        private lateinit var keystore: File
        private lateinit var apk: File            // signed v2/v3, stored resources.arsc and a stored .so
        private lateinit var apkWithOverlay: File // declares HIDE_OVERLAY_WINDOWS
        private lateinit var apkWithoutDex: File
        private const val STORE_PASS = "fixture-only"
        private const val URL = "https://api.example/v1/ebees/exampleapp/hml/installations"
        private const val PKG = "br.com.example.fixture"
        private val SO = ByteArray(5000) { (it * 7).toByte() }

        private fun exec(vararg cmd: String): String {
            val p = ProcessBuilder(*cmd).redirectErrorStream(true).start()
            val log = p.inputStream.bufferedReader().readText()
            check(p.waitFor() == 0) { "${cmd.take(3)} failed: $log" }
            return log
        }

        private fun tools(): Pair<File, File> = ProtectCliTest.sdkToolPublic()

        private fun manifest(extraPermission: String) = """
            <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="$PKG"
                android:versionCode="42" android:versionName="1.2">
              <uses-sdk android:minSdkVersion="28" android:targetSdkVersion="35"/>
              <uses-permission android:name="android.permission.INTERNET"/>
              $extraPermission
              <application android:label="fixture">
                <activity android:name=".Main" android:exported="true"/>
                <activity android:name="$PKG.pay.PayActivity"/>
              </application>
            </manifest>
        """.trimIndent()

        private fun stored(out: ZipOutputStream, name: String, bytes: ByteArray) {
            val e = ZipEntry(name).apply { method = ZipEntry.STORED; size = bytes.size.toLong(); compressedSize = bytes.size.toLong()
                crc = CRC32().also { it.update(bytes) }.value }
            out.putNextEntry(e); out.write(bytes); out.closeEntry()
        }

        private fun buildApk(name: String, extraPermission: String, withDex: Boolean = true): File {
            val (aapt2, platform) = tools()
            val dir = work.resolve(name).apply { mkdirs() }
            val m = dir.resolve("AndroidManifest.xml").apply { writeText(manifest(extraPermission)) }
            val linked = dir.resolve("linked.zip")
            exec(aapt2.path, "link", "-o", linked.path, "-I", platform.path, "--manifest", m.path)
            val manifestBytes = ZipFile(linked).use { it.getInputStream(it.getEntry("AndroidManifest.xml")).readBytes() }
            val arsc = ZipFile(linked).use { z -> z.getEntry("resources.arsc")?.let { z.getInputStream(it).readBytes() } } ?: ByteArray(64)
            val unsigned = work.resolve("$name-unsigned.apk")
            ZipOutputStream(unsigned.outputStream()).use { z ->
                z.putNextEntry(ZipEntry("AndroidManifest.xml")); z.write(manifestBytes); z.closeEntry()
                if (withDex) { z.putNextEntry(ZipEntry("classes.dex")); z.write(ProtectCliTest.appDex); z.closeEntry() }
                stored(z, "resources.arsc", arsc)
                stored(z, "lib/arm64-v8a/libfixture.so", SO)
                stored(z, "assets/odd.bin", ByteArray(333) { it.toByte() })
            }
            return sign(unsigned, work.resolve("$name.apk"))
        }

        private fun sign(unsigned: File, target: File): File {
            val ks = KeyStore.getInstance("PKCS12").apply { keystore.inputStream().use { load(it, STORE_PASS.toCharArray()) } }
            val key = ks.getKey("fixture", STORE_PASS.toCharArray()) as java.security.PrivateKey
            val cert = ks.getCertificate("fixture") as X509Certificate
            com.android.apksig.ApkSigner.Builder(listOf(com.android.apksig.ApkSigner.SignerConfig.Builder("fixture",
                com.android.apksig.KeyConfig.Jca(key), listOf(cert)).build())).setInputApk(unsigned).setOutputApk(target).build().sign()
            return target
        }

        @BeforeClass @JvmStatic fun fixtures() {
            work = Files.createTempDirectory("protect-apk").toFile()
            keystore = work.resolve("fixture.p12")
            exec(File(System.getProperty("java.home"), "bin/keytool").path, "-genkeypair", "-keystore", keystore.path, "-storetype", "PKCS12",
                "-storepass", STORE_PASS, "-alias", "fixture", "-keyalg", "EC", "-groupname", "secp256r1", "-validity", "2", "-dname", "CN=fixture")
            apk = buildApk("app", "")
            apkWithOverlay = buildApk("overlay", """<uses-permission android:name="android.permission.HIDE_OVERLAY_WINDOWS"/>""")
            apkWithoutDex = buildApk("nodex", "", withDex = false)
        }
    }

    private val token = "builder-token-" + java.util.UUID.randomUUID()
    private val runtime = """"runtime-injection":{"version":"1","enrollmentUrl":"$URL"}"""
    private fun shield(hide: Boolean = true) = """"ui-shield":{"version":"1","mode":"listed_only","activities":["$PKG.Main"],"hideOverlayWindows":$hide}"""

    private val pinning = """"network-pinning":{"version":"1","expiration":"2027-03-31","domains":[{"host":"lab-pin.sentomaru.com.br",
            "includeSubdomains":false,"pins":["sha256/wiHsTSryBCSSgeMtp2iGevQhCi4C1T6dp5yPxEgMS5s="],
            "backupPins":["sha256/jl0tsLo4WkI1z7aBKcSTL/z72E7fhJsNkpqjetYrShI="]}]}"""

    private fun profile(controls: String) = work.resolve("profile-${controls.hashCode()}.json").apply {
        writeText("""{"schemaVersion":"1","kind":"protect","profileId":"fixture-protect",
            "scope":{"organization":"ebees","app":"exampleapp","environment":"prod"},"controls":{$controls}}""")
    }

    private fun run(vararg args: String, env: Map<String, String> = emptyMap()): Triple<Int, String, String> {
        val out = StringBuilder(); val err = StringBuilder()
        val code = Cli.run(args.toList(), env, { out.append(it) }, { err.append(it) })
        return Triple(code, out.toString(), err.toString())
    }

    private fun real(registry: FakeRegistry, input: File, out: File, controls: String, vararg sign: String, env: Map<String, String> = emptyMap()) =
        run("--input", input.path, "--profile", profile(controls).path, "--out", out.path, *sign,
            env = mapOf("SENTOMARU_BUILDER_TOKEN" to token, "SENTOMARU_API" to registry.address.toString()) + env)

    private fun sign() = arrayOf("--sign", "keystore", "--keystore", keystore.path, "--key-alias", "fixture")
    private val pass = mapOf("SENTOMARU_KEYSTORE_PASSWORD" to STORE_PASS)

    private fun report(out: File): JsonObject = JsonParser.parseString(out.resolve("report.json").readText()).asJsonObject
    private fun dump(apkFile: File, vararg what: String) = exec(tools().first.path, "dump", *what, apkFile.path)

    private fun entries(file: File) = ZipFile(file).use { z -> z.entries().toList().associate { it.name to z.getInputStream(it).readBytes() } }

    /** Data offset of every stored entry, read from the central directory and the local headers (not from the Java API). */
    private fun storedOffsets(file: File): Map<String, Long> {
        val bytes = file.readBytes()
        val b = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        var eocd = bytes.size - 22
        while (eocd >= 0 && b.getInt(eocd) != 0x06054b50) eocd--
        check(eocd >= 0) { "no end of central directory" }
        var at = b.getInt(eocd + 16)
        val result = LinkedHashMap<String, Long>()
        repeat(b.getShort(eocd + 10).toInt() and 0xffff) {
            check(b.getInt(at) == 0x02014b50)
            val method = b.getShort(at + 10).toInt()
            val nameLength = b.getShort(at + 28).toInt() and 0xffff
            val extraLength = b.getShort(at + 30).toInt() and 0xffff
            val commentLength = b.getShort(at + 32).toInt() and 0xffff
            val local = b.getInt(at + 42)
            val name = String(bytes, at + 46, nameLength, Charsets.UTF_8)
            if (method == 0) result[name] = (local + 30 + (b.getShort(local + 26).toInt() and 0xffff) + (b.getShort(local + 28).toInt() and 0xffff)).toLong()
            at += 46 + nameLength + extraLength + commentLength
        }
        return result
    }

    @Test fun axmlRoundTripKeepsTheManifestReadable() {
        val bytes = ZipFile(apk).use { it.getInputStream(it.getEntry("AndroidManifest.xml")).readBytes() }
        val again = Axml.parse(bytes).toBytes()
        assertEquals(ArtifactReader.binaryManifest(bytes).permissions, ArtifactReader.binaryManifest(again).permissions)
        assertEquals(PKG, ArtifactReader.binaryManifest(again).packageName)
        assertEquals(28, ArtifactReader.binaryManifest(again).minSdk)
        assertEquals(dumpManifest(bytes), dumpManifest(again))
    }

    private fun dumpManifest(bytes: ByteArray): String {
        val f = Files.createTempFile(work.toPath(), "m", ".xml").toFile()
        ZipOutputStream(f.outputStream()).use { z -> z.putNextEntry(ZipEntry("AndroidManifest.xml")); z.write(bytes); z.closeEntry() }
        return dump(f, "xmltree", "--file", "AndroidManifest.xml")
    }

    @Test fun aRealRunInjectsTheRuntimeSignsAndRegisters() {
        FakeRegistry().use { registry ->
            val out = work.resolve("out-real")
            val (code, stdout, err) = real(registry, apk, out, runtime, *sign(), env = pass)
            assertEquals(err, 0, code)
            assertFalse(stdout.contains(token))
            val protected = out.resolve("app.protected.apk")
            assertTrue(protected.isFile)
            // apksig verifies the v3 scheme (minSdk is 28 or more: it reports v3 and no v1; v2 is not reported separately) and the CLI's reader agrees on the certificate.
            val verified = ApkVerifier.Builder(protected).build().verify()
            assertTrue(verified.errors.toString(), verified.isVerified)
            assertTrue("v1=${verified.isVerifiedUsingV1Scheme} v2=${verified.isVerifiedUsingV2Scheme} v3=${verified.isVerifiedUsingV3Scheme}",
                verified.isVerifiedUsingV3Scheme && !verified.isVerifiedUsingV1Scheme)
            val facts = ArtifactReader.read(protected)
            assertTrue(facts.manifest.declaresSentomaruProvider)
            val certSha = MessageDigest.getInstance("SHA-256").digest(
                KeyStore.getInstance("PKCS12").apply { keystore.inputStream().use { load(it, STORE_PASS.toCharArray()) } }.getCertificate("fixture").encoded)
                .joinToString("") { "%02x".format(it) }
            assertEquals(certSha, facts.signingCertSha256)
            // The platform tool reads the binary manifest: the provider, its authority, exported=false and the meta-data.
            val tree = dump(protected, "xmltree", "--file", "AndroidManifest.xml")
            assertTrue(tree, tree.contains("E: provider"))
            assertTrue(tree, tree.contains("\"${RuntimeInjection.PROVIDER}\""))
            assertTrue(tree, tree.contains("\"$PKG.sentomaru-init\""))
            assertTrue(tree.substringAfter("E: provider").take(1200), Regex("""exported\(0x01010010\)=false""").containsMatchIn(tree))
            assertTrue(tree, tree.contains("\"${AabInjector.ENROLLMENT_URL_KEY}\"") && tree.contains("\"$URL\""))
            assertTrue(dump(protected, "badging").contains("package: name='$PKG'"))
            // Entries: the input's, byte for byte, plus classes2.dex = the runtime; no v1 signature files.
            val before = entries(apk)
            val after = entries(protected)
            assertEquals(before.keys.filter { !it.startsWith("META-INF/") && it != "AndroidManifest.xml" }.toSet() + "classes2.dex" + "AndroidManifest.xml",
                after.keys.filter { !it.startsWith("META-INF/") }.toSet())
            for (name in before.keys.filter { !it.startsWith("META-INF/") && it != "AndroidManifest.xml" }) assertArrayEquals(name, before.getValue(name), after.getValue(name))
            assertArrayEquals(AabInjector.runtimeDex, after.getValue("classes2.dex"))
            assertNotEquals(before.getValue("AndroidManifest.xml").toList(), after.getValue("AndroidManifest.xml").toList())
            assertTrue(after.keys.none { it.matches(Regex("""META-INF/[^/]+\.(SF|RSA|DSA|EC)""")) })
            // Alignment like zipalign: stored entries at 4 bytes, the stored native library at 16 KiB.
            val offsets = storedOffsets(protected)
            assertTrue(offsets.keys.containsAll(listOf("resources.arsc", "lib/arm64-v8a/libfixture.so", "assets/odd.bin")))
            for ((name, at) in offsets) assertEquals("$name at $at", 0L, at % (if (name.endsWith(".so")) 16384 else 4))
            // The report and the registration.
            val r = report(out)
            assertEquals("apk", r.getAsJsonObject("input").get("kind").asString)
            val output = r.getAsJsonObject("output")
            assertTrue(output.get("signed").asBoolean)
            assertEquals(certSha, output.get("signingCertSha256").asString)
            assertEquals(("applied" to "keystore"), r.getAsJsonObject("signing").let { it.get("status").asString to it.get("mode").asString })
            val control = r.getAsJsonArray("controls").first { it.asJsonObject.get("id").asString == "runtime-injection" }.asJsonObject
            assertEquals("applied", control.get("status").asString)
            assertEquals(listOf("dex.added:classes2.dex", "manifest.provider.added:${RuntimeInjection.PROVIDER}"),
                control.getAsJsonArray("changes").map { it.asJsonObject.get("id").asString + ":" + it.asJsonObject.get("target").asString })
            assertEquals(AabInjector.runtimeDexSha256, control.getAsJsonObject("evidence").get("runtimeDexSha256").asString)
            assertEquals("registered", r.getAsJsonObject("registration").get("status").asString)
            assertEquals(output.get("sha256").asString, registry.calls.last().body.get("outputSha256").asString)
            assertEquals("apk", registry.calls.last().body.get("inputKind").asString)
            assertTrue(r.getAsJsonArray("warnings").map { it.asJsonObject.get("code").asString }.contains("input-signature-removed"))
        }
    }

    @Test fun uiShieldAddsItsMetaDataAndTheOverlayPermissionOnlyWhenMissing() {
        FakeRegistry().use { registry ->
            val out = work.resolve("out-shield")
            val (code, _, err) = real(registry, apk, out, "$runtime,${shield(hide = true)}", *sign(), env = pass)
            assertEquals(err, 0, code)
            val protected = out.resolve("app.protected.apk")
            val tree = dump(protected, "xmltree", "--file", "AndroidManifest.xml")
            assertTrue(tree, tree.contains("\"${UiShieldControl.MODE_KEY}\"") && tree.contains("\"listed_only\""))
            assertTrue(tree, tree.contains("\"${UiShieldControl.ACTIVITIES_KEY}\"") && tree.contains("\"$PKG.Main\""))
            assertTrue(tree, tree.contains("\"${UiShieldControl.HIDE_OVERLAY_KEY}\"") && tree.contains("\"true\""))
            assertTrue(tree, tree.contains("\"${UiShieldControl.OVERLAY_PERMISSION}\""))
            // The permission is a child of <manifest> before <application>, the meta-data are inside the init provider.
            assertTrue(tree, tree.indexOf(UiShieldControl.OVERLAY_PERMISSION) < tree.indexOf("E: application"))
            assertTrue(tree, tree.indexOf("E: provider") < tree.indexOf(UiShieldControl.MODE_KEY))
            assertTrue(ApkVerifier.Builder(protected).build().verify().isVerified)
            assertTrue(ArtifactReader.read(protected).manifest.permissions.contains(UiShieldControl.OVERLAY_PERMISSION))
            val shieldReport = report(out).getAsJsonArray("controls").first { it.asJsonObject.get("id").asString == "ui-shield" }.asJsonObject
            assertEquals(listOf("manifest.meta-data.added:ui-shield", "manifest.permission.added:${UiShieldControl.OVERLAY_PERMISSION}"),
                shieldReport.getAsJsonArray("changes").map { it.asJsonObject.get("id").asString + ":" + it.asJsonObject.get("target").asString })
            // Already declared: not declared twice. Not asked: not declared at all.
            val declared = work.resolve("out-shield-declared")
            assertEquals(0, real(registry, apkWithOverlay, declared, "$runtime,${shield(hide = true)}", *sign(), env = pass).first)
            val twice = dump(declared.resolve("overlay.protected.apk"), "xmltree", "--file", "AndroidManifest.xml")
            assertEquals(twice, 1, Regex(Regex.escape("0x01010003)=\"${UiShieldControl.OVERLAY_PERMISSION}\"")).findAll(twice).count())
            val quiet = work.resolve("out-shield-quiet")
            assertEquals(0, real(registry, apk, quiet, "$runtime,${shield(hide = false)}", *sign(), env = pass).first)
            assertFalse(dump(quiet.resolve("app.protected.apk"), "xmltree", "--file", "AndroidManifest.xml").contains(UiShieldControl.OVERLAY_PERMISSION))
        }
    }

    @Test fun unsignedOutputKeepsNoSignatureAndWarns() {
        FakeRegistry().use { registry ->
            val out = work.resolve("out-none")
            val (code, _, err) = real(registry, apk, out, runtime, "--sign", "none")
            assertEquals(err, 0, code)
            val protected = out.resolve("app.protected.apk")
            assertFalse(report(out).getAsJsonObject("output").get("signed").asBoolean)
            val warnings = report(out).getAsJsonArray("warnings").map { it.asJsonObject.get("code").asString }
            assertTrue(warnings.toString(), warnings.containsAll(listOf("output-unsigned", "input-signature-removed")))
            // No signing block: apksig finds no scheme to verify.
            assertFalse(ApkVerifier.Builder(protected).build().verify().isVerified)
            assertTrue(dump(protected, "badging").contains("package: name='$PKG'"))
        }
    }

    @Test fun refusalsKeepTheirCodesAndLeaveNothingInOut() {
        FakeRegistry().use { registry ->
            fun refused(exit: Int, code: String, out: File, vararg args: String, controls: String = runtime, input: File = apk) {
                val (c, _, err) = real(registry, input, out, controls, *args, env = pass)
                assertEquals(err, exit, c)
                assertEquals(err, code, JsonParser.parseString(err).asJsonObject.get("code").asString)
                assertFalse(out.list().orEmpty().toList().toString(), out.list().orEmpty().any { it.endsWith(".apk") || it.endsWith(".tmp") || it.endsWith(".signing") })
            }
            // A control that does not edit an APK in this build.
            val previous = Cli.today
            Cli.today = { java.time.LocalDate.of(2026, 10, 26) }
            try {
                refused(6, "control-failed", work.resolve("o1"), *sign(), controls = "$runtime,$pinning")
            } finally {
                Cli.today = previous
            }
            // The OpenBao signer is a JAR signer.
            refused(2, "usage", work.resolve("o2"), "--sign", "openbao", "--openbao-addr", "https://vault.example", "--openbao-role", "r",
                "--openbao-transit", "transit/key", "--openbao-key", "cert.pem")
            // A wrong key alias or password is sign-failed, and the output is not left behind.
            refused(7, "sign-failed", work.resolve("o3"), "--sign", "keystore", "--keystore", keystore.path, "--key-alias", "missing")
            // An APK without any DEX is not an app the reader takes (and the injector would refuse it again).
            refused(3, "input-format", work.resolve("o4"), *sign(), input = apkWithoutDex)
            // Already protected: the second pass is refused before anything is written.
            val first = work.resolve("o5")
            assertEquals(0, real(registry, apk, first, runtime, *sign(), env = pass).first)
            refused(5, "app-incompatible", work.resolve("o6"), *sign(), input = first.resolve("app.protected.apk"))
        }
    }

    @Test fun aFailureWhileWritingLeavesNothingInOut() {
        FakeRegistry().use { registry ->
            val out = work.resolve("out-fail")
            ApkInjector.afterEntry = { if (it == "classes.dex") throw java.io.IOException("disk full") }
            try {
                val (code, _, err) = real(registry, apk, out, runtime, *sign(), env = pass)
                assertEquals(err, 1, code)
            } finally {
                ApkInjector.afterEntry = {}
            }
            assertFalse(out.list().orEmpty().toList().toString(), out.list().orEmpty().any { it.endsWith(".apk") || it.endsWith(".tmp") })
        }
    }

    @Test fun theDryRunStillPlansAnApkAndWritesNothing() {
        val out = work.resolve("out-dry")
        val (code, _, err) = run("--input", apk.path, "--profile", profile("$runtime,${shield()}").path, "--out", out.path, "--dry-run", "--sign", "none")
        assertEquals(err, 0, code)
        assertFalse(out.list().orEmpty().any { it.endsWith(".apk") })
    }

    @Test fun axmlRefusesAHostileManifestWithInputFormat() {
        val good = ZipFile(apk).use { it.getInputStream(it.getEntry("AndroidManifest.xml")).readBytes() }
        for (bad in listOf(good.copyOf(40), ByteArray(0), good.copyOf().also { it[0] = 9 },
            good.copyOf().also { ByteBuffer.wrap(it).order(ByteOrder.LITTLE_ENDIAN).putInt(12, Int.MAX_VALUE) })) {
            try {
                Axml.parse(bad)
                fail("parsed")
            } catch (e: ProtectException) {
                assertEquals(e.detail, ErrorCode.INPUT_FORMAT, e.error)
            }
        }
    }
}
