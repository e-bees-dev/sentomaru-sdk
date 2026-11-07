package br.com.ebees.sentomaru.protect

import br.com.ebees.sentomaru.sdk.sealed.SealedReader
import br.com.ebees.sentomaru.sdk.sealed.SealedSource
import br.com.ebees.sentomaru.sdk.sealed.SentomaruSealedException
import com.android.apksig.ApkSigner
import com.android.apksig.KeyConfig
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume
import org.junit.BeforeClass
import org.junit.Test
import java.io.File
import java.nio.file.Files
import java.security.KeyStore
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.UUID
import java.util.zip.Inflater
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * D-14c: `asset-encryption` on AABs built at test time (aapt2 proto link, a D8 DEX with stub classes named as the sealed
 * reader markers, bundletool build-bundle). What the CLI writes is checked three ways: against the shared vectors
 * (contracts/devsecops/sealed-v1-vectors.json) with the test-only randomness seam, by the D-14b reader itself
 * (`sdk/android/sealed`, compiled into this source set) on the output AAB and on the APKs bundletool builds from it,
 * and by searching per-run canaries, the `dek`, the `kek` and every file key in every byte of the output (zero hits).
 * The keys of every run are drawn in the test (the seam) or from SecureRandom; none is read from the machine.
 */
class AssetEncryptionTest {
    companion object {
        private lateinit var work: File
        private lateinit var buildTools: File
        private lateinit var androidJar: File
        private lateinit var keystore: File
        private lateinit var vectors: JsonObject
        private lateinit var androidVector: File
        private lateinit var flutterVector: File
        private lateinit var canaryApp: File
        private lateinit var canaryAppNextVersion: File
        private lateinit var canaries: Map<String, String>
        private val fixtures = HashMap<String, File>()
        private const val STORE_PASS = "fixture-only" // a key generated for this run and deleted with it
        private const val URL = "https://api.example/v1/ebees/sealed-lab/hml/installations"
        private const val ANDROID_READER = "br.com.ebees.sentomaru.sdk.sealed.SentomaruSealed"
        private const val FLUTTER_READER = "br.com.ebees.sentomaru.sentomaru_flutter.SentomaruFlutterSealed"
        private const val FIXTURE = "br.com.example.fixture"
        private val dexCache = HashMap<List<String>, ByteArray>()

        // D-14d: apktool is pinned by version and digest. The CI (sdk-core) fetches the official release jar, checks
        // the digest, and passes it in SENTOMARU_APKTOOL with SENTOMARU_APKTOOL_REQUIRED=1, so there the decode is
        // required: a missing jar or another digest FAILS the test. A jar named by SENTOMARU_APKTOOL with another digest
        // always fails. Only without either variable (a developer machine without the authorized local copy) does the
        // test skip with a reason; it never runs an unpinned tool. The local path is the owner's verified copy.
        private const val APKTOOL_VERSION = "3.0.3"
        private const val APKTOOL_SHA256 = "dbf930b076c6b9be08d57c449cacefc3bdd6b71ebd59b3066fc0e1f5b14f9423"
        private val APKTOOL_LOCAL = File(System.getProperty("user.home"),
            ".local/share/sentomaru-tools/apktool_$APKTOOL_VERSION.jar")

        private fun sha256(file: File): String =
            java.security.MessageDigest.getInstance("SHA-256").digest(file.readBytes()).joinToString("") { "%02x".format(it) }

        /**
         * The pinned apktool jar, or null when the test may skip (no variable set and no verified local copy). Named by
         * SENTOMARU_APKTOOL with another digest, or absent with SENTOMARU_APKTOOL_REQUIRED=1: an assertion failure.
         */
        private fun apktoolJar(): File? {
            val named = System.getenv("SENTOMARU_APKTOOL")?.takeIf { it.isNotEmpty() }?.let(::File)
            val required = System.getenv("SENTOMARU_APKTOOL_REQUIRED") == "1"
            val candidate = named ?: APKTOOL_LOCAL
            val ok = candidate.isFile && sha256(candidate) == APKTOOL_SHA256
            if (!ok && (named != null || required))
                fail("apktool $APKTOOL_VERSION required at sha256 $APKTOOL_SHA256: ${candidate.path} is " +
                    (if (candidate.isFile) "another digest" else "missing"))
            return candidate.takeIf { ok }
        }

        private fun exec(vararg cmd: String): String {
            val p = ProcessBuilder(*cmd).redirectErrorStream(true).start()
            val log = p.inputStream.bufferedReader().readText()
            check(p.waitFor() == 0) { "${cmd.take(4)} failed: $log" }
            return log
        }

        private fun java(): String = File(System.getProperty("java.home"), "bin/java").path
        private fun jdk(tool: String): String = File(System.getProperty("java.home"), "bin/$tool").path
        fun bundletool(vararg args: String): String = AabInjectionTest.bundletool(*args)

        internal fun zip(target: File, entries: List<Pair<String, ByteArray>>) = ZipOutputStream(target.outputStream()).use { z ->
            for ((n, bytes) in entries) { z.putNextEntry(ZipEntry(n)); z.write(bytes); z.closeEntry() }
        }

        internal fun entries(file: File) = ZipFile(file).use { z -> z.entries().toList().filter { !it.isDirectory }
            .map { it.name to z.getInputStream(it).readBytes() } }

        fun hex(s: String): ByteArray = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
        fun hex(b: ByteArray): String = b.joinToString("") { "%02x".format(it) }

        /** A real DEX (javac + D8) with the app class and a stub of each of [fqcns]. */
        private fun dex(vararg fqcns: String): ByteArray = dexCache.getOrPut(fqcns.toList()) {
            val dir = work.resolve("dex-${fqcns.joinToString("-") { it.substringAfterLast('.') }.ifEmpty { "app" }}")
            val classes = dir.resolve("classes").apply { mkdirs() }
            val srcs = (listOf("$FIXTURE.App") + fqcns).map { fqcn ->
                val pkg = fqcn.substringBeforeLast('.'); val simple = fqcn.substringAfterLast('.')
                dir.resolve("src/${pkg.replace('.', '/')}").apply { mkdirs() }.resolve("$simple.java").apply {
                    writeText(if (simple == "App") "package $pkg; public class App extends android.app.Application {}"
                        else "package $pkg; public final class $simple {}")
                }
            }
            exec(jdk("javac"), "--release", "11", "-cp", androidJar.path, "-d", classes.path, *srcs.map { it.path }.toTypedArray())
            val out = dir.resolve("out").apply { mkdirs() }
            exec(java(), "-cp", buildTools.resolve("lib/d8.jar").path, "com.android.tools.r8.D8", "--min-api", "28",
                "--lib", androidJar.path, "--output", out.path,
                *classes.walkTopDown().filter { it.isFile }.map { it.path }.toList().toTypedArray())
            out.resolve("classes.dex").readBytes()
        }

        private fun manifest(name: String, pkg: String, versionCode: String?, major: String?): File =
            work.resolve("manifest-$name.xml").apply { writeText("""
                <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="$pkg"
                    ${versionCode?.let { "android:versionCode=\"$it\"" } ?: ""} ${major?.let { "android:versionCodeMajor=\"$it\"" } ?: ""}
                    android:versionName="1.0">
                  <uses-sdk android:minSdkVersion="28" android:targetSdkVersion="35"/>
                  <uses-permission android:name="android.permission.INTERNET"/>
                  <application android:name="$FIXTURE.App" android:label="fixture"/>
                </manifest>""".trimIndent()) }

        /** An AAB (bundletool build-bundle) whose base module has [assets] (canonical path to bytes) and [readers]. */
        fun bundle(name: String, assets: Map<String, ByteArray>, readers: List<String> = listOf(ANDROID_READER),
            pkg: String = FIXTURE, versionCode: String? = "42", major: String? = null): File {
            val proto = work.resolve("linked-$name.zip")
            exec(buildTools.resolve("aapt2").path, "link", "--proto-format", "-o", proto.path, "-I", androidJar.path,
                "--manifest", manifest(name, pkg, versionCode, major).path)
            val withCode = if (versionCode == null) work.resolve("linked-$name-code.zip").also {
                exec(buildTools.resolve("aapt2").path, "link", "--proto-format", "-o", it.path, "-I", androidJar.path,
                    "--manifest", manifest("$name-code", pkg, "1", major).path)
            } else proto
            val module = entries(proto).map { (n, b) -> (if (n == "AndroidManifest.xml") "manifest/AndroidManifest.xml" else n) to b } +
                ("dex/classes.dex" to dex(*readers.toTypedArray())) + assets.map { (p, b) -> p to b }
            val buildable = if (versionCode == null) module.map { (n, b) -> n to if (n == "manifest/AndroidManifest.xml")
                ZipFile(withCode).use { z -> z.getInputStream(z.getEntry("AndroidManifest.xml")).readBytes() } else b } else module
            val base = work.resolve("base-$name.zip").also { zip(it, buildable) }
            val built = work.resolve("$name.aab").also { bundletool("build-bundle", "--modules=${base.path}", "--output=${it.path}") }
            if (versionCode == null) {
                // bundletool refuses a manifest without versionCode: the bundle is built with one and its manifest swapped.
                val manifest = module.first { it.first == "manifest/AndroidManifest.xml" }.second
                val swapped = entries(built).map { (n, b) -> n to if (n == "base/manifest/AndroidManifest.xml") manifest else b }
                zip(built, swapped)
            }
            return built.also { fixtures[name] = it }
        }

        /** The same app as a signed APK (aapt2 binary manifest, D8 DEX, apksig v2). */
        fun apk(name: String, assets: Map<String, ByteArray>, readers: List<String> = listOf(ANDROID_READER), major: String? = null): File {
            val linked = work.resolve("linked-$name.apk")
            exec(buildTools.resolve("aapt2").path, "link", "-o", linked.path, "-I", androidJar.path,
                "--manifest", manifest(name, FIXTURE, "42", major).path)
            val unsigned = work.resolve("$name-unsigned.apk")
            zip(unsigned, entries(linked) + ("classes.dex" to dex(*readers.toTypedArray())) + assets.map { (p, b) -> p to b })
            val ks = KeyStore.getInstance("PKCS12").apply { keystore.inputStream().use { load(it, STORE_PASS.toCharArray()) } }
            val key = ks.getKey("fixture", STORE_PASS.toCharArray()) as PrivateKey
            val cert = ks.getCertificate("fixture") as X509Certificate
            val target = work.resolve("$name.apk")
            ApkSigner.Builder(listOf(ApkSigner.SignerConfig.Builder("fixture", KeyConfig.Jca(key), listOf(cert)).build()))
                .setInputApk(unsigned).setOutputApk(target).build().sign()
            return target
        }

        private fun vectorCase(name: String) = vectors.getAsJsonArray("cases").map { it.asJsonObject }.single { it.get("name").asString == name }

        private fun canaryAssets(version: Int): Map<String, ByteArray> {
            val big = ByteArray(1024 * 1024).also { SecureRandom().nextBytes(it) }
            val c = canaries
            for ((i, at) in listOf(0, 300_000, 1024 * 1024 - 64).withIndex()) c.getValue("big$i").toByteArray().copyInto(big, at)
            return mapOf(
                "assets/regras/tabela.json" to """{"regra":"${c.getValue("json")}","versao":$version}""".toByteArray(),
                "assets/regras/vazio.txt" to ByteArray(0),
                "assets/blob/dados.bin" to big,
                "assets/sentomaru-strings.json" to """{"saudacao":"${c.getValue("string")}","outra":"valor"}""".toByteArray(),
                "assets/livre/nao-selado.txt" to "visible on purpose".toByteArray(),
            )
        }

        @BeforeClass @JvmStatic fun fixtures() {
            work = Files.createTempDirectory("protect-sealed").toFile()
            val home = File(System.getProperty("android.home").ifEmpty { System.getenv("ANDROID_HOME") ?: "" })
            buildTools = home.resolve("build-tools").listFiles()!!.filter { it.resolve("lib/d8.jar").isFile && it.resolve("aapt2").isFile }
                .maxByOrNull { it.name }!!
            androidJar = home.resolve("platforms").listFiles()!!.filter { it.resolve("android.jar").isFile }
                .maxByOrNull { it.name.removePrefix("android-").toIntOrNull() ?: 0 }!!.resolve("android.jar")
            keystore = work.resolve("fixture.p12")
            exec(jdk("keytool"), "-genkeypair", "-keystore", keystore.path, "-storetype", "PKCS12", "-storepass", STORE_PASS,
                "-alias", "fixture", "-keyalg", "EC", "-groupname", "secp256r1", "-validity", "2", "-dname", "CN=fixture")
            vectors = JsonParser.parseString(File("../../../contracts/devsecops/sealed-v1-vectors.json").readText()).asJsonObject
            // The two shared vector cases, as apps: their files, plus files the profile does not mark.
            val a = vectorCase("android-assets-and-strings")
            androidVector = bundle("vector-android", a.getAsJsonArray("files").map { it.asJsonObject }
                .associate { it.get("path").asString to hex(it.get("plainHex").asString) } + ("assets/outro.txt" to "unmarked".toByteArray()),
                pkg = a.get("package").asString, versionCode = a.get("versionCode").asString)
            val f = vectorCase("flutter-asset-without-strings")
            flutterVector = bundle("vector-flutter", f.getAsJsonArray("files").map { it.asJsonObject }
                .associate { it.get("path").asString to hex(it.get("plainHex").asString) } + mapOf(
                    "assets/flutter_assets/AssetManifest.bin" to ByteArray(16) { 1 },
                    "assets/flutter_assets/FontManifest.json" to """[{"family":"Brand","fonts":[{"asset":"assets/dados/marca.bin"}]}]""".toByteArray(),
                    "assets/flutter_assets/assets/dados/marca.bin" to ByteArray(8) { 2 },
                    "assets/flutter_assets/fonts/MaterialIcons-Regular.otf" to ByteArray(8) { 3 }),
                readers = listOf(FLUTTER_READER), pkg = f.get("package").asString, versionCode = f.get("versionCode").asString)
            // Canaries: unique per run, only in the marked files (the unmarked one stays readable on purpose).
            canaries = listOf("json", "string", "big0", "big1", "big2").associateWith { "SENTOMARU-CANARIO-$it-${UUID.randomUUID()}" }
            canaryApp = bundle("canary", canaryAssets(1))
            canaryAppNextVersion = bundle("canary-v43", canaryAssets(1), versionCode = "43")
        }
    }

    private val lab = mapOf("SENTOMARU_LAB" to "1")
    private val runtime = """"runtime-injection":{"version":"1","enrollmentUrl":"$URL"}"""
    private val canarySection = """"asset-encryption":{"version":"1","assets":["assets/regras/tabela.json","assets/regras/vazio.txt",
        "assets/blob/dados.bin"],"strings":"assets/sentomaru-strings.json"}"""
    private val canaryPaths = listOf("assets/regras/tabela.json", "assets/regras/vazio.txt", "assets/blob/dados.bin", "assets/sentomaru-strings.json")

    private fun section(assets: List<String>, strings: String? = null, extra: String = "") =
        """"asset-encryption":{"version":"1","assets":[${assets.joinToString(",") { "\"$it\"" }}]""" +
            (strings?.let { ""","strings":"$it"""" } ?: "") + extra + "}"

    private fun profile(controls: String) = work.resolve("profile-${controls.hashCode()}.json").apply {
        writeText("""{"schemaVersion":"1","kind":"protect","profileId":"fixture-protect",
            "scope":{"organization":"ebees","app":"sealed-lab","environment":"hml"},"controls":{$controls}}""")
    }

    private fun run(vararg args: String, env: Map<String, String> = lab): Triple<Int, String, String> {
        val out = StringBuilder(); val err = StringBuilder()
        val code = Cli.run(args.toList(), env, { out.append(it) }, { err.append(it) })
        return Triple(code, out.toString(), err.toString())
    }

    private fun dry(input: File, out: File, controls: String, env: Map<String, String> = lab) =
        run("--input", input.path, "--profile", profile(controls).path, "--out", out.path, "--dry-run", "--sign", "none", env = env)

    private fun labRun(input: File, out: File, controls: String) =
        run("--input", input.path, "--profile", profile(controls).path, "--out", out.path, "--lab-unregistered")

    private fun report(out: File): JsonObject = JsonParser.parseString(out.resolve("report.json").readText()).asJsonObject
    private fun control(out: File) = report(out).getAsJsonArray("controls").map { it.asJsonObject }.single { it.get("id").asString == AssetEncryption.id }
    private fun changes(c: JsonObject) = c.getAsJsonArray("changes").map { it.asJsonObject.let { x -> x.get("id").asString + ":" + x.get("target").asString } }
    private fun evidence(c: JsonObject) = c.getAsJsonObject("evidence").entrySet().associate { it.key to it.value.asString }
    private fun warnings(out: File) = report(out).getAsJsonArray("warnings").map { it.asJsonObject.get("code").asString }
    private fun output(out: File, input: File, suffix: String = ".lab.aab") = out.resolve(input.name.removeSuffix(".aab") + suffix)

    private fun refused(exit: Int, code: String, detail: String?, result: Triple<Int, String, String>) {
        assertEquals(result.third, exit, result.first)
        val e = JsonParser.parseString(result.third).asJsonObject
        assertEquals(result.third, code, e.get("code").asString)
        if (detail != null) assertEquals(result.third, detail, e.get("detail").asString)
    }

    /** A source for the D-14b reader over a zip: the canonical path under [prefix] (`base/` in an AAB, nothing in an APK). */
    private class ZipSource(private val entries: Map<String, ByteArray>, private val prefix: String) : SealedSource {
        override fun read(path: String, limit: Int): ByteArray? = entries[prefix + path]?.let { it.copyOf(minOf(it.size, limit + 1)) }
        override fun readAll(path: String): ByteArray = entries[prefix + path] ?: throw java.io.FileNotFoundException(path)
    }

    private fun reader(entries: Map<String, ByteArray>, prefix: String, pkg: String, versionCode: Long) =
        SealedReader(ZipSource(entries, prefix), pkg, versionCode)

    private fun integrity(block: () -> Unit) = sealedError(SentomaruSealedException.Code.INTEGRITY, block)

    private fun sealedError(expected: SentomaruSealedException.Code, block: () -> Unit) {
        try {
            block()
            fail("expected ${expected.wire}")
        } catch (e: SentomaruSealedException) {
            assertEquals(expected, e.code)
        }
    }

    /** The APKs bundletool builds from [aab]: [universal] or the default split set (signed with the run's key). */
    private fun apks(aab: File, name: String, universal: Boolean): File {
        val apks = work.resolve("$name.apks")
        apks.delete()
        bundletool("build-apks", "--bundle=${aab.path}", "--output=${apks.path}", *(if (universal) arrayOf("--mode=universal") else emptyArray()),
            "--ks=${keystore.path}", "--ks-key-alias=fixture", "--ks-pass=pass:$STORE_PASS", "--aapt2=${buildTools.resolve("aapt2").path}")
        return apks
    }

    private fun universalEntries(aab: File, name: String): Map<String, ByteArray> =
        ZipFile(apks(aab, name, universal = true)).use { z -> z.getInputStream(z.getEntry("universal.apk")).readBytes() }
            .let { bytes -> work.resolve("$name-universal.apk").apply { writeBytes(bytes) } }.let { entries(it).toMap() }

    /** Every needle searched in [bytes] raw and, when it is a zip, in every entry inflated (zips inside zips too). */
    private fun hits(bytes: ByteArray, needles: Map<String, ByteArray>, where: String, depth: Int = 0): List<String> {
        val found = needles.filter { (_, n) -> indexOf(bytes, n) >= 0 }.keys.map { "$it in $where" }.toMutableList()
        if (depth < 3 && bytes.size > 4 && bytes[0] == 'P'.code.toByte() && bytes[1] == 'K'.code.toByte() && bytes[2] == 3.toByte()) {
            val file = Files.createTempFile(work.toPath(), "scan", ".zip").toFile().apply { writeBytes(bytes) }
            ZipFile(file).use { z -> for (e in z.entries()) if (!e.isDirectory)
                found += hits(z.getInputStream(e).readBytes(), needles, "$where!${e.name}", depth + 1) }
            file.delete()
        }
        return found
    }

    private fun indexOf(haystack: ByteArray, needle: ByteArray): Int {
        outer@ for (i in 0..haystack.size - needle.size) {
            for (j in needle.indices) if (haystack[i + j] != needle[j]) continue@outer
            return i
        }
        return -1
    }

    /** asset-encryption with the randomness of this call: the per-call seam ([AssetEncryption.apply] with a source). */
    private class Seeded(val random: (Int) -> ByteArray) : Control by AssetEncryption {
        override fun apply(section: JsonObject, edit: AabEdit, context: ControlContext): List<Change> =
            AssetEncryption.apply(section, edit, random)
    }

    /**
     * The CLI's writer path with [random]: the plan (compatibility), then [AabInjector.inject] (one write, bundletool
     * validate), as `Cli.run` does in a lab run. The output is `<name>/<input>.lab.aab`.
     */
    private fun seeded(input: File, name: String, controls: String, random: (Int) -> ByteArray): File {
        val section = JsonParser.parseString("{$controls}").asJsonObject.getAsJsonObject(AssetEncryption.id)
        val artifact = ArtifactReader.read(input)
        val context = ControlContext(Cli.today(), lab = true)
        AssetEncryption.validate(section, context)
        AssetEncryption.plan(section, artifact, context)
        val out = work.resolve(name).apply { mkdirs() }
        return AabInjector.inject(input, artifact, listOf(Seeded(random) to section), context, out).output
    }

    /** A source that still draws from SecureRandom but keeps a copy of what it drew (to search the keys afterwards). */
    private fun recording(drawn: MutableList<ByteArray>): (Int) -> ByteArray {
        val secure = SecureRandom()
        return { n -> ByteArray(n).also { secure.nextBytes(it); drawn += it.copyOf() } }
    }

    /** The vector case's values in the draw order of the contract: dek, salt, header nonce, then each file's nonce. */
    private fun vectorDraws(case: JsonObject): (Int) -> ByteArray {
        val t = case.getAsJsonObject("testOnly")
        val queue = ArrayDeque(listOf(t.get("dekHex"), t.get("saltHex"), t.get("headerNonceHex")).map { hex(it.asString) } +
            case.getAsJsonArray("files").map { hex(it.asJsonObject.get("nonceHex").asString) })
        return { n -> queue.removeFirst().also { assertEquals(n, it.size) } }
    }

    // ---- the gate and the section

    /**
     * D-14e: the control is in the distributed CLI. Without the gate (and with values that are not the gate) the dry run
     * plans it exactly as with the gate (a file within 1 MiB), reads the section and compares its version; `controls`
     * lists it with or without the gate. (From D-14c to D-14e it answered control-not-available without the gate.)
     */
    @Test fun withOrWithoutTheLaboratoryGateTheControlIsAvailable() {
        val s = section(listOf("assets/regras/tabela.json"))
        val gated = work.resolve("gate-lab")
        assertEquals(0, dry(androidVector, gated, s).first)
        for ((i, env) in listOf(emptyMap(), mapOf("SENTOMARU_LAB" to "0"), mapOf("SENTOMARU_LAB" to "true")).withIndex()) {
            val out = work.resolve("gate-$i")
            val (code, _, err) = dry(androidVector, out, s, env = env)
            assertEquals(err, 0, code)
            assertEquals(control(gated), control(out))
        }
        refused(4, "control-version-unsupported", "${AssetEncryption.id} 9", dry(androidVector, work.resolve("gate-version"),
            """"asset-encryption":{"version":"9","x":1}""", env = emptyMap()))
        refused(4, "profile-format", "${AssetEncryption.id}.x", dry(androidVector, work.resolve("gate-field"),
            """"asset-encryption":{"version":"1","assets":["assets/regras/tabela.json"],"x":1}""", env = emptyMap()))
        for (env in listOf(emptyMap(), lab)) assertTrue(run("controls", "--json", env = env).second.contains(AssetEncryption.id))
    }

    @Test fun sectionRulesAreProfileFormatWithTheContractDetail() {
        val input = androidVector
        var n = 0
        fun bad(detail: String, controls: String) = refused(4, "profile-format", "asset-encryption.$detail", dry(input, work.resolve("rule-${n++}"), controls))
        val ok = "assets/regras/tabela.json"
        bad("mode", section(listOf(ok), extra = ""","mode":"x""""))
        bad("unknown-field", section(listOf(ok), extra = ""","a b":1"""))
        bad("assets", """"asset-encryption":{"version":"1"}""")
        bad("assets", """"asset-encryption":{"version":"1","assets":"$ok"}""")
        bad("assets", section(emptyList()))
        bad("assets", section(listOf(ok, ok)))
        bad("assets", """"asset-encryption":{"version":"1","assets":[1]}""")
        for (path in listOf("regras/tabela.json", "assets/", "assets", "assets//a.json", "assets/a/", "assets/../a.json",
                "assets/./a.json", "assets/a/../b.json", "assets/*.json", "assets/textures#tcf_astc/a.png", "assets/sentomaru/x.bin",
                "assets/sentomaru/sealed/header.bin", "assets/a b.json", "assets/ação.json", "assets/a%20.json", "assets/a.json\n",
                "/assets/a.json", "assets/" + "a".repeat(506), "assets\\a.json"))
            bad("assets", section(listOf(path.replace("\\", "\\\\").replace("\n", "\\n"))))
        bad("assets", section((1..65).map { "assets/f$it.bin" }))
        bad("assets", section((1..64).map { "assets/f$it.bin" }, strings = "assets/s.json"))
        bad("strings", section(listOf(ok), strings = "assets/sentomaru/s.json"))
        bad("strings", section(listOf(ok), strings = ok))
        bad("strings", section(listOf(ok), extra = ""","strings":1"""))
        bad("strings", section(listOf(ok), extra = ""","strings":["assets/s.json"]"""))
        refused(4, "control-version-unsupported", "asset-encryption 2", dry(input, work.resolve("rule-v2"),
            """"asset-encryption":{"version":"2","assets":["$ok"]}"""))
        // The longest path (512) and 64 files counting strings pass the section rules (and stop at the app: missing).
        refused(5, "app-incompatible", AssetEncryption.ASSET_MISSING, dry(input, work.resolve("rule-512"), section(listOf("assets/" + "a".repeat(505)))))
        refused(5, "app-incompatible", AssetEncryption.ASSET_MISSING, dry(input, work.resolve("rule-64"),
            section((1..63).map { "assets/f$it.bin" }, strings = "assets/s.json")))
        // `"strings": null` is no strings file.
        val (code, _, err) = dry(input, work.resolve("rule-null"), section(listOf(ok), extra = ""","strings":null"""))
        assertEquals(err, 0, code)
        assertEquals("0", evidence(control(work.resolve("rule-null"))).getValue("strings"))
        // The contract's example is valid (its files are not in this app).
        val example = File("../../../contracts/devsecops/examples/protect-profile-asset-encryption-v1.example.json")
        refused(5, "app-incompatible", AssetEncryption.ASSET_MISSING, run("--input", input.path, "--profile", example.path,
            "--out", work.resolve("rule-example").path, "--dry-run", "--sign", "none"))
    }

    // ---- the format: the shared vectors

    @Test fun theWriterPrimitivesMatchTheSharedVectors() {
        for (c in vectors.getAsJsonArray("hkdfRfc5869").map { it.asJsonObject })
            assertEquals(c.get("case").asString, c.get("okmHex").asString, hex(Sealer.hkdf(hex(c.get("ikmHex").asString),
                hex(c.get("saltHex").asString), hex(c.get("infoHex").asString), c.get("length").asInt)))
        assertEquals(vectors.getAsJsonObject("kFmt").get("hex").asString, hex(AssetEncryption.K_FMT))
        for (case in vectors.getAsJsonArray("cases").map { it.asJsonObject }) {
            val t = case.getAsJsonObject("testOnly")
            val kek = case.getAsJsonObject("kek")
            assertEquals(kek.get("kekHex").asString, hex(Sealer.hkdf(AssetEncryption.K_FMT, hex(kek.get("hkdfSaltHex").asString),
                kek.get("hkdfInfo").asString.toByteArray())))
            val header = case.getAsJsonObject("header")
            val nonce = hex(t.get("headerNonceHex").asString)
            assertEquals(header.get("sealedHex").asString, hex("SNTS".toByteArray() + 1.toByte() + hex(t.get("saltHex").asString) + nonce +
                Sealer.gcm(hex(kek.get("kekHex").asString), nonce, hex(header.get("plaintextHex").asString), header.get("aad").asString.toByteArray())))
            for (f in case.getAsJsonArray("files").map { it.asJsonObject }) {
                val key = Sealer.hkdf(hex(t.get("dekHex").asString), ByteArray(0), f.get("hkdfInfo").asString.toByteArray())
                assertEquals(f.get("keyHex").asString, hex(key))
                val n = hex(f.get("nonceHex").asString)
                val length = java.nio.ByteBuffer.allocate(4).putInt(f.get("plainLength").asInt).array()
                assertEquals(f.get("path").asString, f.get("sealedHex").asString, hex("SNTA".toByteArray() + 1.toByte() + length + n +
                    Sealer.gcm(key, n, hex(f.get("deflatedHex").asString), f.get("aad").asString.toByteArray())))
                assertEquals(f.get("sealedEntry").asString, AssetEncryption.SEALED_DIR + AssetEncryption.sha256(f.get("path").asString) + ".bin")
                // The CLI's own DEFLATE is another valid raw stream of the same bytes.
                val inflater = Inflater(true)
                val deflated = Sealer.deflate(hex(f.get("plainHex").asString))
                inflater.setInput(deflated)
                val back = ByteArray(f.get("plainLength").asInt + 1)
                val got = inflater.inflate(back)
                assertTrue(inflater.finished())
                assertEquals(0, inflater.remaining)
                inflater.end()
                assertEquals(f.get("plainHex").asString, hex(back.copyOf(got)))
            }
        }
    }

    /**
     * The CLI's writer path on the two vector apps with the vectors' dek, salt and nonces: `header.bin` is the vector's
     * byte for byte; each `.bin` has the vector's magic, version, length and nonce, and its AEAD opens with the vector's
     * key and AAD to a DEFLATE stream of the plaintext (the compressed bytes are not contractual). The entries removed
     * and added are the vector's; the D-14b reader reads everything back from the AAB and from the universal APK. The
     * CLI itself (SecureRandom) writes the same entries in the same order, the same bytes outside the sealed ones and
     * sealed ones of the same sizes, and its report is checked here.
     */
    @Test fun theCliOutputMatchesTheSharedVectors() {
        // sectionSha256 of each section, computed apart and fixed here: Python json.dumps(sort_keys=True,
        // separators=(",", ":"), ensure_ascii=False), which is the JCS of these sections (ASCII texts, no numbers).
        val sectionHashes = mapOf(
            "android-assets-and-strings" to "115ad85f385042d525f066591b31cf6191cc98e26774f2321e336b12b4a61b0d",
            "flutter-asset-without-strings" to "74c5b9ab172a30e7b278ae9835a2f8d50348b8f25f2b809ae9b62b15815cd70c")
        for ((case, input, controls) in listOf(
            Triple(vectorCase("android-assets-and-strings"), androidVector,
                section(listOf("assets/regras/tabela.json", "assets/regras/vazio.txt"), strings = "assets/sentomaru-strings.json")),
            Triple(vectorCase("flutter-asset-without-strings"), flutterVector,
                section(listOf("assets/flutter_assets/assets/dados/catalogo.bin"))))) {
            val name = case.get("name").asString
            val written = seeded(input, "vector-$name", controls, vectorDraws(case))
            val out = work.resolve("vector-cli-$name")
            val (code, _, err) = labRun(input, out, controls)
            assertEquals(err, 0, code)
            val cli = entries(output(out, input))
            val seededEntries = entries(written)
            assertEquals(seededEntries.map { it.first }, cli.map { it.first })
            for ((n, b) in seededEntries) {
                val c = cli.toMap().getValue(n)
                if (n.startsWith("base/" + AssetEncryption.SEALED_DIR)) assertEquals(n, b.size, c.size) else assertArrayEquals(n, b, c)
            }
            val before = entries(input).toMap()
            val after = seededEntries.toMap()
            val removed = case.getAsJsonArray("removedEntries").map { "base/" + it.asString }
            val added = case.getAsJsonArray("addedEntries").map { "base/" + it.asString }
            assertEquals(before.keys - removed.toSet() + added, after.keys)
            for ((n, b) in before) if (n !in removed && n != AssetEncryption.ASSETS_CONFIG) assertArrayEquals(n, b, after[n])
            // base/assets.pb: the directories left without a direct file go, the sealed one comes (empty targeting).
            val pb0 = com.android.bundle.Files.Assets.parseFrom(before.getValue(AssetEncryption.ASSETS_CONFIG)).directoryList.map { it.path }
            val pb1 = com.android.bundle.Files.Assets.parseFrom(after.getValue(AssetEncryption.ASSETS_CONFIG)).directoryList
            val emptied = pb0.filter { d -> after.keys.none { it.startsWith("base/$d/") && it.removePrefix("base/$d/").none { c -> c == '/' } } }
            assertEquals(pb0 - emptied.toSet() + "assets/sentomaru/sealed", pb1.map { it.path })
            assertTrue(pb1.all { it.targeting == com.android.bundle.Targeting.AssetsDirectoryTargeting.getDefaultInstance() })
            // The added entries together, in name order, where the last base/assets/ entry was.
            val names = ZipFile(written).use { z -> z.entries().toList().map { it.name } }
            val at = names.indexOf(added.first())
            assertEquals(added, names.subList(at, at + added.size))
            assertTrue(names.subList(0, at).last().startsWith("base/assets/"))
            assertArrayEquals(hex(case.getAsJsonObject("header").get("sealedHex").asString), after.getValue("base/" + AssetEncryption.HEADER))
            val pkg = case.get("package").asString
            val versionCode = case.get("versionCode").asLong
            for (f in case.getAsJsonArray("files").map { it.asJsonObject }) {
                val sealed = after.getValue("base/" + f.get("sealedEntry").asString)
                val expected = hex(f.get("sealedHex").asString)
                assertArrayEquals(expected.copyOf(21), sealed.copyOf(21))
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(hex(f.get("keyHex").asString), "AES"), GCMParameterSpec(128, sealed.copyOfRange(9, 21)))
                cipher.updateAAD(f.get("aad").asString.toByteArray())
                val inflater = Inflater(true).apply { setInput(cipher.doFinal(sealed.copyOfRange(21, sealed.size))) }
                val plain = ByteArray(f.get("plainLength").asInt + 1)
                val n = inflater.inflate(plain)
                assertTrue(inflater.finished())
                assertEquals(f.get("plainHex").asString, hex(plain.copyOf(n)))
            }
            // The D-14b reader, on the AAB's base module and on the universal APK bundletool builds from it.
            val universal = universalEntries(written, "vector-$name")
            for ((entriesRead, prefix) in listOf(after to "base/", universal to "")) {
                val r = reader(entriesRead, prefix, pkg, versionCode)
                for (f in case.getAsJsonArray("files").map { it.asJsonObject })
                    assertEquals(f.get("plainHex").asString, hex(r.bytes(f.get("path").asString)))
                for (l in case.getAsJsonArray("lookups").map { it.asJsonObject })
                    assertEquals(l.get("value").takeIf { !it.isJsonNull }?.asString, r.string(l.get("key").asString))
                for (p in case.getAsJsonArray("removedEntries")) assertNull(entriesRead[prefix + p.asString])
            }
            // Report: closed change ids, targets are digests (never the path), the evidence of the contract.
            val c = control(out)
            assertEquals("applied", c.get("status").asString)
            val paths = case.getAsJsonArray("files").map { it.asJsonObject.get("path").asString }
            assertEquals(listOf("sealed.header.added:base/${AssetEncryption.HEADER}") +
                paths.flatMap { listOf("asset.sealed:${AssetEncryption.sha256(it)}", "asset.removed:${AssetEncryption.sha256(it)}") } +
                "assets-config.updated:${AssetEncryption.ASSETS_CONFIG}", changes(c))
            val e = evidence(c)
            assertEquals(listOf("files", "bytesIn", "bytesOut", "strings", "format", "sectionSha256"), e.keys.toList())
            assertEquals(paths.size.toString(), e["files"])
            assertEquals(case.getAsJsonArray("files").sumOf { it.asJsonObject.get("plainLength").asInt }.toString(), e["bytesIn"])
            assertEquals(added.sumOf { after.getValue(it).size }.toString(), e["bytesOut"])
            assertEquals(case.getAsJsonArray("lookups").count { !it.asJsonObject.get("value").isJsonNull }.toString(), e["strings"])
            assertEquals("v1", e["format"])
            val jcs = Jcs.canonical(JsonParser.parseString("{$controls}").asJsonObject.getAsJsonObject(AssetEncryption.id))
            assertEquals(hex(java.security.MessageDigest.getInstance("SHA-256").digest(jcs.toByteArray())), e["sectionSha256"])
            assertEquals(sectionHashes.getValue(name), e["sectionSha256"])
            assertTrue(warnings(out).contains(AssetEncryption.READ_LINE))
            val text = out.resolve("report.json").readText()
            for (p in paths) assertFalse(p, text.contains(p))
        }
    }

    @Test fun theSectionHashTellsANullStringsFromAnAbsentOne() {
        val absent = JsonParser.parseString("""{"version":"1","assets":["assets/a.json"]}""").asJsonObject
        val nul = JsonParser.parseString("""{"version":"1","assets":["assets/a.json"],"strings":null}""").asJsonObject
        assertEquals("""{"assets":["assets/a.json"],"strings":null,"version":"1"}""", Jcs.canonical(nul))
        assertNotEquals(Jcs.canonical(absent), Jcs.canonical(nul))
        // Computed apart (Python json.dumps with sort_keys and compact separators) and fixed here.
        assertEquals("72d65345d73f13346b3a969672568d56f821169b109dd0bcb73a7a143aac455c",
            hex(java.security.MessageDigest.getInstance("SHA-256").digest(Jcs.canonical(nul).toByteArray())))
    }

    // ---- the proof asked by the slice: canaries, bundletool, the reader, tampering

    /**
     * Real randomness (SecureRandom, recorded only to search the keys afterwards, through the CLI's writer path). No
     * canary, no `dek`, no `kek` and no file key is in any byte of that output AAB, of the split and universal APKs
     * bundletool builds from it (every entry inflated); no canary either in the CLI's own output AAB, report, stdout or
     * stderr. The unmarked file stays readable; the reader opens every marked file from the universal APK and the
     * originals are gone.
     */
    @Test fun noCanaryAndNoKeyInTheOutputAndTheApksBuiltFromIt() {
        val drawn = mutableListOf<ByteArray>()
        val protected = seeded(canaryApp, "canary-seeded", canarySection, recording(drawn))
        val out = work.resolve("canary-lab")
        val (code, stdout, err) = labRun(canaryApp, out, canarySection)
        assertEquals(err, 0, code)
        bundletool("validate", "--bundle=${protected.path}")
        val split = apks(protected, "canary-split", universal = false)
        val universal = universalEntries(protected, "canary")
        val dek = drawn[0]
        val salt = drawn[1]
        val kek = Sealer.hkdf(AssetEncryption.K_FMT, salt, "sentomaru-sealed-v1|$FIXTURE|42".toByteArray())
        val needles = canaries.mapValues { it.value.toByteArray() } + mapOf("dek" to dek, "kek" to kek, "dekHex" to hex(dek).toByteArray(),
            "kekHex" to hex(kek).toByteArray()) + canaryPaths.associate { "key:$it" to Sealer.hkdf(dek, ByteArray(0), "asset|$it".toByteArray()) }
        val found = hits(protected.readBytes(), needles, "aab") + hits(output(out, canaryApp).readBytes(), needles, "cli aab") +
            hits(split.readBytes(), needles, "split.apks") +
            hits(work.resolve("canary-universal.apk").readBytes(), needles, "universal.apk") +
            hits(out.resolve("report.json").readBytes(), needles, "report") + hits(stdout.toByteArray(), needles, "stdout") +
            hits(err.toByteArray(), needles, "stderr")
        assertEquals(emptyList<String>(), found)
        // The search itself finds a canary where one is (the input) and the unmarked file stays.
        assertTrue(hits(canaryApp.readBytes(), needles, "input").isNotEmpty())
        assertArrayEquals("visible on purpose".toByteArray(), universal.getValue("assets/livre/nao-selado.txt"))
        val r = reader(universal, "", FIXTURE, 42)
        val plain = canaryAssets(1)
        for (p in canaryPaths) {
            if (p == "assets/blob/dados.bin") assertEquals(1024 * 1024, r.bytes(p).size) else assertArrayEquals(p, plain.getValue(p), r.bytes(p))
            assertNull(p, universal[p])
        }
        assertEquals(canaries.getValue("string"), r.string("saudacao"))
        assertEquals("valor", r.string("outra"))
        assertNull(r.string("ausente"))
        assertEquals("4", evidence(control(out))["files"])
        assertEquals("2", evidence(control(out))["strings"])
    }

    /** The universal APK bundletool builds from [aab], written to its own file (apktool decodes a whole APK). */
    private fun universalApk(aab: File, name: String): File =
        ZipFile(apks(aab, name, universal = true)).use { z -> z.getInputStream(z.getEntry("universal.apk")).readBytes() }
            .let { bytes -> work.resolve("$name-universal.apk").apply { writeBytes(bytes) } }

    /** `apktool d` of [apk] into a fresh dir (own frame path, no network), then every output byte searched for [needles]. */
    private fun apktoolHits(jar: File, apk: File, where: String, needles: Map<String, ByteArray>): List<String> {
        val out = work.resolve("$where-apktool").also { it.deleteRecursively() }
        val frames = work.resolve("apktool-frames").apply { mkdirs() }
        // apktool: global command `d`, then its decode options (-p/-f/-o are after `d`, never before it).
        exec(java(), "-jar", jar.path, "d", "-p", frames.path, "-f", "-o", out.path, apk.path)
        return out.walkTopDown().filter { it.isFile }.flatMap { f ->
            val bytes = f.readBytes()
            needles.filter { (_, n) -> indexOf(bytes, n) >= 0 }.keys.map { "$it in $where!${f.relativeTo(out)}" }
        }.toList()
    }

    /**
     * D-14d, §13: `apktool d` (pinned version and digest) of the APKs bundletool builds from the sealed AAB, searching
     * every decoded byte for the per-run canaries and the `dek` (a 32-byte window). Expected: zero. This adds decoded
     * resources and baksmali to the raw/unzip search of [noCanaryAndNoKeyInTheOutputAndTheApksBuiltFromIt]. The tool is
     * pinned and, in CI, required (SENTOMARU_APKTOOL_REQUIRED=1: no skip); only on a machine with neither the variables
     * nor ~/.local/share/sentomaru-tools does it skip with a reason. A positive control decodes the UNSEALED input and finds a canary, so
     * a silently empty decode cannot pass.
     */
    @Test fun apktoolDecodeOfTheBundletoolApksCarriesNoCanaryOrDek() {
        val jar = apktoolJar()
        Assume.assumeTrue(
            "apktool $APKTOOL_VERSION unavailable at the pinned digest (set SENTOMARU_APKTOOL to a digest-checked jar, " +
                "or place apktool_$APKTOOL_VERSION.jar in ~/.local/share/sentomaru-tools)", jar != null)
        val drawn = mutableListOf<ByteArray>()
        val protected = seeded(canaryApp, "canary-apktool-seeded", canarySection, recording(drawn))
        val dek = drawn[0] // 32 bytes
        val needles = canaries.mapValues { it.value.toByteArray() } +
            mapOf("dek" to dek, "dekHex" to hex(dek).toByteArray())
        val sealed = universalApk(protected, "canary-apktool-sealed")
        val found = apktoolHits(jar!!, sealed, "sealed", needles)
        assertEquals(found.joinToString(), emptyList<String>(), found)
        // Positive control: the unsealed input still carries the canaries through apktool's decode.
        val plain = universalApk(canaryApp, "canary-apktool-plain")
        assertTrue("apktool decode found no canary in the unsealed input", apktoolHits(jar, plain, "plain", needles).isNotEmpty())
    }

    /**
     * Swap and copy of sealed files are `integrity` in the D-14b reader: a `.bin` under another file's name, one from
     * another run on the same app, a `header.bin` from another run, the same file from another `versionCode`, and one
     * flipped byte. A good file keeps opening next to the broken ones.
     */
    @Test fun swappedAndCopiedSealedFilesFailTheReaderWithIntegrity() {
        val first = work.resolve("tamper-1"); val second = work.resolve("tamper-2"); val other = work.resolve("tamper-v43")
        assertEquals(0, labRun(canaryApp, first, canarySection).first)
        assertEquals(0, labRun(canaryApp, second, canarySection).first)
        assertEquals(0, labRun(canaryAppNextVersion, other, canarySection).first)
        val a = entries(output(first, canaryApp)).toMap()
        val b = entries(output(second, canaryApp)).toMap()
        val v43 = entries(output(other, canaryAppNextVersion)).toMap()
        fun bin(p: String) = "base/" + AssetEncryption.SEALED_DIR + AssetEncryption.sha256(p) + ".bin"
        val json = "assets/regras/tabela.json"; val blob = "assets/blob/dados.bin"
        val header = "base/" + AssetEncryption.HEADER
        // Two runs on the same input differ (dek, salt, nonces): the output is not reproducible with the section.
        assertFalse(a.getValue(header).contentEquals(b.getValue(header)))
        assertNotEquals(report(first).getAsJsonObject("output").get("sha256"), report(second).getAsJsonObject("output").get("sha256"))
        assertEquals(canaries.getValue("string"), reader(a, "base/", FIXTURE, 42).string("saudacao"))
        // Swap: one file's .bin under the other's name.
        val swapped = reader(a + (bin(json) to a.getValue(bin(blob))), "base/", FIXTURE, 42)
        integrity { swapped.bytes(json) }
        assertEquals(1024 * 1024, swapped.bytes(blob).size)
        // Copy from another run of the same app (another dek).
        integrity { reader(a + (bin(json) to b.getValue(bin(json))), "base/", FIXTURE, 42).bytes(json) }
        // Header from another run: every file fails.
        val otherHeader = reader(a + (header to b.getValue(header)), "base/", FIXTURE, 42)
        for (p in canaryPaths) integrity { otherHeader.bytes(p) }
        // The same file sealed for another versionCode (and its header with it).
        integrity { reader(a + (bin(json) to v43.getValue(bin(json))), "base/", FIXTURE, 42).bytes(json) }
        integrity { reader(v43, "base/", FIXTURE, 42).bytes(json) }
        integrity { reader(a, "base/", "br.com.example.other", 42).bytes(json) }
        // One flipped byte in the ciphertext.
        val flipped = a.getValue(bin(json)).copyOf().also { it[it.size - 1] = (it[it.size - 1].toInt() xor 1).toByte() }
        integrity { reader(a + (bin(json) to flipped), "base/", FIXTURE, 42).bytes(json) }
        // The original is gone: a plain read finds nothing.
        assertNull(a["base/$json"])
    }

    // ---- the real run, the dry run and the other controls

    /**
     * D-14e: the control is in the distributed CLI. A registered run without the gate applies it with the other controls
     * (runtime-injection, build-obfuscation checked) and registers the run; with SENTOMARU_LAB=1 it is refused (exit 2,
     * `usage`, before the run is opened, D-16-lab-gate). On an APK, a real run answers 5 (app-incompatible, the
     * compatibility phase) before 6 (control-failed, the APK rule until G-03b3), as the contract orders it. The lab run
     * applies it after runtime-injection and the dry run (with build-obfuscation too, which the lab run does not take)
     * plans the same changes and evidence.
     */
    @Test fun aRegisteredRunAppliesItWithoutTheGateAndTheLabRunAppliesItAsTheDryRunPlans() {
        val controls = """$runtime,"build-obfuscation":{"version":"1"},$canarySection"""
        lateinit var registeredChanges: List<String>
        FakeRegistry().use { registry ->
            val api = mapOf("SENTOMARU_BUILDER_TOKEN" to "builder-token-fixture", "SENTOMARU_API" to registry.address.toString())
            val gated = work.resolve("registered-gate")
            refused(2, "usage", Cli.LAB_GATE_REGISTERED, run("--input", canaryApp.path, "--profile", profile(controls).path,
                "--out", gated.path, env = lab + api))
            assertTrue(registry.calls.isEmpty())
            assertEquals(setOf("report.json"), gated.list()!!.toSet())
            // Without the gate: applied and registered.
            val real = work.resolve("registered")
            val (code, _, err) = run("--input", canaryApp.path, "--profile", profile(controls).path, "--out", real.path, env = api)
            assertEquals(err, 0, code)
            assertEquals(listOf("runtime-injection", "build-obfuscation", "asset-encryption"),
                report(real).getAsJsonArray("controls").map { it.asJsonObject.get("id").asString })
            assertEquals("applied", control(real).get("status").asString)
            assertEquals("registered", report(real).getAsJsonObject("registration").get("status").asString)
            assertTrue(warnings(real).contains(AssetEncryption.READ_LINE))
            registeredChanges = changes(control(real))
            val protected = output(real, canaryApp, ".protected.aab")
            bundletool("validate", "--bundle=${protected.path}")
            val after = entries(protected).toMap()
            assertEquals(canaries.getValue("string"), reader(after, "base/", FIXTURE, 42).string("saudacao"))
            for (p in canaryPaths) assertNull(after["base/$p"])
            // An APK in a real run: compatibility (5) before the APK rule (6), and the gate (2) before both.
            val apk = apk("sealed-apk", canaryAssets(1))
            refused(2, "usage", Cli.LAB_GATE_REGISTERED, run("--input", apk.path, "--profile", profile(canarySection).path, "--out",
                work.resolve("apk-real-gate").path, "--sign", "none", env = lab + api))
            refused(5, "app-incompatible", AssetEncryption.READER_MISSING, run("--input",
                apk("sealed-apk-no-reader", canaryAssets(1), readers = emptyList()).path, "--profile", profile(canarySection).path,
                "--out", work.resolve("apk-real-incompatible").path, "--sign", "none", env = api))
            refused(6, "control-failed", null, run("--input", apk.path, "--profile", profile(canarySection).path, "--out",
                work.resolve("apk-real").path, "--sign", "none", env = api))
            val apkDry = work.resolve("apk-dry")
            assertEquals(0, dry(apk, apkDry, canarySection).first)
            assertEquals("sealed.header.added:${AssetEncryption.HEADER}", changes(control(apkDry)).first())
            refused(5, "app-incompatible", AssetEncryption.READER_MISSING, dry(apk("sealed-apk-no-reader", canaryAssets(1),
                readers = emptyList()), work.resolve("apk-dry-incompatible"), canarySection))
        }
        val out = work.resolve("lab-applied")
        val (code, _, err) = labRun(canaryApp, out, "$runtime,$canarySection")
        assertEquals(err, 0, code)
        val r = report(out)
        assertEquals(listOf("runtime-injection", "asset-encryption"), r.getAsJsonArray("controls").map { it.asJsonObject.get("id").asString })
        val applied = control(out)
        assertEquals("applied", applied.get("status").asString)
        assertEquals("not-registered", r.getAsJsonObject("registration").get("status").asString)
        assertEquals(registeredChanges, changes(applied))
        val protected = output(out, canaryApp)
        assertTrue(entries(protected).toMap().containsKey("base/dex/classes2.dex"))
        bundletool("validate", "--bundle=${protected.path}")
        val universal = universalEntries(protected, "lab-applied")
        assertEquals(canaries.getValue("string"), reader(universal, "", FIXTURE, 42).string("saudacao"))
        val dry = work.resolve("lab-applied-dry")
        assertEquals(0, dry(canaryApp, dry, controls).first)
        assertEquals(listOf("runtime-injection", "build-obfuscation", "asset-encryption"),
            report(dry).getAsJsonArray("controls").map { it.asJsonObject.get("id").asString })
        // build-obfuscation: the canary app has the reader but not SentomaruRoutes, so sdkNamesKept is false.
        val obfuscation = report(dry).getAsJsonArray("controls").map { it.asJsonObject }.single { it.get("id").asString == "build-obfuscation" }
        assertEquals("false", evidence(obfuscation)["sdkNamesKept"])
        val planned = control(dry)
        assertEquals("planned", planned.get("status").asString)
        assertEquals(changes(applied), changes(planned))
        val e = evidence(applied); val p = evidence(planned)
        assertEquals("unknown", p["bytesOut"])
        assertEquals(e - "bytesOut", p - "bytesOut")
        assertTrue(e.getValue("bytesOut").toLong() > 1024 * 1024)
        assertTrue(report(dry).getAsJsonObject("output").get("sha256").isJsonNull)
        assertTrue(warnings(dry).contains(AssetEncryption.READ_LINE))
    }

    /**
     * sdkNamesKept with asset-encryption in the profile: SentomaruRoutes and a reader marker defined → true (the dry run
     * plans both controls). Without the reader the profile is refused first (sealed-reader-missing), so the reader half
     * of the rule is checked by the refusal, not by a false.
     */
    @Test fun buildObfuscationKeepsTheReaderNameWithAssetEncryption() {
        val routes = NetworkSigning.ANDROID_TRANSPORT.removePrefix("L").removeSuffix(";").replace('/', '.')
        val ok = mapOf("assets/regras/tabela.json" to "{}".toByteArray())
        val s = section(listOf("assets/regras/tabela.json"))
        for (reader in listOf(ANDROID_READER, FLUTTER_READER)) {
            val app = bundle("kept-${reader.substringAfterLast('.')}", ok, readers = listOf(routes, reader))
            val out = work.resolve("kept-dry-${reader.substringAfterLast('.')}")
            val (code, _, err) = dry(app, out, """"build-obfuscation":{"version":"1"},$s""")
            assertEquals(err, 0, code)
            val c = report(out).getAsJsonArray("controls").map { it.asJsonObject }.single { it.get("id").asString == "build-obfuscation" }
            assertEquals("true", evidence(c)["sdkNamesKept"])
        }
        refused(5, "app-incompatible", AssetEncryption.READER_MISSING, dry(bundle("kept-no-reader", ok, readers = listOf(routes)),
            work.resolve("kept-dry-none"), """"build-obfuscation":{"version":"1"},$s"""))
    }

    /**
     * Without the section the output is the one before D-14c, byte for byte, against the pre-pipeline writer
     * (PreviousInjector): the lab run of runtime-injection on AABs with assets, on one signed with jarsigner (META-INF
     * signature removed) and on one whose entries are STORED; and the registered run of runtime-injection. The
     * combinations with network-pinning and build-obfuscation have no in-repo reference: they are compared with the
     * CLI of 273fa8e1 (installDist) over the inputs of these tests, outside the suite (D-14c).
     */
    @Test fun withoutTheSectionTheOutputIsTheSameByteForByte() {
        fun reference(input: File) = work.resolve("reference-${input.name}").also {
            PreviousInjector.write(input, ArtifactReader.read(input).manifest.packageName, URL, it)
        }
        val signed = work.resolve("regression-signed.aab").also { f ->
            canaryApp.copyTo(f, overwrite = true)
            exec(jdk("jarsigner"), "-keystore", keystore.path, "-storetype", "PKCS12", "-storepass", STORE_PASS, f.path, "fixture")
        }
        assertTrue(entries(signed).any { it.first.startsWith("META-INF/") && it.first.endsWith(".SF") })
        val stored = work.resolve("regression-stored.aab").also { f -> stored(f, entries(canaryApp)) }
        assertTrue(ZipFile(stored).use { z -> z.entries().toList().count { it.method == ZipEntry.STORED } > 4 })
        for (input in listOf(canaryApp, androidVector, flutterVector, signed, stored)) {
            val out = work.resolve("regression-${input.nameWithoutExtension}")
            assertEquals(0, labRun(input, out, runtime).first)
            assertArrayEquals(input.name, reference(input).readBytes(), output(out, input).readBytes())
        }
        FakeRegistry().use { registry ->
            // D-16-lab-gate: the registered run refuses SENTOMARU_LAB=1; runtime-injection needs no gate.
            val env = mapOf("SENTOMARU_BUILDER_TOKEN" to "builder-token-fixture", "SENTOMARU_API" to registry.address.toString())
            val out = work.resolve("regression-registered")
            val (code, _, err) = run("--input", canaryApp.path, "--profile", profile(runtime).path, "--out", out.path, env = env)
            assertEquals(err, 0, code)
            assertArrayEquals(reference(canaryApp).readBytes(), output(out, canaryApp, ".protected.aab").readBytes())
        }
    }

    /** A zip of [entries] with every asset entry STORED (and the rest DEFLATED), as some build tools write them. */
    private fun stored(target: File, entries: List<Pair<String, ByteArray>>) = ZipOutputStream(target.outputStream()).use { z ->
        for ((n, b) in entries) {
            val e = ZipEntry(n)
            if (n.startsWith("base/assets/")) {
                e.method = ZipEntry.STORED
                e.size = b.size.toLong()
                e.compressedSize = b.size.toLong()
                e.crc = java.util.zip.CRC32().apply { update(b) }.value
            }
            z.putNextEntry(e); z.write(b); z.closeEntry()
        }
    }

    // ---- the compatibility phase

    @Test fun compatibilityRefusalsFollowTheContractOrder() {
        val ok = mapOf("assets/regras/tabela.json" to "{}".toByteArray())
        val s = section(listOf("assets/regras/tabela.json"))
        var n = 0
        fun expect(detail: String, input: File, controls: String = s) {
            refused(5, "app-incompatible", detail, dry(input, work.resolve("compat-${n++}"), controls))
            refused(5, "app-incompatible", detail, labRun(input, work.resolve("compat-${n++}"), controls))
            assertFalse(work.resolve("compat-${n - 1}").list().orEmpty().any { it.endsWith(".aab") || it.endsWith(".tmp") })
        }
        expect(AssetEncryption.VERSION_CODE_MISSING, bundle("no-version-code", ok, versionCode = null))
        expect(AssetEncryption.VERSION_CODE_MISSING, bundle("version-code-major", ok, major = "1"))
        // The binary manifest reader too (an APK, dry run only: the real run takes AABs).
        refused(5, "app-incompatible", AssetEncryption.VERSION_CODE_MISSING, dry(apk("apk-major", ok, major = "1"), work.resolve("compat-apk-major"), s))
        assertEquals(0, dry(apk("apk-plain", ok), work.resolve("compat-apk-plain"), s).first)
        // A protected app (twice), even without the reader: sealed-present comes first.
        expect(AssetEncryption.SEALED_PRESENT, bundle("sealed-present", ok + ("assets/sentomaru/sealed/header.bin" to ByteArray(81)), readers = emptyList()))
        expect(AssetEncryption.READER_MISSING, bundle("no-reader", ok, readers = emptyList()))
        // The plugin class of versions without the reader does not count.
        expect(AssetEncryption.READER_MISSING, bundle("old-plugin", ok, readers = listOf(NetworkSigning.FLUTTER_TRANSPORT.removePrefix("L").removeSuffix(";").replace('/', '.'))))
        assertEquals(0, dry(bundle("flutter-reader", ok, readers = listOf(FLUTTER_READER)), work.resolve("compat-flutter-reader"), s).first)
        // Targeting: a `#` variant of a directory of the path, even when the file exists only in the variant.
        val targeted = bundle("targeted", ok + ("assets/regras#lang_pt/tabela.json" to "{}".toByteArray()))
        expect(AssetEncryption.ASSET_TARGETED, targeted)
        expect(AssetEncryption.ASSET_TARGETED, targeted, section(listOf("assets/regras/so-na-variante.json")))
        val nested = bundle("targeted-nested", mapOf("assets/a/b/c.bin" to ByteArray(1), "assets/a#tcf_astc/b/c.bin" to ByteArray(1)))
        expect(AssetEncryption.ASSET_TARGETED, nested, section(listOf("assets/a/b/c.bin")))
        // A directory cited in base/assets.pb with a targeting (here without any `#` entry); bundletool cites every
        // asset directory with an empty targeting, which does not count.
        fun withAssetsPb(name: String, pb: ByteArray) = work.resolve("$name.aab").also { f ->
            zip(f, entries(bundle("$name-base", ok)).map { (n, b) -> n to if (n == AssetEncryption.ASSETS_CONFIG) pb else b })
        }
        val language = com.android.bundle.Targeting.AssetsDirectoryTargeting.newBuilder()
            .setLanguage(com.android.bundle.Targeting.LanguageTargeting.newBuilder().addValue("pt"))
        expect(AssetEncryption.ASSET_TARGETED, withAssetsPb("assets-pb", com.android.bundle.Files.Assets.newBuilder()
            .addDirectory(com.android.bundle.Files.TargetedAssetsDirectory.newBuilder().setPath("assets/regras").setTargeting(language))
            .build().toByteArray()))
        refused(3, "input-format", null, dry(withAssetsPb("assets-pb-garbled", byteArrayOf(0x0a, 0x7f)), work.resolve("compat-garbled"), s))
        expect(AssetEncryption.ASSET_MISSING, androidVector, section(listOf("assets/regras/tabela.json", "assets/nao/existe.json")))
        expect(AssetEncryption.ASSET_MISSING, androidVector, section(listOf("assets/regras")))
        // Files the Flutter engine or the platform reads without the reader.
        for (p in listOf("assets/flutter_assets/AssetManifest.bin", "assets/flutter_assets/fonts/MaterialIcons-Regular.otf",
                "assets/flutter_assets/assets/dados/marca.bin"))
            expect(AssetEncryption.ENGINE_MANAGED, flutterVector, section(listOf(p)))
        val engine = bundle("engine", mapOf("assets/fonte/Marca.TTF" to ByteArray(4), "assets/dexopt/baseline.prof" to ByteArray(4),
            "assets/flutter_assets/shaders/ink_sparkle.frag" to ByteArray(4), "assets/flutter_assets/packages/p/a.bin" to ByteArray(4),
            "assets/flutter_assets/FontManifest.json" to "not json".toByteArray(), "assets/flutter_assets/assets/x.bin" to ByteArray(4)))
        for (p in listOf("assets/fonte/Marca.TTF", "assets/dexopt/baseline.prof", "assets/flutter_assets/shaders/ink_sparkle.frag",
                "assets/flutter_assets/packages/p/a.bin", "assets/flutter_assets/assets/x.bin"))
            expect(AssetEncryption.ENGINE_MANAGED, engine, section(listOf(p)))
        // Sizes with the laboratory gate (these runs): the format ceiling of 4 MiB per file (exactly 4 MiB passes), so
        // the D-14d proof can seal its 4 MiB canary; 32 MiB in all. The 1 MiB limit of the distributed CLI (D-14e) is
        // in theDistributedLimitIsOneMebibytePerFileRefusedAtBuildTime.
        val four = ByteArray(AssetEncryption.FORMAT_MAX_FILE_BYTES) { (it % 7).toByte() }
        val sizes = bundle("sizes", (0 until 9).associate { "assets/g/$it.bin" to four } + ("assets/g/maior.bin" to four + 0))
        assertEquals(0, dry(sizes, work.resolve("compat-four"), section(listOf("assets/g/0.bin"))).first)
        expect(AssetEncryption.TOO_LARGE, sizes, section(listOf("assets/g/maior.bin")))
        assertEquals(0, dry(sizes, work.resolve("compat-32"), section((0 until 8).map { "assets/g/$it.bin" })).first)
        // A file above the per-file limit is named first, even when the sum is also above 32 MiB.
        expect(AssetEncryption.TOO_LARGE, sizes, section((0 until 8).map { "assets/g/$it.bin" } + "assets/g/maior.bin"))
        expect(AssetEncryption.TOTAL_TOO_LARGE, sizes, section((0 until 9).map { "assets/g/$it.bin" }))
        // The strings file.
        val strings = bundle("strings", ok + mapOf("assets/s/ok.json" to """{"a":"b"}""".toByteArray(),
            "assets/s/array.json" to """["a"]""".toByteArray()))
        expect(AssetEncryption.STRINGS_INVALID, strings, section(listOf("assets/regras/tabela.json"), strings = "assets/s/array.json"))
        assertEquals(0, dry(strings, work.resolve("compat-strings-ok"), section(listOf("assets/regras/tabela.json"), strings = "assets/s/ok.json")).first)
        // The first condition of the order decides: no reader and a missing path → sealed-reader-missing.
        expect(AssetEncryption.READER_MISSING, fixtures.getValue("no-reader"), section(listOf("assets/nao/existe.json")))
    }

    /**
     * D-14e (owner decision, conservative): without the laboratory gate the CLI seals at most 1 MiB (1 048 576 bytes)
     * of plain bytes per file and refuses a larger one at build time, in the compatibility phase (plan, so `--dry-run`
     * too) and in the writer path (apply), on the declared size and again on the inflated bytes, with
     * `app-incompatible` / `asset-too-large`. Since D-14e the control is in Controls.all: the CLI dry run without the
     * gate gives the same answer as the control called with the gate off.
     */
    @Test fun theDistributedLimitIsOneMebibytePerFileRefusedAtBuildTime() {
        assertEquals(1024 * 1024, AssetEncryption.MAX_FILE_BYTES)
        assertEquals(AssetEncryption.MAX_FILE_BYTES, AssetEncryption.maxFileBytes(lab = false))
        assertEquals(4 * 1024 * 1024, AssetEncryption.maxFileBytes(lab = true))
        val one = ByteArray(AssetEncryption.MAX_FILE_BYTES) { (it % 5).toByte() }
        val input = bundle("one-mib", mapOf("assets/m/exato.bin" to one, "assets/m/maior.bin" to one + 0))
        val artifact = ArtifactReader.read(input)
        val off = ControlContext(Cli.today(), lab = false)
        fun section(path: String) = JsonParser.parseString("""{"version":"1","assets":["$path"]}""").asJsonObject
        // Exactly 1 MiB passes.
        assertEquals("planned", AssetEncryption.plan(section("assets/m/exato.bin"), artifact, off).status)
        // One byte more is refused at build time, before anything is written.
        val refused = runCatching { AssetEncryption.plan(section("assets/m/maior.bin"), artifact, off) }
            .exceptionOrNull() as? ProtectException ?: throw AssertionError("a file above 1 MiB was planned")
        assertEquals(ErrorCode.APP_INCOMPATIBLE, refused.error)
        assertEquals(AssetEncryption.TOO_LARGE, refused.detail)
        // A central directory that lies (declares 1 MiB for 1 MiB + 1 byte) passes the declared check and is refused
        // on the bytes actually inflated, the second point of the per-file check.
        val lying = declaring(input, "one-mib-lying", mapOf("base/assets/m/maior.bin" to one.size.toLong()))
        assertEquals(AssetEncryption.TOO_LARGE, refusal { AssetEncryption.plan(section("assets/m/maior.bin"), ArtifactReader.read(lying), off) }.detail)
        // The writer path (apply, gate off) refuses it too, and adds or removes nothing in the edit.
        ZipFile(input).use { zip ->
            val edit = AabEdit(zip, zip.entries().toList(), artifact)
            val writer = refusal { AssetEncryption.apply(section("assets/m/maior.bin"), edit, off) }
            assertEquals(ErrorCode.APP_INCOMPATIBLE, writer.error)
            assertEquals(AssetEncryption.TOO_LARGE, writer.detail)
            assertTrue(edit.additions.isEmpty() && edit.removed.isEmpty() && edit.replaced.isEmpty())
        }
        // Review R M-3 of D-14e: a registered run (no gate) refuses 1 MiB + 1 byte at build time too, with nothing in <out>
        // but the report.
        FakeRegistry().use { registry ->
            val api = mapOf("SENTOMARU_BUILDER_TOKEN" to "builder-token-fixture", "SENTOMARU_API" to registry.address.toString())
            val real = work.resolve("one-mib-registered")
            refused(5, "app-incompatible", AssetEncryption.TOO_LARGE, run("--input", input.path, "--profile",
                profile(this.section(listOf("assets/m/maior.bin"))).path, "--out", real.path, env = api))
            assertEquals(setOf("report.json"), real.list()!!.toSet())
        }
        // The CLI without the gate (D-14e): exactly 1 MiB is planned, one byte more is refused in the dry run.
        assertEquals(0, dry(input, work.resolve("one-mib-cli"), this.section(listOf("assets/m/exato.bin")), env = emptyMap()).first)
        refused(5, "app-incompatible", AssetEncryption.TOO_LARGE,
            dry(input, work.resolve("one-mib-cli-larger"), this.section(listOf("assets/m/maior.bin")), env = emptyMap()))
        // The same file is within the format ceiling only with the laboratory gate (the D-14d proof).
        val parsed = AssetEncryption.parse(section("assets/m/maior.bin"))
        AssetEncryption.inspect(input, artifact, parsed, lab = true).clear()
    }

    /**
     * Review R I-1 of 2e8aba46: the 32 MiB sum without the laboratory gate. 32 files of exactly 1 MiB pass, 33 are
     * refused with `assets-total-too-large` (each file is within the 1 MiB limit); and with a central directory that
     * declares 0 bytes for one of the 33, the declared sum is 32 MiB and the refusal comes from the bytes read.
     */
    @Test fun theSumAbove32MebibytesIsRefusedWithoutTheGateOnDeclaredAndOnReadBytes() {
        val one = ByteArray(AssetEncryption.MAX_FILE_BYTES) { (it % 3).toByte() }
        val paths = (0 until 33).map { "assets/t/$it.bin" }
        val input = bundle("total-33", paths.associateWith { one })
        val artifact = ArtifactReader.read(input)
        val off = ControlContext(Cli.today(), lab = false)
        fun section(list: List<String>) = JsonParser.parseString(
            """{"version":"1","assets":[${list.joinToString(",") { "\"$it\"" }}]}""").asJsonObject
        assertEquals("planned", AssetEncryption.plan(section(paths.take(32)), artifact, off).status)
        val declared = refusal { AssetEncryption.plan(section(paths), artifact, off) }
        assertEquals(ErrorCode.APP_INCOMPATIBLE, declared.error)
        assertEquals(AssetEncryption.TOTAL_TOO_LARGE, declared.detail)
        val lying = declaring(input, "total-33-lying", mapOf("base/${paths.last()}" to 0L))
        val read = refusal { AssetEncryption.plan(section(paths), ArtifactReader.read(lying), off) }
        assertEquals(AssetEncryption.TOTAL_TOO_LARGE, read.detail)
    }

    private fun refusal(block: () -> Unit): ProtectException =
        runCatching(block).exceptionOrNull() as? ProtectException ?: throw AssertionError("not refused")

    /**
     * A copy of [input] with every entry DEFLATED and the central directory's uncompressed size of the entries in
     * [sizes] replaced (a lying header: the local headers carry a data descriptor, so readers take the central size).
     */
    private fun declaring(input: File, name: String, sizes: Map<String, Long>): File {
        val copy = work.resolve("$name.aab").also { zip(it, entries(input)) }
        val bytes = copy.readBytes()
        val buf = java.nio.ByteBuffer.wrap(bytes).order(java.nio.ByteOrder.LITTLE_ENDIAN)
        val eocd = (bytes.size - 22 downTo 0).first { buf.getInt(it) == 0x06054b50 }
        var at = buf.getInt(eocd + 16)
        val patched = mutableSetOf<String>()
        repeat(buf.getShort(eocd + 10).toInt() and 0xffff) {
            check(buf.getInt(at) == 0x02014b50)
            val nameLength = buf.getShort(at + 28).toInt() and 0xffff
            val entry = String(bytes, at + 46, nameLength, Charsets.UTF_8)
            sizes[entry]?.let { buf.putInt(at + 24, it.toInt()); patched += entry }
            at += 46 + nameLength + (buf.getShort(at + 30).toInt() and 0xffff) + (buf.getShort(at + 32).toInt() and 0xffff)
        }
        assertEquals(sizes.keys, patched)
        copy.writeBytes(bytes)
        ZipFile(copy).use { z -> for ((n, size) in sizes) assertEquals(size, z.getEntry(n).size) }
        return copy
    }

    @Test fun theStringsFileIsAFlatObjectOfTextsWithTheContractKeys() {
        fun invalid(text: ByteArray) = try {
            AssetEncryption.strings(text)
            fail(String(text))
        } catch (e: ProtectException) {
            assertEquals(ErrorCode.APP_INCOMPATIBLE, e.error)
            assertEquals(AssetEncryption.STRINGS_INVALID, e.detail)
        }
        for (bad in listOf("", "[]", "\"a\"", "{\"a\":1}", "{\"a\":null}", "{\"a\":{\"b\":\"c\"}}", "{\"a\":[\"b\"]}", "{\"A\":\"b\"}",
                "{\"a-b\":\"c\"}", "{\"\":\"c\"}", "{\"${"a".repeat(65)}\":\"c\"}", "{\"a\":\"b\",\"a\":\"c\"}", "{\"a\":\"b\"} x",
                "{'a':'b'}", "{\"a\":\"b\",}", "{\"a\":\"b\"} // c"))
            invalid(bad.toByteArray())
        invalid(byteArrayOf(0xEF.toByte(), 0xBB.toByte(), 0xBF.toByte()) + "{}".toByteArray())
        invalid("{\"a\":\"".toByteArray() + byteArrayOf(0xC3.toByte(), 0x28) + "\"}".toByteArray())
        invalid(("{" + (0..1024).joinToString(",") { "\"k$it\":\"v\"" } + "}").toByteArray())
        assertEquals(1024, AssetEncryption.strings(("{" + (0 until 1024).joinToString(",") { "\"k$it\":\"v\"" } + "}").toByteArray()))
        assertEquals(0, AssetEncryption.strings("{}".toByteArray()))
        assertEquals(3, AssetEncryption.strings("{\"a.b_c9\":\"Olá\",\"${"z".repeat(64)}\":\"\",\"x\":\"\\u00e9\\n\"}".toByteArray()))
    }

    // ---- the editor (D-14c item 11)

    /** A test control that runs [step] on the bundle being edited. */
    private class Step(val step: (AabEdit) -> Unit) : Control {
        override val id = "test-step"
        override val version = "1"
        override val stage = "harden"
        override val order = 99
        override val prerequisites = emptyList<String>()
        override val changeIds = emptyList<String>()
        override val changesBinary = true
        override fun validate(section: JsonObject, context: ControlContext) {}
        override fun plan(section: JsonObject, artifact: Artifact, context: ControlContext) = ControlPlan(id, version, "planned", emptyList())
        override fun apply(section: JsonObject, edit: AabEdit, context: ControlContext): List<Change> { step(edit); return emptyList() }
    }

    private fun edited(input: File, name: String, step: (AabEdit) -> Unit): List<String> {
        val out = work.resolve("edit-$name").apply { mkdirs() }
        val injected = AabInjector.inject(input, ArtifactReader.read(input), listOf(Step(step) to JsonObject()),
            ControlContext(Cli.today(), lab = true), out)
        return ZipFile(injected.output).use { z -> z.entries().toList().map { it.name } }
    }

    private fun internal(block: () -> Unit) = try {
        block()
        fail("expected internal-error")
    } catch (e: ProtectException) {
        assertEquals(e.detail, ErrorCode.INTERNAL, e.error)
    }

    @Test fun theEditorRemovesEntriesAndAnchorsAdditionsOnTheNextSurvivor() {
        val input = androidVector
        val source = ZipFile(input).use { z -> z.entries().toList().map { it.name } }
        val assets = source.filter { it.startsWith("base/assets/") }
        val firstAsset = assets.first()
        // Removed, and an addition after it takes its place (before the next survivor).
        val names = edited(input, "remove-anchor") { e ->
            e.remove(firstAsset)
            e.add(firstAsset, "base/assets/zz/novo.bin", byteArrayOf(1))
        }
        val i = source.indexOf(firstAsset)
        assertEquals(source.subList(0, i) + "base/assets/zz/novo.bin" + source.subList(i + 1, source.size), names)
        // The last entry of the bundle removed: the addition goes at the end (a bundle with an asset entry last).
        val reordered = work.resolve("asset-last.aab").also { f ->
            val all = entries(input)
            zip(f, all.filter { it.first != firstAsset } + all.single { it.first == firstAsset })
        }
        val order = ZipFile(reordered).use { z -> z.entries().toList().map { it.name } }
        assertEquals(order.dropLast(1) + "base/assets/zz/fim.bin", edited(reordered, "remove-last") { e ->
            e.remove(firstAsset); e.add(firstAsset, "base/assets/zz/fim.bin", byteArrayOf(1))
        })
        // A removed name can be added again (replaced in place).
        assertEquals(source, edited(input, "replace") { e -> e.remove(firstAsset); e.add(firstAsset, firstAsset, byteArrayOf(9)) })
        // Defects of a control: removing twice, an absent entry, an added one, the manifest; adding an existing name.
        val artifact = ArtifactReader.read(input)
        ZipFile(input).use { zip ->
            val edit = AabEdit(zip, zip.entries().toList(), artifact)
            edit.remove(firstAsset)
            internal { edit.remove(firstAsset) }
            internal { edit.remove("base/assets/nao-existe") }
            edit.add(firstAsset, "base/assets/zz/a.bin", byteArrayOf(1))
            internal { edit.remove("base/assets/zz/a.bin") }
            internal { edit.add(firstAsset, "base/assets/zz/a.bin", byteArrayOf(1)) }
            internal { edit.add(firstAsset, assets.last(), byteArrayOf(1)) }
            internal { edit.add("base/nao-existe", "base/assets/zz/b.bin", byteArrayOf(1)) }
            internal { edit.remove(AabInjector.MANIFEST) }
        }
    }

    @Test fun theEditorReplacesAnEntryInPlaceAndRefusesTheDefects() {
        val input = androidVector
        val source = entries(input)
        val target = source.first { it.first.startsWith("base/assets/") }.first
        val out = work.resolve("edit-replace-in-place").apply { mkdirs() }
        val injected = AabInjector.inject(input, ArtifactReader.read(input), listOf(Step { e -> e.replace(target, byteArrayOf(7, 7)) } to JsonObject()),
            ControlContext(Cli.today(), lab = true), out)
        // Same place, new bytes, the source entry's time; everything else as it was.
        assertEquals(source.map { it.first }, entries(injected.output).map { it.first })
        assertArrayEquals(byteArrayOf(7, 7), entries(injected.output).toMap().getValue(target))
        for ((n, b) in source) if (n != target) assertArrayEquals(n, b, entries(injected.output).toMap().getValue(n))
        val time = { f: File -> ZipFile(f).use { z -> z.getEntry(target).time } }
        assertEquals(time(input), time(injected.output))
        // Defects of a control: absent, a directory entry, removed, replaced twice, the manifest, the resource table,
        // and removing a replaced one.
        val withDir = work.resolve("with-dir.aab").also { f ->
            ZipOutputStream(f.outputStream()).use { z ->
                z.putNextEntry(ZipEntry("base/assets/pasta/")); z.closeEntry()
                for ((n, b) in source) { z.putNextEntry(ZipEntry(n)); z.write(b); z.closeEntry() }
            }
        }
        val artifact = ArtifactReader.read(withDir)
        ZipFile(withDir).use { zip ->
            val edit = AabEdit(zip, zip.entries().toList(), artifact)
            internal { edit.replace("base/assets/nao-existe", byteArrayOf(1)) }
            internal { edit.replace("base/assets/pasta/", byteArrayOf(1)) }
            edit.remove(target)
            internal { edit.replace(target, byteArrayOf(1)) }
            val other = source.last { it.first.startsWith("base/assets/") && it.first != target }.first
            edit.replace(other, byteArrayOf(1))
            internal { edit.replace(other, byteArrayOf(2)) }
            internal { edit.remove(other) }
            internal { edit.replace(AabInjector.MANIFEST, byteArrayOf(1)) }
            internal { edit.replace(AabInjector.RESOURCES, byteArrayOf(1)) }
        }
    }

    // ---- the randomness seam and the zeroing

    /** No mutable state in the control (the seam is per call) and the production source is a plain SecureRandom. */
    @Test fun theProductionRandomnessIsSecureRandomAndTheSeamIsPerCall() {
        assertEquals(SecureRandom::class.java, AssetEncryption.randomSource.javaClass)
        val fields = AssetEncryption::class.java.declaredFields.filter { !java.lang.reflect.Modifier.isStatic(it.modifiers) }
        assertEquals(emptyList<String>(), fields.filter { !java.lang.reflect.Modifier.isFinal(it.modifiers) }.map { it.name })
        val statics = AssetEncryption::class.java.declaredFields.filter { java.lang.reflect.Modifier.isStatic(it.modifiers) }
        assertEquals(emptyList<String>(), statics.filter { !java.lang.reflect.Modifier.isFinal(it.modifiers) }.map { it.name })
    }

    /**
     * The `dek` the writer drew is zeroed when it returns and when it fails (here: a file nonce of the wrong size). Only
     * the `dek` can be seen from outside: the zeroing of `kek`, `k_i`, the header payload and the deflated bytes has no
     * test (their arrays never leave [Sealer]).
     */
    @Test fun theWriterZeroesTheDekAlsoOnAFailure() {
        val parsed = SealedSection(listOf("assets/regras/tabela.json"), null)
        val files = mapOf("assets/regras/tabela.json" to "{}".toByteArray())
        val drawn = mutableListOf<ByteArray>()
        Sealer.seal(FIXTURE, 42, parsed, files) { n -> ByteArray(n) { 7 }.also { drawn += it } }
        assertEquals(4, drawn.size)
        assertTrue(drawn[0].all { it == 0.toByte() })
        val failing = mutableListOf<ByteArray>()
        try {
            Sealer.seal(FIXTURE, 42, parsed, files) { n -> ByteArray(if (failing.size == 3) n + 1 else n) { 7 }.also { failing += it } }
            fail("expected internal-error")
        } catch (e: ProtectException) {
            assertEquals(ErrorCode.INTERNAL, e.error)
        }
        assertTrue(failing[0].all { it == 0.toByte() })
    }

    // ---- signing, signed and STORED inputs, the report of a refusal

    /**
     * The signature of a sealed bundle (a key generated in the test). D-14e: a registered CLI run with `--sign keystore`
     * signs the sealed bundle (the `sign == "keystore"` wiring and `report.output.signed`); the writer path is also
     * checked as `Cli.run` takes it: profile → controls → plan → [AabInjector.inject] with `lab = false` (the
     * `.protected.aab` name) and [AabSigner.sign] on the validated temporary file, with the gate off in the context.
     */
    @Test fun theInjectorSignsTheSealedBundleWithAKeyGeneratedInTheTest() {
        val context = ControlContext(Cli.today(), lab = false)
        val profile = Profile.read(profile("$runtime,$canarySection"))
        val resolved = Controls.resolve(profile, context)
        assertEquals(listOf(RuntimeInjection, AssetEncryption), resolved.map { it.first })
        val artifact = ArtifactReader.read(canaryApp)
        resolved.forEach { (control, section) -> control.plan(section.fields, artifact, context) }
        val out = work.resolve("signed-run").apply { mkdirs() }
        var certificate: String? = null
        val injected = AabInjector.inject(canaryApp, artifact, resolved.map { it.first to it.second.fields }, context, out,
            lab = false) { temp -> certificate = AabSigner.sign(temp, keystore, "fixture", mapOf("SENTOMARU_KEYSTORE_PASSWORD" to STORE_PASS)) }
        val protected = output(out, canaryApp, ".protected.aab")
        assertEquals(protected.canonicalFile, injected.output.canonicalFile)
        assertNotNull(certificate)
        assertTrue(exec(jdk("jarsigner"), "-verify", protected.path).contains("jar verified."))
        assertEquals(injected.sha256, sha256(protected))
        assertTrue(injected.changes.getValue(AssetEncryption.id).isNotEmpty())
        bundletool("validate", "--bundle=${protected.path}")
        assertEquals(canaries.getValue("string"), reader(entries(protected).toMap(), "base/", FIXTURE, 42).string("saudacao"))
        // The CLI run: registered, signed with the keystore, the report says so.
        FakeRegistry().use { registry ->
            val env = mapOf("SENTOMARU_BUILDER_TOKEN" to "builder-token-fixture", "SENTOMARU_API" to registry.address.toString(),
                "SENTOMARU_KEYSTORE_PASSWORD" to STORE_PASS)
            val cli = work.resolve("signed-cli")
            val (code, _, err) = run("--input", canaryApp.path, "--profile", profile("$runtime,$canarySection").path, "--out", cli.path,
                "--sign", "keystore", "--keystore", keystore.path, "--key-alias", "fixture", env = env)
            assertEquals(err, 0, code)
            val r = report(cli)
            val output = r.getAsJsonObject("output")
            assertTrue(output.get("signed").asBoolean)
            assertEquals(certificate, output.get("signingCertSha256").asString)
            assertEquals("applied", r.getAsJsonObject("signing").get("status").asString)
            assertEquals("registered", r.getAsJsonObject("registration").get("status").asString)
            val signed = output(cli, canaryApp, ".protected.aab")
            assertEquals(output.get("sha256").asString, sha256(signed))
            assertTrue(exec(jdk("jarsigner"), "-verify", signed.path).contains("jar verified."))
            assertEquals(canaries.getValue("string"), reader(entries(signed).toMap(), "base/", FIXTURE, 42).string("saudacao"))
        }
    }

    @Test fun signedAndStoredInputsAreSealedAndRead() {
        val signed = work.resolve("sealed-signed-input.aab").also { f ->
            canaryApp.copyTo(f, overwrite = true)
            exec(jdk("jarsigner"), "-keystore", keystore.path, "-storetype", "PKCS12", "-storepass", STORE_PASS, f.path, "fixture")
        }
        val stored = work.resolve("sealed-stored-input.aab").also { f -> stored(f, entries(canaryApp)) }
        for ((input, removed) in listOf(signed to true, stored to false)) {
            val out = work.resolve("sealed-${input.nameWithoutExtension}")
            val (code, _, err) = labRun(input, out, canarySection)
            assertEquals(err, 0, code)
            assertEquals(removed, warnings(out).contains("input-signature-removed"))
            val protected = output(out, input)
            val after = entries(protected).toMap()
            assertTrue(after.keys.none { it.startsWith("META-INF/") && (it.endsWith(".SF") || it.endsWith(".EC") || it.endsWith(".RSA")) })
            bundletool("validate", "--bundle=${protected.path}")
            val r = reader(after, "base/", FIXTURE, 42)
            assertEquals(canaries.getValue("string"), r.string("saudacao"))
            assertArrayEquals(canaryAssets(1).getValue("assets/regras/tabela.json"), r.bytes("assets/regras/tabela.json"))
            for (p in canaryPaths) assertNull(after["base/$p"])
        }
    }

    /** A refused strings file: neither its content nor its path reaches the report, stdout or stderr. */
    @Test fun aStringsRefusalCarriesNothingOfTheFile() {
        val secret = "SENTOMARU-CANARIO-strings-${UUID.randomUUID()}"
        val app = bundle("strings-refused", mapOf("assets/regras/tabela.json" to "{}".toByteArray(),
            "assets/segredo/textos.json" to """{"chave":["$secret"]}""".toByteArray()))
        val controls = section(listOf("assets/regras/tabela.json"), strings = "assets/segredo/textos.json")
        for ((mode, result) in listOf("dry" to dry(app, work.resolve("strings-refused-dry"), controls),
                "lab" to labRun(app, work.resolve("strings-refused-lab"), controls))) {
            refused(5, "app-incompatible", AssetEncryption.STRINGS_INVALID, result)
            val report = work.resolve("strings-refused-$mode").resolve("report.json")
            val texts = listOf(result.second, result.third) + listOfNotNull(report.takeIf { it.isFile }?.readText())
            for (t in texts) {
                assertFalse(t, t.contains(secret))
                assertFalse(t, t.contains("segredo"))
            }
        }
    }

    @Test fun engineManagedPathsAreTheContractList() {
        for (p in listOf("assets/flutter_assets/AssetManifest.bin", "assets/flutter_assets/NOTICES.Z", "assets/flutter_assets/kernel_blob.bin",
                "assets/flutter_assets/NativeAssetsManifest.json", "assets/flutter_assets/novo-arquivo-do-motor",
                "assets/flutter_assets/shaders/x.frag", "assets/flutter_assets/fonts/x.bin", "assets/flutter_assets/packages/a/b.png",
                "assets/a.ttf", "assets/a/b.OTF", "assets/c.Ttc", "assets/dexopt/baseline.prof"))
            assertTrue(p, AssetEncryption.engineManaged(p))
        for (p in listOf("assets/flutter_assets/assets/dados/catalogo.bin", "assets/regras/tabela.json", "assets/ttf", "assets/a.ttf.bin",
                "assets/fonts/x.bin", "assets/flutter_assets2/x.bin"))
            assertFalse(p, AssetEncryption.engineManaged(p))
    }
}
