package br.com.ebees.sentomaru.protect

import com.google.gson.JsonParser
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/** G-03g1: `protect --dry-run` over a synthetic IPA (zip with a plist, no app content). */
class IpaReaderTest {
    @get:Rule val tmp = TemporaryFolder()

    private val xmlPlist = """<?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict>
          <key>CFBundleIdentifier</key><string>br.com.example.ios</string>
          <key>CFBundleShortVersionString</key><string>1.2.3</string>
          <key>CFBundleVersion</key><string>45</string>
          <key>MinimumOSVersion</key><string>15.0</string>
          <key>CFBundleExecutable</key><string>Runner</string>
        </dict></plist>""".trimIndent().toByteArray()

    /** A binary plist (`bplist00`) with the same five string entries, built with 1-byte offsets and references. */
    private fun binaryPlist(): ByteArray {
        val pairs = listOf("CFBundleIdentifier" to "br.com.example.ios", "CFBundleShortVersionString" to "1.2.3",
            "CFBundleVersion" to "45", "MinimumOSVersion" to "15.0", "CFBundleExecutable" to "Runner")
        val body = ByteArrayOutputStream().apply { write("bplist00".toByteArray()) }
        val offsets = ArrayList<Int>()
        fun str(s: String) {
            offsets.add(body.size())
            if (s.length < 15) body.write(0x50 or s.length) else { body.write(0x5F); body.write(0x10); body.write(s.length) }
            body.write(s.toByteArray(Charsets.US_ASCII))
        }
        // object 0 = the dictionary (written last, but its offset is slot 0), 1..5 keys, 6..10 values
        offsets.add(-1)
        pairs.forEach { str(it.first) }
        pairs.forEach { str(it.second) }
        offsets[0] = body.size()
        body.write(0xD0 or pairs.size)
        (1..5).forEach { body.write(it) }
        (6..10).forEach { body.write(it) }
        val table = body.size()
        offsets.forEach { body.write(it) }
        val trailer = ByteArray(32)
        trailer[6] = 1; trailer[7] = 1; trailer[15] = offsets.size.toByte(); trailer[23] = 0; trailer[31] = table.toByte()
        body.write(trailer)
        return body.toByteArray()
    }

    private fun ipa(name: String = "app.ipa", plist: ByteArray? = xmlPlist, extra: List<String> = emptyList(), app: String = "Runner.app"): File {
        val file = tmp.newFile(name)
        ZipOutputStream(file.outputStream()).use { z ->
            fun put(n: String, b: ByteArray) { z.putNextEntry(ZipEntry(n)); z.write(b); z.closeEntry() }
            put("Payload/$app/Runner", byteArrayOf(1))
            if (plist != null) put("Payload/$app/Info.plist", plist)
            extra.forEach { put("Payload/$app/$it", byteArrayOf(0)) }
        }
        return file
    }

    private fun profile() = tmp.newFile().apply {
        writeText("""{"schemaVersion":"1","kind":"protect","profileId":"fixture-protect",
            "scope":{"organization":"ebees","app":"exampleapp","environment":"hml"},"controls":{"runtime-injection":{"version":"1","enrollmentUrl":"https://api.example/enroll"}}}""")
    }

    private fun run(vararg args: String): Triple<Int, String, String> {
        val out = StringBuilder(); val err = StringBuilder()
        val code = Cli.run(args.toList(), emptyMap(), { out.append(it) }, { err.append(it) })
        return Triple(code, out.toString(), err.toString())
    }

    private fun dry(input: File) = arrayOf("--input", input.path, "--profile", profile().path, "--out", tmp.newFolder().path, "--dry-run")

    @Test fun reportsXmlPlistFactsAndFrameworks() {
        val file = ipa(extra = listOf("Frameworks/SentomaruCore.framework/SentomaruCore", "Frameworks/App.framework/App", "embedded.mobileprovision"))
        val (code, out, err) = run(*dry(file))
        assertEquals(err, 0, code)
        val report = JsonParser.parseString(out).asJsonObject
        val input = report.getAsJsonObject("input")
        assertEquals("ipa", input.get("kind").asString)
        assertEquals("br.com.example.ios", input.get("bundleId").asString)
        assertEquals("1.2.3", input.get("shortVersion").asString)
        assertEquals("15.0", input.get("minimumOsVersion").asString)
        assertEquals(listOf("App.framework", "SentomaruCore.framework"), input.getAsJsonArray("frameworks").map { it.asString })
        assertTrue(input.get("sentomaruFramework").asBoolean)
        assertTrue(input.get("hasProvisioningProfile").asBoolean)
        assertEquals(listOf("ipa-controls-not-evaluated"), report.getAsJsonArray("warnings").map { it.asJsonObject.get("code").asString })
        assertTrue(report.getAsJsonArray("controls").isEmpty)
    }

    @Test fun readsABinaryPlistLikeTheXmlOne() {
        assertEquals(IpaReader.parsePlist(xmlPlist.inputStream()), IpaReader.parsePlist(binaryPlist().inputStream()))
        val (code, out, err) = run(*dry(ipa(plist = binaryPlist())))
        assertEquals(err, 0, code)
        assertEquals("br.com.example.ios", JsonParser.parseString(out).asJsonObject.getAsJsonObject("input").get("bundleId").asString)
    }

    @Test fun warnsWhenNoSdkFrameworkIsEmbedded() {
        val (_, out, _) = run(*dry(ipa()))
        val report = JsonParser.parseString(out).asJsonObject
        assertFalse(report.getAsJsonObject("input").get("sentomaruFramework").asBoolean)
        assertTrue(report.getAsJsonArray("warnings").any { it.asJsonObject.get("code").asString == "ipa-sdk-framework-absent" })
    }

    @Test fun aRealRunOfAnIpaIsAUsageError() {
        val (code, _, err) = run("--input", ipa().path, "--profile", profile().path, "--out", tmp.newFolder().path, "--sign", "none")
        assertEquals(err, 2, code)
        assertEquals("usage", JsonParser.parseString(err).asJsonObject.get("code").asString)
    }

    @Test fun refusesWhatIsNotAnIpa() {
        fun inputFormat(file: File) {
            val (code, _, err) = run(*dry(file))
            assertEquals(err, 3, code)
            assertEquals("input-format", JsonParser.parseString(err).asJsonObject.get("code").asString)
        }
        inputFormat(tmp.newFile("notzip.ipa").apply { writeText("not a zip") })
        inputFormat(ipa("noplist.ipa", plist = null))
        inputFormat(ipa("noid.ipa", plist = "<plist><dict><key>A</key><string>b</string></dict></plist>".toByteArray()))
        inputFormat(ipa("odd.ipa", plist = "<plist><dict><key>A</key></dict></plist>".toByteArray()))
        inputFormat(ipa("truncated.ipa", plist = binaryPlist().copyOf(30)))
        val two = tmp.newFile("two.ipa")
        ZipOutputStream(two.outputStream()).use { z ->
            listOf("A.app", "B.app").forEach { z.putNextEntry(ZipEntry("Payload/$it/Info.plist")); z.write(xmlPlist); z.closeEntry() }
        }
        inputFormat(two)
        val slip = tmp.newFile("slip.ipa")
        ZipOutputStream(slip.outputStream()).use { z -> z.putNextEntry(ZipEntry("Payload/../x")); z.closeEntry() }
        inputFormat(slip)
    }

    @Test fun doesNotResolveExternalEntities() {
        val xxe = """<?xml version="1.0"?><!DOCTYPE plist [<!ENTITY x SYSTEM "file:///etc/hostname">]>
            <plist><dict><key>CFBundleIdentifier</key><string>&x;</string></dict></plist>""".toByteArray()
        val (code, out, _) = run(*dry(ipa(plist = xxe)))
        if (code == 0) assertEquals("", JsonParser.parseString(out).asJsonObject.getAsJsonObject("input").get("bundleId").asString.trim())
        else assertEquals(3, code)
    }
}
