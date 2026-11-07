package br.com.ebees.sentomaru.sdk.sealed

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.fail
import org.junit.Test
import java.io.File
import java.io.FileNotFoundException

/**
 * D-14x10: `allowPlainFallback`. Off (the default), an unsealed package is `not-sealed`; on, it reads the plain file at
 * the canonical path, but only when the package has no `header.bin`. The unsealed case is the sample-app's own assets
 * (src/main/assets/d14b, what a debug build without the CLI ships); the sealed case is the shared vectors.
 */
class SealedFallbackTest {
    private val sampleAssets = File(requireNotNull(System.getProperty("sentomaru.sampleAssets")) { "sentomaru.sampleAssets not set" })
    private val rules = "assets/d14b/regras.json"
    private val strings = "assets/d14b/sentomaru-strings.json"

    private fun unsealed(): SealedAssets {
        val source = DirSource(sampleAssets)
        return SealedAssets(source, SealedReader(source, "br.com.ebees.sentomaru.sample", 1))
    }

    private fun code(block: () -> Unit): String = try {
        block()
        fail("expected SentomaruSealedException")
        error("unreachable")
    } catch (e: SentomaruSealedException) {
        e.code.wire
    }

    @Test
    fun `the sample-app without the CLI reads plain with the fallback on`() {
        val assets = unsealed()
        assertArrayEquals(File(sampleAssets, "d14b/regras.json").readBytes(), assets.bytes(rules, allowPlainFallback = true))
        assertEquals("Olá, técnico", assets.string("saudacao", allowPlainFallback = true, plainStringsPath = strings))
        assertNull(assets.string("ausente", allowPlainFallback = true, plainStringsPath = strings))
    }

    @Test
    fun `the sample-app without the CLI fails with not-sealed with the fallback off`() {
        val assets = unsealed()
        assertEquals("not-sealed", code { assets.bytes(rules, allowPlainFallback = false) })
        assertEquals("not-sealed", code { assets.string("saudacao", allowPlainFallback = false, plainStringsPath = strings) })
    }

    @Test
    fun `fallback strings need the plain strings path`() {
        assertEquals("not-sealed", code { unsealed().string("saudacao", allowPlainFallback = true, plainStringsPath = null) })
    }

    @Test
    fun `fallback to a missing plain file fails like the AssetManager`() {
        try {
            unsealed().bytes("assets/d14b/ausente.json", allowPlainFallback = true)
            fail("expected FileNotFoundException")
        } catch (e: FileNotFoundException) {
            // the same failure as `assets.open` of a missing file
        }
    }

    @Test
    fun `with header bin present the fallback has no effect`() {
        val case = Vectors.case("android-assets-and-strings")
        val entries = Vectors.entries(case)
        // A plain file at a canonical path that is not sealed: a sealed package never reads it, even with the option on.
        entries["assets/regras/outro.json"] = "{}".toByteArray()
        val source = MapSource(entries)
        val assets = SealedAssets(source, SealedReader(source, case["package"] as String, Vectors.versionCode(case)))
        assertEquals("not-sealed", code { assets.bytes("assets/regras/outro.json", allowPlainFallback = true) })
        val f = Vectors.files(case)[0]
        assertArrayEquals(Vectors.hex(f["plainHex"] as String), assets.bytes(f["path"] as String, allowPlainFallback = true))
        assertEquals("Concluir", assets.string("app.rotulo.fim", allowPlainFallback = true, plainStringsPath = "assets/regras/outro.json"))
    }

    @Test
    fun `a broken header is never a reason to fall back`() {
        val case = Vectors.case("android-assets-and-strings")
        val entries = Vectors.entries(case)
        val header = entries.getValue(SealedFormat.HEADER)
        entries[SealedFormat.HEADER] = header.copyOf().also { it[it.size - 1] = (it[it.size - 1].toInt() xor 1).toByte() }
        val f = Vectors.files(case)[0]
        entries[f["path"] as String] = Vectors.hex(f["plainHex"] as String)
        val source = MapSource(entries)
        val assets = SealedAssets(source, SealedReader(source, case["package"] as String, Vectors.versionCode(case)))
        assertEquals("integrity", code { assets.bytes(f["path"] as String, allowPlainFallback = true) })
    }

    @Test
    fun `an unknown header format stays format-unsupported with the fallback on`() {
        val case = Vectors.case("android-assets-and-strings")
        val entries = Vectors.entries(case)
        entries[SealedFormat.HEADER] = entries.getValue(SealedFormat.HEADER).copyOf().also { it[4] = 2 }
        val f = Vectors.files(case)[0]
        entries[f["path"] as String] = Vectors.hex(f["plainHex"] as String)
        val source = MapSource(entries)
        val assets = SealedAssets(source, SealedReader(source, case["package"] as String, Vectors.versionCode(case)))
        assertEquals("format-unsupported", code { assets.bytes(f["path"] as String, allowPlainFallback = true) })
        assertEquals("format-unsupported",
            code { assets.string("saudacao", allowPlainFallback = true, plainStringsPath = f["path"] as String) })
    }
}
