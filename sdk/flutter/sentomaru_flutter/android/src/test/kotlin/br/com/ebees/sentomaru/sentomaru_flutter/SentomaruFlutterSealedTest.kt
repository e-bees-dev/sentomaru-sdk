package br.com.ebees.sentomaru.sentomaru_flutter

import br.com.ebees.sentomaru.sdk.sealed.SentomaruSealedException
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel.Result
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.io.FileNotFoundException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * D-14b: the channel side of `SentomaruSealed` in Dart. Failure classes: a pubspec key that does not become the
 * canonical path the CLI sealed (checked against the Flutter case of the shared vectors), a read on the caller's thread,
 * a typed error that reaches Dart under another code, a bad key or configuration that reaches the reader, and the plain
 * fallback's missing file confused with `not-sealed`. The decryption itself is the sealed module's (its own tests run
 * every vector).
 */
class SentomaruFlutterSealedTest {
    private class Recorder : Result {
        val done = CountDownLatch(1)
        @Volatile var value: Any? = null
        @Volatile var error: String? = null
        @Volatile var notImplemented = false
        override fun success(result: Any?) { value = result; done.countDown() }
        override fun error(errorCode: String, errorMessage: String?, errorDetails: Any?) { error = errorCode; done.countDown() }
        override fun notImplemented() { notImplemented = true; done.countDown() }
        fun await() = assertTrue("no reply", done.await(5, TimeUnit.SECONDS))
    }

    private class FakeReader(val fail: Exception? = null) : SentomaruFlutterSealed.Reader {
        val calls = mutableListOf<String>()
        @Volatile var thread: Thread? = null
        override fun configure(allowPlainFallback: Boolean, plainStringsPath: String?) {
            calls += "configure:$allowPlainFallback:$plainStringsPath"
        }
        override fun bytes(path: String): ByteArray {
            thread = Thread.currentThread()
            calls += "bytes:$path"
            fail?.let { throw it }
            return path.toByteArray()
        }
        override fun string(key: String): String? {
            thread = Thread.currentThread()
            calls += "string:$key"
            fail?.let { throw it }
            return if (key == "ausente") null else "v:$key"
        }
    }

    private val executor = Executors.newSingleThreadExecutor()

    @After
    fun stop() {
        executor.shutdownNow()
    }

    private fun sealed(reader: SentomaruFlutterSealed.Reader) = SentomaruFlutterSealed(reader, { it.run() }, executor)

    private fun call(reader: SentomaruFlutterSealed.Reader, method: String, args: Any?): Recorder =
        Recorder().also { sealed(reader).onMethodCall(MethodCall(method, args), it); it.await() }

    @Test
    fun pubspecKeyBecomesTheCanonicalPathOfTheVectors() {
        val path = requireNotNull(System.getProperty("sentomaru.sealedVectors")) { "sentomaru.sealedVectors not set" }
        val cases = JSONObject(File(path).readText(Charsets.UTF_8)).getJSONArray("cases")
        var flutter = 0
        for (i in 0 until cases.length()) {
            val files = cases.getJSONObject(i).getJSONArray("files")
            for (j in 0 until files.length()) {
                val f = files.getJSONObject(j)
                if (!f.has("flutterKey")) continue
                assertEquals(f.getString("path"), SentomaruFlutterSealed.canonical(f.getString("flutterKey")))
                val reader = FakeReader()
                val r = call(reader, "sealedLoad", mapOf("key" to f.getString("flutterKey")))
                assertArrayEquals(f.getString("path").toByteArray(), r.value as ByteArray)
                flutter++
            }
        }
        assertEquals(1, flutter)
    }

    @Test
    fun readsRunOffTheCallerThread() {
        val reader = FakeReader()
        call(reader, "sealedLoad", mapOf("key" to "assets/dados/catalogo.bin"))
        assertNotSame(Thread.currentThread(), reader.thread)
        call(reader, "sealedString", mapOf("key" to "saudacao"))
        assertNotSame(Thread.currentThread(), reader.thread)
    }

    @Test
    fun stringsAreLookedUpByKeyAndAbsentIsNull() {
        val reader = FakeReader()
        assertEquals("v:app.rotulo.fim", call(reader, "sealedString", mapOf("key" to "app.rotulo.fim")).value)
        val absent = call(reader, "sealedString", mapOf("key" to "ausente"))
        assertEquals(null, absent.value)
        assertEquals(null, absent.error)
        assertEquals(listOf("string:app.rotulo.fim", "string:ausente"), reader.calls)
    }

    @Test
    fun typedErrorsReachDartUnderTheContractCodes() {
        for (code in SentomaruSealedException.Code.entries) {
            val r = call(FakeReader(SentomaruSealedException(code)), "sealedLoad", mapOf("key" to "assets/x.bin"))
            assertEquals(code.wire, r.error)
            val s = call(FakeReader(SentomaruSealedException(code)), "sealedString", mapOf("key" to "k"))
            assertEquals(code.wire, s.error)
        }
        assertEquals(setOf("not-sealed", "integrity", "format-unsupported"), SentomaruSealedException.Code.entries.map { it.wire }.toSet())
    }

    @Test
    fun missingPlainFileAndOtherFailuresAreNotContractCodes() {
        assertEquals("AssetNotFound", call(FakeReader(FileNotFoundException("x")), "sealedLoad", mapOf("key" to "a/b")).error)
        assertEquals("ChannelError", call(FakeReader(IllegalStateException("x")), "sealedLoad", mapOf("key" to "a/b")).error)
    }

    @Test
    fun badKeysNeverReachTheReader() {
        val reader = FakeReader()
        for (key in listOf(null, 7, "", "/abs", "a//b", "a/./b", "../x", "a/..", "a/", "x".repeat(513))) {
            assertEquals("key $key", "InvalidArgument", call(reader, "sealedLoad", mapOf("key" to key)).error)
        }
        assertEquals("InvalidArgument", call(reader, "sealedString", mapOf("key" to "")).error)
        assertEquals("InvalidArgument", call(reader, "sealedString", null).error)
        assertTrue(reader.calls.isEmpty())
    }

    @Test
    fun configureTranslatesTheStringsKeyAndRefusesBadArguments() {
        val reader = FakeReader()
        call(reader, "sealedConfigure", mapOf("allowPlainFallback" to true, "plainStringsKey" to "assets/textos.json"))
        call(reader, "sealedConfigure", mapOf("allowPlainFallback" to false, "plainStringsKey" to null))
        assertEquals(listOf("configure:true:assets/flutter_assets/assets/textos.json", "configure:false:null"), reader.calls)
        for (args in listOf(null, emptyMap<String, Any?>(), mapOf("allowPlainFallback" to "true"),
                mapOf("allowPlainFallback" to true, "plainStringsKey" to "../x"),
                mapOf("allowPlainFallback" to true, "plainStringsKey" to 3))) {
            assertEquals("$args", "InvalidArgument", call(reader, "sealedConfigure", args).error)
        }
        assertEquals(2, reader.calls.size)
    }

    @Test
    fun onlyTheSealedMethodsAreHandled() {
        val s = sealed(FakeReader())
        assertTrue(s.handles("sealedLoad") && s.handles("sealedString") && s.handles("sealedConfigure"))
        assertFalse(s.handles("sign"))
        assertFalse(s.handles("load"))
    }

    @Test
    fun outOfMemoryIsAChannelErrorNotACrash() {
        val reader = object : SentomaruFlutterSealed.Reader {
            override fun configure(allowPlainFallback: Boolean, plainStringsPath: String?) = Unit
            override fun bytes(path: String): ByteArray = throw OutOfMemoryError("test")
            override fun string(key: String): String? = throw OutOfMemoryError("test")
        }
        assertEquals("ChannelError", call(reader, "sealedLoad", mapOf("key" to "a/b")).error)
        assertEquals("ChannelError", call(reader, "sealedString", mapOf("key" to "k")).error)
    }

    @Test
    fun shutdownAnswersPendingReadsAndRefusesLaterOnes() {
        val started = CountDownLatch(1)
        val release = CountDownLatch(1)
        val reader = object : SentomaruFlutterSealed.Reader {
            override fun configure(allowPlainFallback: Boolean, plainStringsPath: String?) = Unit
            override fun bytes(path: String): ByteArray {
                started.countDown()
                release.await(5, TimeUnit.SECONDS)
                return ByteArray(0)
            }
            override fun string(key: String): String? = "v"
        }
        val sealed = sealed(reader)
        val first = Recorder()
        val pending = Recorder()
        sealed.onMethodCall(MethodCall("sealedLoad", mapOf("key" to "a/b")), first)
        assertTrue(started.await(5, TimeUnit.SECONDS))
        sealed.onMethodCall(MethodCall("sealedString", mapOf("key" to "k")), pending)
        sealed.shutdown()
        pending.await()
        assertEquals("ChannelError", pending.error)
        val later = Recorder()
        sealed.onMethodCall(MethodCall("sealedString", mapOf("key" to "k")), later)
        later.await()
        assertEquals("ChannelError", later.error)
        release.countDown()
        first.await()   // the interrupted read still answers (Flutter drops it after a detach)
    }

    /** A Context whose package manager does not know its own package (the SDK turns it into IllegalStateException). */
    private class UnknownPackageContext : android.content.ContextWrapper(null) {
        val asked = mutableListOf<String>()
        override fun getApplicationContext(): android.content.Context = this.also { asked += "applicationContext" }
        override fun getPackageName(): String = "br.com.ebees.sentomaru.exemplos".also { asked += "packageName" }
        override fun getAssets(): android.content.res.AssetManager? = null.also { asked += "assets" }
        override fun getPackageManager(): android.content.pm.PackageManager {
            asked += "packageManager"
            throw android.content.pm.PackageManager.NameNotFoundException()
        }
    }

    @Test
    fun theContextReaderGoesThroughTheSdkWithTheApplicationContext() {
        val context = UnknownPackageContext()
        try {
            SentomaruFlutterSealed.sdkReader(context).bytes(SentomaruFlutterSealed.canonical("assets/dados/catalogo.bin"))
            org.junit.Assert.fail("expected IllegalStateException")
        } catch (e: IllegalStateException) {
            // SentomaruSealed: no versionCode for the own package, no key
        }
        assertEquals(listOf("applicationContext", "assets", "packageName", "packageManager"), context.asked)
        val viaChannel = Recorder()
        SentomaruFlutterSealed(context, { it.run() }).onMethodCall(MethodCall("sealedLoad", mapOf("key" to "a/b")), viaChannel)
        viaChannel.await()
        assertEquals("ChannelError", viaChannel.error)
    }

    @Test
    fun thePluginRoutesOnlyTheSealedMethodsAndReleasesThemOnDetach() {
        val plugin = SentomaruFlutterPlugin()
        val reader = FakeReader()
        plugin.sealed = sealed(reader)
        val load = Recorder()
        plugin.onMethodCall(MethodCall("sealedLoad", mapOf("key" to "assets/dados/catalogo.bin")), load)
        load.await()
        assertEquals(listOf("bytes:assets/flutter_assets/assets/dados/catalogo.bin"), reader.calls)
        val other = Recorder()
        plugin.onMethodCall(MethodCall("scaffoldInfo", null), other)
        other.await()
        assertEquals("sentomaru_flutter:0.0.1", other.value)
        assertEquals(1, reader.calls.size)
        plugin.releaseSealed()
        assertEquals(null, plugin.sealed)
        assertTrue(executor.isShutdown)
        val after = Recorder()
        plugin.onMethodCall(MethodCall("sealedLoad", mapOf("key" to "a/b")), after)
        after.await()
        assertTrue(after.notImplemented)
        assertEquals(1, reader.calls.size)
    }
}
