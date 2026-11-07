package br.com.ebees.sentomaru.sentomaru_flutter

import android.content.Context
import br.com.ebees.sentomaru.sdk.sealed.SentomaruSealed
import br.com.ebees.sentomaru.sdk.sealed.SentomaruSealedException
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel.Result
import java.io.FileNotFoundException
import java.util.concurrent.ExecutorService
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.Executors

/**
 * D-14b: the Android side of `SentomaruSealed.load`/`string`/`configure` in Dart. It decrypts with the SDK's sealed
 * reader ([SentomaruSealed], module `sdk/android/sealed`); there is no cryptography in Dart. Dart passes the key of the
 * `pubspec.yaml` (`assets/dados/x.bin`), translated here to the canonical path the CLI sealed
 * (`assets/flutter_assets/assets/dados/x.bin`, contracts/devsecops/cli-v1.md, asset-encryption).
 *
 * Also the marker `sentomaru protect` (asset-encryption) looks for by name in the app's DEX (`-keepnames` in
 * consumer-rules.pro; `SentomaruFlutterPlugin` exists in plugin versions without the reader and does not count). Like
 * every marker, it proves the reader is linked, not that the app calls it.
 *
 * Reads run on a worker thread of their own (up to 4 MiB to decrypt and inflate), never the main thread nor the
 * plugin's signing executor; replies go through [post] (the main looper in the plugin).
 */
class SentomaruFlutterSealed internal constructor(
    private val reader: Reader,
    private val post: (Runnable) -> Unit,
    private val executor: ExecutorService = Executors.newSingleThreadExecutor(),
) {
    /** The SDK reader's calls, by canonical path; a seam for the plugin's JVM tests. */
    internal interface Reader {
        fun configure(allowPlainFallback: Boolean, plainStringsPath: String?)
        fun bytes(path: String): ByteArray
        fun string(key: String): String?
    }

    internal constructor(context: Context, post: (Runnable) -> Unit) : this(sdkReader(context), post)

    /** True for the channel methods this class answers. */
    fun handles(method: String): Boolean = method in METHODS

    fun onMethodCall(call: MethodCall, result: Result) {
        val args = call.arguments as? Map<*, *>
        when (call.method) {
            CONFIGURE -> {
                val allow = args?.get("allowPlainFallback") as? Boolean
                val stringsKey = args?.get("plainStringsKey")
                if (allow == null || (stringsKey != null && (stringsKey !is String || !validKey(stringsKey)))) {
                    return reply { result.error(INVALID_ARGUMENT, "Invalid sealed configuration", null) }
                }
                // Synchronous and cheap: the next read sees it.
                reader.configure(allow, (stringsKey as String?)?.let(::canonical))
                reply { result.success(null) }
            }
            LOAD -> run(result, args?.get("key"), ::validKey) { reader.bytes(canonical(it)) }
            STRING -> run(result, args?.get("key"), String::isNotEmpty) { reader.string(it) }
            else -> reply { result.notImplemented() }
        }
    }

    /**
     * The engine detached: reads not started yet are answered with an error (none is left without a reply) and the
     * one in flight is interrupted; Flutter drops replies of a detached engine. Later calls are refused the same way.
     */
    fun shutdown() {
        for (pending in executor.shutdownNow()) (pending as? Read)?.refuse()
    }

    /** One read on [executor]; [refuse] answers it when it never runs. */
    private inner class Read(private val result: Result, private val key: String, private val read: (String) -> Any?) :
        Runnable {
        override fun run() {
            try {
                val value = read(key)
                reply { result.success(value) }
            } catch (e: SentomaruSealedException) {
                reply { result.error(e.code.wire, e.code.wire, null) }
            } catch (e: FileNotFoundException) {
                // Only with the plain fallback (an unsealed debug build): the asset is not in the package.
                reply { result.error(ASSET_NOT_FOUND, "Asset not found", ASSET_NOT_FOUND) }
            } catch (e: Exception) {
                reply { result.error(CHANNEL_ERROR, "Native sealed read failed", null) }
            } catch (e: OutOfMemoryError) {
                // Up to 4 MiB compressed plus the plaintext in memory: on a small heap the read fails, the app does not.
                reply { result.error(CHANNEL_ERROR, "Native sealed read out of memory", null) }
            }
        }

        fun refuse() = reply { result.error(CHANNEL_ERROR, "Sentomaru plugin detached", null) }
    }

    private fun run(result: Result, key: Any?, valid: (String) -> Boolean, read: (String) -> Any?) {
        if (key !is String || !valid(key)) {
            return reply { result.error(INVALID_ARGUMENT, "Invalid sealed asset key", null) }
        }
        val task = Read(result, key, read)
        try {
            executor.execute(task)
        } catch (e: RejectedExecutionException) {
            task.refuse()
        }
    }

    private fun reply(block: () -> Unit) = post(Runnable { block() })

    internal companion object {
        const val CONFIGURE = "sealedConfigure"
        const val LOAD = "sealedLoad"
        const val STRING = "sealedString"
        val METHODS = setOf(CONFIGURE, LOAD, STRING)
        const val INVALID_ARGUMENT = "InvalidArgument"
        const val ASSET_NOT_FOUND = "AssetNotFound"
        const val CHANNEL_ERROR = "ChannelError"
        /** Where the Flutter tool puts the app's assets in the APK. */
        const val FLUTTER_ASSETS = "assets/flutter_assets/"

        /** A `pubspec.yaml` asset key: relative, non-empty, no empty, `.` or `..` segment. */
        fun validKey(key: String): Boolean =
            key.isNotEmpty() && key.length <= 512 && key.split('/').none { it.isEmpty() || it == "." || it == ".." }

        /** The canonical path of a `pubspec.yaml` key (the path in the profile and in the sealed format). */
        fun canonical(key: String): String = FLUTTER_ASSETS + key

        /** The production [Reader]: the SDK's [SentomaruSealed] with the plugin's application context. */
        fun sdkReader(context: Context): Reader = object : Reader {
            override fun configure(allowPlainFallback: Boolean, plainStringsPath: String?) =
                SentomaruSealed.configure(allowPlainFallback, plainStringsPath)
            override fun bytes(path: String): ByteArray = SentomaruSealed.bytes(context, path)
            override fun string(key: String): String? = SentomaruSealed.string(context, key)
        }
    }
}
