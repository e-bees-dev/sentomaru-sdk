package br.com.ebees.sentomaru.sdk.sealed

import android.content.Context
import android.content.pm.PackageManager
import android.content.res.AssetManager
import java.io.ByteArrayOutputStream
import java.io.ByteArrayInputStream
import java.io.FileNotFoundException
import java.io.IOException
import java.io.InputStream

/**
 * D-14b: reads the assets that `sentomaru protect` (control `asset-encryption`) sealed into
 * `assets/sentomaru/sealed/` (contracts/devsecops/cli-v1.md, asset-encryption, "Leitura"; ADR 0003). The app replaces
 * `assets.open("regras/tabela.json")` by `SentomaruSealed.open(context, "assets/regras/tabela.json")`: the path is the
 * **canonical** one, as in the profile (with the `assets/` prefix).
 *
 * This is data obfuscation, not secrecy (D-14x1): the key is derived on the device, without network, from values in the
 * package and a public constant of the format, so whoever has the APK recovers the files. A failed tag is a typed error,
 * never a tamper verdict.
 *
 * Lazy: nothing runs at startup. The first call reads `header.bin` and derives the `kek`; the `dek` stays in the process
 * memory; the plaintext never goes to disk. [open] returns the whole file already decrypted in memory (GCM releases the
 * plaintext only after the tag), not a stream. Plaintext is not cached: each call opens the entry again.
 *
 * Builds without the CLI (debug, tests): [configure] with `allowPlainFallback = true` reads the plain file when the
 * package has no `header.bin` (D-14x10). Off by default; turn it on only with `BuildConfig.DEBUG`. With `header.bin`
 * present it has no effect: a sealed package never falls back to plain.
 *
 * Readers that bypass this API cannot read a sealed file: `file:///android_asset/` in a WebView, `AAssetManager` in
 * native code, `AssetFileDescriptor`/`MediaPlayer`/`SoundPool`, `Typeface.createFromAsset`.
 */
object SentomaruSealed {
    /** M2 of the review: both options change together, in one immutable snapshot a read sees whole. */
    private class Config(val allowPlainFallback: Boolean, val plainStringsPath: String?)

    @Volatile private var config = Config(allowPlainFallback = false, plainStringsPath = null)
    @Volatile private var assets: SealedAssets? = null
    private val lock = Any()

    /**
     * [allowPlainFallback]: read plain files when the package is not sealed (debug builds only). [plainStringsPath]: the
     * canonical path of the plain strings file [string] reads in that case (the header names it in a sealed package;
     * an unsealed one has no header), e.g. `assets/sentomaru-strings.json`; null makes [string] `not-sealed` there.
     */
    @JvmStatic
    @JvmOverloads
    fun configure(allowPlainFallback: Boolean = false, plainStringsPath: String? = null) {
        plainStringsPath?.let { checkPath(it) }
        config = Config(allowPlainFallback, plainStringsPath)
    }

    /** The plaintext of the asset at its canonical [path] (`assets/...`), as a stream over memory. @WorkerThread */
    @JvmStatic
    @Throws(IOException::class)
    fun open(context: Context, path: String): InputStream = ByteArrayInputStream(bytes(context, path))

    /** The plaintext of the asset at its canonical [path] (`assets/...`). @WorkerThread: up to 4 MiB to decrypt. */
    @JvmStatic
    @Throws(IOException::class)
    fun bytes(context: Context, path: String): ByteArray {
        checkPath(path)
        return assets(context).bytes(path, config.allowPlainFallback)
    }

    /**
     * The value of [key] in the profile's strings file, or null when the file has no such key.
     *
     * @WorkerThread: each call opens, decrypts, inflates and parses the whole strings file (up to 4 MiB, 1024 entries);
     * nothing of it is cached. An app that reads many keys keeps the values it needs. Whether the reader should cache
     * the parsed map is measured in the D-14d (first read and memory).
     */
    @JvmStatic
    @Throws(IOException::class)
    fun string(context: Context, key: String): String? {
        val c = config
        return assets(context).string(key, c.allowPlainFallback, c.plainStringsPath)
    }

    private fun checkPath(path: String) {
        require(path.startsWith("assets/") && path.length > "assets/".length) { "canonical asset path expected (assets/...)" }
    }

    /**
     * Built once per process, from the application context.
     *
     * @throws IllegalStateException when the package manager does not know the app's own package (a broken or
     * instrumented environment): without the `versionCode` no key can be derived.
     */
    private fun assets(context: Context): SealedAssets {
        assets?.let { return it }
        synchronized(lock) {
            assets?.let { return it }
            val app = context.applicationContext ?: context
            val manager = app.assets
            return assetsOf(app.packageName, { app.packageManager.getPackageInfo(it, 0).longVersionCode },
                { manager.open(it, AssetManager.ACCESS_STREAMING) }).also { assets = it }
        }
    }
}

/**
 * The production wiring of [SentomaruSealed] without the `Context` (I3 of the review: tested on the JVM). [versionCode]
 * is `PackageInfo.longVersionCode` of [packageName]; [open] is `AssetManager.open`, relative to `assets/`.
 */
internal fun assetsOf(packageName: String, versionCode: (String) -> Long, open: (String) -> InputStream): SealedAssets {
    val code = try {
        versionCode(packageName)
    } catch (e: PackageManager.NameNotFoundException) {
        throw IllegalStateException("the package manager does not know this app's package")
    }
    val source = AssetSource(open)
    return SealedAssets(source, SealedReader(source, packageName, code))
}

/** The `AssetManager` reads paths relative to `assets/`; the canonical path keeps the prefix. */
internal class AssetSource(private val open: (String) -> InputStream) : SealedSource {
    override fun read(path: String, limit: Int): ByteArray? {
        val stream = try {
            open(path.removePrefix("assets/"))
        } catch (e: FileNotFoundException) {
            return null
        }
        return stream.use { readAtMost(it, limit + 1) }
    }

    override fun readAll(path: String): ByteArray = open(path.removePrefix("assets/")).use { it.readBytes() }
}

/** At most [max] bytes of [input], never reading past them (`InputStream.readNBytes` is API 33; minSdk is 28). */
internal fun readAtMost(input: InputStream, max: Int): ByteArray {
    val out = ByteArrayOutputStream()
    val buf = ByteArray(64 * 1024)
    while (out.size() < max) {
        val n = input.read(buf, 0, minOf(buf.size, max - out.size()))
        if (n < 0) break
        out.write(buf, 0, n)
    }
    return out.toByteArray()
}
