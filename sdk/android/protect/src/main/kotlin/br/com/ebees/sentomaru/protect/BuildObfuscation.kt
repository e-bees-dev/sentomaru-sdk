package br.com.ebees.sentomaru.protect

import com.google.gson.JsonObject
import java.io.File
import java.io.InputStream
import java.util.zip.ZipFile

/**
 * D-08 (`build-obfuscation`, harden/10; contract "build-obfuscation (D-08)").
 * In the distributed CLI since D-08f (behind the laboratory gate from D-08d to D-08e). The control does not obfuscate
 * (D-08x1): R8 and `--obfuscate` belong to the
 * client's build. It only reads the artifact and reports, `checked` with no change, in the dry-run and the real run,
 * and never fails for a missing obfuscation (D-08x5): it warns.
 *
 * - `sdkProbeRenamed`: with the SDK in the app, the probe class is **not** defined under its source name (the
 *   criterion of the vendor's check r8 names check). It says whether R8 renamed the **SDK**, not the app.
 * - `sdkNamesKept`: `SentomaruRoutes` is defined under its source name and, when the profile has `asset-encryption`,
 *   one of the reader markers too.
 * - `dartObfuscated`: read from every `libapp.so` of the base module (a heuristic, see [dartObfuscated]; validated with
 *   real builds with and without the option, D-08b and D-08d).
 * - `debuggable`: `android:debuggable` of the base manifest ([ManifestFacts.debuggable]).
 *
 * "App without the SDK" (`unknown`) is a base DEX with no class under `Lbr/com/ebees/sentomaru/sdk/` and without the
 * plugin class.
 */
object BuildObfuscation : Control {
    override val id = "build-obfuscation"
    override val version = "1"
    override val stage = "harden"
    override val order = 10
    override val prerequisites = emptyList<String>()
    override val changeIds = emptyList<String>()

    /** Not kept by any consumer rule of the SDK: with R8 it does not survive under its source name. */
    const val SDK_PROBE = "Lbr/com/ebees/sentomaru/sdk/AndroidInstallationStore;"
    const val SDK_PACKAGE = "Lbr/com/ebees/sentomaru/sdk/"
    /** D-14 reader markers (contract "asset-encryption"), kept by name by the SDK's and the plugin's consumer rules. */
    const val ANDROID_READER = "Lbr/com/ebees/sentomaru/sdk/sealed/SentomaruSealed;"
    const val FLUTTER_READER = "Lbr/com/ebees/sentomaru/sentomaru_flutter/SentomaruFlutterSealed;"
    const val ASSET_ENCRYPTION = "asset-encryption"

    /**
     * Plugin Dart identifiers the sample app reaches (so AOT tree shaking keeps them), present in a plain release
     * `libapp.so` and absent after `--obfuscate`. The same list as the vendor's check dart obfuscation check,
     * which validates it on real Flutter builds in CI (a test here keeps the two equal).
     */
    val DART_IDENTIFIERS = listOf("SentomaruClient", "SentomaruConfig", "SignalObservation")

    /**
     * The ELF dynamic symbol of every Dart AOT snapshot (`gen_snapshot` output), the same with and without
     * `--obfuscate`: it says the file is a Dart snapshot at all.
     */
    const val SNAPSHOT_SYMBOL = "_kDartIsolateSnapshotData"

    /**
     * A framework identifier every Flutter app reaches (`runApp` initializes the binding), so present in any snapshot
     * built without `--obfuscate` and renamed by it. Checked on the real debug, release and `--obfuscate` builds of the
     * Flutter sample (3 ABIs, 27/10/2026, Flutter 3.41.9) and in CI by check_dart_obfuscation.py.
     */
    const val PLAIN_MARKER = "WidgetsFlutterBinding"

    private val FIELD = Regex("""\A[A-Za-z0-9_-]{1,64}\z""")

    override fun validate(section: JsonObject, context: ControlContext) {
        // Closed, without options: any member besides `version` is a new version of the control. The member is named in
        // `detail` only when it is a short plain name (the detail lands in the report).
        (section.keySet() - "version").sorted().firstOrNull()?.let {
            throw ProtectException(ErrorCode.PROFILE_FORMAT, "$id.${if (FIELD.matches(it)) it else "unknown-field"}")
        }
    }

    override fun plan(section: JsonObject, artifact: Artifact, context: ControlContext): ControlPlan {
        val file = artifact.file ?: throw ProtectException(ErrorCode.INTERNAL, "$id: artifact without its file")
        val scan = DexScan.scan(file, artifact.kind,
            setOf(SDK_PROBE, NetworkSigning.ANDROID_TRANSPORT, NetworkSigning.FLUTTER_TRANSPORT, ANDROID_READER, FLUTTER_READER),
            setOf(SDK_PACKAGE), id)
        val found = scan.found
        val plugin = NetworkSigning.FLUTTER_TRANSPORT in found
        val sdk = SDK_PACKAGE in found || plugin
        val reader = context.sections.any { it.id == ASSET_ENCRYPTION }
        // An absence proves nothing when a base DEX was skipped (above the limits or not well formed): both unknown.
        val decided = sdk && !scan.skipped
        val renamed = if (!decided) UNKNOWN else (SDK_PROBE !in found).toString()
        val kept = if (!decided) UNKNOWN else (NetworkSigning.ANDROID_TRANSPORT in found &&
            (!reader || ANDROID_READER in found || FLUTTER_READER in found)).toString()
        val dart = dartObfuscated(LibApp.scan(file, artifact.kind, DART_IDENTIFIERS + SNAPSHOT_SYMBOL + PLAIN_MARKER), plugin)
        val debuggable = artifact.manifest.debuggable
        if (renamed == "false") context.warn("build-obfuscation-sdk-not-renamed",
            "the SDK probe class keeps its source name: R8 did not rename the SDK (no minification, or a broad -keep rule)")
        if (dart == "false") context.warn("build-obfuscation-dart-not-obfuscated",
            "Dart identifiers are readable in libapp.so: the Dart code was not built with --obfuscate")
        if (debuggable) context.warn("build-obfuscation-debuggable", "the base manifest declares android:debuggable")
        return ControlPlan(id, version, "checked", emptyList(), evidence = linkedMapOf("sdkProbeRenamed" to renamed,
            "sdkNamesKept" to kept, "dartObfuscated" to dart, "debuggable" to debuggable.toString()))
    }

    private const val UNKNOWN = "unknown"

    /**
     * [scans]: one per `libapp.so` (null when one could not be read within the limits). Every file must be a readable
     * Dart snapshot ([LibApp.Snapshot.dart]: a whole ELF with [SNAPSHOT_SYMBOL]), else `unknown`. `false` when every
     * file has the whole plugin list, or every file has [PLAIN_MARKER] (not obfuscated, plugin used or not). `true` only
     * when no file has any plugin identifier nor the marker **and** the plugin class is in the DEX. Anything else, or no
     * `libapp.so` (not Flutter, or a debug build), is `unknown`.
     */
    internal fun dartObfuscated(scans: List<LibApp.Snapshot>?, plugin: Boolean): String = when {
        scans.isNullOrEmpty() || scans.any { !it.dart } -> UNKNOWN
        scans.all { it.found.containsAll(DART_IDENTIFIERS) } || scans.all { PLAIN_MARKER in it.found } -> "false"
        plugin && scans.all { s -> PLAIN_MARKER !in s.found && DART_IDENTIFIERS.none { it in s.found } } -> "true"
        else -> UNKNOWN
    }
}

/**
 * D-08d: read-only look at the Dart AOT snapshots of the base module (`base/lib/<abi>/libapp.so` in an AAB,
 * `lib/<abi>/libapp.so` in an APK; the DexScan reads only DEX). Each file is streamed once and searched for fixed ASCII
 * needles; only its ELF header and its length are kept. Bounded: at most [MAX_FILES] files of at most [MAX_BYTES]
 * each and [MAX_TOTAL_BYTES] inflated in all (counted on the bytes read, not on the declared sizes), otherwise the
 * answer is null (the heuristic does not decide).
 */
internal object LibApp {
    const val MAX_BYTES: Long = 512L * 1024 * 1024
    const val MAX_TOTAL_BYTES: Long = 1024L * 1024 * 1024
    const val MAX_FILES = 16
    private const val ELF_HEADER = 64
    private val APK = Regex("""lib/[^/]+/libapp\.so""")
    private val AAB = Regex("""base/lib/[^/]+/libapp\.so""")

    /** One file: the needles found, and whether it is a whole little-endian ELF (its section headers fit in it). */
    class Snapshot(val found: Set<String>, val elf: Boolean) {
        val dart: Boolean get() = elf && BuildObfuscation.SNAPSHOT_SYMBOL in found
    }

    /** Per `libapp.so` of the base module, in entry order; null over a limit or for an entry that does not inflate. */
    fun scan(file: File, kind: ArtifactKind, needles: List<String>, maxFiles: Int = MAX_FILES, maxBytes: Long = MAX_BYTES,
        maxTotal: Long = MAX_TOTAL_BYTES): List<Snapshot>? {
        val pattern = if (kind == ArtifactKind.AAB) AAB else APK
        try {
            ZipFile(file).use { zip ->
                val entries = zip.entries().asSequence().filter { !it.isDirectory && pattern.matches(it.name) }.toList()
                if (entries.size > maxFiles) return null
                var left = maxTotal
                return entries.map { entry ->
                    if (entry.size > maxBytes) return null
                    val read = zip.getInputStream(entry).use { read(it, needles, minOf(maxBytes, left)) } ?: return null
                    left -= read.total
                    Snapshot(read.found, elf(read.header, read.total))
                }
            }
        } catch (e: java.io.IOException) {
            return null // an entry that does not inflate: the heuristic does not decide (the control never fails)
        }
    }

    class Read(val found: Set<String>, val header: ByteArray, val total: Long)

    /** The needles (ASCII, non-empty) that occur in [input], its first bytes and its length; null above [limit] bytes. */
    internal fun read(input: InputStream, needles: List<String>, limit: Long): Read? {
        val wanted = needles.map { it to it.toByteArray(Charsets.US_ASCII) }
        // The last bytes of each chunk are carried over, so a needle across two reads is still found.
        val keep = wanted.maxOf { it.second.size } - 1
        val buffer = ByteArray(keep + (1 shl 16))
        val header = java.io.ByteArrayOutputStream(ELF_HEADER)
        val hit = LinkedHashSet<String>()
        var carried = 0
        var total = 0L
        while (true) {
            val n = input.read(buffer, carried, buffer.size - carried)
            if (n < 0) break
            if (header.size() < ELF_HEADER) header.write(buffer, carried, minOf(n, ELF_HEADER - header.size()))
            total += n
            if (total > limit) return null
            val length = carried + n
            for ((name, bytes) in wanted) if (name !in hit && indexOf(buffer, length, bytes)) hit += name
            carried = minOf(keep, length)
            System.arraycopy(buffer, length - carried, buffer, 0, carried)
        }
        return Read(hit, header.toByteArray(), total)
    }

    /**
     * A little-endian ELF32/ELF64 whose section header table ends within the file: a truncated file (the table is
     * written last) or anything that is not ELF fails.
     */
    internal fun elf(header: ByteArray, total: Long): Boolean {
        if (header.size < 52 || header[0] != 0x7f.toByte() || header[1] != 'E'.code.toByte() || header[2] != 'L'.code.toByte() ||
            header[3] != 'F'.code.toByte() || header[5] != 1.toByte()) return false
        val b = java.nio.ByteBuffer.wrap(header).order(java.nio.ByteOrder.LITTLE_ENDIAN)
        val (offset, entry, count) = when (header[4].toInt()) {
            1 -> Triple(b.getInt(0x20).toLong() and 0xffffffffL, b.getShort(0x2E).toLong() and 0xffff, b.getShort(0x30).toLong() and 0xffff)
            2 -> if (header.size < ELF_HEADER) return false
                else Triple(b.getLong(0x28), b.getShort(0x3A).toLong() and 0xffff, b.getShort(0x3C).toLong() and 0xffff)
            else -> return false
        }
        return count > 0 && entry > 0 && offset >= 52 && offset <= total && offset + entry * count <= total
    }

    private fun indexOf(buffer: ByteArray, length: Int, needle: ByteArray): Boolean {
        val first = needle[0]
        for (i in 0..length - needle.size) {
            if (buffer[i] != first) continue
            if (needle.indices.all { buffer[i + it] == needle[it] }) return true
        }
        return false
    }
}
