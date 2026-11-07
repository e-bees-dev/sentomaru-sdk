package br.com.ebees.sentomaru.signals

import java.io.File
import java.io.IOException
import java.security.MessageDigest
import java.util.zip.ZipFile

/**
 * D-12c: the code digests of algorithm `apk-code-sha256-v1` (the Shield registry contract, "Code digests") over the
 * installed APKs, and their aggregate (normative since D-12a: SHA-256 of `path\nsha256\n` per file, in ascending ordinal
 * order of path). Same file set as the vendor's code-digest tool: every root `classes*.dex` (no leading zero) and every
 * `lib/<abi>/<name>.so`, uncompressed bytes. With splits, the files of every APK are listed together; the same path in
 * two APKs is refused (which one would the platform load?).
 *
 * Blocking and possibly slow (the whole code of the app is read): never call it on the main thread. Unlike the CLI,
 * it reads entries through `ZipFile` (the platform verified the installed APK's signature over the whole file at
 * install), and only checks that each entry gives exactly its declared size.
 */
object ApkCodeDigests {
    const val ALGORITHM = "apk-code-sha256-v1"
    const val MAX_FILES = 256
    const val MAX_CODE_BYTES = 2L * 1024 * 1024 * 1024

    val CODE_PATH = Regex("classes([2-9]|[1-9][0-9]{1,3})?\\.dex|lib/[a-z0-9_-]{1,32}/[A-Za-z0-9._+-]{1,128}\\.so")

    /** One code file: its path inside the APK and the lowercase hex SHA-256 of its uncompressed bytes. */
    data class CodeFile(val path: String, val sha256: String)

    sealed class Result {
        data class Computed(val files: List<CodeFile>, val aggregate: String) : Result()

        /**
         * Not computed; [cause] is a fixed code: `apk_unreadable`, `entry_unreadable`, `duplicate_entry`,
         * `no_code_files`, `too_many_files`, `too_large`.
         */
        data class Refused(val cause: String) : Result()
    }

    private class Refusal(val code: String) : Exception(code)

    fun compute(apks: List<File>): Result = try {
        val files = ArrayList<CodeFile>()
        val seen = HashSet<String>()
        var total = 0L
        for (apk in apks) {
            val archive = try { ZipFile(apk) } catch (_: IOException) { throw Refusal("apk_unreadable") }
            catch (_: SecurityException) { throw Refusal("apk_unreadable") }
            archive.use { zip ->
                val names = HashSet<String>()
                val code = zip.entries().asSequence().filter { entry ->
                    if (!names.add(entry.name)) throw Refusal("duplicate_entry")
                    !entry.isDirectory && CODE_PATH.matches(entry.name)
                }.toList()
                for (entry in code) {
                    if (!seen.add(entry.name)) throw Refusal("duplicate_entry") // same path in two APKs of the set
                    if (seen.size > MAX_FILES) throw Refusal("too_many_files")
                    val digest = MessageDigest.getInstance("SHA-256")
                    var read = 0L
                    try {
                        zip.getInputStream(entry).use { input ->
                            val buffer = ByteArray(CHUNK)
                            while (true) {
                                val n = input.read(buffer)
                                if (n < 0) break
                                read += n
                                total += n
                                if (total > MAX_CODE_BYTES) throw Refusal("too_large")
                                digest.update(buffer, 0, n)
                            }
                        }
                    } catch (_: IOException) {
                        throw Refusal("entry_unreadable")
                    }
                    if (entry.size >= 0 && read != entry.size) throw Refusal("entry_unreadable")
                    files += CodeFile(entry.name, hex(digest.digest()))
                }
            }
        }
        if (files.isEmpty()) throw Refusal("no_code_files")
        files.sortWith { a, b -> compareOrdinal(a.path, b.path) }
        Result.Computed(files, aggregate(files))
    } catch (refusal: Refusal) {
        Result.Refused(refusal.code)
    }

    /** Aggregate of algorithm v1: SHA-256 of `path\nsha256\n` per file, in the given (ordinal) order. */
    fun aggregate(files: List<CodeFile>): String {
        val digest = MessageDigest.getInstance("SHA-256")
        for (file in files) digest.update("${file.path}\n${file.sha256}\n".toByteArray(Charsets.UTF_8))
        return hex(digest.digest())
    }

    // CODE_PATH admits ASCII only, so UTF-16 order is the byte order of the contract.
    private fun compareOrdinal(a: String, b: String): Int = a.compareTo(b)

    private fun hex(bytes: ByteArray) = bytes.joinToString("") { "%02x".format(it) }

    private const val CHUNK = 64 * 1024
}
