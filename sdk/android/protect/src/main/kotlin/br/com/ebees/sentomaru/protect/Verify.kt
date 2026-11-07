package br.com.ebees.sentomaru.protect

import java.io.File
import java.io.IOException
import java.util.concurrent.TimeUnit

/**
 * `sentomaru verify receipt|audit-export`: the two third-party verifiers of the Trust module as subcommands of the CLI.
 *
 * It adds no verification logic. It runs the same Python scripts a third party ran before (`tools/trust/verify_receipt.py`
 * and `tools/trust/verify_audit_export.py`, standard library plus `openssl`, bundled in the distribution under
 * `lib/verify/`) with the arguments it was given, prints what they print and returns their exit code: 0 the document is
 * valid, 1 it is not (the verifier's reason code is the only stdout line), 2 usage error. A failure to run a verifier at all
 * (no trusted Python, no bundled script, a timeout, no `openssl`, output that is not the verifier contract) is also exit 2 with a `verify-unavailable` line on stderr, never 0 or 1, so a
 * broken environment cannot be read as "valid" or as "invalid". Nothing here touches the network or the Sentomaru API.
 */
object Verify {
    /** Subcommand name to the bundled script. The Gradle distribution copies exactly these files (see build.gradle.kts). */
    val SCRIPTS = mapOf("receipt" to "verify_receipt.py", "audit-export" to "verify_audit_export.py")
    const val USAGE = "usage: sentomaru verify receipt|audit-export [verifier options]  (--help after the name shows the verifier's options)"
    const val TIMEOUT_SECONDS = 120L

    /** What to do about an untrusted node. The rule is not relaxed: the node has to change, or another directory has to be named. */
    const val FIX = "To fix it, make the node named above and every directory above it owned by you or root and not writable by group or others " +
        "(chmod go-w on it; unpack the distribution with umask 022), or set SENTOMARU_VERIFY_DIR to a directory you created with mode 0700 that holds the verifier. " +
        "A system directory such as /usr/local (root:staff, mode 2775 on Debian and Ubuntu) is refused too and is not to be changed: " +
        "name a binary in a path only root writes with SENTOMARU_PYTHON (python3) or SENTOMARU_OPENSSL (openssl), for example /usr/bin/python3"

    fun run(args: List<String>, env: Map<String, String>, out: (String) -> Unit, err: (String) -> Unit): Int {
        val name = args.firstOrNull()
        if (name == null || name == "-h" || name == "--help") {
            (if (name == null) err else out)(USAGE)
            return if (name == null) 2 else 0
        }
        val script = SCRIPTS[name]
        if (script == null) {
            err("sentomaru verify: unknown verifier '$name'. $USAGE")
            return 2
        }
        val dir = env["SENTOMARU_VERIFY_DIR"]?.let { File(it) } ?: bundledDir()
        val file = dir?.resolve(script)
        if (file == null || !file.isFile) {
            err("verify-unavailable: the bundled verifier $script was not found")
            return 2
        }
        val python = resolvePython(env)
        if (python == null) {
            val skipped = (env["PATH"] ?: "").split(File.pathSeparator).filter { !(it.startsWith("/") || (it.length > 2 && it[1] == ':')) }
            err("verify-unavailable: no trusted Python 3 interpreter (an absolute path to a regular, executable file that " +
                "only its owner can write; SENTOMARU_PYTHON, or python3 found on PATH; a python3 under /usr/local that is group-writable, " +
                "as on Debian and Ubuntu, is refused: set SENTOMARU_PYTHON=/usr/bin/python3)" +
                (if (skipped.isEmpty()) "" else "; these PATH entries are not absolute and were not searched: " +
                    skipped.joinToString(", ") { if (it.isEmpty()) "(empty)" else it }))
            return 2
        }
        val (realScript, untrusted) = trustProblem(file, env["SENTOMARU_VERIFY_ALLOW_UNCHECKED"] == "1")
        if (realScript == null) {
            err("verify-unavailable: the verifier $script $untrusted. $FIX")
            return 2
        }
        val process = try {
            // -I: isolated mode, so a file in the current directory is never imported in place of the standard library.
            ProcessBuilder(listOf(python.path, "-I", realScript.path) + args.drop(1)).start()
        } catch (e: IOException) {
            err("verify-unavailable: could not run ${python.path} (Python 3 and openssl are required)")
            return 2
        }
        process.outputStream.close()
        val outBuf = java.io.ByteArrayOutputStream()
        val errBuf = java.io.ByteArrayOutputStream()
        // Both pipes are drained while the process runs, so a verifier that writes more than a pipe holds cannot block.
        val readOut = Thread { process.inputStream.copyTo(outBuf) }.apply { isDaemon = true; start() }
        val readErr = Thread { process.errorStream.copyTo(errBuf) }.apply { isDaemon = true; start() }
        if (!process.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
            // Children first: a verifier that started `openssl` must not leave it running after the timeout.
            process.descendants().forEach { it.destroyForcibly() }
            process.destroyForcibly()
            process.waitFor(5, TimeUnit.SECONDS)
            err("verify-unavailable: the verifier did not finish in ${TIMEOUT_SECONDS}s")
            return 2
        }
        readOut.join(5000)
        readErr.join(5000)
        val stdout = outBuf.toByteArray().toString(Charsets.UTF_8)
        val stderr = errBuf.toByteArray().toString(Charsets.UTF_8)
        val code = process.exitValue()
        // The launcher only passes through what the verifier contract allows. Anything else (an interpreter that is not
        // Python, a crash, a signal) is "could not verify", never "valid" and never "invalid".
        val help = args.drop(1).any { it == "-h" || it == "--help" }
        val contract = when (code) {
            0 -> if (help) stdout.isNotEmpty() else if (name == "receipt") stdout == "ok\n" else validAuditSummary(stdout)
            1 -> singleReasonLine(name, stdout, stderr)
            2 -> !stderr.startsWith("Traceback")
            else -> false
        }
        if (!contract) {
            err("verify-unavailable: the verifier ended with exit $code and output that is not the verifier contract")
            return 2
        }
        if (stdout.isNotEmpty()) out(stdout.trimEnd('\n'))
        if (stderr.isNotEmpty()) err(stderr.trimEnd('\n'))
        return code
    }

    /** receipt: stdout is exactly one reason line. audit-export: stdout is empty and stderr starts `audit-export-invalid: `. */
    private fun singleReasonLine(name: String, stdout: String, stderr: String): Boolean =
        if (name == "receipt") Regex("[a-z0-9-]+\n").matches(stdout)
        else stdout.isEmpty() && stderr.startsWith("audit-export-invalid: ")

    /** The success summary of `verify_audit_export.py` is one JSON object on stdout. */
    private fun validAuditSummary(stdout: String): Boolean = stdout.startsWith("{") && stdout.trimEnd().endsWith("}")

    /**
     * Why [path] cannot be trusted to be run, or null when it can. Rules (POSIX only):
     *  - the path is resolved with symlinks followed, and what is run is the resolved path, so a link cannot be swapped later;
     *  - the file is a regular file owned by root or by the current user and not writable by group or others;
     *  - every directory above it, both along the path as given (links included) and along the resolved path, is owned by root
     *    or the current user and is not writable by group or others (a sticky directory owned by root, such as /tmp, is accepted
     *    as an ancestor because others cannot rename or delete what it holds).
     * The files cannot be opened once and handed to the child from the JVM, so the validation and the start still are two
     * steps; what closes the gap between them is that nobody but the owner and root can write to any directory on the way.
     * [currentUser] exists for tests: it replaces the uid read from the process, so the owner rule can be exercised without a second account.
     * Without POSIX permissions (Windows) there is nothing to check and the launcher refuses unless
     * SENTOMARU_VERIFY_ALLOW_UNCHECKED=1 is set.
     */
    internal fun trustProblem(path: File, uncheckedAllowed: Boolean, currentUser: Int? = null): Pair<File?, String?> {
        if (!posix()) {
            return if (uncheckedAllowed) Pair(path, null) else Pair(null, "cannot be checked on this platform (set SENTOMARU_VERIFY_ALLOW_UNCHECKED=1 to accept that)")
        }
        val given = path.absoluteFile.toPath().normalize()
        val real = try { given.toRealPath() } catch (e: IOException) { return Pair(null, "cannot be resolved") }
        if (!java.nio.file.Files.isRegularFile(real)) return Pair(null, "is not a regular file")
        val me = currentUser ?: currentUid() ?: return Pair(null, "cannot be checked (own user id unknown)")
        nodeProblem(real, me, leaf = true)?.let { return Pair(null, it) }
        for (chain in listOf(given, real)) {
            var dir = chain.parent
            while (dir != null) {
                nodeProblem(dir, me, leaf = false)?.let { return Pair(null, "has an untrusted directory above it ($it)") }
                dir = dir.parent
            }
        }
        // links inside the given path (a file that is itself a link, or a directory link) must be owned by a trusted user too
        var node: java.nio.file.Path? = given
        while (node != null) {
            if (java.nio.file.Files.isSymbolicLink(node)) {
                val owner = uidOf(node)
                if (owner == null || (owner != 0 && owner != me)) return Pair(null, "goes through a symbolic link owned by another user")
            }
            node = node.parent
        }
        return Pair(real.toFile(), null)
    }

    private fun posix(): Boolean = java.nio.file.FileSystems.getDefault().supportedFileAttributeViews().let { "posix" in it && "unix" in it }

    private fun uidOf(p: java.nio.file.Path): Int? = try {
        (java.nio.file.Files.getAttribute(p, "unix:uid", java.nio.file.LinkOption.NOFOLLOW_LINKS) as Int)
    } catch (e: Exception) { null }

    private fun modeOf(p: java.nio.file.Path): Int? = try {
        (java.nio.file.Files.getAttribute(p, "unix:mode", java.nio.file.LinkOption.NOFOLLOW_LINKS) as Int)
    } catch (e: Exception) { null }

    /**
     * The uid this process runs as. Linux: the effective uid on the `Uid:` line of /proc/self/status (the owner of /proc/self is
     * root when the process is not dumpable, so it is not used). Elsewhere, or if that fails, the owner of a probe file in the
     * temporary directory (created with a unique name, removed at once).
     */
    internal fun currentUid(): Int? = procSelfUid() ?: probeUid()

    private fun procSelfUid(): Int? = try {
        parseUidLine(java.nio.file.Files.readAllLines(java.nio.file.Paths.get("/proc/self/status")))
    } catch (e: Exception) { null }

    /** The effective uid (second number) of the `Uid:` line of a /proc status file, or null when there is no well-formed line. */
    internal fun parseUidLine(lines: List<String>): Int? {
        val line = lines.firstOrNull { it.startsWith("Uid:") } ?: return null
        val fields = line.removePrefix("Uid:").trim().split(Regex("\\s+"))
        return if (fields.size == 4) fields[1].toIntOrNull()?.takeIf { it >= 0 } else null
    }

    private fun probeUid(): Int? = try {
        val probe = java.nio.file.Files.createTempFile("sentomaru-uid", ".probe")
        try { uidOf(probe) } finally { java.nio.file.Files.deleteIfExists(probe) }
    } catch (e: Exception) { null }

    private fun nodeProblem(p: java.nio.file.Path, me: Int, leaf: Boolean): String? {
        val owner = uidOf(p) ?: return "$p: owner unknown"
        val mode = modeOf(p) ?: return "$p: mode unknown"
        if (owner != 0 && owner != me) return "$p: owned by another user"
        val writableByOthers = (mode and 0b000_010_010) != 0
        if (!writableByOthers) return null
        if (!leaf && owner == 0 && (mode and 0x200) != 0) return null // sticky root directory (/tmp)
        return "$p: writable by group or others (mode ${Integer.toOctalString(mode and 0xFFF).padStart(4, '0')})"
    }

    /**
     * `SENTOMARU_PYTHON` when set, otherwise the first `python3` in an absolute directory of PATH that passes [trustProblem].
     * A relative name or an empty or relative PATH entry is never searched, so the current directory cannot supply the
     * interpreter. Returns the resolved path to run, or null.
     */
    private fun resolvePython(env: Map<String, String>): File? {
        val explicit = env["SENTOMARU_PYTHON"]
        val unchecked = env["SENTOMARU_VERIFY_ALLOW_UNCHECKED"] == "1"
        val candidates = if (explicit != null) listOf(File(explicit)) else
            (env["PATH"] ?: "").split(File.pathSeparator).filter { it.startsWith("/") || (it.length > 2 && it[1] == ':') }.map { File(it, "python3") }
        return candidates.firstNotNullOfOrNull {
            if (!it.isAbsolute || !it.canExecute()) null else trustProblem(it, unchecked).first
        }
    }

    /** `<install>/lib/verify`, next to the CLI jar (the Gradle `installDist` layout). Null when run from a loose class path. */
    private fun bundledDir(): File? = try {
        File(Verify::class.java.protectionDomain.codeSource.location.toURI()).parentFile?.resolve("verify")
    } catch (e: Exception) {
        null
    }
}
