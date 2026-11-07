package br.com.ebees.sentomaru.protect

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/**
 * `sentomaru verify receipt|audit-export` only starts the bundled Python verifiers and passes their output and exit code
 * through. These tests use stand-in scripts (so they check the dispatcher alone: arguments, stdout, stderr, exit code) and
 * the real scripts for the cases that need no key (`--help`, a missing file). A valid receipt or export is checked by
 * the vendor's test verify receipt check and test_verify_audit_export_mutations.py against the same scripts.
 */
class VerifyCliTest {
    @get:Rule val tmp = TemporaryFolder()

    private val ownerOnlyDir = java.nio.file.attribute.PosixFilePermissions.fromString("rwx------")
    private val ownerOnlyFile = java.nio.file.attribute.PosixFilePermissions.fromString("rw-------")

    /**
     * Under umask 002 (a CI checkout, `unzip` in a shared account) every directory this test creates is 775 and every file 664, and
     * the launcher refuses those. The root of the test folder is the ancestor of everything it runs, so it is locked to 0700 here;
     * the helpers below give 0700/0600 to what they create. Tests that want a loose node set its mode themselves.
     */
    @Before fun lockTheRoot() {
        java.nio.file.Files.setPosixFilePermissions(tmp.root.toPath(), ownerOnlyDir)
    }

    private fun ownerOnlyFile(file: File, text: String): File {
        file.writeText(text)
        java.nio.file.Files.setPosixFilePermissions(file.toPath(), ownerOnlyFile)
        return file
    }

    private val sourceDir = File(System.getProperty("sentomaru.trustTools") ?: "../../../tools/trust").canonicalFile

    /**
     * The real scripts, copied into a directory this test creates (mode 0700, owned by the current user). The launcher refuses
     * a verifier whose directory chain is writable by group/other, and a CI checkout can be (group-writable on Linux runners),
     * so running the scripts in place would test the checkout's permissions instead of the verifiers.
     */
    private val realDir: File by lazy {
        val dir = java.nio.file.Files.createTempDirectory(tmp.root.toPath(), "real-trust")
        for (script in Verify.SCRIPTS.values) {
            java.nio.file.Files.copy(sourceDir.resolve(script).toPath(), dir.resolve(script))
            java.nio.file.Files.setPosixFilePermissions(dir.resolve(script), ownerOnlyFile)
        }
        java.nio.file.Files.setPosixFilePermissions(dir, ownerOnlyDir)
        dir.toFile().canonicalFile
    }

    private class Result(val code: Int, val out: String, val err: String)

    private fun run(vararg args: String, env: Map<String, String> = emptyMap()): Result {
        val out = StringBuilder()
        val err = StringBuilder()
        val code = Cli.run(listOf("verify") + args, env + System.getenv().filterKeys { it == "PATH" },
            { out.append(it).append('\n') }, { err.append(it).append('\n') })
        return Result(code, out.toString(), err.toString())
    }

    private fun stubDir(receipt: String, audit: String = "import sys; sys.exit(0)"): File {
        val dir = java.nio.file.Files.createTempDirectory(tmp.root.toPath(), "stubs").toFile()
        java.nio.file.Files.setPosixFilePermissions(dir.toPath(), ownerOnlyDir)
        ownerOnlyFile(dir.resolve("verify_receipt.py"), receipt)
        ownerOnlyFile(dir.resolve("verify_audit_export.py"), audit)
        return dir
    }

    @Test fun `no name is a usage error and --help is not`() {
        val none = run()
        assertEquals(2, none.code)
        assertTrue(none.err.contains("usage: sentomaru verify receipt|audit-export"))
        val help = run("--help")
        assertEquals(0, help.code)
        assertTrue(help.out.contains("receipt|audit-export"))
    }

    @Test fun `an unknown name is a usage error that does not start anything`() {
        val r = run("sdk", env = mapOf("SENTOMARU_VERIFY_DIR" to tmp.newFolder("empty").path))
        assertEquals(2, r.code)
        assertTrue(r.err.contains("unknown verifier 'sdk'"))
    }

    @Test fun `the arguments, stdout and exit code 0 pass through`() {
        val dir = stubDir("import sys\nprint('ok')\nsys.stderr.write('warn:' + ','.join(sys.argv[1:]) + '\\n')\nsys.exit(0)")
        val r = run("receipt", "--receipt", "r.json", "--pubkey", "k.pem", env = mapOf("SENTOMARU_VERIFY_DIR" to dir.path))
        assertEquals(0, r.code)
        assertEquals("ok\n", r.out)
        assertEquals("warn:--receipt,r.json,--pubkey,k.pem\n", r.err)
    }

    @Test fun `exit code 1 and the reason line pass through, for each verifier`() {
        val dir = stubDir("import sys\nprint('signature-invalid')\nsys.exit(1)", "import sys\nsys.stderr.write('audit-export-invalid: header-shape\\n')\nsys.exit(1)")
        val env = mapOf("SENTOMARU_VERIFY_DIR" to dir.path)
        val receipt = run("receipt", env = env)
        assertEquals(1, receipt.code)
        assertEquals("signature-invalid\n", receipt.out)
        val audit = run("audit-export", env = env)
        assertEquals(1, audit.code)
        assertEquals("", audit.out)
        assertEquals("audit-export-invalid: header-shape\n", audit.err)
    }

    @Test fun `a missing interpreter is exit 2 with verify-unavailable, never 0 or 1`() {
        val r = run("receipt", env = mapOf("SENTOMARU_VERIFY_DIR" to stubDir("pass").path, "SENTOMARU_PYTHON" to "/nonexistent/python3"))
        assertEquals(2, r.code)
        assertTrue(r.err.startsWith("verify-unavailable: no trusted Python 3 interpreter"))
        assertEquals("", r.out)
    }

    @Test fun `an interpreter that is not Python (exit 0, empty stdout) is exit 2, not valid`() {
        val dir = stubDir("pass")
        val r = run("receipt", "--receipt", "r.json", env = mapOf("SENTOMARU_VERIFY_DIR" to dir.path, "SENTOMARU_PYTHON" to trueBinary()))
        assertEquals(2, r.code)
        assertTrue(r.err.startsWith("verify-unavailable:"))
        assertEquals("", r.out)
    }

    @Test fun `exit 0 with output outside the contract and exit codes other than 0, 1, 2 are exit 2`() {
        val noisy = stubDir("print('looks fine')")
        assertEquals(2, run("receipt", env = mapOf("SENTOMARU_VERIFY_DIR" to noisy.path)).code)
        val crash = stubDir("import sys\nsys.exit(7)")
        assertEquals(2, run("receipt", env = mapOf("SENTOMARU_VERIFY_DIR" to crash.path)).code)
        val manyLines = stubDir("import sys\nprint('a')\nprint('b')\nsys.exit(1)")
        assertEquals(2, run("receipt", env = mapOf("SENTOMARU_VERIFY_DIR" to manyLines.path)).code)
    }

    @Test fun `a relative or world-writable interpreter or script is not trusted`() {
        val dir = stubDir("print('ok')")
        assertEquals(2, run("receipt", env = mapOf("SENTOMARU_VERIFY_DIR" to dir.path, "SENTOMARU_PYTHON" to "python3")).code)
        dir.resolve("verify_receipt.py").setWritable(true, false)
        java.nio.file.Files.setPosixFilePermissions(dir.resolve("verify_receipt.py").toPath(), java.nio.file.attribute.PosixFilePermissions.fromString("rw-rw-rw-"))
        val r = run("receipt", env = mapOf("SENTOMARU_VERIFY_DIR" to dir.path))
        assertEquals(2, r.code)
        assertTrue(r.err.contains("writable by group or others"))
    }

    @Test fun `a directory further up the chain that others can write makes the script untrusted`() {
        val outer = java.nio.file.Files.createTempDirectory(tmp.root.toPath(), "outer").toFile()
        val inner = outer.resolve("inner").also { it.mkdir() }
        java.nio.file.Files.setPosixFilePermissions(inner.toPath(), ownerOnlyDir)
        ownerOnlyFile(inner.resolve("verify_receipt.py"), "print('ok')")
        java.nio.file.Files.setPosixFilePermissions(outer.toPath(), java.nio.file.attribute.PosixFilePermissions.fromString("rwxrwxrwx"))
        val r = run("receipt", env = mapOf("SENTOMARU_VERIFY_DIR" to inner.path))
        assertEquals(2, r.code)
        assertTrue(r.err, r.err.contains("untrusted directory above it"))
    }

    @Test fun `a group-writable directory (what umask 002 makes) is refused with the node, its mode and what to do`() {
        val dir = stubDir("print('ok')")
        java.nio.file.Files.setPosixFilePermissions(dir.toPath(), java.nio.file.attribute.PosixFilePermissions.fromString("rwxrwxr-x"))
        val r = run("receipt", env = mapOf("SENTOMARU_VERIFY_DIR" to dir.path))
        assertEquals(r.err, 2, r.code)
        assertEquals("", r.out)
        assertTrue(r.err, r.err.contains(dir.absolutePath))
        assertTrue(r.err, r.err.contains("writable by group or others (mode 0775)"))
        assertTrue(r.err, r.err.contains("chmod go-w"))
        assertTrue(r.err, r.err.contains("umask 022"))
        assertTrue(r.err, r.err.contains("SENTOMARU_VERIFY_DIR"))
        // the same chain with mode 0700 (what the helper makes) runs: the rule was not relaxed, the node was fixed
        java.nio.file.Files.setPosixFilePermissions(dir.toPath(), ownerOnlyDir)
        val ok = run("receipt", env = mapOf("SENTOMARU_VERIFY_DIR" to dir.path))
        assertEquals(ok.err, 0, ok.code)
    }

    @Test fun `PATH entries that are not absolute are named when no interpreter is found`() {
        val out = StringBuilder()
        val err = StringBuilder()
        val code = Verify.run(listOf("receipt"), mapOf("SENTOMARU_VERIFY_DIR" to stubDir("pass").path, "PATH" to "bin::/nonexistent-dir"),
            { out.append(it) }, { err.append(it) })
        assertEquals(2, code)
        assertTrue(err.toString(), err.contains("not absolute and were not searched: bin, (empty)"))
    }

    @Test fun `a script owned by another user is refused even when nobody can write it`() {
        val dir = stubDir("print('ok')")
        val script = dir.resolve("verify_receipt.py")
        val owner = java.nio.file.Files.getAttribute(script.toPath(), "unix:uid") as Int
        org.junit.Assume.assumeTrue("root owns everything it may run", owner != 0)
        // the real owner is accepted ...
        val (accepted, none) = Verify.trustProblem(script, false, currentUser = owner)
        assertTrue(none, accepted != null && none == null)
        // ... and the same file, seen by someone else, is refused for its owner and not for its mode (0600 in a 0700 directory)
        val (refused, why) = Verify.trustProblem(script, false, currentUser = owner + 1)
        assertEquals(null, refused)
        assertTrue(why, why!!.contains("owned by another user"))
    }

    @Test fun `the uid is the effective uid of the status line and not the owner of proc self`() {
        assertEquals(1000, Verify.parseUidLine(listOf("Name:\tjava", "Uid:\t1000\t1000\t1000\t1000", "Gid:\t1000\t1000\t1000\t1000")))
        assertEquals(1001, Verify.parseUidLine(listOf("Uid:\t1000\t1001\t1000\t1001")))   // setuid: the effective one
        assertEquals(0, Verify.parseUidLine(listOf("Uid:\t0\t0\t0\t0")))
        assertEquals(null, Verify.parseUidLine(listOf("Name:\tjava")))
        assertEquals(null, Verify.parseUidLine(listOf("Uid:\t1000")))
        assertEquals(null, Verify.parseUidLine(listOf("Uid:\tx\ty\tz\tw")))
        assertEquals(null, Verify.parseUidLine(listOf("Uid:\t-1\t-1\t-1\t-1")))
    }

    @Test fun `the process uid is the owner of a file this process creates`() {
        val file = tmp.newFile("owned")
        assertEquals(java.nio.file.Files.getAttribute(file.toPath(), "unix:uid") as Int, Verify.currentUid())
    }

    @Test fun `a refusal says that a group-writable system directory is not to be changed and what to set`() {
        assertTrue(Verify.FIX, Verify.FIX.contains("/usr/local"))
        assertTrue(Verify.FIX, Verify.FIX.contains("SENTOMARU_PYTHON") && Verify.FIX.contains("SENTOMARU_OPENSSL"))
        val err = StringBuilder()
        Verify.run(listOf("receipt"), mapOf("SENTOMARU_VERIFY_DIR" to stubDir("pass").path, "SENTOMARU_PYTHON" to "/nonexistent/python3"), {}, { err.append(it) })
        assertTrue(err.toString(), err.contains("SENTOMARU_PYTHON=/usr/bin/python3"))
    }

    @Test fun `a link to the script is followed to the real file and a link from an untrusted place is refused`() {
        val dir = stubDir("print('ok')")
        val links = java.nio.file.Files.createTempDirectory(tmp.root.toPath(), "links").toFile()
        java.nio.file.Files.createSymbolicLink(links.resolve("verify_receipt.py").toPath(), dir.resolve("verify_receipt.py").toPath())
        assertEquals(0, run("receipt", env = mapOf("SENTOMARU_VERIFY_DIR" to links.path)).code)
        java.nio.file.Files.setPosixFilePermissions(links.toPath(), java.nio.file.attribute.PosixFilePermissions.fromString("rwxrwxrwx"))
        val r = run("receipt", env = mapOf("SENTOMARU_VERIFY_DIR" to links.path))
        assertEquals(2, r.code)
        assertTrue(r.err, r.err.contains("untrusted directory above it"))
    }

    @Test fun `a verifier that fills both pipes does not hang the launcher`() {
        val dir = stubDir("import sys\nsys.stderr.write('e' * 300000)\nsys.stdout.write('ok\\n')\nsys.exit(0)")
        val r = run("receipt", env = mapOf("SENTOMARU_VERIFY_DIR" to dir.path))
        assertEquals(0, r.code)
        assertEquals("ok\n", r.out)
    }

    private fun trueBinary(): String = listOf("/usr/bin/true", "/bin/true").first { File(it).isFile }

    @Test fun `a missing bundled script is exit 2 with verify-unavailable`() {
        val r = run("audit-export", env = mapOf("SENTOMARU_VERIFY_DIR" to tmp.newFolder("nothing").path))
        assertEquals(2, r.code)
        assertTrue(r.err.startsWith("verify-unavailable: the bundled verifier verify_audit_export.py was not found"))
    }

    @Test fun `the real receipt verifier answers a missing file with its own code and line`() {
        val r = run("receipt", "--receipt", tmp.root.resolve("absent.json").path, "--pubkey", "k.pem", env = mapOf("SENTOMARU_VERIFY_DIR" to realDir.path))
        assertEquals("stdout=${r.out} stderr=${r.err}", 1, r.code)
        assertEquals("stderr=${r.err}", "input-unreadable\n", r.out)
    }

    @Test fun `the real verifiers keep their own usage errors and --help`() {
        val env = mapOf("SENTOMARU_VERIFY_DIR" to realDir.path)
        val missing = run("receipt", env = env)
        assertEquals("stdout=${missing.out} stderr=${missing.err}", 2, missing.code)
        assertTrue("stderr=${missing.err}", missing.err.contains("the following arguments are required: --receipt"))
        val help = run("audit-export", "--help", env = env)
        assertEquals("stdout=${help.out} stderr=${help.err}", 0, help.code)
        assertTrue("stdout=${help.out} stderr=${help.err}", help.out.contains("--envelope"))
    }

    @Test fun `the bundled script names are the ones the distribution copies`() {
        assertEquals(setOf("receipt", "audit-export"), Verify.SCRIPTS.keys)
        for (script in Verify.SCRIPTS.values) assertTrue(script, sourceDir.resolve(script).isFile)
    }
}
