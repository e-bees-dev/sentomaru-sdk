package br.com.ebees.sentomaru.protect

import com.google.gson.GsonBuilder
import com.google.gson.JsonArray
import com.google.gson.JsonNull
import com.google.gson.JsonObject
import java.io.File
import java.security.MessageDigest
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneOffset
import java.util.Base64
import java.util.UUID
import kotlin.system.exitProcess

/** `sentomaru protect`: contracts/devsecops/cli-v1.md. Exit codes and error codes are the contract's. */
object Cli {
    const val VERSION = "1"
    // G-03e: real run (entitlement, AAB injection, keystore or OpenBao signing, registration). D-08f: 0.5.0, the
    // build-obfuscation control in Controls.all (`controls --json` changes even without a profile); D-07f: network-pinning
    // in Controls.all too, still 0.5.0 because the release cli-v0.5.0 is still to be published
    // (contracts/devsecops/cli-distribution-v1.md). D-16-lab-gate: SENTOMARU_LAB=1 refused in a registered run, still 0.5.0.
    // D-14e: asset-encryption in Controls.all too, still 0.5.0 (cli-v0.5.0 still to be published).
    // G-10c: 0.6.0, ui-shield in Controls.all (`controls --json` lists six); cli-v0.6.0 is still to be published.
    const val BUILD = "0.6.0"
    /** D-16-lab-gate: the stable `detail` of the `usage` refusal of SENTOMARU_LAB=1 in a registered run (cli-v1.md). */
    const val LAB_GATE_REGISTERED = "lab-gate-registered: SENTOMARU_LAB=1 needs --lab-unregistered"
    // The injected runtime (:protect-runtime). G-03b2 ships the init runtime only; the SDK client joins with G-03c.
    const val RUNTIME_SDK = "runtime-0.1.0"

    private val gson = GsonBuilder().setPrettyPrinting().disableHtmlEscaping().serializeNulls().create() // null fields stay (contract)

    /** Runs and returns the exit code; [out]/[err] receive stdout/stderr text. */
    fun run(args: List<String>, env: Map<String, String> = System.getenv(), out: (String) -> Unit = ::println,
        err: (String) -> Unit = { System.err.println(it) }): Int {
        if (args.firstOrNull() == "protect") return run(args.drop(1), env, out, err)
        if (args.firstOrNull() == "verify") return Verify.run(args.drop(1), env, out, err)
        if (args == listOf("--version") || args == listOf("--version", "--json")) {
            out(if ("--json" in args) gson.toJson(cli()) else "sentomaru protect $BUILD (contract v$VERSION, runtime sdk $RUNTIME_SDK)")
            return 0
        }
        if (args == listOf("controls") || args == listOf("controls", "--json")) {
            val list = Controls.all.map { mapOf("id" to it.id, "version" to it.version, "stage" to it.stage, "order" to it.order,
                "prerequisites" to it.prerequisites, "changeIds" to it.changeIds) }
            out(if ("--json" in args) gson.toJson(list) else list.joinToString("\n") { "${it["id"]} v${it["version"]} ${it["stage"]}/${it["order"]}" })
            return 0
        }
        if (args.firstOrNull() == "register") return register(args.drop(1), env, out, err)
        if (args.firstOrNull() == "openbao-certificate") return openBaoCertificate(args.drop(1), env, out, err)
        val report = skeleton("--dry-run" in args)
        val warnings = report.getAsJsonArray("warnings")
        fun warn(code: String, detail: String) = warnings.add(gson.toJsonTree(mapOf("code" to code, "detail" to detail)))
        var reportPath: File? = null
        var produced: File? = null // the output: deleted if anything fails before it is registered
        var registry: Registry? = null
        var scope: Scope? = null
        var opened = false         // the run is open on the API (entitlement checked): a failure closes it as failed
        var inputFacts: Map<String, String>? = null
        val runId = report.get("runId").asString
        fun closeFailed(error: ErrorCode) {
            val api = registry ?: return
            if (!opened) return
            opened = false
            try {
                api.close(scope!!, runId, mapOf("result" to "failed", "errorCode" to error.code) + (inputFacts ?: emptyMap()))
            } catch (e: ProtectException) {
                warn("registration-failed", "the failed run was not recorded (${e.error.code})")
            }
        }
        try {
            val options = Options.parse(args)
            // `<out>` is an argument: checked before anything else is read (contract precedence).
            if (!(options.out.isDirectory || options.out.mkdirs()) || !options.out.canWrite())
                throw ProtectException(ErrorCode.OUTPUT_UNWRITABLE, "--out")
            val path = options.report ?: File(options.out, "report.json")
            if (path.canonicalFile == options.input.canonicalFile || path.canonicalFile == options.profile.canonicalFile)
                throw ProtectException(ErrorCode.USAGE, "--report would overwrite an input")
            reportPath = path
            // Precedence (contract): arguments → profile and its scope → credential and entitlement → input →
            // full profile validation → compatibility → controls → signing → registration.
            val profile = Profile.read(options.profile)
            scope = profile.scope
            report.add("profile", gson.toJsonTree(mapOf("id" to profile.id, "sha256" to profile.sha256,
                "scope" to mapOf("organization" to profile.scope.organization, "app" to profile.scope.app,
                    "environment" to profile.scope.environment))))
            if (options.input.name.endsWith(".ipa", ignoreCase = true)) {
                // G-03g1: an IPA is only inspected. Nothing is planned, applied, signed or registered for it yet.
                if (!options.dryRun) throw ProtectException(ErrorCode.USAGE, "an IPA input supports --dry-run only in this build")
                val ipa = IpaReader.read(options.input)
                inputFacts = mapOf("inputSha256" to ipa.sha256, "inputKind" to "ipa")
                report.add("input", gson.toJsonTree(mapOf("kind" to "ipa", "sha256" to ipa.sha256, "bundleId" to ipa.bundleId,
                    "shortVersion" to ipa.shortVersion, "buildVersion" to ipa.buildVersion, "minimumOsVersion" to ipa.minimumOsVersion,
                    "executable" to ipa.executable, "frameworks" to ipa.frameworks, "sentomaruFramework" to ipa.sentomaruFramework,
                    "hasProvisioningProfile" to ipa.hasProvisioningProfile)))
                warn("ipa-controls-not-evaluated", "no control is evaluated for an IPA in this build; the report only describes the input")
                if (!ipa.sentomaruFramework) warn("ipa-sdk-framework-absent",
                    "no Sentomaru*.framework in Frameworks/; an SDK compiled into the app (the Flutter plugin) is not detected")
                write(reportPath, report)
                out(gson.toJson(report))
                return 0
            }
            val real = !options.dryRun && !options.lab
            if (options.lab) {
                // Not a contract run (kept for the device gate, see the contract): explicit on the command line and
                // in the environment, never registered.
                if (env["SENTOMARU_LAB"] != "1") throw ProtectException(ErrorCode.USAGE, "--lab-unregistered needs SENTOMARU_LAB=1")
                report.addProperty("lab", true)
                warn("lab-unregistered", "laboratory run: no entitlement check, not registered, not for distribution")
            } else if (real) {
                // D-16-lab-gate: the laboratory gate changes what a released control does (the asset-encryption size
                // limit) and the server cannot tell, so a registered run refuses it before the run is opened.
                if (env["SENTOMARU_LAB"] == "1") throw ProtectException(ErrorCode.USAGE, LAB_GATE_REGISTERED)
                registry = registry(env)
                // Arguments first (a missing keystore is `usage`), then the entitlement (open), then the signer.
                if (options.sign == "keystore" && !File(options.keystore!!).isFile) throw ProtectException(ErrorCode.USAGE, "--keystore is not a file")
                registry.open(profile.scope, runId, profile, BUILD)
                opened = true
            }
            val artifact = ArtifactReader.read(options.input, ::warn)
            inputFacts = mapOf("inputSha256" to artifact.sha256, "inputKind" to artifact.kind.label)
            report.add("input", gson.toJsonTree(mapOf("kind" to artifact.kind.label, "sha256" to artifact.sha256,
                "package" to artifact.manifest.packageName, "versionCode" to artifact.manifest.versionCode,
                "minSdk" to artifact.manifest.minSdk, "targetSdk" to artifact.manifest.targetSdk,
                "signingCertSha256" to artifact.signingCertSha256, "modules" to artifact.modules)))
            val minSdk = artifact.manifest.minSdk
            if (minSdk == null || minSdk < 28) throw ProtectException(ErrorCode.MIN_SDK_UNSUPPORTED, "minSdk ${minSdk ?: "absent"}")
            // The signing mode depends on the artifact kind, so this argument rule can only be checked here.
            val sign = options.sign ?: if (artifact.kind == ArtifactKind.AAB) "none"
                else throw ProtectException(ErrorCode.USAGE, "an APK needs --sign keystore, openbao or none")
            if (artifact.kind == ArtifactKind.APK && sign == "none") warn("output-unsigned", "an unsigned APK does not install")
            if (options.lab && artifact.kind != ArtifactKind.AAB) throw ProtectException(ErrorCode.USAGE, "the lab run supports an AAB only in this build")
            if (options.lab && sign != "none") throw ProtectException(ErrorCode.USAGE, "the lab run is unsigned: use --sign none")
            // No control is behind the laboratory gate since D-14e: build-obfuscation left it in D-08f, network-pinning in
            // D-07f and asset-encryption in D-14e. The gate still raises the asset-encryption per-file limit to the format
            // ceiling (4 MiB, the D-14d proof). D-16-lab-gate: a registered run already refused SENTOMARU_LAB=1 above, so
            // `lab` is true only in the dry run and the lab run (review R M5: `!real` keeps that invariant here too,
            // without relying on the refusal coming first).
            val context = ControlContext(today(), lab = !real && env["SENTOMARU_LAB"] == "1", sections = profile.controls, warn = ::warn)
            val resolved = Controls.resolve(profile, context)
            val planned = resolved.map { (control, section) -> control.plan(section.fields, artifact, context) }
            if (planned.any { it.id == NetworkSigning.id }) warn("network-signing-install-line",
                "the CLI checks that the SDK or plugin is linked, not that the app installs it in one line with the profile hosts and routes")
            val plans = if (options.dryRun) planned else {
                // Apply: every control that changes the binary edits the same AAB, in stage order (one write, one
                // validation). network-signing (G-03c) is the SDK transport the app installs and build-obfuscation (D-08d)
                // only reads the build, both already checked by plan(); the lab run takes neither. Anything else fails closed.
                for ((control, _) in resolved) if (!control.changesBinary && (options.lab || control !in Controls.checkOnly))
                    throw ProtectException(ErrorCode.CONTROL_FAILED, "${control.id}: not applicable by this build")
                val steps = resolved.filter { it.first.changesBinary }.map { it.first to it.second.fields }
                if (steps.isEmpty()) throw ProtectException(ErrorCode.CONTROL_FAILED, "nothing to apply")
                if (artifact.kind != ArtifactKind.AAB)
                    throw ProtectException(ErrorCode.CONTROL_FAILED, "${steps.first().first.id}: APK input not supported by this build (AAB only)")
                var certificate: String? = null
                val injected = AabInjector.inject(options.input, artifact, steps, context, options.out, lab = options.lab) { temp ->
                    if (sign == "keystore") certificate = AabSigner.sign(temp, File(options.keystore!!), options.keyAlias!!, env)
                    if (sign == "openbao") certificate = (openBaoFactory ?: { t, e -> OpenBaoSigner(t, e) })(options.openbao!!, env).sign(temp)
                }
                produced = injected.output
                // A signature this run just made that does not verify is the signing failing (7), never the input (3).
                if (certificate != null) {
                    val verified = try {
                        verifySigned(injected.output)
                    } catch (e: ProtectException) {
                        throw ProtectException(ErrorCode.SIGN_FAILED, "the signed bundle does not verify (${e.error.code})")
                    }
                    if (verified != certificate) throw ProtectException(ErrorCode.SIGN_FAILED, "the signed bundle does not verify")
                }
                if (injected.removedSignature) warn("input-signature-removed", "the input JAR signature no longer matches and was removed")
                report.add("output", gson.toJsonTree(mapOf("sha256" to injected.sha256, "signed" to (certificate != null),
                    "signingCertSha256" to certificate, "sizeDeltaBytes" to injected.sizeDeltaBytes)))
                // Controls that change nothing (network-signing, build-obfuscation) keep their plan (`checked`).
                planned.map { p -> injected.changes[p.id]?.let {
                    ControlPlan(p.id, p.version, "applied", it, evidence = p.evidence + injected.evidence[p.id].orEmpty()) } ?: p }
            }
            report.add("controls", gson.toJsonTree(plans.map { p ->
                mapOf("id" to p.id, "version" to p.version, "status" to p.status,
                    "changes" to p.changes.map { mapOf("id" to it.id, "target" to it.target) },
                    "notInstrumentable" to p.notInstrumentable,
                    "evidence" to when {
                        p.id == RuntimeInjection.id && p.status == "applied" -> mapOf("runtimeDexSha256" to AabInjector.runtimeDexSha256,
                            "validation" to "bundletool validate")
                        else -> p.evidence
                    })
            }))
            val signed = report.getAsJsonObject("output").get("signed")?.takeIf { !it.isJsonNull }?.asBoolean == true
            report.add("signing", gson.toJsonTree(mapOf("mode" to sign,
                "status" to when { sign == "none" -> "skipped"; options.dryRun -> "planned"; signed -> "applied"; else -> "skipped" })))
            if (options.lab) report.getAsJsonObject("registration").addProperty("status", "not-registered")
            registry?.let { api ->
                val output = report.getAsJsonObject("output")
                val closing = mapOf("result" to "protected", "outputSha256" to output.get("sha256").asString, "signed" to signed,
                    "signingCertSha256" to output.get("signingCertSha256").takeIf { !it.isJsonNull }?.asString) + inputFacts!!
                report.add("closing", gson.toJsonTree(closing)) // what `protect register` re-sends if the close fails
                try {
                    val registered = api.close(profile.scope, runId, closing)
                    opened = false
                    produced = null // registered: never deleted from here on
                    report.remove("closing")
                    report.add("registration", gson.toJsonTree(mapOf("status" to "registered", "buildId" to registered.buildId)))
                } catch (e: ProtectException) {
                    // Contract: the finished artifact stays, the report says it was not registered (retry possible).
                    opened = false
                    produced = null
                    report.add("registration", gson.toJsonTree(mapOf("status" to "not-registered", "buildId" to null)))
                    throw e
                }
            }
            write(reportPath, report)
            out(gson.toJson(report))
            return 0
        } catch (e: ProtectException) {
            produced?.delete()
            closeFailed(e.error)
            return refuse(e.error, e.detail, report, reportPath, err)
        } catch (e: Throwable) {
            produced?.delete()
            closeFailed(ErrorCode.INTERNAL)
            return refuse(ErrorCode.INTERNAL, e.javaClass.simpleName, report, reportPath, err)
        }
    }

    /** The API client of a real run: credential from the environment (checked), address `SENTOMARU_API`. */
    private fun registry(env: Map<String, String>): Registry {
        val token = env["SENTOMARU_BUILDER_TOKEN"]
        if (token.isNullOrEmpty()) throw ProtectException(ErrorCode.CREDENTIAL_MISSING, "SENTOMARU_BUILDER_TOKEN")
        if (token.length > 512 || token.any { it.isISOControl() || it.isWhitespace() })
            throw ProtectException(ErrorCode.CREDENTIAL_MISSING, "SENTOMARU_BUILDER_TOKEN is not a credential")
        return (registryFactory ?: { uri, t -> Registry(uri, t) })(Registry.address(env["SENTOMARU_API"]), token)
    }

    /**
     * `sentomaru protect register --report <report.json>`: re-sends the close of a run whose artifact was produced but
     * not registered (contract "Saída e relatório": the registration can be redone). The close is idempotent on the
     * server; the report is updated in place. Exit 0 when registered, the contract's 8 codes otherwise.
     */
    private fun register(args: List<String>, env: Map<String, String>, out: (String) -> Unit, err: (String) -> Unit): Int {
        val fail = { error: ErrorCode, detail: String ->
            err(gson.toJson(mapOf("code" to error.code, "detail" to detail))); error.exit }
        if (args.size != 2 || args[0] != "--report") return fail(ErrorCode.USAGE, "register --report <report.json>")
        val path = File(args[1])
        val report = try {
            StrictJson.parse(path.readBytes()).asJsonObject
        } catch (e: Exception) {
            return fail(ErrorCode.USAGE, "--report is not a report")
        }
        return try {
            val closing = report.getAsJsonObject("closing")
                ?: throw ProtectException(ErrorCode.USAGE, "the report has nothing to register")
            val slug = Regex("""\A[a-z0-9_-]{2,32}\z""")
            val scope = report.getAsJsonObject("profile").getAsJsonObject("scope").let { o ->
                val parts = listOf("organization", "app", "environment").map { o.get(it)?.takeIf { e -> e.isJsonPrimitive }?.asString ?: "" }
                if (parts.any { !slug.matches(it) }) throw ProtectException(ErrorCode.USAGE, "the report scope is not valid")
                Scope(parts[0], parts[1], parts[2])
            }
            val runId = report.get("runId")?.takeIf { it.isJsonPrimitive }?.asString
                ?.takeIf { runCatching { UUID.fromString(it).toString() == it }.getOrDefault(false) }
                ?: throw ProtectException(ErrorCode.USAGE, "the report runId is not a UUID")
            if (!REGISTER_KEYS.containsAll(closing.keySet()) || closing.get("result")?.asString != "protected")
                throw ProtectException(ErrorCode.USAGE, "the report closing is not a protected result")
            val body = closing.entrySet().associate { (k, v) -> k to (if (v.isJsonNull) null else if (v.asJsonPrimitive.isBoolean) v.asBoolean else v.asString) }
            // The artifact next to the report must be the one the closing declares.
            val outputSha = body["outputSha256"] as? String ?: throw ProtectException(ErrorCode.USAGE, "the report has no output digest")
            val artifact = path.absoluteFile.parentFile.listFiles { f -> f.name.endsWith(".protected.aab") }?.singleOrNull()
                ?: throw ProtectException(ErrorCode.USAGE, "no single protected artifact next to the report")
            val actual = MessageDigest.getInstance("SHA-256").digest(artifact.readBytes()).joinToString("") { "%02x".format(it) }
            if (actual != outputSha) throw ProtectException(ErrorCode.USAGE, "the artifact differs from the report")
            val registered = registry(env).close(scope, runId, body)
            report.remove("closing")
            report.add("registration", gson.toJsonTree(mapOf("status" to "registered", "buildId" to registered.buildId)))
            // Only the registration failures are resolved; any other error of the run stays in the report.
            val errors = report.getAsJsonArray("errors")
            val kept = errors.filter { e -> e.asJsonObject.get("code")?.asString !in setOf("register-failed", "registry-unavailable") }
            while (errors.size() > 0) errors.remove(0)
            kept.forEach(errors::add)
            write(path, report)
            out(gson.toJson(report))
            0
        } catch (e: ProtectException) {
            fail(e.error, e.detail)
        } catch (e: Exception) {
            fail(ErrorCode.USAGE, "--report is not a report")
        }
    }

    private val REGISTER_KEYS = setOf("result", "outputSha256", "signed", "signingCertSha256", "inputSha256", "inputKind")

    /** Test seam: the verification of the bundle this run signed (JarFile, every entry, one signer). */
    internal var verifySigned: (File) -> String? = { ArtifactReader.read(it).signingCertSha256 }

    /** Test seam: how the OpenBao signer is built. */
    internal var openBaoFactory: ((OpenBaoSigner.Target, Map<String, String>) -> OpenBaoSigner)? = null

    /**
     * `sentomaru protect openbao-certificate --openbao-addr <url> --openbao-role <role> --openbao-transit <mount>/<key>
     * --common-name <cn> --out <cert.pem> [--years 30] [--openbao-cacert <pem>] [--openbao-audience <aud>]`: the
     * self-signed certificate of the Transit key, signed in the vault (the upload certificate for the Play Console and
     * the `--openbao-key` of `--sign openbao`). Never overwrites a file. Prints the certificate SHA-256.
     */
    private fun openBaoCertificate(args: List<String>, env: Map<String, String>, out: (String) -> Unit, err: (String) -> Unit): Int {
        val fail = { error: ErrorCode, detail: String -> err(gson.toJson(mapOf("code" to error.code, "detail" to detail))); error.exit }
        val known = setOf("--openbao-addr", "--openbao-role", "--openbao-transit", "--openbao-cacert", "--openbao-audience",
            "--common-name", "--out", "--years")
        val values = mutableMapOf<String, String>()
        var i = 0
        while (i < args.size) {
            val a = args[i]; val v = args.getOrNull(i + 1)
            if (a !in known || a in values || v == null || v.startsWith("--") || v.isEmpty()) return fail(ErrorCode.USAGE, if (a in known) "$a needs one value" else "unknown argument")
            values[a] = v; i += 2
        }
        return try {
            for (required in listOf("--openbao-addr", "--openbao-role", "--openbao-transit", "--common-name", "--out"))
                if (required !in values) throw ProtectException(ErrorCode.USAGE, required)
            val years = values["--years"]?.toIntOrNull()?.takeIf { it in 1..50 } ?: if ("--years" in values) throw ProtectException(ErrorCode.USAGE, "--years must be 1..50") else 30
            val target = File(values.getValue("--out"))
            if (target.exists()) throw ProtectException(ErrorCode.USAGE, "--out exists: a certificate is never overwritten")
            val t = OpenBaoSigner.Target.of(values.getValue("--openbao-addr"), values.getValue("--openbao-role"), values.getValue("--openbao-transit"),
                null, values["--openbao-cacert"], values["--openbao-audience"])
            val pem = (openBaoFactory ?: { x, e -> OpenBaoSigner(x, e) })(t, env).selfSignedCertificate(values.getValue("--common-name"), years)
            try {
                target.absoluteFile.parentFile?.mkdirs()
                java.nio.file.Files.newOutputStream(target.toPath(), java.nio.file.StandardOpenOption.CREATE_NEW).use { it.write(pem.toByteArray()) }
            } catch (e: java.nio.file.FileAlreadyExistsException) {
                throw ProtectException(ErrorCode.USAGE, "--out exists: a certificate is never overwritten")
            } catch (e: java.io.IOException) {
                throw ProtectException(ErrorCode.OUTPUT_UNWRITABLE, "--out")
            }
            val der = Base64.getMimeDecoder().decode(pem.lines().filter { !it.startsWith("-----") }.joinToString(""))
            out(gson.toJson(mapOf("certificate" to target.path, "sha256" to MessageDigest.getInstance("SHA-256").digest(der).joinToString("") { "%02x".format(it) })))
            0
        } catch (e: ProtectException) {
            fail(e.error, e.detail)
        } catch (e: Throwable) {
            fail(ErrorCode.INTERNAL, e.javaClass.simpleName)
        }
    }

    /** Test seam: the UTC date of the run (the network-pinning expiration rule). */
    internal var today: () -> LocalDate = { LocalDate.now(ZoneOffset.UTC) }

    /** Test seam: how the API client is built (a local fake registry in the tests). */
    internal var registryFactory: ((java.net.URI, String) -> Registry)? = null

    private fun cli() = mapOf("version" to VERSION, "build" to BUILD, "runtime" to mapOf("sdk" to RUNTIME_SDK, "dexSha256" to AabInjector.runtimeDexSha256))

    /** Every report carries every top-level member of the contract; what this run did not reach stays null or empty. */
    private fun skeleton(dryRun: Boolean) = JsonObject().apply {
        addProperty("reportVersion", "1")
        addProperty("runId", UUID.randomUUID().toString())
        addProperty("startedAt", Instant.now().toString())
        addProperty("dryRun", dryRun)
        add("cli", gson.toJsonTree(cli()))
        add("profile", JsonNull.INSTANCE)
        add("input", JsonNull.INSTANCE)
        add("output", gson.toJsonTree(mapOf("sha256" to null, "signed" to null, "signingCertSha256" to null, "sizeDeltaBytes" to null)))
        add("controls", JsonArray())
        add("signing", gson.toJsonTree(mapOf("mode" to null, "status" to null)))
        add("registration", gson.toJsonTree(mapOf("status" to null, "buildId" to null)))
        add("warnings", JsonArray())
        add("errors", JsonArray())
    }

    private fun refuse(error: ErrorCode, detail: String, report: JsonObject, reportPath: File?, err: (String) -> Unit): Int {
        val body = mapOf("code" to error.code, "detail" to detail)
        report.getAsJsonArray("errors").add(gson.toJsonTree(body))
        err(gson.toJson(body))
        reportPath?.let { runCatching { write(it, report) } }
        return error.exit
    }

    private fun write(path: File, report: JsonObject) {
        path.parentFile?.let { if (!it.isDirectory && !it.mkdirs()) throw ProtectException(ErrorCode.OUTPUT_UNWRITABLE, "report directory") }
        try {
            path.writeText(gson.toJson(report) + "\n")
        } catch (e: Exception) {
            throw ProtectException(ErrorCode.OUTPUT_UNWRITABLE, "report")
        }
    }
}

/** Command-line options (contract "Invocação"); anything unknown, repeated or incomplete is `usage`. */
/** [lab]: `--lab-unregistered`, a laboratory run outside the contract (no credential, no entitlement, no registration). */
data class Options(val input: File, val profile: File, val out: File, val dryRun: Boolean, val report: File?, val sign: String?,
    val lab: Boolean = false, val keystore: String? = null, val keyAlias: String? = null, val openbao: OpenBaoSigner.Target? = null) {
    companion object {
        private val VALUED = setOf("--input", "--profile", "--out", "--report", "--sign", "--keystore", "--key-alias",
            "--openbao-addr", "--openbao-role", "--openbao-key", "--openbao-transit", "--openbao-cacert", "--openbao-audience")
        private val SIGNING = mapOf("keystore" to setOf("--keystore", "--key-alias"),
            "openbao" to setOf("--openbao-addr", "--openbao-role", "--openbao-key", "--openbao-transit"), "none" to emptySet())
        /** Options a mode may take besides its required ones. */
        private val OPTIONAL = mapOf("openbao" to setOf("--openbao-cacert", "--openbao-audience"))

        fun parse(args: List<String>): Options {
            val values = mutableMapOf<String, String>()
            var dryRun = false
            var json = false
            var lab = false
            var i = 0
            while (i < args.size) {
                val a = args[i]
                when {
                    a == "--dry-run" && !dryRun -> dryRun = true
                    a == "--json" && !json -> json = true
                    a == "--lab-unregistered" && !lab -> lab = true
                    a in VALUED && a !in values -> {
                        // A missing value must not swallow the next option (`--out --dry-run`).
                        val v = args.getOrNull(i + 1)
                        if (v == null || v.startsWith("--") || v.isEmpty()) throw ProtectException(ErrorCode.USAGE, "$a needs a value")
                        values[a] = v
                        i++
                    }
                    // Only option names go to stderr, never a stray value (it may be a path or a secret).
                    else -> throw ProtectException(ErrorCode.USAGE, if (a in VALUED || a == "--dry-run" || a == "--json" || a == "--lab-unregistered") "repeated $a" else "unknown argument")
                }
                i++
            }
            val input = values["--input"] ?: throw ProtectException(ErrorCode.USAGE, "--input")
            val profile = values["--profile"] ?: throw ProtectException(ErrorCode.USAGE, "--profile")
            val out = values["--out"] ?: throw ProtectException(ErrorCode.USAGE, "--out")
            val sign = values["--sign"]
            val signingOptions = values.keys.filter { o -> SIGNING.values.any { o in it } || OPTIONAL.values.any { o in it } }.toSet()
            if (sign == null) {
                if (signingOptions.isNotEmpty()) throw ProtectException(ErrorCode.USAGE, "signing options without --sign")
            } else {
                val expected = SIGNING[sign] ?: throw ProtectException(ErrorCode.USAGE, "--sign $sign")
                if (!signingOptions.containsAll(expected) || !(expected + OPTIONAL[sign].orEmpty()).containsAll(signingOptions)) throw ProtectException(ErrorCode.USAGE, "--sign $sign needs ${expected.sorted().joinToString(" ").ifEmpty { "no options" }}")
            }
            if (!File(profile).isFile) throw ProtectException(ErrorCode.USAGE, "--profile is not a file")
            if (lab && dryRun) throw ProtectException(ErrorCode.USAGE, "--lab-unregistered and --dry-run are exclusive")
            val openbao = if (sign == "openbao") OpenBaoSigner.Target.of(values.getValue("--openbao-addr"), values.getValue("--openbao-role"),
                values.getValue("--openbao-transit"), values.getValue("--openbao-key"), values["--openbao-cacert"], values["--openbao-audience"]) else null
            return Options(File(input), File(profile), File(out), dryRun, values["--report"]?.let(::File), sign, lab,
                values["--keystore"], values["--key-alias"], openbao)
        }
    }
}

fun main(args: Array<String>) {
    exitProcess(Cli.run(args.toList()))
}
