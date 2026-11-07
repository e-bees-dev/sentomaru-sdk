package br.com.ebees.sentomaru.signals

/**
 * Definition of a capability registered in the signals catalog.
 */
data class CapabilityDefinition(
    val capabilityId: String,
    val version: String,
    val description: String,
    val source: String,
    val supportedPlatforms: List<String>,
    val minSdk: Int,
    val supportedStates: List<SignalState>,
    val budgetMs: Long,
    val limitations: String,
)

/**
 * The client_observed part of the contract catalog `contracts/sdk/signals-catalog-v1.json` (the server_verified
 * capabilities are set by the API, never by the SDK). `SignalsCatalogContractTest` compares it with the JSON.
 */
object SignalsCatalog {
    const val VERSION = "1.15.0"

    /** Catalog 1.0.0 capabilities, frozen until the J-04 report: `SignalsCollector.defaultDetectors()`. */
    val DEFAULT_CAPABILITY_IDS: List<String> = listOf(
        "debug_attached", "emulator_detected", "root_indicated", "app_signing_digest", "installer_source", "os_version",
    )

    /** D-05 (catalog 1.3.0) capabilities, opt-in: `SignalsCollector.raspDetectors()`. */
    val RASP_CAPABILITY_IDS: List<String> = listOf(
        "debugger_attached", "app_debuggable", "dev_settings_enabled", "root_artifacts", "emulator_indicated",
        "hook_framework_java",
    )

    /** D-12c (catalog 1.5.0) capabilities, opt-in: `SignalsCollector.appIntegrityDetectors(...)`. */
    val APP_INTEGRITY_CAPABILITY_IDS: List<String> = listOf("app_signer_mismatch", "installer_class", "code_integrity")

    /** D-24 (catalog 1.8.0) consultive device threat capabilities, opt-in: `SignalsCollector.deviceThreatDetectors(...)`. */
    val DEVICE_THREAT_CAPABILITY_IDS: List<String> = listOf("a11y_risk", "overlay", "ime_untrusted", "synthetic_input", "known_malware")

    /** D-20 (catalog 1.10.0) consultive screen capabilities, opt-in: `SignalsCollector.screenDetectors(...)`. */
    val SCREEN_CAPABILITY_IDS: List<String> = listOf("screen_capture", "screen_shared")

    /** F-07/F-08 (catalog 1.13.0) consultive session context capabilities, opt-in: `SignalsCollector.sessionDetectors(...)`. */
    val SESSION_CAPABILITY_IDS: List<String> = listOf("location_mock", "call_active")

    /**
     * D-15a: the closed `type` of a `SentomaruSignalEvent` per capability. Only the D-05 and D-12c capabilities emit
     * events; the six catalog 1.0.0 ones never do (`installer_source` carries a package name and `app_signing_digest` a
     * digest in their detail, and both are frozen).
     */
    val EVENT_TYPES: Map<String, String> = linkedMapOf(
        "debugger_attached" to "debugger",
        "app_debuggable" to "debuggable_build",
        "dev_settings_enabled" to "developer_options",
        "root_artifacts" to "root_artifacts",
        "emulator_indicated" to "emulator",
        "hook_framework_java" to "hook_framework_java",
        "app_signer_mismatch" to "app_signer",
        "code_integrity" to "code_integrity",
        "installer_class" to "installer_class",
        "a11y_risk" to "accessibility_risk",
        "overlay" to "overlay",
        "ime_untrusted" to "ime_untrusted",
        "synthetic_input" to "synthetic_input",
        "known_malware" to "known_malware",
        "screen_capture" to "screen_capture",
        "screen_shared" to "screen_shared",
        "location_mock" to "location_mock",
        "call_active" to "call_active",
    )

    /**
     * D-15a: the only reason codes a `SentomaruSignalEvent` may carry, per capability: the fixed check codes of each
     * detector (indicators), `partial` when a check did not run, `timeout` when the collector's deadline replaced the
     * observation, the `result` of `app_signer_mismatch`, the classes of `installer_class` (`class_*`, `initiator_*`)
     * and the `reason`/`cause` codes of `code_integrity`. Never a count, digest, aggregate, path, package name or free
     * text. `SignalEventsTest` checks that every code the detectors emit (RASP and app-integrity detectors, by
     * doubles) is listed here, and locks the lists. The lists live only in the SDK: they are not in the catalog JSON,
     * the server, the Flutter plugin nor the Console, and the catalog version does not change with them. Changing a
     * list is a new version of its capability.
     */
    val EVENT_REASON_CODES: Map<String, Set<String>> = linkedMapOf(
        "debugger_attached" to setOf("jdwp_connected", "jdwp_waiting", "partial", "timeout"),
        "app_debuggable" to setOf("flag_debuggable", "partial", "timeout"),
        "dev_settings_enabled" to setOf("adb_enabled", "development_settings", "partial", "timeout"),
        "root_artifacts" to setOf(
            "su_path", "manager_path", "build_props", "test_keys", "build_type", "root_package", "mountinfo", "partial",
            "timeout",
        ),
        "emulator_indicated" to setOf("build_props", "qemu_device", "sensor_missing", "partial", "timeout"),
        "hook_framework_java" to setOf("xposed_class", "hook_frame", "partial", "timeout"),
        "app_signer_mismatch" to setOf("match", "mismatch", "no_reference", "unreadable", "timeout"),
        "installer_class" to setOf(
            "class_play", "class_none", "class_other", "class_unknown",
            "initiator_play", "initiator_none", "initiator_other", "initiator_unknown", "timeout",
        ),
        "code_integrity" to setOf(
            "not_compared", "timeout", "partial", "main_thread", "apk_list", "executor", "hash_failed", "apk_unreadable",
            "duplicate_entry", "entry_unreadable", "no_code_files", "too_large", "too_many_files",
        ),
        "a11y_risk" to setOf("none", "listed", "unlisted_present", "partial", "timeout"),
        "overlay" to setOf("obscured", "clear", "no_touches", "timeout"),
        "ime_untrusted" to setOf("known", "unknown", "no_reference", "partial", "timeout"),
        "synthetic_input" to setOf("virtual_pointer", "injected_touch", "partial", "timeout"),
        "known_malware" to setOf("matched", "clear", "no_reference", "partial", "timeout"),
        "screen_capture" to setOf("captured", "none", "no_screens", "timeout"),
        "screen_shared" to setOf("presentation_display", "secondary_display", "screen_recording", "partial", "timeout"),
        "location_mock" to setOf("mock_flagged", "clean", "no_permission", "no_fix", "partial", "timeout"),
        "call_active" to setOf("cellular", "communication", "none", "partial", "timeout"),
    )

    /**
     * Root-manager packages `root_artifacts` 1.0.0 looks up, the only `<queries>` entries, in the opt-in
     * `signals-rasp` manifest (never QUERY_ALL_PACKAGES; `SignalsManifestTest` keeps both equal). Changing the list is
     * a new `root_artifacts` version. A manager installed under a randomized package name is not visible.
     */
    val ROOT_MANAGER_PACKAGES: List<String> = listOf(
        "com.topjohnwu.magisk",
        "io.github.vvb2060.magisk",
        "io.github.huskydg.magisk",
        "me.weishu.kernelsu",
        "me.bmax.apatch",
        "eu.chainfire.supersu",
        "com.koushikdutta.superuser",
        "com.noshufou.android.su",
        "com.thirdparty.superuser",
        "com.kingroot.kinguser",
    )

    val CAPABILITIES: List<CapabilityDefinition> = listOf(
        CapabilityDefinition(
            capabilityId = "debug_attached",
            version = "1.0.0",
            description = "Indicates whether a debugger is currently attached or app is running in debug mode.",
            source = "client_observed",
            supportedPlatforms = listOf("android", "ios"),
            minSdk = 28,
            supportedStates = listOf(SignalState.DETECTED, SignalState.NOT_DETECTED, SignalState.ERROR),
            budgetMs = 5L,
            limitations = "Observes android.os.Debug.isDebuggerConnected() and FLAG_DEBUGGABLE; does not detect ptrace hooks attached outside the JVM runtime. iOS (D-10e, catalog 1.7.0): P_TRACED of the process read by sysctl KERN_PROC_PID, detail debugger_connected only (no debug-build flag on iOS); ERROR when the call fails. A debugger that hides P_TRACED, or a hook on sysctl, is not seen.",
        ),
        CapabilityDefinition(
            capabilityId = "emulator_detected",
            version = "1.0.0",
            description = "Detects well-known indicators of a generic Android emulator, the iOS simulator or virtualized execution environments.",
            source = "client_observed",
            supportedPlatforms = listOf("android", "ios"),
            minSdk = 28,
            supportedStates = listOf(SignalState.DETECTED, SignalState.NOT_DETECTED, SignalState.UNKNOWN, SignalState.ERROR),
            budgetMs = 5L,
            limitations = "Inspects Build properties (FINGERPRINT, MODEL, HARDWARE, PRODUCT, MANUFACTURER); sophisticated emulators spoofing authentic OEM properties may not be detected locally. iOS (D-10e, catalog 1.7.0): decided by how the app was built, not by probing the device: a simulator build is DETECTED (matched_indicators=simulator), an iOS build on an iPhone or iPad NOT_DETECTED (matched_indicators=none), and an iOS app running on a Mac (Mac Catalyst, iPhone app on Apple silicon) UNKNOWN (reason=not_ios_device). A virtualized or emulated iOS device is not detected.",
        ),
        CapabilityDefinition(
            capabilityId = "root_indicated",
            version = "1.0.0",
            description = "Checks for common presence of test-keys in build tags or known root binaries in standard system locations without spawning shell processes (on iOS, known jailbreak artifacts).",
            source = "client_observed",
            supportedPlatforms = listOf("android", "ios"),
            minSdk = 28,
            supportedStates = listOf(SignalState.DETECTED, SignalState.NOT_DETECTED, SignalState.UNKNOWN, SignalState.ERROR),
            budgetMs = 10L,
            limitations = "Checks standard paths (/system/bin/su, /sbin/su, etc.) and Build.TAGS. Hidden root (Magisk Zygisk, KernelSU) bypassing standard file visibility will not be detected locally. iOS (D-10e, catalog 1.7.0): only on an iPhone or iPad: known rootful and rootless jailbreak paths, a write outside the app sandbox and hooking libraries in the dyld image list, detail jb_path, sandbox_write and hooking_library (true or false), the result reused for 60 s per process; the simulator (reason=simulator) and an iOS app on a Mac (reason=not_ios_device) are UNKNOWN, never NOT_DETECTED. A hidden rootless jailbreak is not detected; no URL scheme query.",
        ),
        CapabilityDefinition(
            capabilityId = "app_signing_digest",
            version = "1.0.0",
            description = "Computes SHA-256 digest of the app's own signing certificate history.",
            source = "client_observed",
            supportedPlatforms = listOf("android"),
            minSdk = 28,
            supportedStates = listOf(SignalState.DETECTED, SignalState.ERROR, SignalState.UNSUPPORTED),
            budgetMs = 15L,
            limitations = "Reads signing certificates via PackageManager.GET_SIGNING_CERTIFICATES; requires verification on server against registered app certificate digests.",
        ),
        CapabilityDefinition(
            capabilityId = "installer_source",
            version = "1.0.0",
            description = "Determines the package name of the installer application that installed the current app.",
            source = "client_observed",
            supportedPlatforms = listOf("android"),
            minSdk = 28,
            supportedStates = listOf(SignalState.DETECTED, SignalState.NOT_DETECTED, SignalState.UNKNOWN, SignalState.ERROR),
            budgetMs = 5L,
            limitations = "Observes PackageManager installer/install source info. Sideloaded or adb installations report NOT_DETECTED (null package).",
        ),
        CapabilityDefinition(
            capabilityId = "os_version",
            version = "1.0.0",
            description = "Reports the OS version: on Android the SDK integer and release string, on iOS the platform and release.",
            source = "client_observed",
            supportedPlatforms = listOf("android", "ios"),
            minSdk = 28,
            supportedStates = listOf(SignalState.DETECTED, SignalState.ERROR),
            budgetMs = 5L,
            limitations = "Reads Build.VERSION values. May be modified on custom ROMs. iOS (D-10e, catalog 1.7.0): ProcessInfo.operatingSystemVersion, detail platform=ios and release=MAJOR.MINOR.PATCH (no sdk_int); the fixture is the Android one. An iOS app running on a Mac reports platform=ios with the host macOS version.",
        ),
        CapabilityDefinition(
            capabilityId = "debugger_attached",
            version = "1.0.0",
            description = "D-05: a JDWP debugger is connected to the app process or the process is waiting for one (Debug.isDebuggerConnected, Debug.waitingForDebugger).",
            source = "client_observed",
            supportedPlatforms = listOf("android"),
            minSdk = 28,
            supportedStates = listOf(SignalState.DETECTED, SignalState.NOT_DETECTED, SignalState.UNKNOWN, SignalState.UNSUPPORTED, SignalState.ERROR),
            budgetMs = 5L,
            limitations = "Declared by the app, not verified by the server: an instrumented process (Frida, LSPosed) can rewrite the value before the installation key signs it. Observes only the Java debugger (JDWP); a native debugger or ptrace (TracerPid) is not seen (D-19). Does not read FLAG_DEBUGGABLE (that is app_debuggable). The SDK reports NOT_DETECTED only when both calls ran and returned false; NOT_DETECTED means not detected in this collection, never a clean environment. The SDK reports UNKNOWN when a known measurement fails, ERROR only for an unexpected exception in the detector, and UNSUPPORTED only where the check does not exist (iOS in the Flutter plugin; no Android detector at minSdk 28). The SDK is specified to send fixed codes only in detail (no path, package name, device property or identifier). Server side: the API reads a state outside supportedStates or another major version as UNKNOWN. budgetMs is provisional outside the SM-A055M (D-05c measured warm p95 0.104 ms there and kept 5).",
        ),
        CapabilityDefinition(
            capabilityId = "app_debuggable",
            version = "1.0.0",
            description = "D-05: the running app has FLAG_DEBUGGABLE set in its ApplicationInfo (debug build, or a release repackaged with the flag on).",
            source = "client_observed",
            supportedPlatforms = listOf("android"),
            minSdk = 28,
            supportedStates = listOf(SignalState.DETECTED, SignalState.NOT_DETECTED, SignalState.UNKNOWN, SignalState.UNSUPPORTED, SignalState.ERROR),
            budgetMs = 2L,
            limitations = "Declared by the app, not verified by the server: a hook can return a cleared flag. A repackaged release without the flag is not seen (certificate and installer against the profile are D-13). DETECTED is expected on any debug build. The SDK reports NOT_DETECTED only when ApplicationInfo was read and the flag is off. The SDK reports UNKNOWN when a known measurement fails, ERROR only for an unexpected exception in the detector, and UNSUPPORTED only where the check does not exist (iOS in the Flutter plugin; no Android detector at minSdk 28). The SDK is specified to send fixed codes only in detail (no path, package name, device property or identifier). Server side: the API reads a state outside supportedStates or another major version as UNKNOWN. budgetMs is provisional outside the SM-A055M (D-05c measured warm p95 0.144 ms there and kept 2).",
        ),
        CapabilityDefinition(
            capabilityId = "dev_settings_enabled",
            version = "1.0.0",
            description = "D-05: Settings.Global ADB_ENABLED or DEVELOPMENT_SETTINGS_ENABLED is on (developer options or USB debugging enabled on the device).",
            source = "client_observed",
            supportedPlatforms = listOf("android"),
            minSdk = 28,
            supportedStates = listOf(SignalState.DETECTED, SignalState.NOT_DETECTED, SignalState.UNKNOWN, SignalState.UNSUPPORTED, SignalState.ERROR),
            budgetMs = 3L,
            limitations = "Declared by the app, not verified by the server. Describes a device setting, not an attack: many legitimate users (and every developer device) have it on, so it is a context signal, never a deny reason on its own. Wireless debugging is not read separately. The SDK reports NOT_DETECTED only when both settings were read and are off. The SDK reports UNKNOWN when a known measurement fails, ERROR only for an unexpected exception in the detector, and UNSUPPORTED only where the check does not exist (iOS in the Flutter plugin; no Android detector at minSdk 28). The SDK is specified to send fixed codes only in detail (no path, package name, device property or identifier). Server side: the API reads a state outside supportedStates or another major version as UNKNOWN. budgetMs is provisional outside the SM-A055M (D-05c measured warm p95 0.212 ms there and kept 3).",
        ),
        CapabilityDefinition(
            capabilityId = "root_artifacts",
            version = "1.0.0",
            description = "D-05: indicators of root without spawning a process: su and known root-manager paths, Build.TAGS test-keys, Build.TYPE other than user, root-manager packages from a fixed <queries> list, markers in /proc/self/mountinfo.",
            source = "client_observed",
            supportedPlatforms = listOf("android"),
            minSdk = 28,
            supportedStates = listOf(SignalState.DETECTED, SignalState.NOT_DETECTED, SignalState.UNKNOWN, SignalState.UNSUPPORTED, SignalState.ERROR),
            budgetMs = 11L,
            limitations = "Declared by the app, not verified by the server. Hidden root (Magisk with Zygisk and DenyList, KernelSU, APatch) hides exactly these artifacts and is expected NOT to be detected; a root manager with a randomized package name is not in the fixed <queries> list (never QUERY_ALL_PACKAGES). The package check needs the opt-in artifact br.com.ebees.sentomaru:signals-rasp, which carries the <queries>; without it the check does not run, so the capability is never NOT_DETECTED (UNKNOWN with detail partial=root_package, or DETECTED by another indicator). An app that removes those <queries> in its manifest merge while keeping the artifact reads every package as absent. The SDK reports NOT_DETECTED only when every check ran and found nothing; a check that did not run (access denied, read failed) gives UNKNOWN with detail partial. The SDK reports UNKNOWN when a known measurement fails, ERROR only for an unexpected exception in the detector, and UNSUPPORTED only where the check does not exist (iOS in the Flutter plugin; no Android detector at minSdk 28). The SDK is specified to send fixed codes only in detail (no path, package name, device property or identifier). Server side: the API reads a state outside supportedStates or another major version as UNKNOWN. budgetMs is provisional outside the SM-A055M (D-05c measured warm p95 10.696 ms there and set 11).",
        ),
        CapabilityDefinition(
            capabilityId = "emulator_indicated",
            version = "1.0.0",
            description = "D-05: indicators of an emulator: a reviewed list of Build.* values, QEMU/goldfish device files, absence of basic sensors (SensorManager).",
            source = "client_observed",
            supportedPlatforms = listOf("android"),
            minSdk = 28,
            supportedStates = listOf(SignalState.DETECTED, SignalState.NOT_DETECTED, SignalState.UNKNOWN, SignalState.UNSUPPORTED, SignalState.ERROR),
            budgetMs = 10L,
            limitations = "Declared by the app, not verified by the server. An emulator or virtualized image that spoofs OEM Build values, device files and sensors is not detected; some cheap devices lack a sensor and can raise a false indicator. The SDK reports NOT_DETECTED only when every check ran and found nothing; a partial run gives UNKNOWN with detail partial. The SDK reports UNKNOWN when a known measurement fails, ERROR only for an unexpected exception in the detector, and UNSUPPORTED only where the check does not exist (iOS in the Flutter plugin; no Android detector at minSdk 28). The SDK is specified to send fixed codes only in detail (no path, package name, device property or identifier). Server side: the API reads a state outside supportedStates or another major version as UNKNOWN. budgetMs is provisional outside the SM-A055M (D-05c measured warm p95 0.875 ms there and kept 10).",
        ),
        CapabilityDefinition(
            capabilityId = "hook_framework_java",
            version = "1.0.0",
            description = "D-05: Java layer only: Xposed/LSPosed classes loadable by the app class loader, or Xposed/Substrate frames in the stack trace of a controlled exception.",
            source = "client_observed",
            supportedPlatforms = listOf("android"),
            minSdk = 28,
            supportedStates = listOf(SignalState.DETECTED, SignalState.NOT_DETECTED, SignalState.UNKNOWN, SignalState.UNSUPPORTED, SignalState.ERROR),
            budgetMs = 5L,
            limitations = "Declared by the app, not verified by the server: the hook it looks for can hide itself or rewrite the result. Does not detect Frida, native hooks, trampolines or /proc/self/maps artifacts (D-19). The SDK reports NOT_DETECTED only when both checks ran and found nothing. The SDK reports UNKNOWN when a known measurement fails, ERROR only for an unexpected exception in the detector, and UNSUPPORTED only where the check does not exist (iOS in the Flutter plugin; no Android detector at minSdk 28). The SDK is specified to send fixed codes only in detail (no path, package name, device property or identifier). Server side: the API reads a state outside supportedStates or another major version as UNKNOWN. budgetMs is provisional outside the SM-A055M (D-05c measured warm p95 1.774 ms there and kept 5).",
        ),
        CapabilityDefinition(
            capabilityId = "app_signer_mismatch",
            version = "1.0.0",
            description = "D-12c (D-13, declared): the SDK compares every SHA-256 digest of the app's signing certificates (apkContentsSigners with several signers, else signingCertificateHistory, the whole rotation lineage) with the list of expected digests the app passes to the SDK; it sends only match or mismatch and the counts, never a digest.",
            source = "client_observed",
            supportedPlatforms = listOf("android"),
            minSdk = 28,
            supportedStates = listOf(SignalState.DETECTED, SignalState.NOT_DETECTED, SignalState.UNKNOWN, SignalState.UNSUPPORTED, SignalState.ERROR),
            budgetMs = 15L,
            limitations = "Declared by the app, not verified by the server: a repackaged APK whose SDK was patched, or a hook on getPackageInfo (Frida, LSPosed), returns the expected digests and the installation key signs the forged value. The expected list is configuration of the app itself, so it only shows a re-signed APK that kept the original SDK and configuration; the server-verified app_identity_mismatch (D-13a) is the stronger evidence for an enrolled app with hardware attestation. DETECTED (result=mismatch) = at least one digest read is not in the expected list; NOT_DETECTED (result=match) = every digest read is expected; UNKNOWN = no expected list (result=no_reference) or the certificates could not be read (result=unreadable). A key rotation (APK v3) puts the old certificates in the history: list the whole lineage or every rotated install is a mismatch. With Play App Signing the device holds the certificate Google signs with: expect that one. Detail carries result, signers and unexpected (counts) only. Opt-in: never in defaultDetectors(). budgetMs is provisional (not measured on a device yet, D-12d). The SDK reports UNKNOWN when a known measurement fails, ERROR only for an unexpected exception in the detector, and UNSUPPORTED only where the check does not exist (iOS in the Flutter plugin; no Android detector at minSdk 28). Server side: the API reads a state outside supportedStates or another major version as UNKNOWN. Advisory: no default rule uses it.",
        ),
        CapabilityDefinition(
            capabilityId = "installer_class",
            version = "1.0.0",
            description = "D-12c (D-13, declared): fixed class of the package that installed the app (InstallSourceInfo.installingPackageName, API 30+): play (com.android.vending), none (no installer recorded) or other; initiatingPackageName goes as a second class in detail.",
            source = "client_observed",
            supportedPlatforms = listOf("android"),
            minSdk = 28,
            supportedStates = listOf(SignalState.DETECTED, SignalState.UNKNOWN, SignalState.UNSUPPORTED, SignalState.ERROR),
            budgetMs = 5L,
            limitations = "Declared by the app, not verified by the server: a hook can rewrite the answer. A value signal, never NOT_DETECTED: DETECTED = the class was read (detail class=play|none|other and initiator=play|none|other), so a rule reads the class with in/equals on the detail, and a count of DETECTED (the D-05a shadow count, a J-04 report) is how many reads succeeded, never a rate of risk; UNKNOWN (class=unknown) = Android 9 or 10 (no InstallSourceInfo) or the lookup failed. The mapping is provisional until measured on a device: the class an adb install, the system package installer or another store gives is not fixed yet (D-12d). A sideloaded app (an HML build) is expected to read none or other: there the signal only serves measurement. Never a package name in detail (the old installer_source does that and stays frozen). Opt-in: never in defaultDetectors(). budgetMs is provisional (D-12d). The SDK reports UNKNOWN when a known measurement fails, ERROR only for an unexpected exception in the detector, and UNSUPPORTED only where the check does not exist (iOS in the Flutter plugin; no Android detector at minSdk 28). Server side: the API reads a state outside supportedStates or another major version as UNKNOWN. Advisory: no default rule uses it.",
        ),
        CapabilityDefinition(
            capabilityId = "code_integrity",
            version = "1.0.0",
            description = "D-12c (D-12, declared): the SDK computes, off the main thread, the aggregate of algorithm apk-code-sha256-v1 (contracts/shield/registry-v1.md) over every classes*.dex and lib/<abi>/*.so of the installed APKs (sourceDir and splitSourceDirs) and sends it with the algorithm and the file count; the comparison with the build registry is the server's (D-12c-2).",
            source = "client_observed",
            supportedPlatforms = listOf("android"),
            minSdk = 28,
            supportedStates = listOf(SignalState.UNKNOWN, SignalState.UNSUPPORTED, SignalState.ERROR),
            budgetMs = 15L,
            limitations = "Declared by the app, not verified by the server: the SDK of a repackaged APK, or a hook on the APK read, returns the expected aggregate, and the installation key signs it. Never asserts the bytes running (dex loaded at run time, JIT, memory: D-19/D-20). The SDK never decides match or mismatch (the reference lives in the server, never in the APK): it always reports UNKNOWN, with detail reason=not_compared plus algorithm, aggregate (lowercase hex64) and files when computed, reason=timeout while the first hash (cold) runs in the background past the wait, reason=partial when an APK or a code entry could not be read (or none, more than 256 files, a repeated path, more than 2 GiB), reason=main_thread when called on the main thread. supportedStates are the states the SDK may declare: a declared DETECTED or NOT_DETECTED is read as UNKNOWN. The server (D-12c-2) then compares an UNKNOWN reason=not_compared observation with the codeDigests registered for the signing certificate and versionCode attested at enrollment (only when build_unregistered is NOT_DETECTED; every ABI variant of that versionCode counts) and sets the state the policy sees: NOT_DETECTED reason=match (the aggregate of one of those builds); DETECTED reason=mismatch (those builds declared lists, every variant of the versionCode has one, no higher version lacks one, the read was complete, and neither they nor another version of the certificate match); UNKNOWN reason=no_reference, other_version, same_version_unreferenced, newer_version_unreferenced, reference_incomplete, no_build_match, reference_pending (the registry read runs in the background, and a mismatch waits for a read started after it was first seen), registry_unavailable (also when the held reference is over 30 min old and its refresh failed) or aggregate_invalid. Known false DETECTED: an app updated to a versionCode that is not registered, before the SDK re-enrolls (D-04b), gives mismatch (the server knows only the enrolled version). The reference is cached per API process (per replica): replicas read the registry independently and may answer differently for one read (one reference_pending while another already matched). A cached match is only safe because build records are insert-only for the API (no UPDATE nor DELETE grant); a build removed by hand by the owner stays matched for up to 10 min. The compared detail keeps only reason, algorithm and files. A split install (base plus split APKs, as from the Play) matches only a build whose list is the union of those APKs. An unsigned NOT_DETECTED is still read as UNKNOWN (H3). The cache lives in the process, keyed by lastUpdateTime and the APK paths and sizes; the cold cost is reported by D-12d. Opt-in: never in defaultDetectors(). budgetMs is provisional (D-12d). The SDK reports UNKNOWN when a known measurement fails, ERROR only for an unexpected exception in the detector, and UNSUPPORTED only where the check does not exist (iOS in the Flutter plugin; no Android detector at minSdk 28). Server side: the API reads a state outside supportedStates or another major version as UNKNOWN. Advisory: no default rule uses it.",
        ),
        CapabilityDefinition(
            capabilityId = "a11y_risk",
            version = "1.0.0",
            description = "D-24a (consultive, declared): the enabled accessibility services (AccessibilityManager.getEnabledAccessibilityServiceList) against the list of risky packages the app passes to the SDK; it sends only the enum none, listed or unlisted_present, never a service name or hash.",
            source = "client_observed",
            supportedPlatforms = listOf("android"),
            minSdk = 28,
            supportedStates = listOf(SignalState.DETECTED, SignalState.NOT_DETECTED, SignalState.UNKNOWN, SignalState.UNSUPPORTED, SignalState.ERROR),
            budgetMs = 5L,
            limitations = "Declared by the app, not verified by the server: a hook on AccessibilityManager returns an empty list and the installation key signs it. result=none (NOT_DETECTED) = no service enabled; result=listed (DETECTED) = at least one enabled service is on the app's list; result=unlisted_present (UNKNOWN) = services are enabled and none is on the list (they are not judged: a screen reader of a user with a disability is the common case, and the name of an assistive service would reveal a disability, so it is never sent, hashed or counted). A legitimate assistive service placed on the list is a false positive; an empty list never gives listed. A malicious service that is not on the list reads as unlisted_present. The list is configuration of the app and is part of the scope of the data sheet approved by the owner on 3/11/2026. The SDK reports UNKNOWN when a known measurement fails, ERROR only for an unexpected exception in the detector, and UNSUPPORTED only where the check does not exist (iOS in the Flutter plugin; no Android detector at minSdk 28). The SDK is specified to send fixed codes only in detail (no service, keyboard, package or app name, path, device property or identifier). Server side: the API reads a state outside supportedStates or another major version as UNKNOWN. Opt-in: never in defaultDetectors(), raspDetectors() nor appIntegrityDetectors(): SignalsCollector.deviceThreatDetectors(...). budgetMs is provisional (not measured on a device yet). Advisory: no default rule uses it; weight as evidence only, never as a deny reason on its own.",
        ),
        CapabilityDefinition(
            capabilityId = "overlay",
            version = "1.0.0",
            description = "D-24b (consultive, declared): count of touches that reached a screen the app marked through an obscured window (MotionEvent FLAG_WINDOW_IS_OBSCURED or FLAG_WINDOW_IS_PARTIALLY_OBSCURED), per collection window; sent as result and counts, never a window, title or package name.",
            source = "client_observed",
            supportedPlatforms = listOf("android"),
            minSdk = 28,
            supportedStates = listOf(SignalState.DETECTED, SignalState.NOT_DETECTED, SignalState.UNKNOWN, SignalState.UNSUPPORTED, SignalState.ERROR),
            budgetMs = 1L,
            limitations = "Declared by the app, not verified by the server. Counts only touches on the screens the app marks (ObscuredTouchMonitor.shared.onTouch(event) in the dispatchTouchEvent of each marked screen); any other screen is never counted (approved scope). One collection window is the time since the previous read, which clears the count. result=obscured (DETECTED, detail obscured and touches) = at least one touch came through an obscured window; result=clear (NOT_DETECTED) = touches arrived and none was obscured; result=no_touches (UNKNOWN) = no touch on a marked screen in the window, so nothing was measured. An overlay that does not set the flag (some accessibility overlays, a window the app itself shows) is not seen, and a flag can be rewritten by a hook; a legitimate floating window (a chat head, a screen filter) gives obscured. The SDK reports UNKNOWN when a known measurement fails, ERROR only for an unexpected exception in the detector, and UNSUPPORTED only where the check does not exist (iOS in the Flutter plugin; no Android detector at minSdk 28). The SDK is specified to send fixed codes only in detail (no service, keyboard, package or app name, path, device property or identifier). Server side: the API reads a state outside supportedStates or another major version as UNKNOWN. Opt-in: never in defaultDetectors(), raspDetectors() nor appIntegrityDetectors(): SignalsCollector.deviceThreatDetectors(...). budgetMs is provisional (not measured on a device yet). Advisory: no default rule uses it; weight as evidence only, never as a deny reason on its own.",
        ),
        CapabilityDefinition(
            capabilityId = "ime_untrusted",
            version = "1.0.0",
            description = "D-24c (consultive, declared): the default input method (Settings.Secure.DEFAULT_INPUT_METHOD) against the list of known keyboards the app passes to the SDK; it sends only the enum known or unknown, never the package.",
            source = "client_observed",
            supportedPlatforms = listOf("android"),
            minSdk = 28,
            supportedStates = listOf(SignalState.DETECTED, SignalState.NOT_DETECTED, SignalState.UNKNOWN, SignalState.UNSUPPORTED, SignalState.ERROR),
            budgetMs = 3L,
            limitations = "Declared by the app, not verified by the server: a hook on the setting returns a known keyboard. result=known (NOT_DETECTED) = the default keyboard is on the app's list; result=unknown (DETECTED) = it is not (weak signal: a third-party keyboard is common and legitimate, so it is evidence only); result=no_reference (UNKNOWN) = the app passed no list; partial=input_method (UNKNOWN) = the setting could not be read or none is set. The package is never sent. A malicious keyboard that is on the list, or one that impersonates a listed package name, is not seen. The SDK reports UNKNOWN when a known measurement fails, ERROR only for an unexpected exception in the detector, and UNSUPPORTED only where the check does not exist (iOS in the Flutter plugin; no Android detector at minSdk 28). The SDK is specified to send fixed codes only in detail (no service, keyboard, package or app name, path, device property or identifier). Server side: the API reads a state outside supportedStates or another major version as UNKNOWN. Opt-in: never in defaultDetectors(), raspDetectors() nor appIntegrityDetectors(): SignalsCollector.deviceThreatDetectors(...). budgetMs is provisional (not measured on a device yet). Advisory: no default rule uses it; weight as evidence only, never as a deny reason on its own.",
        ),
        CapabilityDefinition(
            capabilityId = "synthetic_input",
            version = "1.1.0",
            description = "D-24e (consultive, declared): a virtual touch or pointer input device is registered (InputDevice.isVirtual with a touchscreen, mouse, stylus or touchpad source), the trace of input injected by a remote-control tool or a virtualized environment.",
            source = "client_observed",
            supportedPlatforms = listOf("android"),
            minSdk = 28,
            supportedStates = listOf(SignalState.DETECTED, SignalState.NOT_DETECTED, SignalState.UNKNOWN, SignalState.UNSUPPORTED, SignalState.ERROR),
            budgetMs = 5L,
            limitations = "Declared by the app, not verified by the server: an injector that creates no virtual device, or a hook on InputDevice, is not seen, and a device with a virtual pointer for a legitimate reason (accessibility tooling, a docking or screen-mirroring feature, an emulator) is a false positive, so it is evidence only. D-27 (1.1.0): the indicator injected_touch comes from touches on screens the app marks (the same call as the overlay signal), where an accessibility-event flag (API 33) or a virtual input device id was seen; no coordinate, pressure, size, time or device name is read or kept, and which of the two marks fired is not sent. A touch on a screen the app does not mark, injection by a device with a real id, or a hook on MotionEvent is not seen, and no marked-screen touch in the window says nothing about touches, never clean. Assistive technology (screen readers, switch access) also produces injected_touch and using it can reveal sensitive data about the person, so it is a false positive by design: evidence only, never a deny reason on its own. The SDK reports NOT_DETECTED only when the devices were enumerated and none is a virtual pointer; a failed enumeration gives UNKNOWN with detail partial. Detail carries the fixed indicator codes virtual_pointer and injected_touch only, never a device name, id or descriptor. The SDK reports UNKNOWN when a known measurement fails, ERROR only for an unexpected exception in the detector, and UNSUPPORTED only where the check does not exist (iOS in the Flutter plugin; no Android detector at minSdk 28). The SDK is specified to send fixed codes only in detail (no service, keyboard, package or app name, path, device property or identifier). Server side: the API reads a state outside supportedStates or another major version as UNKNOWN. Opt-in: never in defaultDetectors(), raspDetectors() nor appIntegrityDetectors(): SignalsCollector.deviceThreatDetectors(...). budgetMs is provisional (not measured on a device yet). Advisory: no default rule uses it; weight as evidence only, never as a deny reason on its own.",
        ),
        CapabilityDefinition(
            capabilityId = "known_malware",
            version = "1.0.0",
            description = "D-24d (consultive, declared): installed apps visible to the SDK compared, on the device, with the signed list of known Android malware (package and signing-certificate SHA-256 pair) that the app loads into the SDK; it sends only the enum matched or clear, a count and the list version, never a package name or certificate hash.",
            source = "client_observed",
            supportedPlatforms = listOf("android"),
            minSdk = 28,
            supportedStates = listOf(SignalState.DETECTED, SignalState.NOT_DETECTED, SignalState.UNKNOWN, SignalState.UNSUPPORTED, SignalState.ERROR),
            budgetMs = 8L,
            limitations = "Declared by the app, not verified by the server: a hook on PackageManager, or an app that never loads the list, hides a match, and the installation key signs the answer. Visibility is partial by design: the SDK manifest declares a launcher-intent queries entry only (no QUERY_ALL_PACKAGES), so an installed app that is not visible to the host app is not compared; result=clear (NOT_DETECTED) means no visible app matched, never that the device is clean. A match needs the package name and the signing-certificate digest of the same sample, so a repackaged or re-signed sample is not seen, and the list only holds samples already reported to its source. result=matched (DETECTED, detail matches = number of visible apps that matched, capped at 9, and listVersion) = at least one visible app is on the list; result=clear (NOT_DETECTED, matches=0, listVersion) = none matched; result=no_reference (UNKNOWN) = no valid list is loaded (none given, signature invalid, older than the one loaded, or no unexpired entry), never reported as clear; partial=packages or partial=certificates (UNKNOWN) = the installed apps or a candidate's signing certificates could not be read and nothing matched. Detail carries fixed codes, one count and the list version only, never a package, app or certificate name or hash. The SDK reports UNKNOWN when a known measurement fails, ERROR only for an unexpected exception in the detector, and UNSUPPORTED only where the check does not exist (iOS; no Android detector at minSdk 28). The SDK is specified to send fixed codes only in detail (no service, keyboard, package or app name, path, device property or identifier). Server side: the API reads a state outside supportedStates or another major version as UNKNOWN. Opt-in: never in defaultDetectors(), raspDetectors() nor appIntegrityDetectors(): SignalsCollector.deviceThreatDetectors(...) with a MalwareListStore. budgetMs is provisional (not measured on a device yet). Advisory: no default rule uses it; weight as evidence only, never as a deny reason on its own.",
        ),
        CapabilityDefinition(
            capabilityId = "screen_capture",
            version = "1.1.0",
            description = "D-20 (consultive, declared): count of screenshots taken while a screen the app marked was in front (Activity.ScreenCaptureCallback, API 34), per collection window; sent as result and a count, never an image, screen or app name.",
            source = "client_observed",
            supportedPlatforms = listOf("android"),
            minSdk = 28,
            supportedStates = listOf(SignalState.DETECTED, SignalState.NOT_DETECTED, SignalState.UNKNOWN, SignalState.UNSUPPORTED, SignalState.ERROR),
            budgetMs = 1L,
            limitations = "Declared by the app, not verified by the server. By default (scope marked) counts only the screenshots taken while a screen the app marks is in front (ScreenShield registered Activity.ScreenCaptureCallback, API 34, permission DETECT_SCREEN_CAPTURE); a capture with any other screen in front, a continuous recording, a MediaProjection capture and a photo of the screen with another camera are not seen, and the platform does not say who captured. One collection window is the time since the previous read, which clears the count. result=captured (DETECTED, detail captures capped at 9) = at least one screenshot; result=none (NOT_DETECTED) = a marked screen was registered in the window and no capture came; result=no_screens (UNKNOWN) = no marked screen was in front, so nothing was measured. UNSUPPORTED below API 34, where the platform has no callback. Detail carries the result and a count, never an image, file, screen or app name. ScreenShield also sets FLAG_SECURE and turns the recents snapshot off on the listed screens only; FLAG_SECURE does not stop an external camera, a hook or a memory read. The marking is per Activity window: a window a marked screen opens on its own (Dialog, DialogFragment, BottomSheet, PopupWindow) gets no FLAG_SECURE from ScreenShield, and whether a capture with such a window on top is counted by the callback has not been measured on a device. The SDK reports UNKNOWN when a known measurement fails, ERROR only for an unexpected exception in the detector, and UNSUPPORTED only where the check does not exist. The SDK is specified to send fixed codes only in detail (no screen, display or app name, path, device property or identifier). Server side: the API reads a state outside supportedStates or another major version as UNKNOWN. Scope (catalog 1.15.0, capability 1.1.0): the above is the default scope (CaptureScope.MARKED). With ScreenShield(..., captureScope = CaptureScope.ALL), opt-in, the callback is also registered on every visible Activity the app does not mark, and those captures are counted apart in detail captures_other (0..9, present only in this scope); captures keeps counting the marked screens, and result=captured / none considers both kinds (none = at least one screen, marked or not, was registered in the window and no capture came). No screen name is kept, and an unmarked screen still gets no FLAG_SECURE, so the system does not block a capture there. The same limits hold: a continuous recording, a MediaProjection capture, an external camera and a Dialog or PopupWindow window are not seen. Scope ALL observes screens the approved ficha did not cover, so it needs the privacy review of the scope-all ficha (D20_TELA_FICHA.md) before an app turns it on. Opt-in: never in defaultDetectors(), raspDetectors(), appIntegrityDetectors() nor deviceThreatDetectors(): SignalsCollector.screenDetectors(...). budgetMs is provisional (not measured on a device yet). Advisory: no default rule uses it; weight as evidence only, never as a deny reason on its own.",
        ),
        CapabilityDefinition(
            capabilityId = "screen_shared",
            version = "1.0.0",
            description = "D-20 (consultive, declared): the screen may be shown or recorded outside the device: a presentation display, another visible display, or (API 35) a screen recording reported by the platform; sent as fixed indicator codes, never a display name, id or creating package.",
            source = "client_observed",
            supportedPlatforms = listOf("android", "ios"),
            minSdk = 28,
            supportedStates = listOf(SignalState.DETECTED, SignalState.NOT_DETECTED, SignalState.UNKNOWN, SignalState.UNSUPPORTED, SignalState.ERROR),
            budgetMs = 3L,
            limitations = "iOS (D-27, catalog 1.12.0): read from UIScreen on the main thread only; secondary_display = more than one screen, screen_recording = a screen reports isCaptured (recording, mirroring or AirPlay); from another thread, or off an iPhone or iPad (simulator, Mac), the state is UNKNOWN (partial), never NOT_DETECTED. iOS gives no per-screen capture callback, so screen_capture stays UNSUPPORTED there. RAT-02 (D-27): a legitimate Android Auto or trusted external monitor connection cannot be told apart from a hostile mirror with certainty on the client: both can show presentation_display or secondary_display, and the car projection is usually a private virtual display that is not listed at all. The client never blocks; treating a reason code as legitimate is a server policy rule per scope, and a car or monitor is a false positive for secondary_display. Declared by the app, not verified by the server. Indicators from public APIs only: presentation_display (a visible display flagged FLAG_PRESENTATION), secondary_display (another visible display that is not the default one: HDMI, Cast or a mirroring feature; a foldable or desktop-mode device can give a false positive) and screen_recording (API 35, WindowManager screen recording callback, permission DETECT_SCREEN_RECORDING, fed by ScreenShield.install). A virtual display created without the public flag (common in MediaProjection sharing) is not enumerated, and the package that created a display is not readable without a hidden API, so it is not sent. Below API 35 screen_recording is never measured: the result is UNKNOWN with detail partial when no display was found, never NOT_DETECTED. NOT_DETECTED only when displays were enumerated and the recording state was read and neither showed anything. Detail carries the fixed codes in indicators (and partial for a check that did not run), never a display name or id. The SDK reports UNKNOWN when a known measurement fails, ERROR only for an unexpected exception in the detector, and UNSUPPORTED only where the check does not exist. The SDK is specified to send fixed codes only in detail (no screen, display or app name, path, device property or identifier). Server side: the API reads a state outside supportedStates or another major version as UNKNOWN. Opt-in: never in defaultDetectors(), raspDetectors(), appIntegrityDetectors() nor deviceThreatDetectors(): SignalsCollector.screenDetectors(...). budgetMs is provisional (not measured on a device yet). Advisory: no default rule uses it; weight as evidence only, never as a deny reason on its own.",
        ),
        CapabilityDefinition(
            capabilityId = "location_mock",
            version = "1.0.0",
            description = "F-07 (consultive, declared): the last location fix the app can already read carries the platform's mock-provider flag (Location.isMock, API 31, or isFromMockProvider below); sent as a result code, never a coordinate, provider, accuracy or time.",
            source = "client_observed",
            supportedPlatforms = listOf("android"),
            minSdk = 28,
            supportedStates = listOf(SignalState.DETECTED, SignalState.NOT_DETECTED, SignalState.UNKNOWN, SignalState.UNSUPPORTED, SignalState.ERROR),
            budgetMs = 5L,
            limitations = "Declared by the app, not verified by the server. The SDK never requests the location permission and never starts a location request: it reads LocationManager.getLastKnownLocation only when the app already holds ACCESS_FINE_LOCATION or ACCESS_COARSE_LOCATION, and uses the newest fix of the passive, gps and network providers that is at most 10 minutes old (with only the coarse permission the gps provider is not read, since it needs the fine one; a provider that refuses is skipped). result=mock_flagged (DETECTED) = that fix carries the mock flag; result=clean (NOT_DETECTED) = that one fix does not, which says nothing about the position now or about a later fix; result=no_permission (UNKNOWN) = the app does not hold the permission; result=no_fix (UNKNOWN) = no fix, or only a stale one; result=partial (UNKNOWN) = the read failed or the fix did not say its origin. A mock-location app that clears the flag (root, a hook on Location, or a system image that does not set it), a fix from a spoofed Wi-Fi or cell database, and a replay of a real route are not seen. A developer using a mock provider on purpose is a false positive. No coordinate, provider name, accuracy, speed, bearing, altitude, time or address is read into detail or kept; detail carries the result code only. Detail never carries a coordinate or a number. The SDK reports UNKNOWN when a known measurement fails, ERROR only for an unexpected exception in the detector, and UNSUPPORTED only where the check does not exist. Server side: the API reads a state outside supportedStates or another major version as UNKNOWN. Opt-in: never in defaultDetectors(), raspDetectors(), appIntegrityDetectors(), deviceThreatDetectors() nor screenDetectors(): SignalsCollector.sessionDetectors(...). budgetMs is provisional (not measured on a device yet). Advisory: no default rule reads it from the SDK directly; the app declares the result to the Fraud API, so weight as evidence only, never as a deny reason on its own.",
        ),
        CapabilityDefinition(
            capabilityId = "call_active",
            version = "1.0.0",
            description = "F-08 (consultive, declared): the system audio mode says a call is in progress (MODE_IN_CALL, a cellular call) or a communication session is (MODE_IN_COMMUNICATION, a VoIP app); sent as a result code, never a number, contact, duration or app name.",
            source = "client_observed",
            supportedPlatforms = listOf("android"),
            minSdk = 28,
            supportedStates = listOf(SignalState.DETECTED, SignalState.NOT_DETECTED, SignalState.UNKNOWN, SignalState.UNSUPPORTED, SignalState.ERROR),
            budgetMs = 1L,
            limitations = "Declared by the app, not verified by the server. Reads AudioManager.getMode() only: no telephony permission (READ_PHONE_STATE) is requested or needed, and nothing about the call itself is read. result=cellular (DETECTED) = MODE_IN_CALL; result=communication (DETECTED) = MODE_IN_COMMUNICATION, which any VoIP or conferencing app (including the app's own) sets; result=none (NOT_DETECTED) = normal, ringing or call-screening mode at the moment of the read, which says nothing about a call that started or ended a moment before; result=partial (UNKNOWN) = the read failed or returned a mode the SDK does not know. An app that holds MODIFY_AUDIO_SETTINGS can set the mode without a call (false positive), a call placed over an app that never sets the mode is not seen (false negative), and a hook on AudioManager hides or invents it. An ordinary call during use is a false positive by design. No number, contact, duration, direction or app name is read or kept; detail carries the result code only, never a coordinate or a number. The SDK reports UNKNOWN when a known measurement fails, ERROR only for an unexpected exception in the detector, and UNSUPPORTED only where the check does not exist. Server side: the API reads a state outside supportedStates or another major version as UNKNOWN. Opt-in: never in defaultDetectors(), raspDetectors(), appIntegrityDetectors(), deviceThreatDetectors() nor screenDetectors(): SignalsCollector.sessionDetectors(...). budgetMs is provisional (not measured on a device yet). Advisory: no default rule reads it from the SDK directly; the app declares the result to the Fraud API, so weight as evidence only, never as a deny reason on its own.",
        ),
    )
}
