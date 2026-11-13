import java.security.MessageDigest

// G-03 `sentomaru protect`: post-build protection CLI (contracts/devsecops/cli-v1.md, ADR 0001). Kotlin/JVM, runs only
// in the client's environment (D-C1). G-03b1: profile validation, artifact inspection (APK binary manifest, AAB
// protobuf manifest), control registry and the dry-run report. G-03b2: runtime injection into an AAB (lab run only).
plugins {
    id("org.jetbrains.kotlin.jvm")
    application
}

kotlin {
    jvmToolchain(17)
}

application {
    mainClass.set("br.com.ebees.sentomaru.protect.MainKt")
    applicationName = "sentomaru"
}

// `sentomaru verify receipt|audit-export` runs the Trust module's third-party verifiers (Python standard library + openssl).
// The distribution carries the two scripts, unchanged, under lib/verify/; Verify.SCRIPTS lists the same two names
// (the vendor's test cli verify bundle check keeps both lists equal).
distributions {
    main {
        contents {
            from(rootProject.file("../../tools/trust")) {
                include("verify_receipt.py", "verify_audit_export.py")
                into("lib/verify")
            }
        }
    }
}

// G-03b2: the injected runtime (:protect-runtime) as one DEX, embedded in the CLI jar as a resource. d8 is the
// pinned R8 release from Google Maven (checksum in gradle/verification-metadata.xml) and the platform jar is pinned by
// digest, so the embedded DEX and cli.runtime.dexSha256 are the same on every machine.
val runtimeJar: Configuration by configurations.creating {
    isCanBeConsumed = false
    isTransitive = false
}
val d8: Configuration by configurations.creating {
    isCanBeConsumed = false
}

// The pinned platform android.jar (gradle.properties sentomaru.android*), checked by SHA-256 when first used.
val pinnedAndroidJar = provider {
    val home = System.getenv("ANDROID_HOME") ?: System.getenv("ANDROID_SDK_ROOT") ?: ""
    val platform = providers.gradleProperty("sentomaru.androidPlatform").get()
    val expected = providers.gradleProperty("sentomaru.androidJarSha256").get()
    val jar = file(home).resolve("platforms/$platform/android.jar")
    if (!jar.isFile) throw GradleException("$platform/android.jar not found under ANDROID_HOME (sdkmanager \"platforms;$platform\")")
    val actual = MessageDigest.getInstance("SHA-256").digest(jar.readBytes()).joinToString("") { "%02x".format(it) }
    if (actual != expected) throw GradleException("$platform/android.jar sha256 $actual, pinned $expected (revision " +
        providers.gradleProperty("sentomaru.androidPlatformRevision").get() + ")")
    jar
}

val runtimeDex by tasks.registering(JavaExec::class) {
    val out = layout.buildDirectory.dir("generated/runtime-dex")
    inputs.files(runtimeJar)
    outputs.dir(out)
    classpath = d8
    mainClass.set("com.android.tools.r8.D8")
    val dexDir = out.map { it.asFile.resolve("br/com/ebees/sentomaru/protect/runtime") }
    doFirst { dexDir.get().deleteRecursively(); dexDir.get().mkdirs() }
    argumentProviders.add(CommandLineArgumentProvider {
        listOf("--release", "--min-api", "28", "--lib", pinnedAndroidJar.get().path, "--output", dexDir.get().path) +
            runtimeJar.files.map { it.path }
    })
}

sourceSets.main {
    resources.srcDir(runtimeDex)
    // D-F1 (Fase D, ativação de módulos em cliente novo): `sentomaru policy study` reads the same model
    // contracts/policy/templates/study-v1.json the C# test suite reads (Integrity.Tests.Policy.StudyPolicyTemplate),
    // embedded as a classpath resource so the two never drift from different copies.
    resources.srcDir(rootProject.file("../../contracts/policy/templates"))
}

dependencies {
    runtimeJar(project(":protect-runtime"))
    d8("com.android.tools:r8:9.4.28")
    implementation("com.google.code.gson:gson:2.11.0")
    implementation("com.android.tools.build:aapt2-proto:9.4.1-15978811")
    implementation("com.google.protobuf:protobuf-java:3.25.5") // aapt2-proto declares it runtime-only
    implementation("com.android.tools.build:apksig:9.4.1")
    // The contract validates every output bundle with bundletool (in process, ValidateBundleCommand).
    implementation("com.android.tools.build:bundletool:1.18.3")
    // D-21p: reads and writes DEX (BSD-3-Clause, AOSP smali project) for the dex-obfuscation control.
    implementation("com.android.tools.smali:smali-dexlib2:3.0.10")
    testImplementation("junit:junit:4.13.2")
}

// D-14c: the CLI's tests read what asset-encryption writes with the D-14b reader itself (sdk/android/sealed), not with a
// copy: its JVM part (no Android import) is compiled into the test source set.
val sealedReaderSources by tasks.registering(Sync::class) {
    from(project(":sealed").file("src/main/kotlin/br/com/ebees/sentomaru/sdk/sealed")) {
        include("SealedFormat.kt", "SealedReader.kt", "StringsJson.kt", "SentomaruSealedException.kt")
    }
    into(layout.buildDirectory.dir("generated/sealed-reader"))
}

kotlin.sourceSets.test {
    kotlin.srcDir(sealedReaderSources)
}

// Fixtures are built at test time with the SDK's aapt2 (a minimal APK and its protobuf manifest for an AAB), so the
// tests need ANDROID_HOME with build-tools and a platform (the CI image has both).
tasks.test {
    systemProperty("android.home", System.getenv("ANDROID_HOME") ?: "")
    // D-21p: APKs of the example apps for the DEX round trip, given by the developer (local run; absent in the CI).
    System.getProperty("sentomaru.dexRoundTripApks")?.let { systemProperty("sentomaru.dexRoundTripApks", it) }
    // D-21a3: the Android SDK's dexdump, for DexObfuscationMeasurementTest's other static acceptance check (local run; absent in the CI).
    System.getProperty("sentomaru.dexdump")?.let { systemProperty("sentomaru.dexdump", it) }
    // The API E2E of the shield suite asks a test to export its fixture bundle there: part of the task inputs.
    inputs.property("e2eFixtureDir", System.getenv("SENTOMARU_E2E_FIXTURE_DIR") ?: "")
}

// G-03f: the published CLI is rebuilt bit for bit from a revision (fixed entry order and times in every archive),
// so the digest in the signed release statement can be checked by rebuilding.
tasks.withType<AbstractArchiveTask>().configureEach {
    isPreserveFileTimestamps = false
    isReproducibleFileOrder = true
}
