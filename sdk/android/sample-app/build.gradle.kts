// Synthetic lab app for the P2 SDK. Not a product app; never published.
import org.cyclonedx.gradle.CyclonedxDirectTask
import java.util.Properties

plugins {
    id("com.android.application")
    id("org.cyclonedx.bom")
}

// D-05g-a: the RASP lab build, only with -Psentomaru.raspLab=true. It has its own package
// (br.com.ebees.sentomaru.rasplab, test APK .rasplab.test) so the scope `ebees/rasp-lab/hml` never sees the J-04s app,
// and it cannot be combined with the J-04s build in one invocation (that one keeps the sample package).
val raspLab = providers.gradleProperty("sentomaru.raspLab").orNull == "true"
val j04sRelease = providers.gradleProperty("sentomaru.j04sRelease").orNull == "true"
if (raspLab && j04sRelease) throw GradleException("sentomaru.raspLab and sentomaru.j04sRelease are separate builds")

// D-08b: the obfuscation/symbolication example build, only with -Psentomaru.d08bRelease=true (the default build, the CI
// lockfile and every other variant are unchanged). It is the normal R8 release plus the lab-only LabCrashActivity
// (src/d08bCrash) and `-keepattributes SourceFile,LineNumberTable` (proguard-rules-d08b.pro), signed with the debug key
// so it installs on the emulator. Built and measured only by .github/workflows/d08b-symbolize-emulator.yml and
// verification/run_d08b_symbolize.py; never published. Separate from the J-04s/raspLab builds (those have no R8).
val d08bRelease = providers.gradleProperty("sentomaru.d08bRelease").orNull == "true"
if (d08bRelease && (raspLab || j04sRelease)) throw GradleException("sentomaru.d08bRelease is a separate build")
val d08eNoR8 = providers.gradleProperty("sentomaru.d08eNoR8").orNull == "true"
if (d08eNoR8 && (raspLab || j04sRelease || d08bRelease)) throw GradleException("sentomaru.d08eNoR8 is a separate build")

// D-14d: the asset-encryption proof build, only with -Psentomaru.d14dSealed=true (the default build, the CI lockfile
// and every other variant are unchanged). It is the normal R8 release (so the SealedAssetSample reader survives R8 like
// a client build) plus the per-run canary assets of build/d14d/assets, generated OUTSIDE the repository by
// verification/devsecops/gen_d14d_canaries.py (never committed; build/ is ignored). Unsigned here, like j04sRelease:
// `sentomaru protect --lab-unregistered --sign none` seals the AAB and run_d14d_seal.py measures size and (on a device)
// read cost. Built and measured only by verification/run_d14d_seal.py; never published. Separate from the other builds.
val d14dSealed = providers.gradleProperty("sentomaru.d14dSealed").orNull == "true"
if (d14dSealed && (raspLab || j04sRelease || d08bRelease || d08eNoR8))
    throw GradleException("sentomaru.d14dSealed is a separate build")
// D-14d read cost: -Psentomaru.d14dReadTest=true (only with d14dSealed) also keeps the Kotlin runtime in the app so the
// androidx.test runner of the androidTest APK can start (proguard-rules-d14d-readtest.pro). The size and cold-start
// APKs are built without it.
val d14dReadTest = providers.gradleProperty("sentomaru.d14dReadTest").orNull == "true"
if (d14dReadTest && !d14dSealed) throw GradleException("sentomaru.d14dReadTest needs -Psentomaru.d14dSealed=true")
// D-14d precise live peak (emulator window): -Psentomaru.d14dLiveProbe=true (only with d14dReadTest) also keeps the
// sealed reader's classes by name (proguard-rules-d14d-liveprobe.pro) for SealedLivePeakProbe. Memory only.
val d14dLiveProbe = providers.gradleProperty("sentomaru.d14dLiveProbe").orNull == "true"
if (d14dLiveProbe && !d14dReadTest) throw GradleException("sentomaru.d14dLiveProbe needs -Psentomaru.d14dReadTest=true")

// D-07e/C-03b: the pinning proof build, only with -Psentomaru.d07e=true (the default build, the
// CI lockfile and every other variant are unchanged). Own package (br.com.ebees.sentomaru.pinlab, test APK .pinlab.test),
// so neither the J-04s app nor the C-06/G-03c suites ever see it. The release build without R8 (not debuggable), signed
// with the debug key: `sentomaru protect --sign none` drops the AAB signature and bundletool signs the universal APK with
// the same debug key, so the test APK (src/androidTestD07e) instruments it. -Psentomaru.d07eCleartext=true adds
// android:usesCleartextTraffic="true" (src/d07eCleartext/AndroidManifest.xml) for the cleartext row. The app's code is
// not changed: the test APK drives the existing transports (OkHttp + addSentomaru, SentomaruUrlConnection.send, a plain
// HttpURLConnection) in the app's process, under the app's network_security_config. Never published.
val d07e = providers.gradleProperty("sentomaru.d07e").orNull == "true"
val d07eCleartext = providers.gradleProperty("sentomaru.d07eCleartext").orNull == "true"
if (d07eCleartext && !d07e) throw GradleException("sentomaru.d07eCleartext needs -Psentomaru.d07e=true")
if (d07e && (raspLab || j04sRelease || d08bRelease || d08eNoR8 || d14dSealed))
    throw GradleException("sentomaru.d07e is a separate build")

// D-12h: -Psentomaru.d12h=original|otherKey|dexMarker, only with the raspLab build. The
// app and its test APK are signed by Gradle with a LOCAL lab key generated by `verification/d12h_keys.py create`
// (lab-original for original and dexMarker, lab-repack for otherKey), read from <keys dir>/<key>.properties
// (storeFile, keyAlias, passwordFile) outside the repository; dexMarker adds src/d12hMarker (one class nothing loads),
// so classes*.dex differ with the same certificate and versionCode. No secret is in the repository.
val d12h = providers.gradleProperty("sentomaru.d12h").orNull
if (d12h != null && d12h !in setOf("original", "otherKey", "dexMarker"))
    throw GradleException("sentomaru.d12h must be original, otherKey or dexMarker")
if (d12h != null && !raspLab) throw GradleException("sentomaru.d12h needs -Psentomaru.raspLab=true")
val d12hKey: Properties? = d12h?.let { variant ->
    val name = if (variant == "otherKey") "lab-repack" else "lab-original"
    val dir = providers.gradleProperty("sentomaru.d12hKeysDir").orNull ?: System.getenv("SENTOMARU_D12H_KEYS_DIR")
        ?: "${System.getProperty("user.home")}/.config/sentomaru/d12h-lab-keys"
    val file = File(dir, "$name.properties")
    if (!file.isFile) throw GradleException("D-12h: $file not found; run `python3 verification/d12h_keys.py create` first")
    Properties().apply {
        file.inputStream().use { load(it) }
        listOf("storeFile", "keyAlias", "passwordFile").forEach {
            if (getProperty(it).isNullOrBlank()) throw GradleException("D-12h: $file has no $it")
        }
    }
}

android {
    namespace = "br.com.ebees.sentomaru.sample"
    compileSdk = 36

    defaultConfig {
        applicationId = when {
            raspLab -> "br.com.ebees.sentomaru.rasplab"
            d07e -> "br.com.ebees.sentomaru.pinlab"
            else -> "br.com.ebees.sentomaru.sample"
        }
        if (raspLab) testApplicationId = "br.com.ebees.sentomaru.rasplab.test"
        if (d07e) testApplicationId = "br.com.ebees.sentomaru.pinlab.test"
        minSdk = 28
        targetSdk = 36
        versionCode = 1
        versionName = "0.0.0-lab"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    if (d12hKey != null) {
        signingConfigs {
            create("d12hLab") {
                storeFile = file(d12hKey.getProperty("storeFile"))
                storeType = "PKCS12"
                keyAlias = d12hKey.getProperty("keyAlias")
                val secret = file(d12hKey.getProperty("passwordFile")).readText().trim()
                storePassword = secret
                keyPassword = secret
            }
        }
    }

    buildTypes {
        getByName("release") {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
        // J-04s2: the synthetic pilot's release build, only with -Psentomaru.j04sRelease=true (the default build, the CI
        // and the lockfile are unchanged). Not debuggable (no FLAG_DEBUGGABLE, so the debug_attached signal is the real
        // one), without R8 (the instrumented journey calls the SDK API the app itself does not use), unsigned here: the
        // runner signs the app and its test APK with the test keystore through apksigner (--ks-pass file:), never Gradle.
        if (j04sRelease) {
            create("j04sRelease") {
                initWith(getByName("release"))
                isDebuggable = false
                isMinifyEnabled = false
                isShrinkResources = false
                signingConfig = null
                matchingFallbacks += listOf("release")
            }
        }
        // D-05g-a: the RASP lab release, same shape as j04sRelease (not debuggable, so app_debuggable is NOT_DETECTED;
        // no R8; unsigned here, signed with the test keystore through apksigner --ks-pass file:, never Gradle). It adds
        // signals-rasp (root-manager <queries>) and its own instrumented test (src/androidTestRaspLab).
        if (raspLab) {
            create("raspLab") {
                initWith(getByName("release"))
                isDebuggable = false
                isMinifyEnabled = false
                isShrinkResources = false
                signingConfig = if (d12hKey != null) signingConfigs.getByName("d12hLab") else null
                matchingFallbacks += listOf("release")
            }
        }
        // D-08b: R8 release + the lab crash trigger and `-keepattributes SourceFile,LineNumberTable`. Debuggable stays
        // false (release default); signed with the debug key so `adb install` and `am start` work on the emulator.
        if (d08bRelease) {
            create("d08bRelease") {
                initWith(getByName("release"))
                signingConfig = signingConfigs.getByName("debug")
                proguardFiles("proguard-rules-d08b.pro")
                matchingFallbacks += listOf("release")
            }
        }
        // D-08e: the size/startup measurement's "without R8" variant, only with -Psentomaru.d08eNoR8=true: the release
        // build as is, minus R8 and resource shrinking (same sources, manifest and rules), so the AAB differs from
        // `release` only by R8. Built and measured by hand; never published.
        if (d08eNoR8) {
            create("d08eNoR8") {
                initWith(getByName("release"))
                isMinifyEnabled = false
                isShrinkResources = false
                matchingFallbacks += listOf("release")
            }
        }
        // D-14d: the R8 release (minify and resource shrink on, debuggable false), unsigned so the lab CLI seals it with
        // --sign none. The app itself gets the release rules only (the sealed reader must survive R8 as in a client
        // build); proguard-rules-d14d-test.pro applies to the androidTest APK only, and with d14dReadTest the app also
        // keeps the Kotlin runtime (proguard-rules-d14d-readtest.pro), which changes the app's R8 output (see there).
        if (d14dSealed) {
            create("d14dSealed") {
                initWith(getByName("release"))
                signingConfig = null
                testProguardFiles("proguard-rules-d14d-test.pro")
                if (d14dReadTest) proguardFiles("proguard-rules-d14d-readtest.pro")
                if (d14dLiveProbe) proguardFiles("proguard-rules-d14d-liveprobe.pro")
                matchingFallbacks += listOf("release")
            }
        }
        // D-07e: the release build as is, minus R8 and resource shrinking (the instrumented test calls SDK API the app
        // itself does not use), not debuggable, signed with the debug key (see the property above).
        if (d07e) {
            create("d07e") {
                initWith(getByName("release"))
                isDebuggable = false
                isMinifyEnabled = false
                isShrinkResources = false
                signingConfig = signingConfigs.getByName("debug")
                matchingFallbacks += listOf("release")
            }
        }
    }
    if (d07eCleartext) sourceSets.getByName("d07e").manifest.srcFile("src/d07eCleartext/AndroidManifest.xml")
    // The per-run canary assets live only under the ignored build directory; the generator writes them before the build
    // and never into a source tree, so no canary is ever tracked.
    if (d14dSealed) sourceSets.getByName("d14dSealed").assets.srcDir("build/d14d/assets")
    // The cold-start control's launch target (reads nothing; src/d14dStart), and the instrumented read-cost test built
    // against this R8 build (AGP applies the app's mapping to the test APK; both signed with the debug key).
    if (d14dSealed) sourceSets.getByName("d14dSealed").kotlin.directories.add("src/d14dStart/kotlin")
    if (d14dSealed) sourceSets.getByName("d14dSealed").manifest.srcFile("src/d14dStart/AndroidManifest.xml")
    if (d14dSealed) testBuildType = "d14dSealed"
    if (d08bRelease) sourceSets.getByName("d08bRelease").kotlin.directories.add("src/d08bCrash/kotlin")
    if (d08bRelease) sourceSets.getByName("d08bRelease").manifest.srcFile("src/d08bCrash/AndroidManifest.xml")
    if (d12h == "dexMarker") sourceSets.getByName("raspLab").kotlin.directories.add("src/d12hMarker/kotlin")
    // D-05g: the lab report's closed reason codes, shared by the instrumented test and its JVM test (testRaspLab).
    if (raspLab) listOf("androidTestRaspLab", "testRaspLab").forEach {
        sourceSets.getByName(it).kotlin.directories.add("src/raspLabShared/kotlin")
    }
    if (j04sRelease) testBuildType = "j04sRelease"
    if (raspLab) testBuildType = "raspLab"
    if (d07e) testBuildType = "d07e"

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    implementation(project(":sdk"))
    implementation(project(":signals"))
    // D-14b: the sealed asset reader (SealedAssetSample); no external dependency.
    implementation(project(":sealed"))
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    androidTestImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test:runner:1.7.0")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
    // D-05g-a: only in the raspLab build (the default build and its lockfile never see it); no external dependency.
    if (raspLab) add("raspLabImplementation", project(":signals-rasp"))
    if (raspLab) add("testRaspLabImplementation", "junit:junit:4.13.2")
}

// Direct runtime inventory BEFORE R8; does not claim every resolved component survives shrink.
tasks.named<CyclonedxDirectTask>("cyclonedxDirectBom") {
    includeConfigs = listOf("releaseRuntimeClasspath")
    includeMetadataResolution = false
    includeBuildSystem = false
    includeBomSerialNumber = false
    jsonOutput = layout.buildDirectory.file("reports/shield/sbom.json")
}
