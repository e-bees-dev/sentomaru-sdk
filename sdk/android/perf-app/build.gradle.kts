// J-03 lab app: measures the §14 goals (journey latency, cold start, memory) on a device; D-05c measures the cost of
// the signals detectors here too (RaspCostInstrumentedTest, verification/run_d05c_cost.py), and D-05d-2 the emulator
// rows of the RASP matrix (RaspMatrixInstrumentedTest, verification/run_d05d_emulator.py). Never published.
import java.util.Random

plugins {
    id("com.android.application")
}

android {
    namespace = "br.com.ebees.sentomaru.perf"
    compileSdk = 36

    defaultConfig {
        applicationId = "br.com.ebees.sentomaru.perf"
        minSdk = 28
        targetSdk = 36
        versionCode = 1
        versionName = "0.0.0-lab"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    // D-05d-2: the release row of `app_debuggable` (verification/run_d05d_emulator.py), only with
    // -Psentomaru.d05dRelease=true (the default build, the CI and the lockfile are unchanged). Not debuggable (no
    // FLAG_DEBUGGABLE), without R8 (the instrumented test calls the SDK directly), signed with the debug keystore so the
    // test APK can instrument it: a lab build, never published.
    buildTypes {
        if (providers.gradleProperty("sentomaru.d05dRelease").orNull == "true") {
            create("d05dRelease") {
                initWith(getByName("release"))
                isDebuggable = false
                isMinifyEnabled = false
                signingConfig = signingConfigs.getByName("debug")
                matchingFallbacks += listOf("release")
            }
        }
    }
    if (providers.gradleProperty("sentomaru.d05dRelease").orNull == "true") testBuildType = "d05dRelease"

    // D-08e: the startup measurement's pair, only with -Psentomaru.d08eVariants=true (the
    // default build, the CI and the lockfile are unchanged): the release build without R8 (`d08eNoR8`) and with R8 and
    // resource shrinking (`d08eR8`, the SDK's consumer rules, no app rule: the activities are kept by the manifest), both
    // signed with the debug keystore so they install on the emulator. They differ only by R8. Never published.
    if (providers.gradleProperty("sentomaru.d08eVariants").orNull == "true") {
        if (providers.gradleProperty("sentomaru.d05dRelease").orNull == "true")
            throw GradleException("sentomaru.d08eVariants is a separate build")
        buildTypes {
            create("d08eNoR8") {
                initWith(getByName("release"))
                isMinifyEnabled = false
                isShrinkResources = false
                signingConfig = signingConfigs.getByName("debug")
                matchingFallbacks += listOf("release")
            }
            create("d08eR8") {
                initWith(getByName("release"))
                isMinifyEnabled = true
                isShrinkResources = true
                proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"))
                signingConfig = signingConfigs.getByName("debug")
                matchingFallbacks += listOf("release")
            }
        }
    }

    // D-12d (verification/run_d12d_cost.py): `code_integrity` hashes every root classes*.dex and lib/<abi>/*.so, and
    // this app has far less code than the ExampleApp. Only with -Psentomaru.d12dFillerMiB=<n> (with d05dRelease), the
    // d05dRelease APK carries <n> MiB of deterministic pseudo-random filler as lib/<abi>/libd12dfiller<i>.so (stored,
    // never loaded, never stripped), so the hash reads as many bytes as the ExampleApp's. The default build, the CI and the
    // lockfile are unchanged.
    val d12dFillerMiB = providers.gradleProperty("sentomaru.d12dFillerMiB").orNull?.toInt()
    if (d12dFillerMiB != null) {
        require(d12dFillerMiB in 1..512) { "sentomaru.d12dFillerMiB must be 1..512" }
        require(providers.gradleProperty("sentomaru.d05dRelease").orNull == "true") { "d12dFillerMiB needs d05dRelease" }
        val fillerDir = layout.buildDirectory.dir("generated/d12dFiller/jniLibs").get().asFile
        fillerDir.deleteRecursively()
        // Split like a fat Flutter APK: the bytes spread over the three ABIs, at most 16 MiB per file.
        val abis = listOf("arm64-v8a", "armeabi-v7a", "x86_64")
        var left = d12dFillerMiB.toLong() * 1024 * 1024
        var index = 0
        val random = Random(0x0D12DL)
        while (left > 0) {
            val size = minOf(left, 16L * 1024 * 1024)
            val file = File(fillerDir, "${abis[index % abis.size]}/libd12dfiller$index.so")
            file.parentFile.mkdirs()
            file.outputStream().buffered().use { out ->
                val chunk = ByteArray(64 * 1024)
                var written = 0L
                while (written < size) {
                    random.nextBytes(chunk)
                    val n = minOf(chunk.size.toLong(), size - written).toInt()
                    out.write(chunk, 0, n)
                    written += n
                }
            }
            left -= size
            index++
        }
        sourceSets.getByName("d05dRelease").jniLibs.directories.add(fillerDir.path)
        packaging.jniLibs.keepDebugSymbols += "**/libd12dfiller*.so"
        packaging.jniLibs.useLegacyPackaging = false
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    implementation(project(":sdk"))
    // D-05c measures the opted-in RASP set, root-manager <queries> included.
    implementation(project(":signals-rasp"))
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    androidTestImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test:runner:1.7.0")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
}
