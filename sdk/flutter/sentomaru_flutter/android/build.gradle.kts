group = "br.com.ebees.sentomaru.sentomaru_flutter"
version = "1.0-SNAPSHOT"

// Verified combination (R4): host app AGP 8.11.1 + KGP 2.2.20 (Flutter 3.41 template, same as the ExampleApp) builds this
// plugin and consumes the SDK AARs that sdk/android builds with AGP 9.4.1 / KGP 2.2.10. The buildscript pins below
// only apply to a standalone build of the plugin; inside a host app the host's AGP/KGP win.
buildscript {
    val kotlinVersion = "2.2.20"
    repositories {
        google()
        mavenCentral()
    }

    dependencies {
        classpath("com.android.tools.build:gradle:8.11.1")
        classpath("org.jetbrains.kotlin:kotlin-gradle-plugin:$kotlinVersion")
    }
}

// R5: the native SDK is NOT shipped as committed binaries. It is built from source and published to a local Maven
// repository, which this plugin consumes:
//   cd <Sentomaru>/sdk/android && ./gradlew publishAllPublicationsToLocalRepoRepository   (-> sdk/android/build/repo)
//   (a consumer without the Sentomaru source extracts the published Maven zip instead: verify_sdk.py --dest <new dir>
//   verifies it and extracts <dir>/maven, the SDK distribution notes)
// Location override: Gradle property `sentomaru.sdkRepo` or env SENTOMARU_SDK_REPO (absolute path).
val sentomaruSdkVersion = "0.2.0-rc.5"
val sentomaruSdkRepo: File = run {
    val override = (findProperty("sentomaru.sdkRepo") as String?) ?: System.getenv("SENTOMARU_SDK_REPO")
    val dir = override?.let { File(it) } ?: File(projectDir, "../../../android/build/repo")
    val marker = File(dir, "br/com/ebees/sentomaru/sdk/$sentomaruSdkVersion/sdk-$sentomaruSdkVersion.aar")
    if (!marker.isFile) {
        throw GradleException(
            "Sentomaru SDK $sentomaruSdkVersion not found in ${dir.canonicalPath}. Build it from source first: " +
                "cd <Sentomaru>/sdk/android && ./gradlew publishAllPublicationsToLocalRepoRepository " +
                "(or set -Psentomaru.sdkRepo / SENTOMARU_SDK_REPO to a repository built that way, or to the maven/ folder " +
                "that verify_sdk.py extracts from the published sentomaru-sdk-maven-$sentomaruSdkVersion.zip)."
        )
    }
    dir.canonicalFile
}

// The host app resolves this plugin's transitive dependencies with its own repositories, so the local repository is
// added to every project, restricted to the Sentomaru group (exclusiveContent: that group never comes from
// Google/Maven Central, and the local repo serves nothing else). Hosts using FAIL_ON_PROJECT_REPOS must declare the
// same repository in their settings instead.
rootProject.allprojects {
    repositories {
        exclusiveContent {
            forRepository { maven { url = uri(sentomaruSdkRepo) } }
            filter { includeGroup("br.com.ebees.sentomaru") }
        }
        google()
        mavenCentral()
    }
}

plugins {
    id("com.android.library")
    id("kotlin-android")
}

android {
    namespace = "br.com.ebees.sentomaru.sentomaru_flutter"

    compileSdk = 36

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    sourceSets {
        getByName("main") {
            java.srcDirs("src/main/kotlin", "../../../hybrid-core/src/main/kotlin") // D-22a1: the bridge core shared with the hybrid layers
        }
        getByName("test") {
            java.srcDirs("src/test/kotlin")
        }
    }

    defaultConfig {
        // Same floor as the SDK AARs (SDK-REL-3). A host below 28 fails at manifest merge instead of crashing at
        // runtime on API 24-27; there is no tools:overrideLibrary.
        minSdk = 28
        // G-03c: `sentomaru protect` (network-signing) finds the plugin by class name in the app's DEX.
        consumerProguardFiles("consumer-rules.pro")
    }

    testOptions {
        unitTests.isReturnDefaultValues = true
        // D-14b: the shared sealed vectors (the Flutter case's pubspec key -> canonical path).
        unitTests.all { test ->
            val vectors = File(projectDir, "../../../../contracts/devsecops/sealed-v1-vectors.json")
            test.inputs.file(vectors)
            test.systemProperty("sentomaru.sealedVectors", vectors.canonicalPath)
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

dependencies {
    implementation("br.com.ebees.sentomaru:sdk:$sentomaruSdkVersion")
    implementation("br.com.ebees.sentomaru:signals:$sentomaruSdkVersion")
    implementation("br.com.ebees.sentomaru:core:$sentomaruSdkVersion")
    // D-14b: the sealed asset reader behind SentomaruSealed.load/string (no cryptography in Dart).
    implementation("br.com.ebees.sentomaru:sealed:$sentomaruSdkVersion")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    // D-25: the system prompt of the transaction key (BiometricPrompt + CryptoObject). FragmentActivity comes with it.
    implementation("androidx.biometric:biometric:1.1.0")
    testImplementation("junit:junit:4.13.2")
    testImplementation("com.squareup.okhttp3:mockwebserver:4.12.0")
    testImplementation("com.squareup.okhttp3:okhttp-tls:4.12.0")
    testImplementation("org.json:json:20240303")
}
