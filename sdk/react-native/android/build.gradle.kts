// React Native layer over the Android SDK. No logic of its own: every call goes to the shared bridge core
// (sdk/hybrid-core) with the arguments of contracts/sdk/hybrid-bridge-v1.json. Build and test:
//   cd <Sentomaru>/sdk/android && ./gradlew publishAllPublicationsToLocalRepoRepository
//   cd <Sentomaru>/sdk/react-native/android && <gradle 8.14> testDebugUnitTest
// AGP 8.11.1 does not run on the Gradle 9 of sdk/android; use the 8.14 wrapper that `flutter build apk` generates in
// sdk/flutter/sentomaru_flutter/sample/android (the plugin's own host build).
plugins {
    id("com.android.library") version "8.11.1"
    id("org.jetbrains.kotlin.android") version "2.2.20"
}

// Same single source as the Flutter plugin (the vendor's test sdk registry check keeps them equal).
val sentomaruSdkVersion = "0.2.0-rc.5"
val sentomaruSdkRepo: File = run {
    val override = (findProperty("sentomaru.sdkRepo") as String?) ?: System.getenv("SENTOMARU_SDK_REPO")
    val dir = override?.let { File(it) } ?: File(projectDir, "../../android/build/repo")
    val marker = File(dir, "br/com/ebees/sentomaru/sdk/$sentomaruSdkVersion/sdk-$sentomaruSdkVersion.aar")
    if (!marker.isFile) {
        throw GradleException(
            "Sentomaru SDK $sentomaruSdkVersion not found in ${dir.canonicalPath}. Build it first: " +
                "cd <Sentomaru>/sdk/android && ./gradlew publishAllPublicationsToLocalRepoRepository " +
                "(or set -Psentomaru.sdkRepo / SENTOMARU_SDK_REPO)."
        )
    }
    dir.canonicalFile
}

repositories {
    exclusiveContent {
        forRepository { maven { url = uri(sentomaruSdkRepo) } }
        filter { includeGroup("br.com.ebees.sentomaru") }
    }
    google()
    mavenCentral()
}


// the new architecture (TurboModule) is chosen the way React Native libraries do: -PnewArchEnabled=true (the
// app's gradle.properties). Then the codegen plugin makes `NativeSentomaruSpec` from src/NativeSentomaru.ts; otherwise
// the hand-written class in src/oldarch is compiled. The plugin exists only inside an app build, so this standalone
// build (tests) is always the old-architecture shape.
val newArchEnabled = (findProperty("newArchEnabled") as String?) == "true"
if (newArchEnabled) apply(plugin = "com.facebook.react")

android {
    namespace = "br.com.ebees.sentomaru.reactnative"
    compileSdk = 36
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    sourceSets {
        getByName("main") {
            java.srcDirs("src/main/kotlin", "../../hybrid-core/src/main/kotlin")
            if (!newArchEnabled) java.srcDir("src/oldarch/kotlin")
        }
        getByName("test") {
            java.srcDirs("src/test/kotlin")
        }
    }
    buildFeatures { buildConfig = true }
    defaultConfig {
        minSdk = 28 // same floor as the SDK AARs
        buildConfigField("boolean", "IS_NEW_ARCHITECTURE_ENABLED", newArchEnabled.toString())
    }
    testOptions {
        unitTests.isReturnDefaultValues = true
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
    // D-14b: the sealed asset reader behind `sealedConfigure`/`sealedLoad`/`sealedString` (SentomaruBridge.SealedReader).
    implementation("br.com.ebees.sentomaru:sealed:$sentomaruSdkVersion")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    // The app provides React Native; compile against the same line the TS layer supports.
    compileOnly("com.facebook.react:react-android:0.76.5")
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20240303")
}
