plugins {
    id("com.android.application")
    id("kotlin-android")
    // The Flutter Gradle Plugin must be applied after the Android and Kotlin Gradle plugins.
    id("dev.flutter.flutter-gradle-plugin")
}

android {
    namespace = "br.com.ebees.sentomaru.sentomaru_flutter_sample"
    compileSdk = flutter.compileSdkVersion
    ndkVersion = flutter.ndkVersion

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = JavaVersion.VERSION_17.toString()
    }

    defaultConfig {
        // TODO: Specify your own unique Application ID (https://developer.android.com/studio/build/application-id.html).
        applicationId = "br.com.ebees.sentomaru.sentomaru_flutter_sample"
        // You can update the following values to match your application needs.
        // For more information, see: https://flutter.dev/to/review-gradle-config.
        minSdk = 28 // Sentomaru SDK requires API 28 (KeyGenParameterSpec/StrongBox); never lower it
        targetSdk = flutter.targetSdkVersion
        versionCode = flutter.versionCode
        versionName = flutter.versionName
        // Real-plugin device tests (integration_test/) run through AndroidJUnitRunner via `am instrument`.
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            // TODO: Add your own signing config for the release build.
            // Signing with the debug keys for now, so `flutter run --release` works.
            signingConfig = signingConfigs.getByName("debug")
        }
    }
}

// D-07e: only the lab build adds the INTERNET permission to release (src/d07e); without the
// property the build is the template's.
if ((findProperty("sentomaru.d07e") as String?)?.toBoolean() == true) {
    android.sourceSets.getByName("release").manifest.srcFile("src/d07e/AndroidManifest.xml")
}

flutter {
    source = "../.."
}

dependencies {
    // Versions pinned by the integration_test plugin's own runtime classpath (consistent resolution).
    androidTestImplementation("androidx.test:runner:1.2.0")
    androidTestImplementation("androidx.test:rules:1.2.0")
}
