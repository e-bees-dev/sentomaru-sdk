// D-20 device gate host: a minimal app that declares DETECT_SCREEN_CAPTURE / DETECT_SCREEN_RECORDING, installs the ScreenShield on one
// activity and logs what the screen_capture / screen_shared detectors read. Driven by verification/run_d20_device_gate.py. Never published.
plugins {
    id("com.android.application")
}

android {
    namespace = "br.com.ebees.sentomaru.screengate"
    compileSdk = 36

    defaultConfig {
        applicationId = "br.com.ebees.sentomaru.screengate"
        minSdk = 28
        targetSdk = 36
        versionCode = 1
        versionName = "0.0.1-gate"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    implementation(project(":signals"))
}
