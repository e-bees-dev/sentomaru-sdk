// G-03b2 device gate: a minimal app WITHOUT the Sentomaru SDK, protected after the build by `sentomaru protect`
// (laboratory injection) and installed on an emulator by verification/run_g03b2_device_gate.py. Never published.
plugins {
    id("com.android.application")
}

android {
    namespace = "br.com.ebees.sentomaru.gate"
    compileSdk = 36

    defaultConfig {
        applicationId = "br.com.ebees.sentomaru.gate"
        minSdk = 28
        targetSdk = 36
        versionCode = 1
        versionName = "0.0.1-gate"
    }

    buildTypes {
        getByName("release") {
            // The gate checks what the CLI adds, not R8: no shrinking, the app stays as small as written.
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}
