// Lab-only host for instrumented tests of :signer. Not a product app.
plugins {
    id("com.android.application")
}

android {
    namespace = "br.com.ebees.sentomaru.lab"
    compileSdk = 36

    defaultConfig {
        applicationId = "br.com.ebees.sentomaru.lab"
        minSdk = 28
        targetSdk = 36
        versionCode = 1
        versionName = "0.0.0-lab"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    implementation(project(":signer"))
    implementation(project(":sdk"))
    androidTestImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test:runner:1.7.0")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
}
