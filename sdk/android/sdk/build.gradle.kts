plugins {
    id("com.android.library")
    `maven-publish`
}

android {
    namespace = "br.com.ebees.sentomaru.sdk"
    compileSdk = 36

    defaultConfig {
        minSdk = 28
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    publishing {
        singleVariant("release")
    }
}

dependencies {
    api(project(":core"))
    api(project(":signals"))
    implementation(project(":signer"))
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    // C-04b: Play Integrity standard request (advisory token at enrollment).
    implementation("com.google.android.play:integrity:1.6.0")
    testImplementation("junit:junit:4.13.2")
    testImplementation("com.squareup.okhttp3:mockwebserver:4.12.0")
}

afterEvaluate {
    publishing {
        publications {
            create<MavenPublication>("release") {
                from(components["release"])
                artifactId = "sdk"
            }
        }
        repositories {
            maven {
                name = "localRepo"
                url = uri(rootProject.layout.buildDirectory.dir("repo"))
            }
        }
    }
}
