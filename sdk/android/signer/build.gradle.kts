plugins {
    id("com.android.library")
    `maven-publish`
}

android {
    namespace = "br.com.ebees.sentomaru.signer"
    compileSdk = 36

    defaultConfig {
        // 28: KeyGenParameterSpec.Builder.setIsStrongBoxBacked and StrongBoxUnavailableException.
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
    testImplementation("junit:junit:4.13.2")
}

afterEvaluate {
    publishing {
        publications {
            create<MavenPublication>("release") {
                from(components["release"])
                artifactId = "signer"
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
