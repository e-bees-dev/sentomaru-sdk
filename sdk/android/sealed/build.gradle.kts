// D-14b: reader of the sealed asset format v1 (contracts/devsecops/cli-v1.md, asset-encryption). No network, no
// permission, no dependency: AES-256-GCM, HMAC-SHA256 and DEFLATE from the platform (javax.crypto, java.util.zip),
// HKDF written over the HMAC (D-14x9). Nothing runs at startup: no ContentProvider, no manifest entry.
plugins {
    id("com.android.library")
    `maven-publish`
}

android {
    namespace = "br.com.ebees.sentomaru.sdk.sealed"
    compileSdk = 36

    defaultConfig {
        minSdk = 28
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    testOptions {
        unitTests.isReturnDefaultValues = true
        unitTests.all { test ->
            // The shared D-14a vectors (every positive and negative case, the RFC 5869 cases) and the plain asset of
            // the sample-app, read the way an unsealed debug build reads it (D-14x10).
            val vectors = rootProject.file("../../contracts/devsecops/sealed-v1-vectors.json")
            test.inputs.file(vectors)
            test.systemProperty("sentomaru.sealedVectors", vectors.absolutePath)
            val sampleAssets = rootProject.file("sample-app/src/main/assets")
            test.inputs.dir(sampleAssets)
            test.systemProperty("sentomaru.sampleAssets", sampleAssets.absolutePath)
        }
    }

    lint {
        error += setOf("PrivateApi", "DiscouragedPrivateApi")
        abortOnError = true
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
                artifactId = "sealed"
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
