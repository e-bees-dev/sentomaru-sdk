plugins {
    id("com.android.library")
    `maven-publish`
}

android {
    namespace = "br.com.ebees.sentomaru.signals"
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
        // SignalsCatalogContractTest compares the SDK catalog with the contract catalog.
        unitTests.all { test ->
            val catalog = rootProject.file("../../contracts/sdk/signals-catalog-v1.json")
            test.inputs.file(catalog)
            test.systemProperty("sentomaru.signalsCatalog", catalog.absolutePath)
            // Shield #2: SignalsManifestTest reads the library manifest (no permission may be declared).
            test.systemProperty("sentomaru.signalsLibraryManifest", file("src/main/AndroidManifest.xml").absolutePath)
            // D-24d: the signed malware list is checked against the shared vectors (the server verifies the same file).
            val malware = rootProject.file("../../contracts/sdk/malware-list-v1-vectors.json")
            test.inputs.file(malware)
            test.systemProperty("sentomaru.malwareListVectors", malware.absolutePath)
            // D-22c: the shared vectors of the hybrid bridge (C# and the bridge core read the same file).
            val bridge = rootProject.file("../../contracts/sdk/hybrid-bridge-v1-vectors.json")
            test.inputs.file(bridge)
            test.systemProperty("sentomaru.hybridBridgeVectors", bridge.absolutePath)
            // D-12c: the code_integrity hash is checked against the shared D-12a vectors.
            val vectors = rootProject.file("../../contracts/shield/code-digests-v1-vectors.json")
            test.inputs.file(vectors)
            test.systemProperty("sentomaru.codeDigestVectors", vectors.absolutePath)
        }
    }

    // D-05: no hidden API (no reflection into the platform, no SystemProperties).
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
                artifactId = "signals"
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
