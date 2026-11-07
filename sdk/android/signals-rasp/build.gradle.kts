// D-05 opt-in: only the <queries> of the root-manager packages (root_artifacts) and a marker class. An app that does
// not depend on this artifact keeps its merged manifest unchanged; root_artifacts then reports root_package as not
// run (partial), never as "not installed".
plugins {
    id("com.android.library")
    `maven-publish`
}

android {
    namespace = "br.com.ebees.sentomaru.signals.rasp"
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
            test.systemProperty("sentomaru.signalsManifest", file("src/main/AndroidManifest.xml").absolutePath)
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
    testImplementation(project(":signals"))
    testImplementation("junit:junit:4.13.2")
}

afterEvaluate {
    publishing {
        publications {
            create<MavenPublication>("release") {
                from(components["release"])
                artifactId = "signals-rasp"
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
