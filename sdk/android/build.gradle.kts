// Android Gradle Plugin 9.4.1 (built-in Kotlin; KGP pinned to 2.2.10, the version AGP 9.4.1 declares).
buildscript {
    dependencies {
        classpath("org.jetbrains.kotlin:kotlin-gradle-plugin:2.2.10")
    }
}

plugins {
    id("org.cyclonedx.bom") version "3.5.1" apply false
    id("com.android.library") version "9.4.1" apply false
    id("com.android.application") version "9.4.1" apply false
}

// P2 Task 0: reproducible dependency resolution. Every configuration is locked (gradle.lockfile per module);
// refresh deliberately with `./gradlew dependencies --write-locks`. Checksums live in gradle/verification-metadata.xml.
allprojects {
    group = "br.com.ebees.sentomaru"
    // G-04: the SDK version has ONE source, gradle.properties (sentomaru.sdkVersion); the Flutter plugin's Gradle file and
    // the Maven/plugin packaging (tools/devsecops/package_sdk.py) are checked against it by verification/devsecops.
    version = property("sentomaru.sdkVersion") as String

    dependencyLocking {
        lockAllConfigurations()
    }
}

// Warnings are errors for Kotlin in every module (pure JVM and Android built-in Kotlin).
subprojects {
    tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile>().configureEach {
        compilerOptions.allWarningsAsErrors.set(true)
    }
}

// G-04 (docs/devsecops/adr-0004-sdk-registry.md): OPT-IN remote Maven repository. Inert by default: without
// -Psentomaru.publish.url (or env SENTOMARU_PUBLISH_URL) no repository is added and the task graph is exactly the
// one-repo (localRepo) graph that existed before. Credentials only from the environment, never from a file or a default:
// SENTOMARU_PUBLISH_USER / SENTOMARU_PUBLISH_TOKEN. Accepts https:// (a registry) or file: (a local layout for tests).
// Nothing here publishes anything: `publish*ToRegistryRepository` must be run by someone on purpose.
val registryUrl: String? = (findProperty("sentomaru.publish.url") as String?)?.takeIf { it.isNotBlank() }
    ?: System.getenv("SENTOMARU_PUBLISH_URL")?.takeIf { it.isNotBlank() }
if (registryUrl != null) {
    require(registryUrl.startsWith("https://") || registryUrl.startsWith("file:")) {
        "sentomaru.publish.url must be https:// or file: (got a different scheme)"
    }
    subprojects {
        plugins.withId("maven-publish") {
            extensions.configure<PublishingExtension> {
                repositories {
                    maven {
                        name = "registry"
                        url = uri(registryUrl)
                        if (registryUrl.startsWith("https://")) {
                            credentials {
                                username = System.getenv("SENTOMARU_PUBLISH_USER")
                                password = System.getenv("SENTOMARU_PUBLISH_TOKEN")
                            }
                        }
                    }
                }
            }
        }
    }
}
