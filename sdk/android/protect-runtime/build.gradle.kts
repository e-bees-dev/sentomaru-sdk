import java.security.MessageDigest

// G-03b2: the runtime `sentomaru protect` injects into the app (contracts/devsecops/cli-v1.md, runtime-injection).
// Plain Java against the platform android.jar, no dependency at all: nothing to relocate and nothing that can clash
// with the app's own classes. :protect turns this jar into a DEX with d8 and embeds it (one DEX per CLI version).
plugins {
    `java-library`
}

java {
    toolchain { languageVersion.set(JavaLanguageVersion.of(17)) }
}

tasks.withType<JavaCompile>().configureEach {
    options.release.set(11)
    options.compilerArgs.addAll(listOf("-Xlint:all", "-Werror"))
}

// The pinned platform android.jar (gradle.properties sentomaru.android*), checked by SHA-256 when first used.
val pinnedAndroidJar = provider {
    val home = System.getenv("ANDROID_HOME") ?: System.getenv("ANDROID_SDK_ROOT") ?: ""
    val platform = providers.gradleProperty("sentomaru.androidPlatform").get()
    val expected = providers.gradleProperty("sentomaru.androidJarSha256").get()
    val jar = file(home).resolve("platforms/$platform/android.jar")
    if (!jar.isFile) throw GradleException("$platform/android.jar not found under ANDROID_HOME (sdkmanager \"platforms;$platform\")")
    val actual = MessageDigest.getInstance("SHA-256").digest(jar.readBytes()).joinToString("") { "%02x".format(it) }
    if (actual != expected) throw GradleException("$platform/android.jar sha256 $actual, pinned $expected (revision " +
        providers.gradleProperty("sentomaru.androidPlatformRevision").get() + ")")
    jar
}

dependencies {
    // compileOnly: the device provides the framework. ANDROID_HOME is required (as for :protect's tests).
    compileOnly(files(pinnedAndroidJar))
    // Bootstrap has no Android type, so its never-throw rules are tested on the JVM.
    testImplementation("junit:junit:4.13.2")
}
