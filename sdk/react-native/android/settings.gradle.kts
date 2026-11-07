pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
rootProject.name = "sentomaru-react-native"
// standalone build, like the Flutter plugin. The native SDK comes from the local Maven repository built from
// sdk/android (see build.gradle.kts); the bridge core is compiled from sdk/hybrid-core.
