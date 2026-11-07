// Sentomaru P0b — Android lab build. All plugin/dependency versions pinned exactly.
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "sentomaru-android"
include(":core", ":signer", ":sdk", ":signals", ":signals-rasp", ":sealed", ":sample-app", ":perf-app", ":app-lab", ":protect", ":protect-gate-app", ":protect-runtime", ":screen-gate-app")
