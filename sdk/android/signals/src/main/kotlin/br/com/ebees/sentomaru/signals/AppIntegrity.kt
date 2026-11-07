package br.com.ebees.sentomaru.signals

/**
 * D-12c: who installed the app, as `InstallSourceInfo` (API 30+) gives it. null = no installer recorded. Never sent:
 * the `installer_class` detector reduces both names to a fixed class.
 */
data class InstallSource(val installingPackageName: String?, val initiatingPackageName: String?)

/** D-12c: one installed APK (base or split) and its size in bytes. */
data class ApkFile(val path: String, val size: Long)

/**
 * D-12c: the APKs the app runs from (`ApplicationInfo.sourceDir` first, then `splitSourceDirs` in order) and
 * `PackageInfo.lastUpdateTime`. It is also the key of the `code_integrity` cache: a new install, an update or another
 * split set changes it.
 */
data class InstalledApks(val lastUpdateTime: Long, val files: List<ApkFile>)
