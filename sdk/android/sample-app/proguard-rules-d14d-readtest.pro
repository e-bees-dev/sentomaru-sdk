# D-14d, lab only (-Psentomaru.d14dReadTest=true, with d14dSealed): the read-cost build of the app keeps the Kotlin
# runtime, because the androidTest APK built against an R8 app does not carry the libraries the app already has, and
# androidx.test 1.7 (Kotlin) needs classes the app's own R8 run removes (kotlin.jvm.internal.Lambda, ...).
# This is NOT the R8 output of a client build: keeping kotlin.** stops R8 from removing, merging and inlining the Kotlin
# runtime the reader calls (intrinsics, collections), so the reader runs with real calls where a client build may have
# inlined them, and the APK is larger (sample: 6,074,427 B sealed universal APK vs 5,545,642 B without this rule).
# The probable bias of the read cost is upward (probably slightly slower). Never used for the size or cold-start APKs.
-keep class kotlin.** { *; }
-dontwarn kotlin.**
