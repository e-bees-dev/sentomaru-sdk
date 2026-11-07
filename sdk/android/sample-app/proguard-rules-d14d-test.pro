# D-14d, lab only: R8 rules of the androidTest APK built against the d14dSealed R8 build (testBuildType). The app's
# own rules are untouched; these only keep the instrumented read-cost test and its runner reachable by name.
-dontwarn com.google.errorprone.annotations.**
-keep class br.com.ebees.sentomaru.d14d.** { *; }
-keep class org.junit.** { *; }
-keep class androidx.test.** { *; }
-keepattributes *Annotation*,Signature,InnerClasses,EnclosingMethod
