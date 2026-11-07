# Sentomaru Android SDK consumer Proguard/R8 rules.
# Packaged into the release AAR as proguard.txt and consumed automatically by client apps.

# Preserve public SDK API classes and methods
-keep class br.com.ebees.sentomaru.sdk.SentomaruClient { *; }
-keep class br.com.ebees.sentomaru.sdk.SentomaruConfig { *; }
-keep class br.com.ebees.sentomaru.sdk.EnrollmentChallenge { *; }
-keep class br.com.ebees.sentomaru.sdk.EnrollmentGrant { *; }
-keep class br.com.ebees.sentomaru.sdk.InstallationState { *; }
-keep class br.com.ebees.sentomaru.sdk.ReenrollmentReason { *; }
-keep class br.com.ebees.sentomaru.sdk.EnrollmentError** { *; }
-keep class br.com.ebees.sentomaru.sdk.IntegrityTokenSource { *; }
-keep class br.com.ebees.sentomaru.sdk.IntegrityRequestHash { *; }
-keep class br.com.ebees.sentomaru.sdk.PlayIntegrityTokenSource { *; }
-keep class br.com.ebees.sentomaru.sdk.transport.SentomaruInterceptor { *; }
-keep class br.com.ebees.sentomaru.sdk.transport.SentomaruOperation { *; }
-keep class br.com.ebees.sentomaru.sdk.transport.SentomaruTransportKt { *; }
# G-03c: `sentomaru protect` (network-signing) looks for this class by name in the app's DEX; keep the name, not the class.
-keepnames class br.com.ebees.sentomaru.sdk.transport.SentomaruRoutes
# S2: the HttpURLConnection transport. Name only: R8 still drops it from an app that never calls it, so in a minified app
# `sentomaru protect` (network-signing) finds it only when the app links the call.
-keepnames class br.com.ebees.sentomaru.sdk.transport.SentomaruUrlConnection

# Preserve RFC 9421 core profile and typed error hierarchy
-keep class br.com.ebees.sentomaru.core.SentomaruError** { *; }
-keep class br.com.ebees.sentomaru.core.SentomaruException { *; }
-keep class br.com.ebees.sentomaru.core.SignedMessage { *; }
-keep class br.com.ebees.sentomaru.core.FrozenRequest { *; }
-keep class br.com.ebees.sentomaru.core.Profile { *; }
