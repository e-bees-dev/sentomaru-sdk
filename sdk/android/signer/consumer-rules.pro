# Sentomaru Signer consumer Proguard/R8 rules.

-keep class br.com.ebees.sentomaru.signer.KeystoreSigner { *; }
-keep class br.com.ebees.sentomaru.signer.GenerationResult** { *; }
-keep class br.com.ebees.sentomaru.signer.StrongBoxUnavailableError { *; }
-keep class br.com.ebees.sentomaru.signer.EcdsaSignatureFormat { *; }
