# Sentomaru sealed asset reader consumer Proguard/R8 rules (D-14b).
# Packaged into the release AAR as proguard.txt and consumed automatically by client apps.

# The public API, kept whole. `sentomaru protect` (asset-encryption) looks for SentomaruSealed by name in the app's DEX
# (`sealed-reader-missing` without it); with -keep it exists in every app that links this module, which proves only that
# the reader is linked, not that the app calls it (contracts/devsecops/cli-v1.md, asset-encryption).
-keep class br.com.ebees.sentomaru.sdk.sealed.SentomaruSealed { *; }
-keep class br.com.ebees.sentomaru.sdk.sealed.SentomaruSealedException { *; }
-keep class br.com.ebees.sentomaru.sdk.sealed.SentomaruSealedException$Code { *; }
