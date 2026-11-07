# Lab sample only (S2): keep the Java HttpURLConnection sample as an entry point so R8 keeps what it calls. The SDK
# class names `sentomaru protect` looks for are kept by the SDK's own consumer rules, not here.
-keep class br.com.ebees.sentomaru.sample.JavaUrlConnectionSample { *; }
# D-14b: the sealed asset sample is an entry point too, so the minified build reads through SentomaruSealed the way an
# app does. The reader's own name is kept by the sealed module's consumer rules, not here.
-keep class br.com.ebees.sentomaru.sample.SealedAssetSample { *; }
