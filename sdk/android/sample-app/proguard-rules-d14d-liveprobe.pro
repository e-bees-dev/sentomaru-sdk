# D-14d, lab only (-Psentomaru.d14dLiveProbe=true, with d14dReadTest): the precise live-peak build keeps the sealed
# reader's classes by name, so SealedLivePeakProbe (androidTest) can wire the production SealedReader through its seams
# (AssetSource, AeadOpen.GCM, Inflate.RAW) with checkpoints. Keeping them stops R8 from inlining or merging the reader;
# the bytes the reader allocates and holds (what this build measures) do not depend on that. Never used for the size,
# cold-start or read-time APKs.
-keep class br.com.ebees.sentomaru.sdk.sealed.** { *; }
