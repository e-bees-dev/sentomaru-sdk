# D-08b lab-only extra rules, added ONLY to the d08bRelease build (-Psentomaru.d08bRelease=true). The default release
# build is unchanged (byte for byte); these rules never reach it, the CI lockfile or any published artifact.

# Mandatory in the lab examples (spec item 1): keep the source file and line numbers so the uncaught stack carries the
# R8 map id and `retrace` resolves file/line. The R8 map-id machinery writes the id into SourceFile when this is kept.
-keepattributes SourceFile,LineNumberTable

# The crash activity is kept (by name) through its manifest <activity>; we deliberately add NO member keep. R8 inlines
# the private helpers into onCreate, but with the line tables above kept, `retrace` reconstructs the inlined
# detonateLevel1/detonateLevel2 frames from the stack — that reconstruction is what the retrace proof checks.
