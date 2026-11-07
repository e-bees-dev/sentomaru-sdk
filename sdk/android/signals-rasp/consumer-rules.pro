# Sentomaru Signals RASP consumer Proguard/R8 rules.

# root_artifacts looks the marker up by name (Class.forName): R8 must keep it, or the opt-in is lost.
-keep class br.com.ebees.sentomaru.signals.rasp.RootManagerQueries
