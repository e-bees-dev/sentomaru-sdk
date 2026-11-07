# Sentomaru Signals consumer Proguard/R8 rules.

# Preserve signals models and collectors
-keep class br.com.ebees.sentomaru.signals.SignalsCollector { *; }
-keep class br.com.ebees.sentomaru.signals.SignalsCatalog { *; }
-keep class br.com.ebees.sentomaru.signals.SignalObservation { *; }
-keep class br.com.ebees.sentomaru.signals.SignalState { *; }
-keep class br.com.ebees.sentomaru.signals.SignalsSnapshot { *; }
-keep class br.com.ebees.sentomaru.signals.CapabilityDefinition { *; }
# D-24b: the app calls onTouch from its marked screens
-keep class br.com.ebees.sentomaru.signals.ObscuredTouchMonitor { *; }
# D-15a: signal events (opt-in)
-keep class br.com.ebees.sentomaru.signals.SentomaruSignalEvent { *; }
-keep class br.com.ebees.sentomaru.signals.SentomaruSignalEvent$Kind { *; }
-keep class br.com.ebees.sentomaru.signals.SentomaruSignalEvents { *; }
-keep interface br.com.ebees.sentomaru.signals.SentomaruSignalEventListener { *; }
# D-07d: local transport events (pin_failure)
-keep class br.com.ebees.sentomaru.signals.SentomaruTransportEvent { *; }
-keep class br.com.ebees.sentomaru.signals.SentomaruTransportEvent$Kind { *; }
-keep interface br.com.ebees.sentomaru.signals.SentomaruTransportListener { *; }
-keep class br.com.ebees.sentomaru.signals.TransportEventCodes { *; }
# D-24d: the app loads the signed malware list into the store
-keep class br.com.ebees.sentomaru.signals.MalwareList { *; }
-keep class br.com.ebees.sentomaru.signals.MalwareListStore { *; }
-keep class br.com.ebees.sentomaru.signals.MalwareListException { *; }
# D-20: the app installs the screen shield and reads the capture monitor
-keep class br.com.ebees.sentomaru.signals.ScreenShield { *; }
# D-22c: Unity (AndroidJavaClass) and .NET for Android reach the shield by name, through plain types
-keep class br.com.ebees.sentomaru.signals.ScreenShieldHost { *; }
-keep class br.com.ebees.sentomaru.signals.CaptureScope { *; }
-keep class br.com.ebees.sentomaru.signals.ScreenCaptureMonitor { *; }
