# sentomaru_flutter consumer R8 rules, applied to the host app.
# G-03c: `sentomaru protect` (control network-signing) looks for this class by name in the app's DEX; keep the name.
-keepnames class br.com.ebees.sentomaru.sentomaru_flutter.SentomaruFlutterPlugin
# D-14b: `sentomaru protect` (control asset-encryption) looks for the plugin's sealed reader by this class name.
-keepnames class br.com.ebees.sentomaru.sentomaru_flutter.SentomaruFlutterSealed
