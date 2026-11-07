import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:sentomaru_flutter/sentomaru_flutter.dart';

/// D-14b, lab only: how a Flutter app reads the assets `sentomaru protect` (asset-encryption) seals. The profile marks
/// `assets/flutter_assets/assets/d14b/catalogo.json` and the strings file
/// `assets/flutter_assets/assets/d14b/sentomaru-strings.json`; the app calls the plugin with the `pubspec.yaml` keys
/// instead of `rootBundle`. Without the CLI the plain fallback is on, and only in debug (D-14x10): a release build that
/// was not sealed fails with `not-sealed`. The proof on a device is D-14d.
const sealedCatalog = 'assets/d14b/catalogo.json';
const sealedStrings = 'assets/d14b/sentomaru-strings.json';

Future<String> readSealedSample() async {
  await SentomaruSealed.configure(allowPlainFallback: kDebugMode, plainStringsKey: sealedStrings);
  final catalog = jsonDecode(utf8.decode(await SentomaruSealed.load(sealedCatalog))) as Map<String, dynamic>;
  final greeting = await SentomaruSealed.string('saudacao');
  return 'Sealed: ${(catalog['catalogo'] as List).length} items, $greeting';
}
