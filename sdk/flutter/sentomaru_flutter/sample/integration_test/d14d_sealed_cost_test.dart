// D-14d, item 13: cost of reading the sealed assets through the plugin on one real device (never in CI; no device in
// P2). The sample must be its sealed build (`flutter build appbundle --obfuscate` then `sentomaru protect`, so the four
// assets/d14d/<n>.bin canary files are sealed and the plain originals are gone), installed on a device. The read goes
// through the real MethodChannel to the native sealed reader (no crypto in Dart). The latencies are printed as one JSON
// line tagged D14D_COST, which the device runner reads; a plain `flutter test integration_test` without a device does
// not run this. The device numbers come from d14d_sealed_cost_app.dart (a plain app entry point launched per
// measurement by verification/run_d14d_flutter_read_cost.py, so each cold read is a fresh process); the 4 MiB memory
// (livePeak4m, allocatedVolume4m) is measured on the native side (SealedReadCostInstrumentedTest).
import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:sentomaru_flutter/sentomaru_flutter.dart';

const _ladder = <String, String>{
  '1k': 'assets/d14d/1k.bin',
  '100k': 'assets/d14d/100k.bin',
  '1m': 'assets/d14d/1m.bin',
  '4m': 'assets/d14d/4m.bin',
};

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('FLT-D14d: sealed read cost (first and subsequent reads per size)', (tester) async {
    const runs = int.fromEnvironment('D14D_RUNS', defaultValue: 200);
    const warmup = int.fromEnvironment('D14D_WARMUP', defaultValue: 20);
    // Sealed package: no plain fallback (a sealed build never falls back, D-14x10).
    await SentomaruSealed.configure(allowPlainFallback: false);

    final sizes = <String, Object>{};
    for (final entry in _ladder.entries) {
      final firstSw = Stopwatch()..start();
      final first = await SentomaruSealed.load(entry.value);
      firstSw.stop();
      final micros = <int>[];
      for (var round = 0; round < warmup + runs; round++) {
        final sw = Stopwatch()..start();
        final b = await SentomaruSealed.load(entry.value);
        sw.stop();
        if (round >= warmup) micros.add(sw.elapsedMicroseconds);
        expect(b.length, first.length);
      }
      micros.sort();
      int pct(int p) => micros.isEmpty ? 0 : micros[(p * micros.length) ~/ 100 >= micros.length ? micros.length - 1 : (p * micros.length) ~/ 100];
      sizes[entry.key] = {
        'plainBytes': first.length,
        'firstReadMicros': firstSw.elapsedMicroseconds,
        'count': micros.length,
        'p50': pct(50),
        'p90': pct(90),
        'p99': pct(99),
        'maxMicros': micros.isEmpty ? 0 : micros.last,
      };
    }
    // ignore: avoid_print
    print('D14D_COST ${jsonEncode({'runs': runs, 'warmup': warmup, 'sizes': sizes})}');
  });
}
