// D-14d, item 13: the Flutter read-cost lab entry point, run on one real device by the vendor's run d14d flutter read cost check
// (never in CI). Built as the app's target (`flutter build appbundle --release --obfuscate -t <this file>`), then sealed
// by `sentomaru protect`, so the four assets/d14d/<n>.bin canary files are sealed and the plain originals are gone.
// It is a plain app, not a flutter_test: the runner launches MainActivity with `am start --esal dart_entrypoint_args`
// and reads the one JSON line tagged D14D_COST from logcat. Every read goes through the real MethodChannel to the
// native sealed reader (no crypto in Dart), so the time includes the channel.
//   cold <size>           ONE timed SentomaruSealed.load of a fresh process (force-stopped before the launch), right
//                         after runApp (it competes with the engine start-up and the first frame)
//   coldframe <size>      the same, but the read starts only after
//                         `WidgetsBinding.instance.waitUntilFirstFrameRasterized` (the first frame on screen), so it
//                         does not compete with the first frame (D-14d emulator)
//   warm [runs] [warmup]  per size one first read, then warmup + runs reads (warmup discarded)
// The 4 MiB memory (livePeak4m, allocatedVolume4m) is not measured here: the reader's buffers live in the Java heap,
// which Dart cannot collect or read; SealedReadCostInstrumentedTest measures them on the same native reader.
import 'dart:convert';

import 'package:flutter/widgets.dart';
import 'package:sentomaru_flutter/sentomaru_flutter.dart';

const _ladder = <String, String>{
  '1k': 'assets/d14d/1k.bin',
  '100k': 'assets/d14d/100k.bin',
  '1m': 'assets/d14d/1m.bin',
  '4m': 'assets/d14d/4m.bin',
};

/// Nearest rank: the ceil(p/100 * n)-th smallest value (as run_j03_perf.percentile); 0 when empty.
int nearestRank(List<int> sorted, int p) {
  if (sorted.isEmpty) return 0;
  final rank = (p * sorted.length + 99) ~/ 100;
  return sorted[(rank < 1 ? 1 : rank) - 1];
}

Future<Map<String, Object>> _cold(String target) async {
  final path = _ladder[target];
  if (path == null) throw ArgumentError('target must be one of ${_ladder.keys}');
  final sw = Stopwatch()..start();
  final bytes = await SentomaruSealed.load(path);
  sw.stop();
  return {
    'mode': 'cold',
    'sizes': {
      target: {'firstReadMicros': sw.elapsedMicroseconds, 'plainBytes': bytes.length},
    },
  };
}

Future<Map<String, Object>> _warm(int runs, int warmup) async {
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
      if (b.length != first.length) throw StateError('read ${entry.key} changed size');
      if (round >= warmup) micros.add(sw.elapsedMicroseconds);
    }
    micros.sort();
    sizes[entry.key] = {
      'plainBytes': first.length,
      'firstReadMicros': firstSw.elapsedMicroseconds,
      'count': micros.length,
      'p50': nearestRank(micros, 50),
      'p90': nearestRank(micros, 90),
      'p99': nearestRank(micros, 99),
      'maxMicros': micros.isEmpty ? 0 : micros.last,
    };
  }
  return {'mode': 'warm', 'runs': runs, 'warmup': warmup, 'sizes': sizes};
}

Future<void> main(List<String> args) async {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const Directionality(textDirection: TextDirection.ltr, child: Center(child: Text('d14d'))));
  Map<String, Object> result;
  try {
    // Sealed package: no plain fallback (a sealed build never falls back, D-14x10).
    await SentomaruSealed.configure(allowPlainFallback: false);
    final mode = args.isEmpty ? '' : args[0];
    if (mode == 'cold' && args.length > 1) {
      result = await _cold(args[1]);
    } else if (mode == 'coldframe' && args.length > 1) {
      await WidgetsBinding.instance.waitUntilFirstFrameRasterized;
      result = {...await _cold(args[1]), 'mode': 'coldframe'};
    } else if (mode == 'warm') {
      result = await _warm(args.length > 1 ? int.parse(args[1]) : 200, args.length > 2 ? int.parse(args[2]) : 20);
    } else {
      result = {'error': 'args must be `cold <size>`, `coldframe <size>` or `warm [runs] [warmup]`'};
    }
  } catch (e) {
    result = {'error': e.runtimeType.toString()};
  }
  // ignore: avoid_print
  print('D14D_COST ${jsonEncode(result)}');
}
