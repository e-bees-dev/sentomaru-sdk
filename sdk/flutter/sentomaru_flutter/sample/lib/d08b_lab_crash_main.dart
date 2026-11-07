// D-08b lab-only crash entrypoint. NOT the app's `main` (that is lib/main.dart): the emulator job builds this target
// on its own with `flutter build apk --release --obfuscate --split-debug-info=<dir> --target lib/d08b_lab_crash_main.dart`
// and never ships it. The push-path CI build (flutter-plugin-android) builds the normal main.dart, so a mistake here
// cannot break that build. On launch it throws a deterministic exception through a two-level call chain so the job can
// capture the AOT-obfuscated Dart stack from logcat and prove `flutter symbolize` recovers the original names with the
// matching `--split-debug-info` symbols (and produces wrong output with another build's symbols: the runbook picks the
// symbols file by build-id). `--obfuscate` renames `labDetonateLevelOne`/`labDetonateLevelTwo`; symbolize brings them
// back.

import 'dart:async';

import 'package:flutter/widgets.dart';

const String labCrashMark = 'sentomaru-d08b-lab-crash';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  // Throw from a timer callback once the engine is up: an UNHANDLED async error reaches the Dart VM, which prints the
  // AOT crash dump (`*** *** ***`, the build-id and `#NN abs ...` frames) to logcat. A throw caught by the Flutter
  // framework would print a framework-formatted error instead, which `flutter symbolize` does not consume. Timer.run
  // returns void, so there is no future to await (no unawaited_futures lint).
  WidgetsBinding.instance.addPostFrameCallback((_) {
    Timer.run(labDetonateLevelOne);
  });
  runApp(const _LabCrashApp());
}

@pragma('vm:never-inline')
void labDetonateLevelOne() {
  labDetonateLevelTwo();
}

@pragma('vm:never-inline')
Never labDetonateLevelTwo() {
  throw StateError(labCrashMark);
}

class _LabCrashApp extends StatelessWidget {
  const _LabCrashApp();

  @override
  Widget build(BuildContext context) => const SizedBox.shrink();
}
