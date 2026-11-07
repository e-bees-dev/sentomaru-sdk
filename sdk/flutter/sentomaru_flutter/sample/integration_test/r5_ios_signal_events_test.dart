// R-5: on iOS the plugin has no `signal` events. No network is needed.
import 'dart:async';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:sentomaru_flutter/sentomaru_flutter.dart';

const _config = SentomaruConfig(
  organization: 'ebees',
  app: 'flutter-device-test',
  environment: 'lab',
  enrollmentUrl: 'https://127.0.0.1:9/v1/ebees/flutter-device-test/lab/installations',
  allowedHosts: {'127.0.0.1'},
);

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('R-5: iOS reports signalEventsSupported false and emits no signal event', (tester) async {
    expect(Platform.isIOS, isTrue, reason: 'R-5 runs on the iPhone');
    final client = SentomaruClient();
    await client.reset().catchError((_) {});
    await client.initialize(_config);
    expect(client.signalEventsSupported, isFalse);

    final events = <SentomaruSignalEvent>[];
    final sub = client.signalEvents.listen(events.add);
    await client.collectSignalsSnapshot();
    await client.collectSignalsSnapshot(rasp: true);
    await Future<void>.delayed(const Duration(seconds: 2));
    await sub.cancel();
    expect(events, isEmpty);
  });
}
