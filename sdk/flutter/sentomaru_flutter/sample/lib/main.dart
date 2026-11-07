import 'package:dio/dio.dart';
import 'package:flutter/material.dart';
import 'package:sentomaru_flutter/sentomaru_flutter.dart';

import 'd14b_sealed_sample.dart';

void main() {
  runApp(const SentomaruSampleApp());
}

class SentomaruSampleApp extends StatefulWidget {
  final SentomaruClient? client;

  const SentomaruSampleApp({super.key, this.client});

  @override
  State<SentomaruSampleApp> createState() => _SentomaruSampleAppState();
}

class _SentomaruSampleAppState extends State<SentomaruSampleApp> {
  late final SentomaruClient _client;
  late final Dio _dio;
  InstallationState _state = InstallationState.notEnrolled;
  List<SignalObservation> _signals = [];
  String _statusMessage = 'Initialized';

  @override
  void initState() {
    super.initState();
    _client = widget.client ?? SentomaruClient();
    _dio = Dio();
    _dio.addSentomaru(_client);

    _initClient();
  }

  Future<void> _initClient() async {
    const config = SentomaruConfig(
      organization: 'ebees',
      app: 'exampleapp',
      environment: 'dev',
      enrollmentUrl: 'https://api.ebees.com.br/enroll',
      allowedHosts: {'api.ebees.com.br'},
    );

    try {
      await _client.initialize(config);
      final s = await _client.state();
      setState(() {
        _state = s;
        _statusMessage = 'State: ${s.name}';
      });
    } catch (e) {
      setState(() {
        _statusMessage = 'Init error: $e';
      });
    }
  }

  /// D-14b: reads the sample's assets through the sealed reader (plain fallback only in debug, D-14x10).
  Future<void> _readSealed() async {
    try {
      final summary = await readSealedSample();
      setState(() => _statusMessage = summary);
    } catch (e) {
      setState(() => _statusMessage = 'Sealed error: $e');
    }
  }

  Future<void> _collectSignals() async {
    try {
      final sigs = await _client.collectSignals();
      setState(() {
        _signals = sigs;
        _statusMessage = 'Collected ${sigs.length} signals';
      });
    } catch (e) {
      setState(() {
        _statusMessage = 'Signals error: $e';
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(title: const Text('Sentomaru Flutter Lab')),
        body: Padding(
          padding: const EdgeInsets.all(16.0),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text('Status: $_statusMessage', key: const Key('status_text')),
              Text('Installation State: ${_state.name}', key: const Key('state_text')),
              const SizedBox(height: 16),
              ElevatedButton(
                key: const Key('collect_signals_button'),
                onPressed: _collectSignals,
                child: const Text('Collect Signals'),
              ),
              ElevatedButton(
                key: const Key('read_sealed_button'),
                onPressed: _readSealed,
                child: const Text('Read Sealed Assets'),
              ),
              const SizedBox(height: 16),
              Expanded(
                child: ListView.builder(
                  key: const Key('signals_list'),
                  itemCount: _signals.length,
                  itemBuilder: (context, index) {
                    final s = _signals[index];
                    return ListTile(
                      title: Text(s.capabilityId),
                      subtitle: Text('${s.state.name} (${s.source})'),
                    );
                  },
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
