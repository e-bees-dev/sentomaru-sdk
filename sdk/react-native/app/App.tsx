// the app that mounts a screen AND calls the SDK through the typed layer (../src), which goes to the native module
// SentomaruModule (sdk/react-native/android) and from there to the Android SDK. It proves that the module builds with
// newArchEnabled=true and that the JS bundle resolves the facade; running it needs a device or emulator and a server.
// The values below are placeholders: replace them with the ones of your organization, and take the challenge from your server.
import React, { useState } from 'react';
import { Button, SafeAreaView, ScrollView, Text } from 'react-native';
import { Sentomaru, SentomaruError } from '../src';

const CONFIG = {
  organization: 'example-org', app: 'example-app', environment: 'hml',
  enrollmentUrl: 'https://api.example.test/v1/enroll', allowedHosts: ['api.example.test'],
};

export default function App() {
  const [log, setLog] = useState<string[]>(['Sentomaru React Native (new architecture)']);
  const add = (line: string) => setLog((l) => [...l, line]);

  const run = async () => {
    try {
      await Sentomaru.initialize(CONFIG);
      add(`state: ${await Sentomaru.state()}`);
      const grant = await Sentomaru.enroll({ challenge: 'challenge-from-your-server' });
      add(`enrolled: ${grant.installationId}`);
      const headers = await Sentomaru.sign({
        method: 'POST', targetUri: 'https://api.example.test/v1/pay', operation: 'pay', body: Uint8Array.from('{"amount":1}', (c) => c.charCodeAt(0)),
      });
      add(`signed headers: ${Object.keys(headers).join(', ')}`);
      const snapshot = await Sentomaru.collectSignalsSnapshot();
      add(`signals: ${snapshot.observations.length} observations in ${snapshot.durationMs} ms`);
    } catch (e) {
      add(e instanceof SentomaruError ? `error ${e.code}` : 'error');
    }
  };

  return (
    <SafeAreaView style={{ flex: 1, padding: 16 }}>
      <Button title="Run Sentomaru" onPress={run} />
      <ScrollView>{log.map((l, i) => <Text key={i}>{l}</Text>)}</ScrollView>
    </SafeAreaView>
  );
}
