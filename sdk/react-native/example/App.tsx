// the shortest path through the facade (initialize, enroll, sign, snapshot). It is a sketch for an app
// that already has a React Native project; it was NOT built or run (no RN toolchain in this slice). Values are placeholders.
import React, { useState } from 'react';
import { Button, ScrollView, Text, View } from 'react-native';
import { Sentomaru, SentomaruError } from '@ebees/sentomaru-react-native';

export default function App() {
  const [log, setLog] = useState<string[]>([]);
  const add = (line: string) => setLog((l) => [...l, line]);

  const run = async () => {
    try {
      await Sentomaru.initialize({
        organization: 'example-org', app: 'example-app', environment: 'hml',
        enrollmentUrl: 'https://api.example.test/v1/enroll', allowedHosts: ['api.example.test'],
      });
      add(`state: ${await Sentomaru.state()}`);
      // The challenge comes from your server; here a placeholder.
      const grant = await Sentomaru.enroll({ challenge: 'challenge-from-your-server' });
      add(`enrolled: ${grant.installationId}`);
      const headers = await Sentomaru.sign({
        method: 'POST', targetUri: 'https://api.example.test/v1/pay', operation: 'pay',
        body: new TextEncoder().encode('{"amount":1}'),
      });
      add(`signed headers: ${Object.keys(headers).join(', ')}`);
      const snapshot = await Sentomaru.collectSignalsSnapshot();
      add(`signals: ${snapshot.observations.length} observations in ${snapshot.durationMs} ms`);
    } catch (e) {
      add(e instanceof SentomaruError ? `error ${e.code}` : 'error');
    }
  };

  return (
    <View style={{ flex: 1, padding: 16 }}>
      <Button title="Run Sentomaru" onPress={run} />
      <ScrollView>{log.map((l, i) => <Text key={i}>{l}</Text>)}</ScrollView>
    </View>
  );
}
