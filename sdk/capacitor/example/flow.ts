// the shortest path through the facade (initialize, enroll, sign, signals snapshot). `sdk` is the facade, so the same
// function runs on a device (main.ts passes the real one) and under `npm test` (a fake native). Values are placeholders.
import type { createSentomaru } from '../src/bridge.ts';
import { SentomaruError } from '../src/types.ts';

export async function runFlow(sdk: ReturnType<typeof createSentomaru>, add: (line: string) => void, challenge = 'challenge-from-your-server'): Promise<void> {
  try {
    await sdk.initialize({
      organization: 'example-org', app: 'example-app', environment: 'hml',
      enrollmentUrl: 'https://api.example.test/v1/enroll', allowedHosts: ['api.example.test'],
    });
    add(`state: ${await sdk.state()}`);
    const grant = await sdk.enroll({ challenge }); // the challenge comes from YOUR server
    add(`enrolled: ${grant.installationId}`);
    const headers = await sdk.sign({
      method: 'POST', targetUri: 'https://api.example.test/v1/pay', operation: 'pay', body: new TextEncoder().encode('{"amount":1}'),
    });
    add(`signed headers: ${Object.keys(headers).join(', ')}`);
    const snapshot = await sdk.collectSignalsSnapshot();
    add(`signals: ${snapshot.observations.length} observations in ${snapshot.durationMs} ms`);
  } catch (e) {
    add(e instanceof SentomaruError ? `error ${e.code}` : 'error');
  }
}
