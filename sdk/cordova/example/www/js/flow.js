// the shortest path through the facade (initialize, enroll, sign, signals snapshot). `sdk` is window.Sentomaru on a device
// (the plugin clobbers it) and the real facade over a fake native under `npm test`. Values are placeholders.
'use strict';
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.runSentomaruFlow = factory().runFlow;
})(typeof self !== 'undefined' ? self : this, function () {
  async function runFlow(sdk, add, challenge) {
    try {
      await sdk.initialize({
        organization: 'example-org', app: 'example-app', environment: 'hml',
        enrollmentUrl: 'https://api.example.test/v1/enroll', allowedHosts: ['api.example.test'],
      });
      add('state: ' + (await sdk.state()));
      const grant = await sdk.enroll({ challenge: challenge || 'challenge-from-your-server' }); // the challenge comes from YOUR server
      add('enrolled: ' + grant.installationId);
      const headers = await sdk.sign({
        method: 'POST', targetUri: 'https://api.example.test/v1/pay', operation: 'pay', body: new TextEncoder().encode('{"amount":1}'),
      });
      add('signed headers: ' + Object.keys(headers).join(', '));
      const snapshot = await sdk.collectSignalsSnapshot();
      add('signals: ' + snapshot.observations.length + ' observations in ' + snapshot.durationMs + ' ms');
    } catch (e) {
      add(e && typeof e.code === 'string' ? 'error ' + e.code : 'error');
    }
  }
  return { runFlow: runFlow };
});
