# Sentomaru for React Native

Typed JavaScript layer over the Android SDK. It adds no method, default or retry: each function maps to one method of
`contracts/sdk/hybrid-bridge-v1.json` and goes through the single native entry `call(method, args)` of the module in
`android/`. Fachada: `src/bridge.ts`; TurboModule spec: `src/NativeSentomaru.ts`; errors: `SentomaruError.code` carries the
contract's stable code.

- `body` (sign) and the result of `sealedLoad` cross the bridge as Base64; the facade converts, you pass `Uint8Array`.
- Tests: `npm test` (Node 22+, parity with the contract, fake native). Types: `npm run typecheck` (needs `typescript`).
- `example/App.tsx` is a sketch. It was not built or run.
- Not published to a public registry. iOS is not covered by this package.

## Garantia de inscrição portátil: `EnrollmentAssurance` (D-W-port)

Decisão de projeto (11/11/2026): a lógica de "garantir a inscrição" (reaproveitar instalação, rotacionar depois de
atualização do app no Android D-04b, reinscrever só quando necessário) passa a morar nos SDKs. `EnrollmentAssurance`
(`src/enrollmentAssurance.ts`) é essa lógica, portada dos SDKs Android e Flutter — mas, ao contrário deles, é
TypeScript puro por cima da fachada já existente (`createSentomaru`'s `state`/`reenrollmentReason`/`enroll`/
`rotate`/`reset`/`sessionId`): a ponte nativa (`bridge.ts`, `sdk/hybrid-core`, `sdk/ios-hybrid-core`) não ganhou
nenhum método novo, seguindo a mesma regra que já valia pra `bridge.ts` ("a hybrid layer adds no method, no
default and no retry") — a decisão mora uma camada acima.

```ts
import { Sentomaru } from '@ebees/sentomaru-react-native';
import { EnrollmentAssurance } from '@ebees/sentomaru-react-native/src/enrollmentAssurance.ts';

const assurance = new EnrollmentAssurance(Sentomaru, secureStore, mirrorStore);
const result = await assurance.ensureEnrolled(subject, tenant, (s, t) => myBackend.fetchChallenge(s, t));
if (!result.current) return; // uma chamada mais nova (outro sujeito/tenant) já venceu
const sessionId = result.sessionId ?? (await Sentomaru.sessionId()); // null = nada mudou
```

**Sem dependência nova.** Diferente do Flutter (`flutter_secure_storage`) e do Android (`androidx.security:
security-crypto`), este pacote não tem hoje nenhuma dependência de runtime, e não existe uma biblioteca de
armazenamento seguro dominante no ecossistema React Native — por isso `EnrollmentAssurance` recebe `secureStore` e
`mirrorStore` (interface `PrincipalStore`: `read`/`write`/`delete` assíncronos) injetados pelo app, em vez de
embutir uma escolha. Combinação de referência (não incluída aqui, o app escolhe a sua):
`react-native-keychain` (seguro) + `@react-native-async-storage/async-storage` (cópia de reserva) — a mesma relação
de "cópia de reserva contra perda de chave" dos outros dois ports.

**`principalOf`** usa um SHA-256 escrito à mão (sem dependência, conferido contra os vetores do NIST): o Hermes não
garante `crypto.subtle` sem um polyfill, mesma razão pela qual `bridge.ts` já escreve Base64 à mão em vez de usar
`Buffer`.

**Achado corrigido de passagem:** `EnrollOptions.challenge` em `types.ts` era tipado `string` — nunca teria
funcionado contra a ponte nativa de verdade, que espera um objeto (`id`, `token`, `expiresAtEpochMs`,
`attestationChallengeB64`, exatamente como `SentomaruBridge.parseChallenge`/`HybridBridge.enrollmentArguments`
leem). Corrigido para `EnrollmentChallenge` (nova interface em `types.ts`); nada neste pacote testava isso contra a
ponte real antes.

**Provado:** `test/enrollmentAssurance.test.ts` (modelo: `bridge.test.ts`), com uma fachada `Sentomaru` falsa e
`PrincipalStore`s em memória — todas as decisões acima, "o mais recente vence" (aqui, mais simples que no Android:
o agendamento por microtask do JavaScript garante que a chamada mais antiga nem chega a pedir desafio, sem precisar
de thread real), o hook de migração, o guarda de reinstalação (e que ele não gasta um `reset()` à toa numa
instalação Android nova, achado nesta própria bateria de testes). `tsc --noEmit` limpo. **Não provado:** aparelho
real, ponte nativa real (Android ou iOS), servidor real, `react-native-keychain`/`AsyncStorage` de verdade.


## Message for the end user

`userMessage(situation, locale?, overrides?)`, `userMessageForCode(code, ...)` and `SentomaruError.userMessage(locale?, overrides?)` give the fixed text that tells the user some critical operations are blocked until approval (`pt-BR`, `en`, `es`; contract `contracts/sdk/user-message-v1.md`). It carries no code, reason or detection detail; the host may override the text per language. A code that is not a block (cancelled, not initialized, bad configuration or request, unknown) gives `null`: the app decides. Codes and behaviour do not change.

```ts
try {
  await sentomaru.renewSession();
} catch (e) {
  if (e instanceof SentomaruError) {
    const text = e.userMessage();                                 // device locale; null when e.code is not a block
    const custom = e.userMessage('pt-BR', { 'pt-BR': 'Texto do app.' }); // override per language
  }
}
```

Which codes are a block (4 situations: `attestation_failed`, `enrollment_pending`, `unavailable`, `verification_denied`): full map in `contracts/sdk/user-message-vectors-v1.json` (`mobileCodes.map`).
