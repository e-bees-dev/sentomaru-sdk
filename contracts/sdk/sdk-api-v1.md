# Sentomaru SDK API Contract — v1 (P2), revisão v1.1

> **v1.1 (2026-10-10, BREAKING, sem aliases):** mapa de nomes aplicado. Flutter `sentomaru_flutter` 0.3.0: `SentomaruThreatEvent` → `SentomaruRiskEvent`, chave `threatEvent` → `riskEvent`, `threatScore` → `riskIndex` (opcional, consultivo), `onThreatEvent` → `onRiskEvent`. Kotlin: nenhum símbolo renomeado. Tabela completa e migração: [`docs/hardening/rename-migration.md`](../../docs/hardening/rename-migration.md).

Este contrato formaliza a superfície pública do SDK de integridade do cliente Sentomaru (Kotlin/Android e Flutter), cobrindo módulos, modelos, ciclo de vida, erros tipados, regras de consumidor (ProGuard/R8) e política de transporte HTTP/RFC 9421.

---

## 1. Módulos e Coordenadas Maven

Todos os módulos utilizam `group = "br.com.ebees.sentomaru"` e versão `0.1.0`:

| Módulo | Tipo | Artefato | Descrição |
|---|---|---|---|
| `:core` | Pure JVM (Kotlin) | `core-0.1.0.jar` | Núcleo RFC 9421 / RFC 9530, codificação de envelope e assinatura. |
| `:signer` | Android Library (AAR) | `signer-0.1.0.aar` | Gerador e assinador de chave em AndroidKeyStore (P-256 / SHA-256) com Key Attestation. |
| `:signals` | Android Library (AAR) | `signals-0.1.0.aar` | Coletor de sinais locais do dispositivo (catálogo versionado). |
| `:sdk` | Android Library (AAR) | `sdk-0.1.0.aar` | Fachada principal Android: ciclo de inscrição, interceptor OkHttp, transporte `HttpURLConnection` (S2), armazenamento seguro. |
| `sentomaru_flutter` | Flutter Plugin | `pubspec.yaml` | Adapter Flutter com Dart `SentomaruClient` e Dio interceptor via MethodChannel (Android; iOS desde 0.18.0, D-10b, sobre `sdk/ios`). |

---

## 2. Superfície Pública do SDK Android (`:sdk`)

### 2.1 Configuração (`SentomaruConfig`)

```kotlin
data class SentomaruConfig(
    val organization: String,
    val app: String,
    val environment: String,
    val allowedHosts: Set<String>,
    val clockSkewToleranceSeconds: Long = 30,
    val signatureTtlSeconds: Long = 60,
    val maxBodyBytes: Long = 65536,
    val alias: String = "sentomaru_installation",
    val requireStrongBox: Boolean = false,
)
```

- **`allowedHosts`**: Host allowlist estrita. Qualquer requisição para host fora desta lista não recebe assinatura nem credenciais (`SentomaruError.HostNotAllowed`).
- **`maxBodyBytes`**: Limite estrito de 65.536 bytes para corpo de requisição. Corpos maiores são rejeitados com `SentomaruError.BodyTooLarge`.

### 2.1.0 Renovação assinada da sessão (J-04r)

`SentomaruConfig(…, renewalUrl = "https://<consumidor>/…/sessions")` (opcional, https e host em `allowedHosts`; no
plugin Flutter 0.9.0, `SentomaruConfig(renewalUrl: …)`). O grant vive 10 min no servidor. Com `renewalUrl`:

- `SentomaruClient.needsRenewal()` é verdadeiro quando o grant está na margem do fim da vida, `min(RENEWAL_MARGIN
  (120 s), vida/5)` (`EnrollmentGrant.issuedAt` + `ttlSeconds`; o grant da inscrição conta 600 s; registro sem
  `issuedAt`, de antes da J-04r, renova logo), salvo nos `RENEWAL_BACKOFF` (60 s) depois de uma renovação que falhou
  (`canRenewNow()`, que o caminho reativo também respeita).
- Espera depois de falhas `ServerRejected(SUSPENDED)` seguidas: 5 s, depois 15 s, depois 60 s a cada nova falha
  (`SUSPENDED_RENEWAL_BACKOFF_STEPS`). O degrau volta ao início (5 s) com uma renovação bem-sucedida, com `reset()`,
  quando `session-unavailable` apaga o grant, ou com qualquer falha que não seja SUSPENDED (essa espera 60 s). Cada falha
  começa uma espera nova, que substitui a anterior; não se somam. É uma troca **do cliente**, sem garantia do servidor.
  Liberada logo pelo operador, a instalação renova no próximo "Tentar de novo" após 5 s. Em troca, o app manda no máximo
  3 renovações nos primeiros 20 s da suspensão, 4 nos primeiros 80 s e depois 1 por minuto (≈60/h, o mesmo teto das
  falhas comuns; com 5 s fixos seriam até 720/h). Numa suspensão mais longa, a recuperação depois da liberação pode
  esperar até 60 s. Só há renovação quando ela é pedida (grant na margem ou `session-expired`); ficar parado não gera
  tráfego.
- `renewalBackingOff()` é verdadeiro só quando a renovação seria possível (`renewalUrl` configurada e `state()`
  `Enrolled`) e a espera ainda corre. `canRenewNow()` = possível e sem espera.
- `renewSession()` do plugin: dentro da espera responde `RenewalBackoff` (`EnrollmentError.RenewalBackoff`; no Dart
  `SentomaruErrorCode.renewalBackoff`). Quando a renovação não é possível (sem `renewalUrl` ou instalação não inscrita)
  responde `InvalidRequest:PARAMS`, mesmo que haja espera pendente. O grant não muda em nenhum dos dois casos.
- Desde o plugin 0.9.2, a recusa `RenewalBackoff` leva em `details` o `SentomaruError.code` da falha que começou a espera,
  no mesmo formato do código de `serverRejected` (`ServerRejected:SUSPENDED` numa suspensão; `NetworkUnavailable`,
  `ServerRejected:UNAVAILABLE` etc. nas demais). Vale também quando quem falhou foi a renovação silenciosa antes do
  `sign` (`renewIfDue`): o app distingue "suspenso" de "indisponível" sem esperar a espera acabar. `details` é `null` se
  a falha não teve código (exceção do transporte que não é `SentomaruException`). Um grant de outra chave na resposta
  fica registrado como `InvalidRequest:PARAMS`, o mesmo código que `renew` lança. No SDK Android o mesmo valor sai de
  `SentomaruClient.lastRenewalFailure()`, só enquanto `renewalBackingOff()` é verdadeiro; ele é guardado com o instante
  da falha e limpo junto com a espera. `SentomaruClient.renewalGate()` devolve a decisão (`backingOff`, `canRenewNow`) e
  o código numa leitura só, sob a trava do cliente; o plugin usa só ela.
- `details` é uma pista sobre a última falha, **não** o estado atual do servidor: se a instalação for liberada dentro da
  janela, o app continua vendo "suspenso" até a espera acabar e a próxima renovação dar certo.
- `renew(send)` assina `POST renewalUrl`, corpo `{}`, operação `session_renew`, sessão = grant atual, com a chave da
  instalação (**sem atestação**); `send` entrega ao consumidor e devolve `RenewedGrant` (`RenewedGrant.parse` lê a
  resposta; `ttlSeconds` é o tempo restante, 1–86 400). O grant novo substitui o antigo no app (no servidor o antigo
  vale até vencer, e repetir a renovação devolve o mesmo grant novo); falha mantém o atual. `session-unavailable`
  (`EnrollmentError.EnrollmentRequired` vindo de `send`) apaga o grant: `state()` vira `EnrollmentRequired` e o app
  reinscreve (`reset` + `enroll`); a cadeia termina 7 dias depois da inscrição. `renewIfDue(send)` renova só se ainda for devido
  sob a trava do cliente; `markGrantStale()` força a próxima renovação.
- **iOS (contrato v1.11, D-09c, para o SDK Swift da D-10).** Instalação inscrita com `apple-app-attest` e atestação
  verificada: o corpo assinado da renovação é exatamente `{"appAssertion":"<base64 padrão com padding do CBOR>"}`, com
  a assertion de `DCAppAttestService.generateAssertion(keyId, clientDataHash:)` da chave App Attest da inscrição e
  `clientDataHash = SHA-256("sentomaru-app-assertion-v1\n" ‖ sessionId ‖ "\n" ‖ nonce ‖ "\n" ‖
  base64url-sem-padding(SHA-256(SPKI)))`: `sessionId` = o `x-sentomaru-session` desta renovação (UUID minúsculo),
  `nonce` = o `nonce` do `Signature-Input` desta mesma requisição, `SPKI` = o DER da chave de requisição inscrita.
  Uma assertion nova a cada tentativa (o retry depois de resposta perdida também gera nonce e assertion novos). Uma
  renovação por vez por instalação, sob a trava do cliente, como no Android: renovações simultâneas entram em fila no
  servidor e a de contador menor é recusada. Toda falha da assertion é `403 session-unavailable`
  (`EnrollmentRequired`): reinscrever gera chave App Attest nova. Perfil: the Sentomaru Apple attestation profile,
  seção "Assertion na renovação". O SDK Android não muda (corpo `{}`, não lido). D-09d (sem mudança no fio nem na
  versão): o servidor aceita a atestação e a assertion como a Apple as emite num aparelho (flags `0xC0` e mapa CBOR
  de extensões no `authData`); o SDK passa os bytes de `attestKey` e `generateAssertion` sem mexer neles.
- O interceptor do OkHttp renova antes de assinar quando devido e, diante de `403` com `code` `session-expired` (ou
  cabeçalho `Sentomaru-Error: session-expired`) numa requisição assinada, renova e reenvia **uma vez**. O plugin faz o
  mesmo: renovação nativa antes do `sign` e `renewSession()` + um reenvio no Dio.
- **Desvio aceito:** se a renovação do Dio falhar (`ServerRejected:SUSPENDED`, `RenewalBackoff` ou qualquer outra
  `SentomaruException`), o erro é engolido e o chamador recebe o `403 session-expired` original, sem o motivo. Quem
  precisa do motivo chama `SentomaruClient.renewSession()` direto e trata o código (é o que faz o binder do ExampleApp).
- Sem `renewalUrl`, nada muda (sessão longa termina em `session-expired`).
- `403 installation-suspended` (contrato v1.5): suspensão temporária da instalação, por operador ou regra de resposta,
  respondida só à chave da própria instalação. **Não** é `EnrollmentRequired`: o grant fica e o app tenta de novo mais
  tarde. Na renovação (transporte do plugin 0.9.1 e interceptor OkHttp do SDK) vira
  `EnrollmentError.ServerRejected(SUSPENDED)` (código `ServerRejected:SUSPENDED`; no Dart `serverRejected` com esse texto
  em `details`), com o grant mantido e a espera curta em degraus (5 s → 15 s → 60 s, acima): liberada pelo operador, a
  instalação renova no próximo "Tentar de novo" sem reabrir o app. Na inscrição, o mesmo 403 vira
  `ServerRejected:SUSPENDED` em vez de `ServerRejected:INVALID`. Só o `403` com `code` exatamente
  `installation-suspended` — qualquer outro 403 segue como antes (falha comum, espera de 60 s). Não há
  estado próprio em `state()` (tarefa 7). Nas requisições do app é uma falha comum da requisição.
  Revogação (quarentena) continua `session-unavailable` → `EnrollmentRequired`.

O consumidor expõe a rota pública e repassa ao privado `POST /v1/{org}/{app}/{env}/sessions` (adaptador 4.1.0:
`RenewSessionAsync`; `context` opcional).

### 2.1.1 Play Integrity na inscrição (C-04b)

- `SentomaruConfig(..., playIntegrityCloudProjectNumber: Long? = null)`: número do projeto Google Cloud vinculado ao
  app no Play Console (ou ao SDK Sentomaru no Play SDK Console, D-G2). Null = desligado. Fora da identidade da
  instalação. O número deve ser do projeto vinculado ao `applicationId` final (com sufixo, se houver).
- Porta pública `fun interface IntegrityTokenSource { fun token(requestHash: String): String? }`; implementação Android
  `PlayIntegrityTokenSource` (standard request, 4 s por etapa, provedor reaproveitado e preparado de novo uma vez se
  expirar). `SentomaruClient.initialize` liga a implementação quando o número está configurado.
- `IntegrityRequestHash.of(challenge, packageName)`: o vínculo que o servidor confere
  ([play-integrity-v1](../api/play-integrity-v1.md)).
- Comportamento: o token é pedido **fora da trava do cliente**, só quando um corpo novo de inscrição/rotação será
  montado e só se faltarem mais de 20 s para o desafio vencer; fica congelado com o corpo; qualquer falha inscreve sem
  ele; interrupção cancela (`EnrollmentError.Cancelled`).

### 2.1.2 Reinscrição depois de atualizar o app (D-04b)

- O registro local guarda o `versionCode` com que a chave em uso foi gerada (é o que a Key Attestation dela nomeia):
  `InstallationRecord.versionCode` / `PendingRotation.versionCode`, no arquivo do `noBackupFilesDir`. `SentomaruClient.initialize`
  lê o `versionCode` do app em execução (`PackageInfo.longVersionCode`; minSdk 28) e o passa ao cliente
  (`SentomaruClient(…, appVersionCode = …)`, construtor com `@JvmOverloads`).
- `SentomaruClient.reenrollmentReason(): ReenrollmentReason?` devolve `APP_UPDATED` quando `state()` é `Enrolled` e o
  `versionCode` guardado é **diferente** do atual (atualização ou rebaixamento). `null` quando é igual, quando o registro
  não tem versão (instalação inscrita antes do D-04b: tratada como desconhecida, nunca força reinscrição; a próxima
  inscrição ou rotação grava a versão), quando a versão atual não pôde ser lida, ou fora de `Enrolled`
  (`EnrollmentRequired` já diz "inscreva de novo").
- **Não** é um estado novo de `InstallationState`: a instalação continua `Enrolled` e assinando. O SDK não consegue
  pedir desafio sozinho (o desafio vem do backend do consumidor), então quem refaz a inscrição é o app: pede um desafio
  **novo** a cada vez que `reenrollmentReason() != null` e
  chama `rotate(challenge)` (chave nova com atestação nova; a chave atual segue assinando até o grant novo chegar e fica
  aposentada no período de graça) ou `reset()` + `enroll(challenge)`. Quando geram chave nova, as duas gravam o
  `versionCode` atual e o pedido some. App que não consulta `reenrollmentReason()` segue como antes (a evidência de
  build gravada no servidor envelhece).
- Desafio é de uso único no servidor ([p0-attestation-profile](../p0-attestation-profile.md)): outro corpo no mesmo
  desafio recebe 409 `enrollment-conflict`, e o replay idêntico devolve o grant original. Por isso, com o **mesmo**
  desafio, `rotate` (e `enroll`) sempre reenvia a pendência congelada, mesmo que outra versão a tenha congelado: isso só
  recupera o grant perdido, o registro fica com a versão antiga e `reenrollmentReason()` continua `APP_UPDATED`. Com um
  desafio **diferente**, a pendência é descartada e a chave e a atestação novas gravam a versão atual. Reaproveitar o
  desafio de uma rotação interrompida não reinscreve.
- Leitura tolerante: no arquivo local, só inteiro positivo é versão; ausente, `null`, texto, negativo ou fração viram
  desconhecido (nunca `KeyInvalidated`). Um `InstallationStore` próprio precisa persistir `InstallationRecord.versionCode`
  e `PendingRotation.versionCode`; se não persistir, a versão vira desconhecida e a consulta nunca pede reinscrição.
- Rebaixar o SDK para uma versão anterior ao D-04b: ela ignora o campo e o descarta na próxima escrita do registro;
  ao voltar para esta versão, a instalação conta como sem versão (desconhecida) até a próxima inscrição ou rotação.
- `InstallationRecord` e `PendingRotation` ganharam `versionCode` como último parâmetro com padrão; os construtores têm
  `@JvmOverloads` (as assinaturas Java antigas continuam). Código Kotlin já compilado que usa os padrões precisa ser
  recompilado (o construtor sintético dos padrões muda).
- **Identidade no servidor:** toda inscrição, inclusive a rotação, cria uma instalação nova no servidor (`installationId`
  novo, código `INS-…` novo, nome e etiquetas do Console não herdados); o `subject`/`tenant` vêm do desafio que o app
  pede. Não há hoje rota que ligue a chave nova à instalação anterior.
- Plugin Flutter 0.10.0: `SentomaruClient.reenrollmentReason()` → `Future<ReenrollmentReason?>` (`appUpdated`;
  `unknown` para um nome que o plugin não conhece). Canal: método `reenrollmentReason`, resposta `"APP_UPDATED"` ou `null`.
- Regra de consumidor: `-keep class br.com.ebees.sentomaru.sdk.ReenrollmentReason { *; }`.

### 2.2 Cliente Principal (`SentomaruClient`)

```kotlin
class SentomaruClient @JvmOverloads constructor(
    val config: SentomaruConfig,
    keys: InstallationKeys,
    store: InstallationStore,
    clock: Clock = Clock.systemUTC(),
    integrity: IntegrityTokenSource? = null,  // C-04b
    packageName: String? = null,              // C-04b
    appVersionCode: Long? = null,             // D-04b
) {
    fun state(): InstallationState
    fun reenrollmentReason(): ReenrollmentReason?  // D-04b
    fun retiredKeys(): List<RetiredKey>
    fun enroll(challenge: EnrollmentChallenge, strongBox: Boolean = false, requiresHardware: Boolean = false,
        send: (SignedMessage) -> EnrollmentGrant): EnrollmentGrant
    fun rotate(challenge: EnrollmentChallenge, strongBox: Boolean = false, requiresHardware: Boolean = false,
        send: (SignedMessage) -> EnrollmentGrant): EnrollmentGrant
    fun signRequest(frozen: FrozenRequest): SignedMessage
    fun sign(method: String, targetUri: String, operation: String, body: ByteArray,
        optional: Map<String, String> = emptyMap()): SignedMessage
    fun sessionId(): String?
    fun needsRenewal(): Boolean; fun canRenewNow(): Boolean; fun renewalBackingOff(): Boolean  // J-04r
    fun lastRenewalFailure(): String?; fun renewalGate(): RenewalGate
    fun renewIfDue(send: (SignedMessage) -> RenewedGrant): EnrollmentGrant?
    fun renew(send: (SignedMessage) -> RenewedGrant): EnrollmentGrant
    fun markGrantStale()
    fun reset()
    companion object { fun initialize(context: Context, config: SentomaruConfig): SentomaruClient }
}
// OkHttp: OkHttpClient.Builder.addSentomaru(client[, routes]) (transport); HttpURLConnection: SentomaruUrlConnection.send
```

Erros saem como `SentomaruException` com `EnrollmentError`/`SentomaruError` (não `Result`). `initialize` liga o
armazenamento (`AndroidInstallationStore`), as chaves do Android Keystore (`AndroidInstallationKeys`), o Play Integrity
quando configurado e o `versionCode` do app.

### 2.3 Modelos de Inscrição

```kotlin
data class EnrollmentChallenge(
    val challengeId: String,
    val challenge: String,
    val attestationChallenge: ByteArray,
    val expiresAt: Long,
)

data class EnrollmentGrant(
    val installationId: String,
    val keyId: String,
    val sessionId: String,
    val attestationStatus: String,
    val hardwareStatus: String,
    val attestationReason: String,
)

sealed interface InstallationState {
    data object Unenrolled : InstallationState
    data class Enrolled(val grant: EnrollmentGrant) : InstallationState
}
```

### 2.4 Rotação que reinscreve a mesma instalação (D-04d)

`rotate(challenge)` gera a chave nova e põe no corpo congelado da inscrição o membro `predecessor`
(`installationId` do grant atual + assinatura feita com a chave **atual**, the Sentomaru re-enrollment API contract). Num
servidor com o contrato v1.6 a instalação nova herda `installationCode`, nome, tags e suspensão, e a chave antiga deixa
de valer no servidor assim que a rotação é aceita (o SDK ainda a guarda pelo `rotationGracePeriod`, só no aparelho).
Se a assinatura com a chave atual falhar, a chave nova é apagada e a atual continua ativa. Um retry reenvia os mesmos
bytes (replay idêntico). `reset()` + `enroll()` não leva prova: instalação nova, sem a suspensão. Num servidor anterior
ao v1.6 a rotação recebe 400 `json-format`: publique o SDK depois da API. O plugin Flutter repassa `rotate()` sem
mudança.

- **Resposta perdida depois do commit.** A rotação pendente ganha a marca `sent` (gravada antes de entregar o corpo ao
  `send`; leitura tolerante como o `versionCode`: ausente ou qualquer valor que não seja `true` = não enviada; um
  `InstallationStore` próprio deve persistir `PendingRotation.sent`). Se a pendência já foi enviada e o app chama
  `rotate` com desafio **novo** (ou outras opções), o SDK reenvia primeiro o corpo congelado com o desafio dele: o
  servidor devolve o grant original no replay idêntico mesmo com o desafio expirado. 200 → o SDK adota esse grant e a
  `rotate` termina (o desafio novo não é usado). Só quando o servidor **prova** que não aceitou aquele corpo —
  `ServerRejected` `EXPIRED` (`challenge-invalid`), `REVOKED` (`enrollment-revoked`) ou `CONFLICT` (`409
  enrollment-conflict`, valor novo no fim do enum) — a pendência é descartada e a rotação segue com o desafio novo.
  Qualquer outra recusa (`INVALID`: 4xx genérico, 403 de proxy, 404, 408, corpo ilegível, `proof-invalid`), erro de
  rede, `UNAVAILABLE`, `RATE_LIMITED` ou cancelamento → mantém a pendência e lança. Um `send` próprio mapeia
  `EXPIRED`/`REVOKED`/`CONFLICT` só desses códigos exatos (o `EnrollmentTransport` do plugin Flutter faz assim).
  O grant adotado pode já ter passado dos 10 minutos: a renovação (`renew`, J-04r) o aceita enquanto a cadeia não
  passar de 7 dias desde a reinscrição; depois disso o servidor responde `session-unavailable`, o SDK cai em
  `EnrollmentRequired` e o app faz `reset()` + `enroll()` (instalação nova). Sem envio anterior, vale a regra da D-04b
  (desafio novo descarta a pendência).
- **`EnrollmentError.ReenrollmentRefused`** (código `ReenrollmentRefused`; Dart `SentomaruErrorCode.reenrollmentRefused`):
  o servidor respondeu `401 predecessor-invalid` — a instalação atual não pode ser reinscrita (quarentenada, já
  substituída, outro `subject`/`tenant`, ou prova que não confere). Rotacionar de novo não resolve: chame `reset()` e
  depois `enroll()` (instalação nova: código novo, sem nome, tags nem suspensão). Um `send` próprio deve lançar esse
  erro para essa resposta (o `EnrollmentTransport` do plugin Flutter lança); a pendência cuja reenvio recebe essa
  recusa é descartada.
- A sucessora pode ter nível de atestação diferente da anterior (por exemplo `hardware` → `software`): o
  `hardwareStatus` do grant é o da nova inscrição.
- **Limite:** rotacionar zera as contagens das regras de resposta automática da instalação no servidor (evidências e
  incidentes ficam na linha anterior); a suspensão já gravada é copiada.

### 2.5 Reatestação sob desafio, por opção (D-12c)

`SentomaruReattestation(client, challengeUrl, submitUrl, minInterval = 24 h)`: rotas públicas do consumidor (mesma
allowlist e `https` do `SentomaruConfig`) que repassam para `POST …/reattestations/challenges` e `POST …/reattestations`
(the Sentomaru re-attestation API contract). Não muda `SentomaruConfig` nem o `SentomaruClient` (só leitura interna das
chaves); nada liga por padrão.

- `reattestIfDue(strongBox, send)`: se `due()`, os dois passos; senão `ReattestationNotNow(NOT_DUE, resto)` sem enviar.
  `reattest(strongBox, send)` ignora `due()`; `requestChallenge(send)` e `reattest(challenge, strongBox, send)` são os
  passos separados.
- `send: (SignedMessage) -> ReattestationAnswer(status, body, retryAfterSeconds?)`: o consumidor só repassa; o SDK lê o
  `code` da recusa. `IOException` = "agora não" (`UNAVAILABLE`).
- Resultados: `ReattestationChallengeIssued`, `ReattestationCompleted(result)` (campos da resposta 200, validados contra
  o desafio e o `installationId` do grant), `ReattestationNotNow(reason, retryAfter)` (`RATE_LIMITED`,
  `VERIFIER_UNAVAILABLE`, `UNAVAILABLE`, `NOT_DUE`), `ReattestationRefused(code, status)` (código do servidor ou
  `unexpected-answer`). Falhas locais lançam como na inscrição (`NotEnrolled`, `KeyUnavailable`,
  `StrongBoxUnavailable`, `Cancelled`); a thread principal é recusada com `IllegalStateException`.
- Novas tentativas: no máximo uma por chamada e por passo, só para `503 verifier-unavailable` e `409 replay`, assinada
  de novo com o mesmo corpo, depois de `max(Retry-After, 2 s)` e só se couber em 30 s e antes do fim do desafio menos
  10 s. `429` nunca é repetido. O intervalo (`minInterval`, 1 h depois de `revocation_unchecked`) e as esperas de
  "agora não" (entre 60 s e 24 h) ficam só em memória; `reattestation-disabled`, `reattestation-unsupported` e
  `installation-suspended` esperam 24 h.
- `due()` não bloqueia (lê um campo volátil); os passos usam uma trava própria. Desafio recusado localmente só 60 s
  depois do `expiresAt`; resposta 200/201 acima de 4096 caracteres = `unexpected-answer`.
- **Flutter (plugin 0.13.0, D-12e):** `SentomaruConfig(reattestation: SentomaruReattestationConfig(challengeUrl,
  submitUrl, minInterval))` cria um `SentomaruReattestation` por `initialize` (rota recusada = `configurationError`);
  `SentomaruClient.reattestationDue()` chama `due()` na thread da plataforma (não bloqueia) e `reattestIfDue({strongBox})`
  chama `reattestIfDue` numa thread de trabalho própria do plugin (nem a principal nem a do `sign`), enviando pelo
  `EnrollmentTransport` (allowlist, https, sem redirect, um envio; `Retry-After` só em segundos). Sem rotas na
  configuração, os dois dão `invalidRequest` (só no Android). Resultados `ReattestationCompleted`, `ReattestationNotNow`
  (`ReattestationWait`), `ReattestationRefused(code, status)`; iOS = `ReattestationUnsupported` sem chamar o canal.

---

## 3. Taxonomia de Erros Tipados

Nenhuma exceção não tratada deve vazar para a aplicação hospedeira. Erros são modelados como tipos estritos:

### 3.1 Erros de Transporte e Assinatura (`SentomaruError`)

- `SentomaruError.HostNotAllowed(host)`: Requisição direcionada para host fora de `allowedHosts`.
- `SentomaruError.BodyTooLarge(actualSize, maxSize)`: Corpo da requisição excede o orçamento de 64 KiB.
- `SentomaruError.InvalidRequest(reason)`: Cabeçalhos ou método HTTP incompatíveis com o perfil RFC 9421.
- `SentomaruError.SignatureFormat(details)`: Erro ao gerar assinatura P1363 ou codificar parâmetros.

### 3.2 Erros de Inscrição (`EnrollmentError`)

- `EnrollmentError.ChallengeExpired`: Desafio expirado pelo relógio local antes do início.
- `EnrollmentError.StrongBoxUnavailable`: Hardware StrongBox solicitado (`requiresStrongBox: true`), mas ausente no dispositivo.
- `EnrollmentError.NetworkUnavailable`: Falha transitória de conectividade com o servidor.
- `EnrollmentError.ServerRejected(statusCode, errorCode, detail)`: Servidor P1 rejeitou a inscrição (e.g. 403 context, 409 conflict, 422 hardware-not-proven).
- `EnrollmentError.KeyUnavailable`: Falha na geração/acesso à chave no AndroidKeyStore.
- `EnrollmentError.StorageUnavailable`: Falha de I/O no armazenamento de credenciais.
- `EnrollmentError.Cancelled`: Operação cancelada antes da conclusão.
- `EnrollmentError.ReenrollmentRefused` (código `ReenrollmentRefused`, Dart `reenrollmentRefused`, D-04d): `401
  predecessor-invalid` na `rotate`; `reset()` + `enroll()` (§2.4).
- `EnrollmentError.RenewalBackoff` (código `RenewalBackoff`, Dart `renewalBackoff`): renovação não tentada porque a espera
  da última falha ainda corre (5 s/15 s/60 s após `ServerRejected:SUSPENDED` seguidas, 60 s nas demais). Só com
  `renewalUrl` e instalação inscrita; fora disso o código é `InvalidRequest:PARAMS`.

---

## 4. Política de Transporte HTTP e Segurança

1. **Protocolo:** Requer HTTPS (TLS 1.2+); conexões HTTP puras em texto claro são expressamente rejeitadas.
2. **Redirects (301/302/303/307/308)** — mesmas regras no OkHttp (`addSentomaru`), no `HttpURLConnection`
   (`SentomaruUrlConnection.send`, item 5) e no Dio (`dio.addSentomaru`):
   - Redirect para host fora da allowlist **não é seguido**: o 3xx volta ao chamador; nenhum método, corpo, assinatura, cabeçalho Sentomaru, `Authorization` ou `Cookie` chega ao destino.
   - Redirect para `http://` de host permitido é recusado com `HostNotAllowed` antes de enviar.
   - 301/302/303 viram GET (HEAD continua HEAD) sem corpo e sem assinatura.
   - 307/308 mantêm método e bytes congelados e geram assinatura nova para o novo `@target-uri`.
   - `Authorization` e `Cookie` são removidos quando o host muda.
3. **Idempotência e Retentativas — NÃO IMPLEMENTADO (SDK-NET-4):**
   - **`operationId` assinado (J-01f, 2026-10-16):** o chamador põe `x-sentomaru-operation-id` (16–64 `[A-Za-z0-9-]`, um
     por operação de negócio, **o mesmo em cada nova tentativa**) na requisição; o SDK (OkHttp e Dio) o assina junto com
     os sinais (componentes opcionais, `contracts/p0-http-profile.md`). Cada envio tem nonce novo; o servidor responde
     o primeiro veredito numa nova tentativa (`firstAdmission=false`) e o adaptador do consumidor não roda o efeito de
     novo. Sem o cabeçalho, uma nova tentativa depois do efeito pode executá-lo duas vezes (idempotência do consumidor).
   - O `retryOnConnectionFailure` padrão do OkHttp reenvia a mesma requisição assinada (mesmo nonce); se a primeira tentativa chegou ao servidor, o reenvio recebe 409 (replay) — falha fechada.

4. **Tabela de rotas (G-03c, 17/10/2026):** `addSentomaru(client, SentomaruRoutes.of(hosts, routes))` (Android) e
   `dio.addSentomaru(client, routes: SentomaruRoutes(...))` / `SentomaruRoutes.fromProfileSection(secao)` (Flutter,
   plugin 0.8.0) recebem a seção `network-signing` do perfil da CLI (`contracts/devsecops/cli-v1.md`). Requisição sem
   operação declarada cujo host está em `hosts` e cujo caminho casa com uma rota é assinada como a operação da rota;
   operação declarada prevalece. Regras iguais às do perfil: hosts `[a-z0-9.-]{1,253}` únicos, operação
   `[a-z0-9_]{1,64}`, caminho começando com `/`, segmento `*` casa um segmento não vazio, demais sem diferenciar
   maiúsculas, uma barra final ignorada, sem query/fragmento, caminho repetido recusado. Rota em host fora de
   `allowedHosts` → `HostNotAllowed`; cliente não inicializado (Flutter) → `notInitialized`; nunca sai sem assinatura.
   No Dio a tabela vale só na requisição do chamador, não num salto de redirecionamento (307/308 reassinam com a
   operação da rota; 301/302/303 viram GET sem assinatura). As rotas são tentadas **na ordem e a primeira que casa
   vence**; caminhos comparados já decodificados; **porta ignorada**; host com um ponto final (`api.example.`) é o mesmo
   host e é recusado pela allowlist (`HostNotAllowed`). A instalação **recusa** `hosts` fora de `allowedHosts`
   (Android sempre; Flutter quando o cliente já está inicializado, senão a requisição falha fechada). A evidência em aparelho é só Android/OkHttp; o Dio tem só testes unitários e de transporte real em loopback, sem aparelho.

5. **`HttpURLConnection` (S2, 20/10/2026):** API pública e estática, usável de Java:

   ```java
   HttpURLConnection conn = SentomaruUrlConnection.send(client, routes, "POST", url, bodyBytes, headers);
   HttpURLConnection conn = SentomaruUrlConnection.send(client, routes, method, url, body, headers, operation, opener);
   ```

   `routes` pode ser `null`; `operation` (`SentomaruOperation`, nome e sinais) e `opener`
   (`SentomaruUrlConnection.Opener`, `@Throws(IOException) HttpURLConnection open(URL)`, padrão `url.openConnection()`)
   são opcionais. Declara `IOException` e `SentomaruException` (exceção verificada, capturável em Java). Faz a troca
   inteira e devolve a conexão final já respondida. Regras iguais às do `addSentomaru`, compartilhadas no código
   (`SentomaruWire`, interno): operação pelo cabeçalho `x-sentomaru-operation`, senão `operation`, senão
   `routes.operationFor`; host fora de `allowedHosts` sem operação sai sem assinatura e sem cabeçalhos Sentomaru, com
   operação → `HostNotAllowed`; `routes` com host fora de `allowedHosts` → `IllegalArgumentException`
   (`network-signing.hosts not within allowedHosts`); https, URI canônica, `content-type` exato, corpo copiado na chamada
   e limitado a `Profile.MAX_BODY_BYTES`, sinais e `x-sentomaru-operation-id` assinados; renovação J-04r antes da
   operação e um reenvio após `session-expired`, com os mesmos mapeamentos (`session-unavailable` →
   `EnrollmentRequired`, `installation-suspended` → `ServerRejected(SUSPENDED)`); redirects seguidos pelo SDK
   (`setInstanceFollowRedirects(false)`, `MAX_REDIRECTS` = 5). Diferenças do OkHttp: corpo só `ByteArray` (sem
   streaming nem tamanho desconhecido), enviado bufferizado; `Host`, `Content-Length`, `Transfer-Encoding` nos cabeçalhos
   → `InvalidRequest:HEADER_NAME`; nome repetido com outra grafia → `InvalidRequest:HEADER_VALUE`; corpo em GET/HEAD →
   `InvalidRequest:METHOD`; um 403 lido para procurar `session-expired` volta como conexão delegadora (mesmo status,
   cabeçalhos e corpo). Como o `retryOnConnectionFailure` do OkHttp, a implementação da plataforma pode reenviar
   sozinha um corpo bufferizado após falha de conexão (no JDK, `sun.net.http.retryPost`): mesmo nonce, 409 se o primeiro
   chegou — falha fechada (não testado). Evidência: testes JVM com o `HttpURLConnection` do JDK, sem aparelho.

6. **Falha de pino, evento local (D-07d, 26/10/2026):** com o app protegido pela `sentomaru protect` com
   `network-pinning` (`contracts/devsecops/cli-v1.md`, "network-pinning (D-07)"), o `SentomaruClient.initialize` lê a
   meta-data `br.com.ebees.sentomaru.pinning.hosts` (hosts separados por vírgula; formato fora da regra = nenhum host;
   `SentomaruClient.pinnedHosts: Set<String>`). Uma `IOException` de qualquer troca do `addSentomaru(client, routes,
   events)` ou do `SentomaruUrlConnection.send(client, routes, method, url, body, headers, operation, events, opener)`
   (sobrecarga nova; as anteriores não mudam) com um host da meta-data vira `SentomaruTransportEvent` (`signals`:
   `kind` `TRANSPORT`, `type` `pin_failure`, `reason` `pin_mismatch` | `tls_untrusted` | `tls_other`, `host`,
   `sequence` compartilhada) para quem chamou `SentomaruSignalEvents.addTransportListener(executor, listener)`
   (`removeTransportListener`, `hasTransportListeners`; `observePinFailure(host, reason)` descarta motivo fora do
   conjunto e host que não seja nome em minúsculas). `pin_mismatch` = `CertificateException` com a mensagem
   `Pin verification failed` da plataforma na cadeia de causas; `tls_untrusted` = outra `CertificateException`,
   `CertPathValidatorException` ou `SSLPeerUnverifiedException`; `tls_other` = outra `SSLException` (inclusive
   `SSLHandshakeException` sem falha de certificado na cadeia, refinamento da spec); sem TLS na cadeia, nenhum evento. A exceção chega
   ao app sem mudança; nada é repetido, gravado nem enviado (D-07x9); sem meta-data, sem `events` ou sem ouvinte, nada
   muda. Vocabulário em `TransportEventCodes`, fora do catálogo de sinais. Casamento exato do host (subdomínio de
   `includeSubdomains` não gera evento). Evidência: testes JVM com handshake TLS real e recusa de pino imitada no
   cliente; a recusa da plataforma em emulador e aparelho é da D-07e.

---

## 5. Regras de Consumidor ProGuard / R8 (`consumer-rules.pro`)

Os arquivos AAR empacotam regras de consumidor (`proguard.txt`) que preservam as interfaces públicas:

```proguard
# Símbolos públicos do SDK Android
-keep class br.com.ebees.sentomaru.sdk.SentomaruClient { *; }
-keep class br.com.ebees.sentomaru.sdk.SentomaruConfig { *; }
-keep class br.com.ebees.sentomaru.sdk.EnrollmentChallenge { *; }
-keep class br.com.ebees.sentomaru.sdk.EnrollmentGrant { *; }
-keep class br.com.ebees.sentomaru.sdk.InstallationState { *; }
-keep class br.com.ebees.sentomaru.sdk.ReenrollmentReason { *; }
-keep class br.com.ebees.sentomaru.sdk.EnrollmentError** { *; }
-keep class br.com.ebees.sentomaru.sdk.IntegrityTokenSource { *; }
-keep class br.com.ebees.sentomaru.sdk.IntegrityRequestHash { *; }
-keep class br.com.ebees.sentomaru.sdk.PlayIntegrityTokenSource { *; }
-keep class br.com.ebees.sentomaru.sdk.transport.SentomaruInterceptor { *; }
-keep class br.com.ebees.sentomaru.sdk.transport.SentomaruOperation { *; }
# G-03c: a CLI (network-signing) procura esta classe pelo nome no DEX do app
-keepnames class br.com.ebees.sentomaru.sdk.transport.SentomaruRoutes
# S2: idem para o transporte HttpURLConnection (só o nome: num app minificado ela só existe se o app a chama)
-keepnames class br.com.ebees.sentomaru.sdk.transport.SentomaruUrlConnection

# Núcleo RFC 9421 e erros
-keep class br.com.ebees.sentomaru.core.SentomaruError** { *; }
-keep class br.com.ebees.sentomaru.core.SentomaruException { *; }
-keep class br.com.ebees.sentomaru.core.SignedMessage { *; }
-keep class br.com.ebees.sentomaru.core.FrozenRequest { *; }
-keep class br.com.ebees.sentomaru.core.Profile { *; }

# Signer Keystore
-keep class br.com.ebees.sentomaru.signer.KeystoreSigner { *; }
-keep class br.com.ebees.sentomaru.signer.GenerationResult** { *; }
-keep class br.com.ebees.sentomaru.signer.StrongBoxUnavailableError { *; }

# Signals
-keep class br.com.ebees.sentomaru.signals.SignalsCollector { *; }
-keep class br.com.ebees.sentomaru.signals.SignalsCatalog { *; }
-keep class br.com.ebees.sentomaru.signals.SignalObservation { *; }
-keep class br.com.ebees.sentomaru.signals.SignalState { *; }
-keep class br.com.ebees.sentomaru.signals.SignalsSnapshot { *; }
```

---

## 6. Adapter Flutter (`sentomaru_flutter`)

O plugin Flutter expõe o cliente Dart idêntico em capacidade:

```dart
class SentomaruClient {
  Future<InstallationState> getInstallationState();
  Future<EnrollmentGrant> enroll(EnrollmentChallenge challenge, {bool requiresHardware = false});
  Future<void> unenroll();
  SentomaruDioInterceptor createDioInterceptor();
}
```

- **Integração com Dio:** `SentomaruDioInterceptor` assina requisições no estágio final (após serialização em bytes).
- **Sem UI biométrica no interceptor:** A assinatura da chave do laboratório é não-interativa; nenhuma UI é disparada dentro da camada de rede.
- **Evento de Risco (`SentomaruRiskEvent`, v1.1):** `dio.addSentomaru(client, onRiskEvent: ...)` recebe o objeto `riskEvent` do corpo de uma resposta de erro, se o backend consumidor o enviar (o servidor Sentomaru não o emite). Campos: `code`, `reason`, `riskIndex?`, `riskBand?`, `challengeNonce?`. Consultivo; não há veredito booleano de segurança.

---

## 7. SDK iOS (`sdk/ios`, SwiftPM)

- **D-10a (núcleo, iOS 15+):** `SentomaruClient` em Swift com o mesmo protocolo do Android (perfil `sentomaru-p0`,
  inscrição v1.7 com `attestationFormat: "apple-app-attest"`, rotação D-04d, renovação J-04r), chave da requisição só no Secure Enclave
  (`Unsupported:SECURE_ENCLAVE` sem ele), `Unsupported:APP_ATTEST` sem App Attest, Keychain
  `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` e auxiliar de `URLRequest`. Sem sinais na D-10a (ver D-10e abaixo). Provado só por `swift test` no macOS: os 81 vetores cross-SDK, fluxo com App Attest e servidor falsos e
  Keychain isolado. O `swift test` não usa iPhone nem objeto real da Apple; a evidência de aparelho da D-09d (iPhone 13, 27/10/2026, SDK da branch `next/d10a`; perfil, "Objetos reais") foi conferida só offline, nos vetores. Superfície e limites em [`sdk/ios/README.md`](../../sdk/ios/README.md).
- **Com a D-09c na mesma árvore (contrato v1.11, integração da onda 2 iOS + Trust):** o corpo da renovação iOS é
  `{"appAssertion": …}`, com uma asserção App Attest ligada à sessão, ao nonce e à SPKI. O servidor desta árvore exige
  esse corpo na renovação de instalação iOS com chave App Attest gravada (sem ele, 403 `session-unavailable`) e o
  confere com o `authData` real da D-09d. Do lado do SDK, a compatibilidade está provada só contra os vetores do
  servidor (`app-attest-assertion-v1.json`, incluídos os casos da D-09d e as assertions reais do iPhone) e um servidor
  falso, em `swift test`: a D-10a ainda não foi reexecutada contra o servidor com a D-09c/D-09d (local ou HML).
- O `send` passado a `enroll`, `rotate` e `renew` não pode chamar o mesmo cliente: a fila do cliente não é reentrante e
  a chamada espera para sempre.
- **D-10b (plugin Flutter 0.18.0):** o plugin ganha `ios/` (pod CocoaPods, iOS 15+) que responde o mesmo canal
  `sentomaru_flutter` sobre este SDK, com a mesma API Dart. No iOS, `playIntegrityCloudProjectNumber`, `strongBox` e as
  rotas de reatestação são ignorados; `requiresHardware: true` é recusado antes de criar chave (`InvalidRequest:PARAMS`,
  D-IOS9); `reenrollmentReason` é sempre nulo; `collectSignals` devolve lista vazia. Sem App Attest ou Secure Enclave,
  `SentomaruErrorCode.unsupported` (novo, no fim do enum) com `details` `Unsupported:APP_ATTEST` ou
  `Unsupported:SECURE_ENCLAVE`. Sem parâmetro de ambiente App Attest: vale o entitlement
  `com.apple.developer.devicecheck.appattest-environment` do build, igual ao `apple_attest_environment` do escopo.
  Nenhuma mudança de protocolo. Provado só no simulador com fakes; aparelho e servidor pendentes.
- **D-10e (sinais iOS; plugin Flutter 0.19.0):** `SignalsCollector` coleta no iOS as seis capacidades do catálogo
  1.0.0, com os mesmos ids, versões, ordem e formato do Android. O `SentomaruURLSession` criado com
  `signals: SignalsCollector()` as assina em `x-sentomaru-signals` (H3) quando a requisição não traz snapshot; o padrão é
  `nil`, sem coleta, como o interceptor OkHttp. Estados no iOS: `debug_attached`
  por `P_TRACED` (`sysctl`; `ERROR` se a chamada falhar); `emulator_detected` `DETECTED` no simulador e `NOT_DETECTED`
  no aparelho; `root_indicated` só no aparelho (caminhos de jailbreak, escrita fora do sandbox, biblioteca de hooking
  carregada; detalhe com três booleanos, nunca o caminho; resultado guardado 60 s por processo, com o `observedAt` da
  checagem real: uma regra com `maxSignalAgeSeconds` < 60 mede pelo `collectedAt` e não garante essa idade ao
  `root_indicated`, que pode ter até 59 s, e um jailbreak ou hook carregado depois da última checagem pode passar sem
  ser visto por até 60 s; TTL fixo), `UNKNOWN` no simulador e num Mac (Catalyst ou app de iPhone no Mac, `reason=not_ios_device`);
  `app_signing_digest`
  `UNSUPPORTED`; `installer_source` `UNKNOWN` (`reason=not_applicable`); `os_version` `DETECTED` com `platform` e
  `release`. Os ids da D-05 e da D-12c, quando pedidos, saem `UNSUPPORTED`. O plugin responde `collectSignals` e
  `collectSignalsSnapshot` no iOS com esse coletor (antes: lista vazia). Desde o catálogo 1.7.0 o
  `supportedPlatforms` de `debug_attached`, `emulator_detected`, `root_indicated` e `os_version` diz `android` e `ios`
  (`minIosVersion` 15.0) e as `limitations` delas descrevem o iOS; `app_signing_digest` e `installer_source` seguem só
  `android` (no iOS não têm valor). Sem mudança no servidor:
  as seis presentes bastam para a política padrão não dar `SIGNALS_MISSING`
  (teste do servidor, sobre o snapshot de referência
  `verification/sdk/vectors/ios-signals-snapshot-v1.json`).

---

## 8. Ponte dos híbridos (D-22a, rascunho)

`contracts/sdk/hybrid-bridge-v1.json` lista as chamadas que o plugin Flutter troca entre o Dart e o SDK Android (17 métodos,
argumentos, forma da resposta e códigos de erro da ponte). As camadas React Native, Capacitor/Cordova/Ionic e .NET MAUI
(D-22a..c) repetem esse conjunto e não têm lógica própria. O teste `sdk/flutter/sentomaru_flutter/test/hybrid_bridge_contract_test.dart`
falha se o plugin e o arquivo divergirem. Nenhuma camada híbrida existe ainda; o arquivo é o ponto de partida delas.

**D-22a1/D-22a2 (3/11/2026):** o lado nativo dessas chamadas vive em `sdk/hybrid-core` (`SentomaruBridge`, `PluginConfig`,
`EnrollmentTransport`), compilado por diretório-fonte compartilhado no plugin Flutter e no módulo React Native Android
(`sdk/react-native/android`, uma entrada `call(método, argumentos)`; `body` e bytes de resposta cruzam como Base64). O comportamento do
plugin Flutter não mudou (67 testes JVM iguais, R8 mantém os nomes). Falta a fachada TypeScript, o app de exemplo e o job de CI.
