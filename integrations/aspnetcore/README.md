# Sentomaru.AspNetCore

Adapter oficial ASP.NET Core (.NET 10) para serviços consumidores (ex.: um serviço de pedidos) validarem integridade de requisições móveis via Sentomaru.

## 🚀 Capacidades

- **`ISentomaruClient` / `SentomaruClient`**: Cliente HTTP tipado com autenticação Bearer de workload e timeout estrito (default 2s). Nunca fabrica um "allow": indisponibilidade do Sentomaru volta como falha 503.
- **`SentomaruExtractor`**: Extração de `ForwardedMessageDto` a partir de `HttpRequest` (URI absoluta, corpo em Base64 até 64 KiB, inclusive sem `Content-Length`). Encaminha **somente** a allowlist `SentomaruExtractor.ForwardedHeaders`: componentes assinados do perfil (`content-type`, `content-digest`, `x-sentomaru-profile/org/app/environment/session/operation`), `Signature`, `Signature-Input`, `Content-Length` e `x-sentomaru-signals` (sinais observados pelo cliente, não assinados). `Authorization`, `Cookie` e qualquer outro cabeçalho do usuário nunca são enviados ao Sentomaru.
- **`[SentomaruIntegrity("operacao")]`**: Filtro de ação / endpoint que valida a prova criptográfica e as políticas de integridade do Sentomaru antes da execução da action.
- **`SentomaruClientOptions`**: Configuração centralizada para endereço base, `org/app/env`, token de workload, timeout e resiliência (fail-open vs fail-closed).

## 📦 Como Usar

### 1. Injeção de Dependência no `Program.cs`

```csharp
using Sentomaru.AspNetCore;

builder.Services.AddSentomaruClient(options =>
{
    options.BaseAddress = new Uri(builder.Configuration["Sentomaru:BaseAddress"]!); // https fora de Development
    options.WorkloadToken = builder.Configuration["Sentomaru:WorkloadToken"]; // do secret store, nunca do appsettings versionado
    options.Org = "ebees";
    options.App = "exampleapp";
    options.Env = "prod";
    options.Timeout = TimeSpan.FromSeconds(2);
    options.EnrollmentTimeout = TimeSpan.FromSeconds(10); // 4.8.0: só a inscrição (verifica a atestação); padrão 10 s
});
```

`Timeout` vale para avaliação, desafio, renovação e as demais chamadas. A inscrição verifica a atestação (cadeia Android
ou App Attest: ~1,1 s só de verificação no servidor de testes, e um consumidor real viu passar dos 2 s) e espera o maior entre
`Timeout` e `EnrollmentTimeout` (4.8.0), nunca menos que `Timeout`. `Timeout` zero, negativo ou infinito deixa o prazo
do `HttpClient` também para a inscrição. Os dois têm teto de 5 min, conferido na partida. Prazo estourado é 503
`sentomaru-unavailable` para o app, e uma recusa da inscrição sai no log com o `AttestationReason` (4.8.0).

### Semântica de segurança (fail closed)

| Situação | Resultado |
|---|---|
| Sem `Signature-Input` **ou** sem `Signature` (ou vazios) | 401 `proof-required` (sempre; `FailOpen` não muda isso). Cabeçalhos presentes não significam prova válida: a validade só o Sentomaru decide |
| `ISentomaruClient` não registrado | 503 `integrity-unavailable` |
| Corpo > 64 KiB | 413 `body-limit` |
| Cabeçalhos de assinatura presentes (não verificados), Sentomaru fora (timeout/503) | 503; só em `Development` com `FailOpen: true` a action roda — nesse caso uma prova forjada passa durante a queda |
| Veredito `allow`/`shadow` | action roda; `deny`/`challenge`/desconhecido → 403/401 (4.5.0: `challenge` `step_up` roda só se o `ISentomaruChallengeHandler` do consumidor devolver `Proceed`; 4.6.0: `reattest` em `ZeroTrust` é sempre 401) |
| Fora de `Development`: `FailOpen: true`, `BaseAddress`/`PublicBaseUrl` http, nem `PublicBaseUrl` nem `KnownProxies`, ou `Enabled: false` sem `DisabledAcknowledged: true` | o host **não sobe** (`OptionsValidationException` em `ValidateOnStart`) |
| `Enabled: false` + `DisabledAcknowledged: true` fora de `Development` | chave de desligamento deliberada e auditável: log Error na partida e em cada requisição protegida liberada sem verificação |

`@target-uri`: `[SentomaruIntegrity(PublicBaseUrlOverride=...)]`, senão `Sentomaru:PublicBaseUrl`, senão a própria requisição; `X-Forwarded-Proto`/`X-Forwarded-Host` só valem quando o par direto está em `Sentomaru:KnownProxies`.

`DeviceAssuranceLevel.Observe` (antigo `DeviceTrustLevel.Observe`/`RuntimeTrust`) é **só telemetria e não oferece proteção**: a action sempre roda; se houver prova ela é avaliada e o veredito vai para o log. Nunca é padrão (`ZeroTrust` é); declare-o explicitamente só em operações conscientemente desprotegidas. `Enabled: false` desliga a verificação: em `Development` com aviso; fora dele só com `DisabledAcknowledged: true` (log Error), caso contrário o host não sobe e, se a validação for contornada, o filtro responde 503.

## 4.17.0 — observação web pronta (só acréscimos; não publicado)

Uma chamada de registro e uma linha no ponto onde o host já valida o desafio de bot (CAPTCHA/Turnstile/similar). Sem banco, sem migração, sem worker nem armazenamento próprio no host. Desligado por padrão: com `Enabled` falso nada é enviado nem gravado.

```csharp
// Program.cs (depois de AddSentomaruClient): o único diretório que o pacote precisa
services.AddSentomaruWebObservation(o =>
{
    o.Enabled = builder.Configuration.GetValue<bool>("Sentomaru:Web:Enabled");
    o.OutcomeDirectory = "/var/lib/app/sentomaru-web";
});

// onde o host valida o desafio (injete ISentomaruWebObserver); passed: true | false | null (sem veredito)
observer.ObserveChallenge("login", passed);
```

Há também `AddSentomaruWebObservation(IConfiguration, "Sentomaru:Web")` (seção com as mesmas opções).

- **Fonte única.** Só o desafio tem fonte: passou = `NOT_DETECTED`, falhou = `DETECTED`, ausência/erro/ignorado = `UNKNOWN` (`SentomaruWebChallengeState` também serve). Os outros quatro sinais do catálogo vão **sempre `UNKNOWN`, nunca `NOT_DETECTED`**. A resposta é só consultiva e nunca muda o que o usuário vê.
- **Sem espera, sem repetição.** `ObserveChallenge` volta na hora; a chamada tem prazo próprio (`Deadline`, 1 s) e qualquer falha, recusa ou tempo esgotado só vira contador. Só age com `SentomaruClientOptions.Enabled` também ligado. `ObserveChallengeAsync` espera o fim (testes, desligamento). `Operations` é uma lista opcional de nomes permitidos; vazia, vale qualquer nome `[a-z0-9._-]{1,64}` (passe constantes, nunca id de conta, pedido ou sessão).
- **Contadores.** `SentomaruWebObservationMetrics` (por operação e resultado: `skipped`, `build-null`, `200`/código HTTP, `exception`, `timeout`, `outcome-recorded`, `outcome-skipped`, `outcome-failed`) e o medidor `Sentomaru.AspNetCore.Web` (`sentomaru.web.observations`) para OpenTelemetry/Prometheus.
- **Desfecho por célula, em arquivo.** Cada resposta válida soma 1 na célula (dia UTC, operação, cinco estados, ação avaliada, versão da política): sem conta, sessão, aparelho, IP nem hora. Os contadores ficam em `OutcomeDirectory`, um arquivo JSON por dia e por processo (escrita atômica; vários processos dividem o diretório sem travar um ao outro, a leitura junta os arquivos; dias com mais de `OutcomeRetentionDays`, 90, são apagados). Sem `OutcomeDirectory` os contadores ficam em memória. Resposta inválida (sem versão de política, ação fora de `allow`/`challenge`/`defer`) e falha de gravação não chegam ao chamador.
- **Tabela semanal.** O serviço de exportação vem registrado pela mesma chamada e escreve `web-outcome-table-v1` (`contracts/web/web-outcome-table-v1.md`) como arquivo, um por semana fechada (segunda a segunda, UTC) e versão de política, em `OutcomeDirectory/tables` (ou `ExportDirectory`), sem reescrever o existente. Célula com menos de 5 avaliações é omitida; tudo sai `unlabeled` (sem fonte de rótulo). Não há endpoint nem envio a ninguém. `ExportEnabled = false` desliga. `SentomaruWebOutcomeTable.Build` é o builder puro.
- **Ponto de extensão opcional.** `ISentomaruWebOutcomeStore` (`RecordAsync`, `ReadAsync`) só existe para quem quiser outro armazenamento: `services.AddSingleton<ISentomaruWebOutcomeStore, MeuStore>()`. Não é o caminho padrão.

## Mensagem ao usuário final (só acréscimos; não publicado)

`SentomaruUserMessage` traz o texto padrão de uma operação bloqueada (`pt-BR`, `en`, `es`: "Algumas operações críticas estão bloqueadas até a aprovação…"), a resolução de idioma e o mapa de código de recusa para situação (`contracts/sdk/user-message-v1.md`). Com `SentomaruClientOptions.IncludeUserMessage = true` o corpo de recusa (401 `proof-required`/`challenge-required`, 403, 5xx) ganha o membro `message`, no idioma de `Accept-Language`; `UserMessages` troca o texto por idioma (em branco = padrão). Desligado por padrão: o corpo de recusa é contrato que os apps já leem e fixam, então segue idêntico até o host ligar. Código e status nunca mudam; `operation-replayed`, `caller-context-missing` e `body-limit` não levam mensagem; o texto não traz código nem motivo.

## 4.16.0 — avaliação web de política (só acréscimos; não publicado)

O backend do consumidor que observa sinais web (catálogo fechado) pergunta à política `channel: web` do escopo (`contracts/web/web-evaluation-v1.md`):

```csharp
var request = SentomaruWeb.TryBuild("checkout", [(SentomaruWebSignals.CookieReplayNoProof, SentomaruWebSignalStates.Detected)]);
if (request is not null)
{
    var result = await client.EvaluateWebAsync(request, ct);   // POST /v1/{org}/{app}/{env}/web/evaluations
    if (result.Succeeded) { var seen = result.Value!.EvaluatedAction; /* o consumidor decide; nunca bloqueie só por isto */ }
}
```

- **Sempre consultiva.** `Advisory` é `true`, `Mode` é `shadow` e `Recommendation` nunca é `challenge` nem `deny`; resposta que diga outra coisa vira `502 invalid-response`. `EvaluatedAction` é o que as regras diriam. Um sinal web é **declaração** do backend ou do navegador: pode ser forjado ou suprimido, e não decide sozinho.
- **`SentomaruWeb.TryBuild`** devolve `null` para operação fora de `[a-z0-9._-]{1,64}`, sinal fora do catálogo, estado fora de `DETECTED`/`NOT_DETECTED`/`UNKNOWN`, sinal repetido ou mais de 16: o servidor responderia `400 web-evaluation-format` para o corpo inteiro. Sinal que você não lista o servidor lê como `UNKNOWN`, nunca como limpo.
- Escopo sem política web ativa: `200` com `PolicyId` nulo, `defer` e `WEB_POLICY_NONE`. Precisa de um Sentomaru com a migração 0126.
- `EvaluateWebAsync` tem implementação padrão 501 `not-implemented`: um cliente escrito antes da 4.16.0 continua compilando. Nada é enviado além de operação e sinais: sem sessão, cookie, conta, usuário, IP, User-Agent ou URL.

## 4.15.0 — leitor do veredito da reconciliação offline (só acréscimos; não publicado)

O backend do consumidor que repassa a reconciliação do app (D-26) e guarda a resposta ganha o mesmo leitor puro que os SDKs Android, Dart e Swift já têm:

```csharp
var verdict = SentomaruOfflineVerdict.Parse(responseBody);   // null quando não é um veredito bem formado
if (verdict is { Accepted: true, Advisories.Count: > 0 }) { /* prova mais fraca: o consumidor pondera */ }
```

- **`Signals`** só guarda os três códigos do contrato (`offline_clock_tampered`, `offline_chain_broken`, `offline_chain_gap_detected`); código fora deles, ou resposta que se contradiz (aceita com sinal, recusada sem), não é veredito (`null`).
- **`Advisories`** (v1.18) diz o que o veredito não pôde conferir (hoje `offline_boot_unavailable`). **Não é sinal e nunca muda `Accepted`.** Código desconhecido é mantido, repetição cai, lê no máximo 8, e lista ausente ou malformada vira lista vazia: nunca é motivo para recusar o veredito.
- Não chama o Sentomaru e não decide nada; o Índice de Risco não lê o aviso.

## 4.14.0 — rótulos de segmento na avaliação de Fraud (só acréscimos; não publicado)

A calibração do Fraud (F-03c) segmenta por plataforma, versão do SDK, nível de atestação e operação, e o servidor só os guarda se a avaliação os declarar em `context` (migração 0122). O adaptador ganhou o campo e dois auxiliares:

```csharp
var request = new FraudEvaluationRequestDto { DeviceId = deviceHandle, SubjectId = accountId }
    .WithInstallation(HttpContext)
    .WithOperation(HttpContext)                                         // a operação da rota que o filtro protegeu (ex.: "pix.transfer")
    .WithContext(platform: "android", sdkVersion: "0.6.1", attestationLevel: "hardware-key-app-match");  // só o que o consumidor realmente sabe
```

- **O que o adaptador sabe sozinho:** só a operação (o nome declarado na própria rota, em `HttpContext.Items[SentomaruIntegrityAttribute.OperationItem]`, nunca lido do cliente). A resposta da avaliação não traz plataforma, versão do SDK nem nível de atestação: esses três só entram se quem integra os tiver (o app os envia ao backend, ou o backend os lê do que já guarda). Não os deduza do `User-Agent`.
- **Declarado, não verificado, nunca pontuado.** O campo só alimenta o relatório de calibração; não muda o score, a decisão nem a política.
- **Formato estreito, não vocabulário fechado.** Só `platform` (android, ios ou web) e `attestationLevel` (um degrau do `assurance-levels-v1` ou `not-covered`) são conjuntos fechados. `sdkVersion` é uma versão pontilhada de 2 a 4 partes numéricas com sufixo `-`/`+` opcional (até 32 caracteres); `operation` tem de 1 a 48 de `[0-9A-Za-z._-]`, começa com letra e não tem sequência de 5 dígitos. Esses dois são rótulos que o consumidor escolhe: o formato dificulta, mas não impede, pôr ali um identificador de pessoa (um nome curto cabe). **Envie só nomes de rota e de build, nunca id de conta, e-mail ou nome.** O servidor recusa a avaliação inteira (400 `fraud-evaluation-format`) se um membro sair do formato, por isso `WithContext` descarta o membro inválido em vez de enviá-lo.
- **Só com servidor 0122 ou mais novo.** Um Sentomaru anterior recusa o membro `context`. Sem chamar `WithContext`/`WithOperation`, o corpo é o mesmo da 4.13.0 (o membro sai omitido, não nulo).

## 4.12.0 — a instalação chega à avaliação de Fraud (só acréscimos; não publicado)

`POST fraud/evaluate` só lê o histórico de atestação do servidor (regra `DEVICE_BOOT_STATE_CHANGED`) se o consumidor declarar `deviceSignals.installationId`. Até aqui nenhum consumidor enviava, e a taxa de divergência da reatestação ficava em zero por falta de entrada. O adaptador agora entrega o id da instalação que o próprio filtro já verificou:

```csharp
// Depois de [SentomaruIntegrity] ter avaliado esta requisição (a instalação vem de HttpContext.Items, nunca do corpo).
var request = new FraudEvaluationRequestDto { DeviceId = deviceHandle, SubjectId = accountId, TransactionId = operationId }
    .WithInstallation(HttpContext);                       // sem avaliação, recusada ou sem id: devolve o pedido como está
var fraud = await client.EvaluateFraudAsync(request, ct);  // POST /v1/{org}/{app}/{env}/fraud/evaluate
```

- **Declaração, não prova.** O id é do próprio consumidor; o servidor só o compara com o seu histórico, ignora um id que não pertence ao escopo (a resposta é a mesma de uma instalação sem histórico) e **não guarda o vínculo**. Não passe um id lido do app ou do usuário.
- **Opcional.** Sem avaliação do Sentomaru na requisição, o campo fica de fora e nada falha. `WithInstallation(Guid)` serve a quem guardou o id de outra forma.
- **O que é enviado.** Só `deviceId`, `subjectId`, `transactionId`, `deviceSignals.installationId` e `sessionSignals.credentialChangedSecondsAgo` (0 a 2592000 s); o servidor recusa membros que não conhece, por isso o adaptador não envia outros.
- `ISentomaruClient.EvaluateFraudAsync` tem implementação padrão 501 `not-implemented`: um cliente escrito antes da 4.12.0 continua compilando.
- Quem chama `POST /fraud/evaluate` fica a cargo de quem integra; este adaptador só entrega o campo. Contrato: `contracts/fraud/api-v1.md`, seção "Declared installation id: who sends it".

## 4.7.0 — núcleo de decisão sem MVC (só acréscimos; não publicado)

- `SentomaruEvaluationPipeline.DecideAsync(HttpContext, SentomaruEvaluationOptions, ILogger?)` é a decisão do
  `[SentomaruIntegrity]` sem MVC: devolve `SentomaruDecision` (`Kind` `Proceed` ou `Refuse`, `Reason`, `StatusCode`,
  `Error` com o mesmo corpo `SentomaruApiError` e `Evaluation`). Uma chamada avalia no máximo uma vez e grava os mesmos
  itens em `HttpContext.Items` (`ObservationItem`, `OperationIdItem`, `FirstAdmissionItem`, `StepUpProceededItem`).
- O atributo passa a delegar a ela: mesmos status, corpos, logs e itens da 4.6.0. Continuam no atributo só a execução
  da action e a liberação do operation id depois de um 5xx (J-01f).
- `SentomaruEvaluationOptions` traz `Operation`, `AssuranceLevel`, `AllowOperationReplay`, `PublicBaseUrlOverride` e
  `UseChallengeHandler` (padrão `true`, como o atributo). Com `false` (verificador de gateway, que não tem sessão para
  step-up), todo `challenge` vira 401 `challenge-required` e o `ISentomaruChallengeHandler` nunca é chamado.
- Para quem chama o núcleo: rode a operação **uma vez** num `Proceed`; num `Refuse`, responda `StatusCode` com `Error`
  como corpo JSON. `Reason` diz por que roda (`Verified`, `Observe`, `Disabled`, `FailOpen`, `StepUpProceeded`).
- Uso previsto: o verificador de gateway (the Sentomaru gateway verifier contract). Nada muda para quem só usa o
  atributo.
- **Correção de segurança:** com `PublicBaseUrl` (ou `PublicBaseUrlOverride`), um caminho que
  comece com `//` (ou `/\`) era uma referência de rede na resolução do `@target-uri`: `//evil.example/x` virava
  `https://evil.example/x`, e a API não confere o host. O `SentomaruExtractor` agora lança `UriFormatException` nesse
  caso e sempre que a autoridade resolvida difere da configurada; o atributo responde **400 `forward-format`** sem
  chamar o Sentomaru (antes, uma `UriFormatException` virava 503 `integrity-unavailable`). O
  `SentomaruEnrollmentControllerBase` já respondia 400 `forward-format`. A montagem continua sendo a resolução relativa
  (a canonização dos vetores não muda).
- **Validação de partida:** `PublicBaseUrl` com user info é recusado em qualquer ambiente.
- Paridade: os vetores de `verification/sdk/vectors/` e as mutações de um byte do `SdkVectorTests`, enviados
  por HTTP ao atributo (MVC) e ao núcleo chamado de um **endpoint mínimo de teste** (sem MVC e sem `UsePathBase`; não é o
  host do verificador, cuja paridade é do verificador), dão a mesma resposta e, quando há avaliação, o mesmo envelope
  byte a byte (`GatewayParityTests`; valores na seção 6 do contrato).

## 4.10.0 — vínculo do token do IdP ao hardware (só acréscimos; não publicado)

Proposta ao dono (contrato the Sentomaru session bindings contract, OpenAPI v1.15). Desligado por padrão.

- **Configuração:** `Sentomaru:TokenBindingIdpIssuer` = o `iss` do seu IdP. Com ele, o filtro calcula `externalTokenBindingHash = SHA-256(org:app:idpIssuer:sub:tokenIdentifier)` com os claims do **principal já autenticado** (`sub`; `sid`, senão `jti`) e o envia na avaliação. O adaptador nunca lê nem envia o token.
- **Registro (no login):** depois de inscrever/renovar o aparelho, chame `BindSessionAsync` com `installationId`, `grantSessionId` (o grant vivo), um `subjectRef` que seja pseudônimo (nunca e-mail, CPF ou nome), o mesmo hash (`SentomaruTokenBinding.ForPrincipal`) e o slug do emissor. A cada refresh do IdP, `RotateSessionBindingAsync` troca o hash sem nova atestação. `ClearSessionBindingAsync` apaga o vínculo (pedido do titular).
- **Falha fechada:** grant vinculado + avaliação sem hash (claim ausente, IdP não configurado) = `403 token-hardware-mismatch`. Um `sid`/`jti` vazio faz o hash voltar a ser estável por usuário; o adaptador se recusa a calcular nesse caso (devolve nulo).
- **Limite:** prova que o token apresentado é o registrado para aquele aparelho; não prova quem é o usuário (isso é do IdP) e depende de você validar o token antes (o adaptador confia no principal que o ASP.NET autenticou).

## 4.9.0 — repasse da reatestação (só acréscimos; não publicado)

- `ISentomaruClient.IssueReattestationChallengeAsync` e `ReattestAsync` (padrão: 501 `not-implemented`) e os DTOs
  `ReattestationEnvelopeDto`, `ReattestationChallengeResponseDto`, `ReattestationResponseDto`. `SentomaruEnrollmentControllerBase`
  ganha `IssueReattestationChallengeAsync` e `ReattestAsync`, uma linha por rota, como a inscrição e a renovação:
  `POST …/reattestations/challenges` e `POST …/reattestations` (contrato the Sentomaru re-attestation API contract).
- Chegam ao app: 400, 401 `proof-invalid` e `challenge-invalid`, 403 `reattestation-disabled`, `reattestation-unsupported`,
  `session-expired` e as demais recusas de sessão, 409, 429 e 503 `verifier-unavailable` (o desafio não foi consumido; o SDK
  tenta mais uma vez). O resto segue a regra das outras rotas (credencial do backend vira 502, indisponibilidade vira 503).
- **Limite:** o cabeçalho `Retry-After` do 429 não é repassado; o SDK usa o intervalo padrão de "agora não".

## 4.6.0 — desafio `reattest` (só acréscimos; não publicado)

- `reattest` passa a ser um tipo conhecido (contrato v1.10): `SentomaruChallengeKinds.Reattest`,
  `SentomaruChallengeKinds.Closed` (`fresh_signals`, `step_up`, `reattest`) e `SentomaruChallengeKind.Reattest`
  (declarado depois de `Unknown`, para os valores da 4.5.0 não mudarem de número).
- O corpo do 401 é o mesmo da 4.5.0 com o tipo:
  `{"code":"challenge-required","attestationReason":null,"challengeKind":"reattest"}`.
- **O gancho `ISentomaruChallengeHandler` nunca roda para `reattest`**, nem um que devolveria `Proceed`: quem confere é
  o Sentomaru, na próxima avaliação. O app chama `reattest()` (a reatestação) e repete a operação uma vez com
  nonce novo; o adaptador não guarda estado nem repete nada.
- A política pode exigir uma reatestação recente aprovada pelo servidor antes de uma operação
  (`reattestationMaxAgeSeconds`). O estado da reatestação não chega ao consumidor: só o `reasonCode` da regra e o tipo.
- A 4.5.0 já entrega o mesmo 401 com `challengeKind: reattest` (tipo desconhecido, bruto, sem gancho); a 4.6.0 só dá
  nome ao tipo (`KnownChallengeKind` vale `Reattest` em vez de `Unknown`).
- **Mudança de comportamento para quem testa `KnownChallengeKind`:** um `switch` escrito contra a 4.5.0 com um ramo
  `Unknown` (ou `default`) para "tipo novo" deixa de receber `reattest`, que passa a cair em `Reattest`. Quem só repassa
  o tipo lê o valor bruto (`EvaluationResponseDto.ChallengeKind` ou `SentomaruObservation.ChallengeKind`), que não
  mudou. A 4.5.0 não foi publicada; a primeira publicação já sai com os dois.

## 4.5.0 — tipo do desafio e gancho de step-up (só acréscimos; não publicado)

- O filtro lê `challengeKind` da avaliação (contrato v1.9). Num veredito `challenge` com tipo, o corpo do 401
  `challenge-required` leva o tipo bruto, conhecido ou não:
  `{"code":"challenge-required","attestationReason":null,"challengeKind":"step_up"}`. Sem tipo, o corpo é o da 4.4.0.
- Tipo desconhecido por esta versão (na 4.5.0, por exemplo `reattest`): não é descartado. Sai bruto no 401, em
  `SentomaruObservation.ChallengeKind` (só em veredito `challenge`) e em `EvaluationResponseDto.ChallengeKind`;
  `KnownChallengeKind` vale `SentomaruChallengeKind.Unknown`. Nunca chama o gancho de step-up: a resposta é a da 4.4.0
  com o tipo. O consumidor vê um tipo novo sem versão nova do adaptador. Valor que não é um token de tipo (minúscula,
  depois até 31 minúsculas, dígitos ou `_`) é lido como `Unknown`, não chama o gancho e não vai para o 401 nem para a
  observação; `EvaluationResponseDto.ChallengeKind` guarda o valor sem filtro. `observedRules` (regras casadas em `stage: observe`) fica legível em
  `EvaluationResponseDto` e não muda nada no filtro.
- `fresh_signals`: o achado some com um snapshot assinado e novo; o Sentomaru confere sozinho na próxima requisição.
- `step_up`: o consumidor pede ao usuário uma reautenticação ou confirmação. **O Sentomaru não verifica o step-up** e
  não guarda estado dele; só recomenda.
- Gancho opcional `ISentomaruChallengeHandler` (registre no DI). É chamado com `SentomaruChallengeContext` (operação,
  tipo, códigos de motivo, `HttpContext`) e devolve `Refuse` (padrão, igual à 4.4.0) ou
  `Proceed` (o consumidor já fez o step-up na sessão dele; a action roda).
  - Só em `ZeroTrust` e só para `challenge` com `step_up`. Nunca roda para `deny`, `fresh_signals`, tipo desconhecido,
    desafio sem tipo nem em `Observe`.
  - Gancho que lança exceção recusa (401). Sem gancho, tudo é como na 4.4.0 (teste
    `ChallengeHandlerAdapterTests.Without_a_hook_the_filter_answers_as_4_4_0`).
  - Requisição com id de operação assinado: o gancho não é chamado (401), nem com `AllowOperationReplay`. O Sentomaru
    só registra um `allow`; num desafio liberado `FirstAdmission` seria nulo e nada impediria a mesma operação de rodar
    de novo na nova tentativa.
  - Depois de um `Proceed`, o `SentomaruObservation` continua dizendo `challenge` (o que o Sentomaru recomendou) e
    `HttpContext.Items[SentomaruIntegrityAttribute.StepUpProceededItem]` é `true`. Um filtro do consumidor que lê a
    observação confere as duas coisas.
  - O corpo sem `challengeKind` igual ao da 4.4.0 vale com o serializador padrão do ASP.NET Core (`System.Text.Json`);
    com `AddNewtonsoftJson` o campo nulo pode sair como `"challengeKind":null`.
  - Loop de step-up: depois da reautenticação o sinal continua DETECTED e a próxima requisição desafia de novo. O gancho
    é onde o consumidor guarda "step-up feito nesta sessão há X minutos". O exemplo
    `integrations/samples/aspnetcore-third-party/StepUpHandler.cs` (step-up falso) aceita um login com `auth_time` de até
    5 minutos.
- Uma regra `enforce` num consumidor em `Observe` não recusa nada: `Observe` nunca bloqueia.

## 4.4.0 — o consumidor lê o que o filtro observou (acréscimos e uma mudança em ZeroTrust)

- Depois de avaliar (Observe e ZeroTrust), `[SentomaruIntegrity]` grava um `SentomaruObservation` em
  `HttpContext.Items[SentomaruIntegrityAttribute.ObservationItem]`, lido por `SentomaruIntegrityAttribute.Observation(ctx)`:
  status HTTP da avaliação, código da recusa (`installation-suspended`, `session-unavailable`, ...), ação recomendada do
  veredito e a instalação cuja chave verificou a prova.
- Uso: um filtro do consumidor que roda **depois** do atributo impõe estados explícitos da instalação para as próprias
  sessões (ex.: sessão móvel vinculada a uma instalação suspensa) sem avaliar a mesma prova de novo. O nonce é de uso
  único: uma segunda avaliação seria `replay` e sujaria a medição.
- A observação traz também `ProofStatus` (`valid` quando a assinatura verificou; nulo numa recusa). Corpo acima de
  64 KiB é gravado como 413 `body-limit`; falha da avaliação (exceção no cliente que não seja cancelamento) como 503
  `integrity-unavailable` — em ZeroTrust a resposta é a mesma de uma indisponibilidade (antes a exceção escapava do
  filtro), em Observe a ação continua rodando.
- `ISentomaruClient.GetInstallationAsync(id)` (GET `installations/{id}`, credencial do workload): estado `active`,
  `suspended` (com `suspendedUntil`) ou `revoked` da instalação do escopo. Serve ao consumidor que já sabe qual
  instalação está por trás da sessão (vínculo verificado antes) e precisa impor o estado numa requisição que não pode
  avaliar, como upload multipart que o app não assina. Não é prova: não diz quem enviou a requisição. Implementações
  próprias de `ISentomaruClient` herdam o padrão 501 `not-implemented`. Exige o servidor com o campo `state`.
- Observe continua sem bloquear sozinho; quem decide é o consumidor.

## 4.3.0 — suspensão temporária chega ao app (só acréscimos)

- `SentomaruEnrollmentControllerBase` repassa ao app o 403 `installation-suspended` (resposta por instalação: suspensão
  temporária, manual ou por regra). Em 4.2.0 ele virava 502 `sentomaru-integration-error`. O app espera e tenta de novo
  mais tarde; **não** reinscreve. Revogação (quarentena) continua `session-unavailable`, que o SDK 0.9.0 trata como
  `EnrollmentRequired`.
- **Ordem obrigatória**: nenhuma política com regra `suspend` (nem suspensão manual de instalação em uso) antes de o
  consumidor rodar o 4.3.0; com 4.2.0 o aparelho suspenso vê 502 na renovação até a suspensão expirar.
- `[SentomaruIntegrity]` já repassava o status e o código da avaliação; nada muda nele.

## 4.2.0 — base do controller de inscrição (só acréscimos)

- **`SentomaruEnrollmentControllerBase`**: as três rotas que o app chama no backend do consumidor (desafio, inscrição e
  renovação) como métodos protegidos. O consumidor mantém o **seu** controller (rotas, atributos, autenticação, apelidos)
  e cada ação vira uma linha. No app Android, essas três rotas **não** podem ser chamadas pelo `OkHttpClient` com
  `addSentomaru`: o interceptor lança `SentomaruException` (`NotEnrolled` ou `EnrollmentRequired`) antes de enviar, porque
  ainda não há concessão para assinar. O app usa outro cliente, sem o interceptor, nelas ([SDK Android](../../sdk/android/README.md)).

  ```csharp
  [ApiController, Route("api/v1/integridade")]
  public sealed class IntegridadeController(ISentomaruClient c, IOptions<SentomaruClientOptions> o, ILogger<IntegridadeController> l)
      : SentomaruEnrollmentControllerBase(c, o, l)
  {
      [HttpPost("challenge")] public Task<IActionResult> Challenge([FromBody] SentomaruChallengeInput? i, CancellationToken ct) => IssueChallengeAsync(i, null, ct);
      [HttpPost("installations"), AllowAnonymous] public Task<IActionResult> Enroll(CancellationToken ct) => CompleteEnrollmentAsync(null, ct);
      [HttpPost("sessions"), AllowAnonymous] public Task<IActionResult> Renew(CancellationToken ct) => RenewSessionAsync(null, ct);

      // Obrigatório: decide se o chamador da sessão pode pedir um desafio (ex.: o tenant é um dos dele). null = segue.
      protected override Task<IActionResult?> AuthorizeCallerAsync(CallerContextDto caller, CancellationToken ct) =>
          Task.FromResult<IActionResult?>(null);
  }
  ```

- O que sai do código do consumidor: o interruptor (`Enabled=false` → 503 `sentomaru-disabled` sem chamar o Sentomaru),
  a conferência do ambiente (404 `sentomaru-env-unknown`), o envelope (`SentomaruExtractor` com `PublicBaseUrl` e
  `KnownProxies`, nunca `X-Forwarded-*` cru), o `application/json` exato que o guard do Sentomaru exige e o mapeamento
  das respostas.
- **Respostas:** 2xx com o valor tipado, **re-serializado pelo formatador JSON do host** (campo que o Sentomaru acrescentar
  e o DTO não tiver é descartado; com Newtonsoft os nomes só batem por camelCase, porque ele ignora `[JsonPropertyName]`);
  400, 409, 413, 422 e 429 com o código (o problema é o pedido do app); 401 só `proof-invalid` e `challenge-invalid` (o app
  pede um desafio novo) e 403 só `session-unavailable`, `session-expired`, `operation-context` e `enrollment-context`
  (URI assinada ou cabeçalhos de escopo que não batem com a rota: pedido do app, ou o `PublicBaseUrl` do backend errado). Qualquer outro 401/403 é a
  credencial, o escopo ou o direito do **backend** e vira 502 `sentomaru-integration-error` (log Error), porque um 401
  que chegasse ao app pode derrubar a sessão do usuário. 5xx ou Sentomaru fora vira 503 `sentomaru-unavailable`.
- **Desafio:** o chamador sai **sempre** do `ISentomaruContextResolver` da sessão (401 sem sessão, 403
  `caller-context-missing` sem chamador usável); o corpo só traz `PublicKeyPem`. Para recusar um chamador (por exemplo
  um tenant do qual o usuário não faz parte) sobrescreva `AuthorizeCallerAsync`.
- Os logs levam o status e o código do Sentomaru, nunca token, corpo nem identificador. Um código que não seja um slug
  curto (`[a-z0-9_-]`, até 64) nunca é repassado ao app: vira `integrity-error`.
- **Ao migrar de controllers copiados** (um serviço consumidor, por exemplo), mudam para o app: o desafio **exige sessão** (401
  `authentication-required` sem ela, em vez de aceitar sujeito e tenant do corpo), 403 `caller-context-missing` sem
  chamador usável, e os erros de repasse deixam de ser `renewal-format`, `enrollment_error` e `validation_error`
  (passam a `forward-format`, `body-limit`, 502 `sentomaru-integration-error` e 503 `sentomaru-unavailable`). O gate de
  ambiente (404 `sentomaru-env-unknown`) agora vale também para a inscrição; apelidos de rota como
  `/api/v1/.../{env}/...` continuam sendo do consumidor.

## 4.0.0 — chamador obrigatório, capacidades e origem da política (C-09, issues #142 e #143; incompatível)

- **Sem chamador, sem avaliação.** O `DefaultSentomaruContextResolver` não cai mais em `anonymous`/`default` quando a
  sessão não tem as claims de sujeito e tenant. O filtro recusa com **403 `caller-context-missing`** (log Error, o
  Sentomaru não é chamado); em `Observe` a ação roda e nada é enviado. `IssueChallengeAsync` também recusa um
  sujeito ou tenant vazio ou reservado sem fazer a chamada. A API do Sentomaru recusa os marcadores com 400
  `caller-context-reserved` **num desafio novo**. Uma instalação já inscrita com esses valores continua sendo
  avaliada, com um Warning e a métrica `sentomaru_reserved_caller_evaluations_total`.
- **`AllowAnonymousContext`** (padrão `false`): só em `Development`, usa os marcadores `development-anonymous`/
  `development-default`. Fora de `Development` o host não sobe com ela ligada.
- **`app.MapSentomaruCapabilities()`** (opt-in): `GET /integrity/capabilities`, sem prova, devolve só se a
  verificação está ligada e cada operação protegida com `enforced` (true = ZeroTrust; false = Observe; quando uma
  operação tem dois níveis, vale o mais fraco). Não tem token, endereço do Sentomaru, escopo, versão nem FailOpen. O que
  ela expõe (os nomes das operações protegidas) já está no binário do app. Opções: `RequireAuthorization`,
  `RateLimitingPolicy` (uma política do seu `AddRateLimiter`) e `MaxAge` (padrão 300 s). A resposta é calculada uma vez.
  O app (plugin `sentomaru_flutter` 0.7.0) e o job de publicação do app (guia de integração, seção 8, passo 9) a leem.
- **`EvaluationResponseDto.PolicySource`**: `published` ou `default` (política embutida). Quando vem `default`, o
  filtro registra um log Warning uma vez por processo (estado `SentomaruNotices`, singleton do `AddSentomaruClient`).
  O Error de requisição sem chamador sai no máximo uma vez por minuto.

**Migração para 4.0.0** (de 1.0.2, 2.x ou 3.x, acumulando as notas abaixo):

1. De 1.x: as mudanças da 2.0.0 (sem allow degradado em 503, validação de startup, token só pelo cofre).
2. De 2.x: a renomeação da 3.0.0, `DeviceTrustLevel` → `DeviceAssuranceLevel`, `TrustLevel` → `AssuranceLevel`
   (sem alias: não compila com o nome antigo).
3. Para 4.0.0: as rotas protegidas e as de desafio exigem login, e o seu `ISentomaruContextResolver` (ou as claims do
   padrão) identifica o chamador; um chamador sem claim deixa de ser avaliado como `anonymous` e passa a ser recusado.

**Ordem de deploy:** suba o consumidor para o adaptador 4.x **antes ou junto** com a API do Sentomaru que recusa os
marcadores no desafio. Um consumidor ainda num adaptador antigo que caia no fallback passa a receber 400
`caller-context-reserved` ao pedir um desafio. Teste de contrato para copiar:
`integrations/samples/aspnetcore-third-party/ConsumerContract.cs`.

## 3.1.0 — efeito único por operação (J-01f, só acréscimos)

- `x-sentomaru-operation-id` passa a ser repassado ao Sentomaru (o app o assina; ver `contracts/p0-http-profile.md`).
- `EvaluationResponseDto` ganha `OperationId` e `FirstAdmission`.
- Uma nova tentativa de um id já admitido (`FirstAdmission == false`) **não roda a action de novo**: 409
  `operation-replayed`. Uma action que guarda o resultado por id e o devolve na nova tentativa declara
  `[SentomaruIntegrity(..., AllowOperationReplay = true)]` e lê `HttpContext.Items[SentomaruIntegrityAttribute.OperationIdItem]`
  e `[FirstAdmissionItem]`.
- Quando a action de uma primeira admissão falha (exceção não tratada ou resultado 5xx), o filtro **libera** o id
  (`ISentomaruClient.ReleaseOperationAsync`), para que a nova tentativa do app volte a ser primeira admissão; se a
  liberação falhar, fica no log e a nova tentativa recebe 409 até o id expirar (24 h). Uma falha depois do filtro
  (na escrita da resposta, por exemplo) não é vista: o efeito é tratado como aplicado.
- Só um `allow` grava o id; uma recusa (`deny`/`challenge`) é reavaliada na nova tentativa. Depois de um `allow` gravado,
  o mesmo id com o mesmo conteúdo recebe esse `allow` mesmo que uma avaliação nova recusasse (a operação já foi admitida).
- **409 `operation-replayed` quer dizer "feita ou em andamento", não "deu certo":** uma nova tentativa que chega enquanto
  a primeira ainda roda recebe 409; se a primeira falhar e liberar o id, a próxima tentativa (com espera) é admitida. O
  app deve tratar o 409 como "consulte o resultado ou tente de novo mais tarde".
- Uma action protegida **não deve devolver 5xx depois de aplicar o efeito**: o 5xx libera o id e a nova tentativa
  aplicaria de novo. Um 4xx mantém o id (a nova tentativa recebe 409). A liberação não deve ser repetida por um
  handler de resiliência (uma liberação atrasada poderia apagar uma admissão mais nova).
- `Observe` ignora `FirstAdmission` (a action sempre roda: é desprotegida por definição).
- `ISentomaruClient` ganhou `ReleaseOperationAsync` com implementação padrão (501), então implementações próprias
  continuam compilando.
- Sem o cabeçalho, nada muda.

## 3.0.0 — renomeação (versão nova de contrato)

- `DeviceTrustLevel` → `DeviceAssuranceLevel`; propriedade `TrustLevel` → `AssuranceLevel` e parâmetro `trustLevel` → `assuranceLevel` em `[SentomaruIntegrity]`. Membros `ZeroTrust` (padrão) e `Observe` inalterados. Sem alias: código que use o nome antigo não compila. Tabela completa em `the rename migration table of the vendor`.
- `x-sentomaru-signals` só é encaminhado quando chega com **um** valor; com vários valores é descartado (tratado como ausente = desconhecido).
- Sinais ausentes, descartados ou obsoletos em operação sensível da política (na política padrão embutida: `criar_demanda`, `concluir_demanda`, `checkout`) viram `challenge`, que este filtro responde com **401 `challenge-required`**. Até a 4.4.0 não há fluxo de step-up (a 4.5.0 acrescenta o gancho opcional para `step_up`, acima): na prática a operação fica bloqueada até o app mandar sinais válidos. É fail-closed por desenho.

- Publicação: o CI publica a 3.0.0 ao chegar na `main` (depois de todos os gates); versões são imutáveis (`--skip-duplicate`), correções saem como 3.0.x. **consumidores que ainda usam controllers copiados ficam em 2.x** até migrar.

## 2.0.0 — mudanças incompatíveis e migração (consumidores com controllers copiados)

- `RuntimeTrust` removido (enum hoje `DeviceAssuranceLevel`); use `Observe` só onde a operação é conscientemente desprotegida.
- `SentomaruClient` não devolve mais "allow degradado" em 503/timeout.
- Fora de `Development` o host não sobe com `FailOpen: true`, `BaseAddress` http, sem `PublicBaseUrl`/`KnownProxies`, ou com `Enabled: false` sem `DisabledAcknowledged`.
- Consumidor com controllers copiados: remover `FailOpen` e o `WorkloadToken` do `appsettings.json` versionado; configurar por variáveis `Sentomaru__BaseAddress` (https), `Sentomaru__PublicBaseUrl`, `Sentomaru__WorkloadToken` (secret store), `Sentomaru__Org/App/Env`. O token que esteve versionado no `appsettings.json` de um consumidor deve ser **revogado e rotacionado** (procedimento de rotação da operação do Sentomaru) — não reutilizar.
- O pacote passa a 2.0.0 (a 1.0.0 com `--skip-duplicate` nunca publicaria a correção).

Ou diretamente a partir da seção de configuração:

```csharp
builder.Services.AddSentomaruClient(builder.Configuration, "Sentomaru");
```

### 2. Protegendo Endpoints Críticos com `[SentomaruIntegrity]`

```csharp
[HttpPost("{id}/concluir")]
[SentomaruIntegrity("demanda_concluir")]
public async Task<IActionResult> ConcluirDemanda(long id, [FromBody] ConcluirDemandaDto dto)
{
    // Executado apenas se a prova RFC 9421 e as políticas de integridade forem aprovadas pelo Sentomaru
    return Ok();
}
```

### 3. Chamando o Cliente Manualmente (ex: Handshake de Challenge)

```csharp
[HttpPost("challenge")]
public async Task<IActionResult> IssueChallenge([FromBody] ChallengeRequestDto request, ISentomaruClient client)
{
    var result = await client.IssueChallengeAsync(request);
    if (!result.Succeeded)
    {
        return StatusCode(result.StatusCode, new { code = result.ErrorCode });
    }
    return Created("", result.Value);
}
```
