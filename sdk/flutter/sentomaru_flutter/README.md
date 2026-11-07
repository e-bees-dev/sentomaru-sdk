# sentomaru_flutter

Plugin Flutter do Sentomaru para Android e, desde 0.18.0, iOS: assinatura RFC 9421 nativa (SDK Android; no iOS, o SDK Swift de `sdk/ios`) e interceptor Dio. Sem Pigeon. Mudanças incompatíveis e migração em `CHANGELOG.md`; uso em `sdk/flutter/README.md`.

> **Ponto único (app e backend): o sujeito e o tenant que o app envia nunca são o fator de decisão.** O backend os
> deriva da própria sessão autenticada (ou os revalida contra ela) no desafio, na inscrição e em cada operação
> protegida; um tenant lido do armazenamento local ou de um padrão de build não identifica ninguém. O adaptador
> Sentomaru.AspNetCore 4.x recusa com 403 `caller-context-missing` um chamador que a sessão não identifica (guia de
> integração, `docs/api/INTEGRATION_GUIDE.md` §3; issues #142 e #143).

## iOS (0.18.0; sinais desde 0.19.0; sem prova em aparelho)

O lado iOS responde o mesmo canal `sentomaru_flutter` que o Android, sobre o SDK Swift de `sdk/ios`: a mesma
API Dart, sem parâmetro novo. O pod (`ios/sentomaru_flutter.podspec`, CocoaPods, iOS 15+) compila os fontes do SDK por
links simbólicos para `sdk/ios/Sources` do mesmo checkout; a dependência por pub `git:` (com `path:
sdk/flutter/sentomaru_flutter`) já traz o repositório inteiro. Os links apontam para fora da raiz do pacote: publicar o
plugin de outro jeito (pub.dev, servidor de pacotes, cópia só da pasta do plugin) exige copiar os fontes de
`sdk/ios/Sources` para dentro do pacote antes. Sem pod de terceiro, sem binário, sem Swift Package
Manager por enquanto (o Flutter 3.41.9 usa CocoaPods por padrão; com SwiftPM ligado no app, o
Flutter cai no CocoaPods para plugin sem `Package.swift`, o que não foi testado aqui).

**Requisitos do app iOS:**

- Alvo mínimo iOS 15.0 (`platform :ios, '15.0'` no `Podfile`).
- Capability **App Attest** no App ID e, no `Runner.entitlements`, a chave
  `com.apple.developer.devicecheck.appattest-environment` com o **mesmo ambiente do escopo** no servidor
  (`apple_attest_environment`): `development` num build instalado pelo Xcode, `production` no TestFlight e na App
  Store. Ambiente trocado = inscrição recusada (`aaguid_env_mismatch`). O ambiente vem do entitlement no build; por
  isso não há parâmetro `appAttestEnvironment` no Dart.
- O escopo precisa de `apple_app_id` (`TeamID.bundleID`) igual ao app (Console).

**O que muda no iOS** (o resto é igual ao Android):

| Chamada | iOS |
|---|---|
| `initialize` | `playIntegrityCloudProjectNumber` e as rotas de reatestação são ignorados; um segundo `initialize` do mesmo escopo com outra `allowedHosts`, `renewalUrl` ou carência é recusado (`invalidRequest`, o SDK guarda um cliente por escopo no processo); a configuração anterior continua valendo. Outra `enrollmentUrl` é outro escopo para o SDK (outro registro no Keychain) e cria outro cliente |
| `enroll`, `rotate` | chave da requisição no Secure Enclave, atestada por App Attest; Keychain `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, não sincronizável; `strongBox` ignorado; `requiresHardware: true` recusado antes de criar chave (`invalidRequest`): uma instalação App Attest é `device_attested`, nunca `hardware` (o servidor recusaria com 422) |
| sem App Attest ou sem Secure Enclave (simulador, aparelho sem suporte, app sem a capability) | `SentomaruErrorCode.unsupported`, `details` `Unsupported:APP_ATTEST` ou `Unsupported:SECURE_ENCLAVE`; nada criado nem enviado; nunca há inscrição sem atestação |
| `sign`, `renewSession`, interceptor Dio | iguais; a renovação leva a asserção App Attest no corpo; asserção recusada ou chave App Attest inválida = `enrollmentRequired` (o app faz `reset` + `enroll`) |
| `reenrollmentReason` | sempre `null` (a atestação da Apple não traz a versão do app) |
| `collectSignals`, `collectSignalsSnapshot` | desde 0.19.0 as seis capacidades do catálogo 1.0.0 pelo SDK Swift: `debug_attached` por `P_TRACED`, `emulator_detected` `detected` no simulador, `root_indicated` por indícios de jailbreak só no aparelho, guardados 60 s (`unknown` no simulador e num Mac), `app_signing_digest` `unsupported`, `installer_source` `unknown`, `os_version`; com `rasp`/`appIntegrity`, os ids RASP e de integridade do app `UNSUPPORTED`. Antes, lista vazia (operação sensível saía `challenge` por `SIGNALS_MISSING`). Detalhes em `sdk/ios/README.md`, "Sinais" |
| `reattestIfDue`, `reattest` | `ReattestationUnsupported` (sem chamar o canal) |
| `signalEvents` | sem eventos `signal` (`signalEventsSupported` falso); `server_response` continua |
| `SentomaruSealed`, `addSentomaruPinning` | não suportados (como antes) |
| argumento de tipo errado no canal (corpo que não é bytes, expiração não numérica) | `invalidRequest` (`InvalidRequest:PARAMS`); no Android, `channelError`. Só acontece com chamada direta ao canal, não pela API Dart |
| ordem das chamadas | uma fila por engine, na ordem de chegada, uma de cada vez (como o executor do Android): `sign` renova e assina sem nada no meio; de dois `initialize` aceitos, vale o último. Respondem na hora, antes das chamadas já na fila: `ConfigurationError` da validação dos argumentos de `initialize`, `scaffoldInfo` e método não implementado; `collectSignals` e `collectSignalsSnapshot` rodam fora da fila e da thread principal (não leem estado do cliente) |

Desinstalar o app não apaga o Keychain no iOS: reinstalado, o app pode achar a instalação anterior. Para começar do
zero, chame `reset()` na primeira execução (marcador em `SharedPreferences`/`UserDefaults`, que a desinstalação apaga).

**Provado:** testes do lado iOS no simulador (`sample/ios/RunnerTests`, cliente do SDK com chaves em software, App
Attest e servidor falsos), testes Dart e `flutter build ios --no-codesign` do `sample/`. **Não provado:** iPhone,
Secure Enclave e Keychain reais pelo plugin, App Attest real pelo plugin, inscrição e renovação contra o servidor.

No CI, o job `flutter-plugin-ios` (runner `ios-pr` do Mac mini, só em PR) roda quando o PR mexe no lado iOS do plugin,
no `lib/`, nos testes `test/ios_*`, no Dart ou no `pubspec.yaml` do `sample/`, ou no `sdk/ios`. Mudança só nos jobs
`sdk-ios`/`flutter-plugin-ios` do `ci.yml` não dispara o filtro (todo PR que mexe no `ci.yml` esperaria o Mac): prove-a
com `workflow_dispatch` da branch do PR (`gh workflow run ci.yml --ref <branch>`).

## Assinatura de rede numa linha (0.8.0)

`dio.addSentomaru(client, routes: SentomaruRoutes.fromProfileSection(perfil['controls']['network-signing']))` (ou
`SentomaruRoutes(hosts: [...], routes: [SentomaruRoute('/v1/pedidos/*', 'concluir_pedido')])`): requisição sem
operação declarada cujo host e caminho casam com uma rota é assinada como essa operação. Operação declarada prevalece;
rota em host fora de `allowedHosts` → `hostNotAllowed`; antes do `initialize` → `notInitialized`; nunca sai sem
assinatura. A tabela vale na requisição do app, não num salto de redirecionamento. Regras em
`contracts/sdk/sdk-api-v1.md` §4 (a primeira rota que casa vence; porta ignorada; host com ponto final recusado; a
instalação recusa `hosts` fora de `allowedHosts` quando o cliente já está inicializado). A regra R8 do plugin mantém o
nome de `SentomaruFlutterPlugin`, que a CLI procura no DEX do app (prova que o plugin está linkado, não que a linha
foi chamada). A evidência em aparelho é só Android/OkHttp; o Dio tem só testes unitários e de transporte real em loopback, sem aparelho.

## Snapshot de sinais e sinais RASP (0.12.0)

```dart
final snapshot = await client.collectSignalsSnapshot();            // as seis capacidades de collectSignals()
final rasp = await client.collectSignalsSnapshot(rasp: true);      // + as seis RASP (desde o catálogo 1.3.0), por opção
await dio.post(url, data: body, options: Options(headers: {
  'x-sentomaru-operation': 'concluir_demanda',
  'x-sentomaru-signals': snapshot.toJson(), // o interceptor codifica e assina o cabeçalho (H3)
}));
```

O plugin monta o JSON do snapshot (`signals-observation-schema-v1.json`): `catalogVersion` do catálogo
(`SentomaruSignalsCatalog.version`: 1.7.0 no código atual, 1.3.0 no 0.12.0 publicado), `collectedAt` e `durationMs` medidos pelo coletor nativo, estado no
nome do servidor (`NOT_DETECTED`), `source` `client_observed`, instantes em UTC e `detail` como texto (valor nulo
omitido). As capacidades `server_verified` do catálogo (`play_integrity_failed`, `build_unregistered`, `app_identity_mismatch`) nunca saem do
app. `collectSignals()` sem argumento não mudou (as seis antigas, mesma lista e mesmo canal).

`rasp: true` acrescenta `debugger_attached`, `app_debuggable`, `dev_settings_enabled`, `root_artifacts`,
`emulator_indicated` e `hook_framework_java`, coletados fora da thread principal com prazo por coleta
(`SignalsCollector.RASP_DEADLINE_MS`, 100 ms, medido em aparelho): o detector que estoura vem `UNKNOWN` `timeout`. Os
sinais são declarados pelo app e evadíveis (Frida, LSPosed ou root oculto podem forjar o valor antes da assinatura);
`NOT_DETECTED` é "não detectado nesta coleta", nunca "ambiente limpo". Nenhuma política padrão usa esses ids.

**`signals-rasp` é do app, não do plugin.** O plugin não depende de `br.com.ebees.sentomaru:signals-rasp` (o artefato
que traz o `<queries>` dos gerenciadores de root), então o manifesto mesclado de quem só atualiza o plugin não ganha
`<queries>`. Para a checagem de pacotes do `root_artifacts`, o app declara o artefato no próprio Android:

```kotlin
// android/app/build.gradle.kts
dependencies { implementation("br.com.ebees.sentomaru:signals-rasp:0.2.0-rc.2") }
```

Sem ele a checagem não roda e `root_artifacts` nunca dá `NOT_DETECTED` (`UNKNOWN` com `partial=root_package`, ou
`DETECTED` por outro indício). No iOS, desde 0.19.0, o snapshot vem do lado nativo (SDK Swift) com as seis
capacidades do catálogo 1.0.0 observadas no iOS; `rasp: true` acrescenta os seis ids RASP como `UNSUPPORTED` (não há
checagem iOS para eles). Até 0.18.0 o Dart respondia sem chamar o canal: sem `rasp`, snapshot vazio.

## Integridade do app e reatestação por opção (0.13.0)

```dart
// Sinais: a lista é do app (SHA-256 de cada certificado aceito; com Play App Signing, o do Google).
final snapshot = await client.collectSignalsSnapshot(
    appIntegrity: AppIntegritySignals(expectedSignerDigests: [certificadoSha256]));

// Reatestação: rotas públicas do consumidor que repassam para a API (the Sentomaru re-attestation API contract).
await client.initialize(SentomaruConfig(/* ... */ reattestation: SentomaruReattestationConfig(
    challengeUrl: 'https://api.example/reattest/challenge', submitUrl: 'https://api.example/reattest')));
await client.renewSession();
switch (await client.reattestIfDue()) {
  case ReattestationCompleted(:final result): log(result.buildMatchState); // consultivo
  case ReattestationNotNow(:final retryAfter): agendar(retryAfter);          // nunca em laço
  case ReattestationRefused(:final code): log(code);                         // ex.: reattestation-disabled
  case ReattestationUnsupported(): break;                                    // iOS
}
```

**Sinais.** `appIntegrity` acrescenta, depois das outras, `app_signer_mismatch`, `installer_class` e `code_integrity`
(catálogo 1.5.0, `SignalsCollector.appIntegrityDetectors` no Android). **Prazo:** sem `rasp` a coleta continua sem
prazo, como no 0.12.0, e as seis antigas nunca dão `UNKNOWN timeout` por causa da opção. Os três novos se limitam
sozinhos: o `code_integrity` espera no máximo 15 ms pelo hash. Com `rasp`, o prazo passa a 135 ms
(`RASP_DEADLINE_MS + APP_INTEGRITY_BUDGET_MS`) e vale para todas: qualquer detector, inclusive os antigos, pode dar
`UNKNOWN` `timeout`, como já acontecia com `rasp`. Os três são declarados pelo app e
evadíveis: um APK reassinado com o SDK corrigido devolve `match`; para app inscrito o sinal forte é o
`app_identity_mismatch` do servidor.

- `app_signer_mismatch`: todos os certificados lidos contra a lista (hex de 64 dígitos, com ou sem `:`, qualquer
  caixa; outro valor = `configurationError` antes de chamar o nativo). `NOT_DETECTED` só se todos são esperados;
  `DETECTED` `mismatch`; `UNKNOWN` `no_reference` (lista vazia) ou `unreadable`. `detail` só com contagens.
- `installer_class`: sinal de valor, nunca `NOT_DETECTED`: `DETECTED` com `class`/`initiator` (`play`, `none`,
  `other`); `UNKNOWN` `class=unknown`. Por `adb install` dá `class=none`, `initiator=other`.
- `code_integrity`: sempre `UNKNOWN` do app (`not_compared` com o agregado, `timeout`, `partial`); quem compara com o
  registro é o servidor. O hash roda em segundo plano: na primeira coleta de um processo, com APK do
  muito grande, sai `timeout`, e as seguintes levam o agregado.
- Com os 15 sinais o cabeçalho fica abaixo de 4 KiB (limite do servidor). No iOS os três vêm `UNSUPPORTED` do lado
  nativo, depois das seis capacidades do catálogo 1.0.0 (desde 0.19.0; até 0.18.0, sem chamar o canal). Nenhuma
  falha vira `NOT_DETECTED`; nenhuma política padrão usa esses ids.

**Reatestação.** `SentomaruConfig.reattestation` cria no `initialize` um `SentomaruReattestation` nativo (as duas rotas
em https e na allowlist; `minInterval` em segundos inteiros, 24 h por padrão; rota recusada = `configurationError`).
Nada reatesta sozinho e o servidor deixa a reatestação desligada até o operador ligar o escopo
(`reattestation-disabled`). `reattestIfDue()` roda numa thread de trabalho do próprio plugin, nunca na principal e
nunca na fila do `sign` (uma reatestação pode segurar Keystore, duas chamadas de rede e uma espera de até 30 s);
`reattestationDue()` não bloqueia: responde na thread da plataforma, lendo um campo volátil do SDK. Regras do SDK Android (`contracts/sdk/sdk-api-v1.md` §2.5): `429` e rede = "agora
não" sem nova tentativa; `503 verifier-unavailable` e `409 replay` com no máximo uma nova tentativa; `session-expired`
= renove antes; `reattestation-disabled`, `reattestation-unsupported` e `installation-suspended` esperam 24 h; o
intervalo fica só em memória. Falhas locais lançam `SentomaruException` (`notEnrolled`, `strongBoxUnavailable`,
`cancelled`; falha de Keystore chega como `unknown` com a mensagem `KeyUnavailable`). Sem `reattestation` na
configuração: `invalidRequest`. iOS: `ReattestationUnsupported`, sem chamar o canal (App Attest não tem reatestação).
O resultado é consultivo. A avaliação só lê o estado e a idade da última reatestação quando uma regra da política
pede (`reattestationMaxAgeSeconds`; desafio `reattest` com `client.reattest()` desde o 0.15.0).

**Sem prova em aparelho:** o caso de reatestação do `sample/integration_test/plugin_test.dart` foi escrito e não rodou. A
reatestação com servidor real foi provada em ensaio pelo SDK Android no app `raspLab`, não pelo
plugin.

## Flag do app e estado do backend (0.6.0, C-09; aviso separado desde 0.7.0)

`SentomaruCapabilities.fetch(dio, Uri.parse('<api>/integrity/capabilities'))` lê o que o backend verifica (rota
opt-in do adaptador 4.x; sem seguir redirecionamento). Com isso, `SentomaruCapabilityGate(appEnforces: …, operations:
…)` decide se o app marca cada operação. Com o backend desligado, ele chama `onMismatch` (registre num log) e, com a
política padrão `degrade`, não marca nenhuma. Uma operação que o backend não protege também deixa de ser marcada. Para
essas operações, a chamada segue sem prova em vez de virar 503; as que o backend protege continuam marcadas e são
decididas por ele. Operação só em Observe não é desencontro: chega em `onWarning` (`operationObserveOnly`) e continua marcada.
`SentomaruMismatchPolicy.keep` mantém a marcação sempre. Rota inacessível conta como desconhecido e mantém a flag do
build. No CI do app, o job de publicação falha a
release quando a combinação é inconsistente (guia §8, passo 9).

## `onRiskEvent`: só atrito, nunca decisão

Hoje nenhum componente do Sentomaru emite `riskEvent`; o callback só dispara se o seu backend incluir esse membro
numa resposta de erro. Use-o só para pedir que o usuário confirme de novo uma ação sensível, nunca para liberar,
bloquear ou pular uma verificação: a decisão é sempre do servidor (guia §7b).

## Operação idempotente e sinais assinados (0.5.0, J-01f2)

```dart
await dio.post(url, data: body, options: Options(headers: {
  'x-sentomaru-operation': 'concluir_demanda',
  'x-sentomaru-operation-id': operationId, // um por operação de negócio; repetido nas novas tentativas
}));
```

O id também pode ir em `extra['sentomaru_operation_id']`. O interceptor manda o id e os sinais ao núcleo nativo, que os
assina (componentes opcionais, `contracts/p0-http-profile.md`); um id malformado é recusado antes do envio. Veja a nota
de migração no `CHANGELOG.md` (sinais assinados mudam a leitura de `NOT_DETECTED` no servidor).

## Play Integrity (C-04b, plugin 0.4.0)

`SentomaruConfig(playIntegrityCloudProjectNumber: <número do projeto Google Cloud>)` liga o token consultivo do Play
Integrity na inscrição (SDK Android). Sem o campo, nada muda. Qualquer falha (sem Google Play, emulador, quota, rede)
inscreve sem o token. Contrato: the Sentomaru Play Integrity API contract.

## Eventos de sinal e de resposta do servidor por opção (0.14.0)

```dart
final sub = client.signalEvents.listen((e) {
  switch (e.kind) {
    case SentomaruSignalEventKind.signal:          // só Android (client.signalEventsSupported)
      log('${e.type} ${e.state?.wireName} ${e.reasonCodes}'); // no máximo avisar e registrar
    case SentomaruSignalEventKind.serverResponse:  // resposta 401/403 de requisição assinada pelo interceptor
      if (e.code == 'challenge-required' && e.challengeKind == 'step_up') pedirReautenticacao();
      if (e.isReattestChallenge) reatestarERepetirUmaVez(); // 0.15.0: client.reattest(), depois a operação uma vez
      if (e.code == 'installation-suspended') mostrarSuspensaoPreservandoRascunhos();
      if (e.code == 'installation-revoked') inscreverDeNovo();
  }
});
await client.collectSignalsSnapshot(rasp: true); // os eventos `signal` saem das coletas que o app já faz
```

Eventos informativos, não veredito: quem controla o processo pode suprimi-los ou inventá-los, e o servidor decide a
cada requisição. Nada é construído enquanto ninguém escuta. No iOS não há eventos `signal` (`signalEventsSupported`
falso); os `server_response` vêm do Dio em qualquer plataforma. Detalhes no CHANGELOG 0.14.0 e no guia de integração.

**Desafio `reattest` (0.15.0).** A política pode exigir uma reatestação recente aprovada pelo servidor antes de
uma operação. O app recebe `challenge-required` com `challengeKind: reattest`, chama `client.reattest()` (a reatestação
sem o prazo local) uma vez e repete a operação uma vez com nonce novo; quem confere é o servidor, na nova
avaliação. Com `ReattestationNotNow` mostra "tente mais tarde" e não repete; se a repetição voltar a ser desafiada, não
reatesta de novo nesta operação. O plugin não reatesta nem repete sozinho.


## Leitura de assets selados (0.17.0; provado no aparelho de referência e medido no emulador; controle da CLI a partir da `cli-v0.5.0`)

Para os arquivos que o controle `asset-encryption` da CLI sela (`contracts/devsecops/cli-v1.md`), o app troca
`rootBundle.load(chave)` por `SentomaruSealed.load(chave)` (`Future<Uint8List>`, mesma chave do `pubspec.yaml`) e lê o
arquivo de strings por `SentomaruSealed.string(chave)` (`null` para chave ausente). A decifração é no lado Android do
plugin, pelo módulo `sealed` do SDK; não há criptografia em Dart. Falhas tipadas: `SentomaruSealedException` com
`notSealed`, `integrity` ou `formatUnsupported`; no iOS, `UnsupportedError`. **`SentomaruSealedException` não estende
`SentomaruException`**: um `on SentomaruException catch` não pega as falhas da leitura selada (são de outro domínio,
os códigos do formato); trate as duas quando o código chamar `load`/`string`.

```dart
await SentomaruSealed.configure(allowPlainFallback: kDebugMode, plainStringsKey: 'assets/textos.json');
final catalogo = await SentomaruSealed.load('assets/dados/catalogo.json');
```

- **É ofuscação de dados, não sigilo:** quem tem o APK recupera os arquivos; um revisor independente
  os recuperou em 4 min 37 s só com o APK e o esquema público. Segredo de servidor não vai no app, selado ou não.
- **Custo medido no aparelho de referência:** a primeira leitura de 1 MiB pelo canal teve p50 de 106 ms em 30 arranques frios,
  acima do limite declarado de 50 ms, em dois modos: ~40 ms na minoria (12 de 30) e ~115 ms na maioria (18 de 30). Que
  o modo lento venha da disputa com a subida do engine é hipótese, não testada no aparelho. No emulador, ler
  depois do primeiro quadro **não** ficou mais barato: o p50 subiu de 202 a 248 ms em todos os tamanhos, por causa não
  diagnosticada; o experimento não decide a hipótese. As leituras seguintes têm p50 18,4 ms.
- **Sem a CLI** (`flutter run`, testes), só com `allowPlainFallback: true` o plugin lê o arquivo em claro, e só quando
  o pacote não tem `header.bin`; desligado por padrão, ligue só com `kDebugMode`. Num pacote selado a opção não tem
  efeito. Arquivo ausente nesse caso vira `SentomaruException` com `details` `AssetNotFound`, não
  `notSealed`.
- `Image.asset`, `rootBundle` e fontes leem sem o plugin: arquivo lido por eles não pode ser selado.
- O marcador `SentomaruFlutterSealed` (`-keepnames` nas regras do plugin) é o que a CLI procura no DEX; prova só que o
  leitor está linkado.

## Pinning da chave do servidor no Dart (0.16.0, C-03a; provado no emulador e no aparelho de referência na C-03b)

O `HttpClient` do `dart:io` não lê o `network_security_config` que a CLI gera para o lado nativo. A parte Dart
é uma linha a mais, na mesma instância de `Dio` que fala com o host fixado, **antes** do `addSentomaru` e da primeira
requisição:

```dart
final pins = SentomaruPins.fromProfileSection(perfil['controls']['network-pinning']); // a mesma seção da CLI
final outcome = dio.addSentomaruPinning(pins); // SentomaruPinningInstall.installed (Android) ou .unsupportedPlatform
dio.addSentomaru(client, routes: rotas);       // ou, numa linha só: dio.addSentomaru(client, routes: rotas, pins: pins)
pins.events.listen((e) => log('${e.reason.wireName} ${e.host}')); // opcional, local, informativo
```

- **Fonte dos pinos:** a seção `network-pinning` v1 do perfil `protect` (`contracts/devsecops/cli-v1.md`), passada pelo
  app (configuração explícita; o plugin não lê o manifesto nem o perfil sozinho). `fromProfileSection` aplica as mesmas
  regras de estrutura da CLI e falha com `FormatException` cuja mensagem é o caminho do campo
  (`network-pinning.domains.pins`), nunca um valor. **Não** confere expiração passada nem o teto de 180 dias: no
  aparelho o relógio não é o do build; uma data passada só deixa o pin-set inativo.
- **Como confere:** a linha põe no `HttpClient` uma `connectionFactory`. Para um host da seção, ela abre o TCP, faz o
  handshake TLS (âncoras do `context`, padrão do sistema, e conferência do nome), calcula o SHA-256 do
  `SubjectPublicKeyInfo` da **folha** e só entrega o socket ao `HttpClient` se o pino estiver em `pins ∪ backupPins`;
  senão fecha o socket e a chamada falha com `SentomaruException(pinningRefused, details: 'pin_mismatch')` dentro de
  um `DioException`. Como o `HttpClient` só escreve depois disso, nenhum byte da requisição (linha, cabeçalhos,
  assinatura RFC 9421, corpo) sai na recusa; o `validateCertificate` do Dio não é usado porque roda depois do envio
  (há um teste de controle mostrando isso). Um ensaio provou no emulador
  (proxy de interceptação: handshake completo e zero bytes de aplicação) e no aparelho de referência (chave não fixada: nenhuma
  requisição completa no servidor; zero bytes não é medido no aparelho); a falha aberta depois da expiração, só no
  emulador. A ficha afirma: "no Flutter ela vale para o `Dio` em que a linha do plugin foi instalada".
- **Falha fechada:** host fixado com proxy configurado no `HttpClient` (o TLS seria feito por cima do túnel, sem
  conferência) → `details: 'proxy'`, sem conectar ao proxy; `http` para host fixado → `details: 'cleartext'`, também
  depois da expiração (como o `domain-config` do Android). Falha de TLS detectada antes pela pilha mantém a
  `HandshakeException`. **Lista de proxies com `DIRECT`** (`findProxy` → `'PROXY p:8080; DIRECT'`): o `HttpClient`
  passa à entrada seguinte depois da recusa, e o host fixado é alcançado **direto e conferido**, nunca pelo proxy; a
  recusa só é terminal quando a lista não tem `DIRECT`.
- **Cancelamento:** se o `connectionTimeout` vence durante o handshake, o socket que ainda chegar é destruído e nunca
  entregue. Um handshake que nunca termina (par mudo) fica pendurado como no `HttpClient` sem fábrica (medido no Dart
  3.11: o `cancel` do `SecureSocket.startConnect` não fecha um handshake em curso).
- **Expiração:** como no Android, a data vale à meia-noite do fuso do aparelho e os pinos são conferidos enquanto
  `agora <= expiração`; depois o host volta à confiança do sistema (falha aberta por desenho). Atrasar o relógio mantém
  o pin-set; adiantá-lo o desliga.
- **`includeSubdomains`** e casamento: a entrada exata vence; senão o pai mais longo com `includeSubdomains`. Caixa e um
  ponto final são normalizados (`host.` não escapa da entrada).
- **Hosts fora da seção — mudança de comportamento (incompatível para quem personaliza a confiança):** conectam como
  antes (direto ou pelo proxy do app), **exceto** que, com uma `connectionFactory`, o `HttpClient` deixa de aplicar o
  `context` e o `badCertificateCallback` que o app tenha posto no `createHttpClient` (ele não os expõe) a toda conexão
  https direta. Consequências: um app que **restringe** a confiança (`HttpClient(context:
  SecurityContext(withTrustedRoots: false)..setTrustedCertificates(minhaCA))`) volta a confiar nas CAs do sistema nos
  hosts não fixados, e um `badCertificateCallback` de desenvolvimento deixa de valer. Repasse os dois:

  ```dart
  final ctx = SecurityContext(withTrustedRoots: false)..setTrustedCertificates('minha-ca.pem');
  dio.httpClientAdapter = IOHttpClientAdapter(createHttpClient: () => HttpClient(context: ctx));
  dio.addSentomaruPinning(pins, context: ctx); // sem `context:` aqui, os hosts não fixados usariam o sistema
  ```

  O `context` vale para toda conexão https direta (fixados inclusive); o `onBadCertificate`, só para hosts fora da
  seção, nunca para um host da seção, nem depois da expiração (como o Android, que volta só às âncoras do sistema). No
  túnel de proxy o `HttpClient` continua usando os dele. O `keyLog` do app se perde; uma `connectionFactory` do próprio
  app é substituída.
- **Adapter:** só o `IOHttpClientAdapter` padrão (outro tipo, `native_dio_adapter`, Cronet ou subclasse → `ArgumentError`).
  A linha põe um `IOHttpClientAdapter` **novo** com o `createHttpClient` (ou `onHttpClientCreate`) e o
  `validateCertificate` do app: proxy e ajustes do `HttpClient` do app ficam, e um `HttpClient` já criado sem a fábrica
  (um `Dio` que já fez requisição) não é reaproveitado. Isso diverge da spec, que pedia envolver o adapter existente:
  envolvê-lo não pega o `HttpClient` que ele guarda em cache. Instalar duas vezes, ou depois do `addSentomaru`
  (o redirecionamento do interceptor podia já ter herdado o adapter antigo), dá `StateError`. Trocar o adapter ou o
  `createHttpClient` depois da linha desliga o pinning. O adapter antigo não é fechado (pode ser de outro `Dio`); um
  `HttpClient` dele em cache fecha as conexões ociosas no `idleTimeout`. `addSentomaru(..., pins:)` não devolve o
  resultado da instalação: para saber se o pinning entrou (fora do Android não entra), use `addSentomaruPinning`.
- **Eventos:** `pins.events` (broadcast, só em memória, nada é enviado) entrega `SentomaruTransportEvent`
  (`kind` `transport`, `type` `pin_failure`, `reason` `pin_mismatch` | `tls_untrusted` | `tls_other`, `host` da
  seção que casou, nunca o subdomínio pedido, e `sequence` própria desse `SentomaruPins`, separada do stream de sinais).
  Sem IP, porta, URL, caminho, cabeçalho, certificado, chave apresentada nem horário. Recusas de proxy e de `http` não
  viram evento (são da configuração do app, e a exceção já diz). Não é veredito.
- **Testes (o que provam):** `test/pinning_transport_test.dart` usa `Dio` + `IOHttpClientAdapter` + `HttpClient`
  reais contra servidores loopback que contam cada byte recebido, com PKI gerada pelo `openssl` no teste (nada
  versionado). Como os hosts fixados são nomes DNS, os testes trocam só a resolução (TCP para 127.0.0.1, com o nome
  ainda no SNI e na conferência); o `SecureSocket.startConnect`/`Socket.startConnect` de produção roda só para hosts
  por IP (não fixáveis). Provam, no Dart da VM Linux: pino casa → envia; não casa → handshake no par e **zero** bytes
  de requisição; proxy/`http` recusados; lista com `DIRECT`; redirecionamento do `HttpClient` e do interceptor;
  keep-alive; expiração no limite; host fora da seção. O aparelho é a C-03b. A classificação `tls_untrusted` lê o
  texto `CERTIFICATE_VERIFY_FAILED` do BoringSSL (Dart 3.11, fixado no teste); se mudar, o evento cai em `tls_other`
  e a recusa não muda. Num fuso cujo horário de verão pula a meia-noite, a expiração do Dart e a do Android podem
  diferir em até 1 h.
- **Limites:** só a folha (o Dart não entrega a cadeia; pino de intermediária ou raiz nunca casa); só o `Dio` em que a
  linha foi instalada (outras instâncias, `HttpClient` cru, `package:http`, WebView ficam fora); só Android (no iOS a
  linha devolve `unsupportedPlatform` e não faz nada); não resiste a quem controla o processo (hooks, reempacotamento);
  sem kill switch remoto nem modo "só reportar".
