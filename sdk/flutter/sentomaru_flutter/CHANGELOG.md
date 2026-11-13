## 0.20.0-rc.4 (candidato)

SDK Android `0.2.0-rc.4`. Traz a autodeclaração do app (`SentomaruConfig.declaredEnforce` e
`declaredInstallationResponse`, enviados como `sdkModes` na inscrição, só informativos: o servidor nunca autoriza nada
com base nisso) e a API abaixo. A numeração segue a série 0.20.0.

Mudança de acréscimo: nenhuma API existente foi removida nem mudou de assinatura; quem não chama a API nova não
precisa alterar nada, exceto adicionar as duas dependências novas do pubspec (abaixo) na resolução do seu próprio
app. Lida e testada no repositório (`test/enrollment_assurance_test.dart`, canal de plataforma e armazenamento
seguro falsos); não testada em aparelho, contra servidor real nem pela troca efetiva de um app para esta API.

**Novo no plugin**

* `SentomaruEnrollmentAssurance` (D-W-port, decisão de projeto de 11/11/2026): API de alto nível que decide, por
  conta própria, reaproveitar a instalação, rotacionar a chave depois de uma atualização do app (D-04b/D-04d) ou
  reinscrever do zero — portada de `sentomaru_service.dart`/`sentomaru_app_update.dart` de um app consumidor, generalizada
  por um `SentomaruChallengeProvider` em vez de um `Dio`/endpoint fixo. Serializa chamadas concorrentes (a mais
  recente vence), guarda o principal por conta própria com cópia de reserva contra perda do armazenamento
  criptografado (`SentomaruPrincipalStore`), resolve por conta própria a reinstalação no iOS (antes
  responsabilidade do app, ver seção "iOS" do README), emite `reenrollReasons` sem dado pessoal, e tem
  `forgetInstallation()`. Detalhes, exemplo e guia de migração: README.md, "Garantia de inscrição portátil".
* Duas dependências novas do pubspec: `flutter_secure_storage` (armazenamento do principal) e
  `shared_preferences` (cópia de reserva e marcador de reinstalação do iOS) — ambas sem código nativo próprio
  deste plugin, mesmas plataformas já suportadas.

## 0.20.0-rc.3 (candidato)

Mesmo código da `0.20.0-rc.2`, com o SDK Android `0.2.0-rc.3`. O que muda é o que acompanha o release: o `verify_sdk.py` publicado exige
`--expect-repository` e não nomeia mais o repositório do fabricante, o verificador do conjunto novo tem linha própria na tabela de pinos,
e a varredura de nomes cobre as formas do endereço do repositório privado.

## 0.20.0-rc.2 (candidato)

Mesmo código da `0.20.0-rc.1`, com o SDK Android `0.2.0-rc.2`. O que muda é o que acompanha o pacote: o SBOM do release lista os pacotes Pub
resolvidos (versão e SHA-256) a partir de um `pubspec.lock` gerado com o Flutter fixado, e os textos públicos (comentários, READMEs, links)
não citam mais caminhos nem detalhes que só existem no repositório do fabricante.

## 0.20.0-rc.1 (candidato)

Mudanças de acréscimo: nenhuma API existente foi removida nem mudou de assinatura. Quem não usa as opções novas
não precisa alterar o código do app (veja abaixo o que muda no manifesto e nas dependências). Esta versão foi lida e testada no repositório; o que não foi provado em aparelho ou contra um
servidor está dito em cada item.

**Novo no plugin**

* `SentomaruTransactionSigner` (Android e iOS): assina uma operação de cada vez com uma chave que pede a presença da
  pessoa a cada uso. O valor vai no cabeçalho `x-sentomaru-tx-signature`, ou em `options.extra['sentomaru_tx_signature']`
  do `SentomaruDioInterceptor`, que o assina junto com a requisição e o remove nos redirecionamentos. No Android a chave é
  atestada pelo hardware e o servidor pode provar presença; no iOS ela é evidência consultiva e nunca satisfaz uma exigência
  de presença. No Android o prompt exige que a atividade do app seja uma `FlutterFragmentActivity`; com outra atividade, sem
  biometria cadastrada ou sem sensor a chamada falha com erro tipado e não assina. Só a passagem Dart pelo interceptor foi
  testada com plataforma falsa; não houve prova em aparelho com biometria forte.
* `SentomaruOfflineChain` (só iOS): cadeia de prova offline, com `sealOperation` e o corpo de reconciliação. Prova a ordem
  e a ausência de remoção feita pelo SDK íntegro; não prova que o conteúdo é verdadeiro, não protege a cauda ainda não
  enviada e não confirma a hora real de um item. O contador de boots do iOS não foi medido em aparelho.
* `collectSignalsSnapshot(screen: true)` (iOS): acrescenta `screen_capture` (`UNSUPPORTED`) e `screen_shared`
  (tela secundária, gravação ou espelhamento), consultivos. No Android o parâmetro é ignorado.

**Catálogo de sinais 1.15.0**

* A cópia do catálogo no plugin passa de 1.7.0 para 1.15.0 e o `catalogVersion` do snapshot acompanha. Entram, só no
  Android e por opção no SDK, os ids `a11y_risk`, `overlay`, `ime_untrusted`, `synthetic_input` (com o indicador
  `injected_touch`), `known_malware`, `screen_capture`, `screen_shared`, `location_mock` e `call_active`, e os novos
  vocabulários de eventos. **O plugin não coleta nenhum desses ids**: as coletas e o conteúdo do snapshot não mudam; quem os
  quer usa o SDK Android direto. O servidor lê `catalogVersion` como texto de até 32 caracteres (leitura do código; não
  conferido contra o servidor do HML).

**Dependências e permissões**

* Android: nova dependência `androidx.biometric:biometric:1.1.0` (usada só pelo prompt da chave de transação). A biblioteca
  `signals` passa a declarar `<queries>` para apps com entrada de lançador (usado pelo sinal opt-in `known_malware`), sem
  `QUERY_ALL_PACKAGES`, e nenhuma `<uses-permission>`. Esse `<queries>` é mesclado ao manifesto do app.
* iOS: o pod passa a ligar o framework `LocalAuthentication`.
* O SDK Android do plugin é o 0.2.0-rc.1 (era 0.1.0) e agora compartilha o núcleo da ponte com as camadas híbridas.

**Correções**

* iOS: ao descartar uma rotação de chave pendente, o registro pendente também é apagado; antes um reenvio posterior podia
  falhar por falta da chave.

## 0.19.0 (2026-10-29, D-10e: sinais no iOS; não publicado)

* **iOS: `collectSignals()` deixa de devolver lista vazia.** O lado nativo usa o `SignalsCollector` do SDK Swift
  (`sdk/ios`, D-10e) e devolve as seis capacidades do catálogo 1.0.0, no mesmo formato do Android: `debug_attached`
  (`P_TRACED`; `error` se o `sysctl` falhar), `emulator_detected` (`detected` no simulador, `not_detected` no
  aparelho), `root_indicated` (indícios de jailbreak só no aparelho, guardados 60 s por processo; `unknown` no
  simulador e num Mac: Catalyst ou app de iPhone no Mac), `app_signing_digest`
  (`unsupported`), `installer_source` (`unknown`, `reason=not_applicable`) e `os_version` (`detected`, `platform` e
  `release`). Sem isso o snapshot do app ia vazio e toda operação de `sensitiveOperations` saía `challenge` por
  `SIGNALS_MISSING` (prova no iPhone de 29/10/2026: `criar_demanda` 401 `challenge-required`). O app não muda: quem
  já põe `collectSignals()` ou `collectSignalsSnapshot()` em `x-sentomaru-signals` (o interceptor assina o cabeçalho,
  H3) passa a mandar os seis no iOS.
* **iOS: `collectSignalsSnapshot()` vai ao canal** (`collectSignalsSnapshot`, mesmos argumentos do Android) e devolve
  os seis acima; com `rasp`/`appIntegrity`, os ids da D-05 e da D-12c continuam `UNSUPPORTED` (agora depois dos seis).
  Antes o Dart respondia sem chamar o canal, sem os seis. As duas coletas rodam fora da thread principal e fora da fila
  serial do engine (não leem estado do cliente; como no Android, não pedem `initialize`). `rasp` que não seja `bool`
  no canal (texto, ou número 1/0 de um `int` do Dart) = `InvalidRequest:PARAMS` (só por chamada direta ao canal).
  O `durationMs` do iOS vem do relógio de parede, não de um relógio monotônico. As plataformas sem lado nativo seguem como
  antes.
* Sem eventos `signal` no iOS (`signalEventsSupported` falso): os detectores da D-05/D-12c não existem lá.
* Pod: link novo `ios/Classes/SDK/Sentomaru/Signals.swift`. `PrivacyInfo.xcprivacy` inalterado (nenhuma API de motivo
  obrigatório).
* Sem prova em aparelho: testes Dart, XCTest do plugin no simulador e `swift test` do SDK.

## 0.18.0 (2026-10-29, D-10b: plataforma iOS sobre o SDK Swift da D-10a; não publicado)

* **iOS.** Lado nativo novo em `ios/` (pod CocoaPods `sentomaru_flutter`, iOS 15+) que responde o mesmo canal
  `sentomaru_flutter` do Android, sobre o SDK Swift de `sdk/ios` (D-10a): inscrição e rotação com a chave da requisição
  no Secure Enclave atestada por App Attest, registro no Keychain `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`,
  assinatura RFC 9421 com os mesmos bytes do Android, renovação J-04r com a asserção App Attest da D-09c e `reset`.
  O pod compila os fontes do SDK por um link simbólico por arquivo para `sdk/ios/Sources` (o checkout por pub `git:`
  traz o repositório inteiro); sem pod de terceiro e sem binário. `pubspec.yaml` declara a plataforma `ios`.
* **API Dart sem mudança de assinatura.** No iOS: `playIntegrityCloudProjectNumber`, `strongBox` e as rotas de
  reatestação são ignorados; `requiresHardware: true` é recusado antes de criar chave (`invalidRequest`; o servidor
  recusaria com 422, D-IOS9); `reenrollmentReason()` é sempre `null`; `collectSignals()` devolve lista vazia (o SDK
  Swift não tem sinais); snapshot, reatestação, eventos `signal`, assets selados e pinning seguem como antes
  (`UNSUPPORTED`, `ReattestationUnsupported`, sem eventos, `UnsupportedError`, linha sem efeito).
* Novo `SentomaruErrorCode.unsupported` (acrescentado no fim; ordinais antigos iguais): sem App Attest ou sem Secure
  Enclave (simulador, aparelho sem suporte, app sem a capability App Attest) a inscrição falha sem criar nem enviar
  nada, com `details` `Unsupported:APP_ATTEST` ou `Unsupported:SECURE_ENCLAVE`. Nunca no Android. Um `switch`
  exaustivo sobre `SentomaruErrorCode` no app precisa do caso novo.
* Sem parâmetro `appAttestEnvironment`: o ambiente App Attest é o do entitlement
  `com.apple.developer.devicecheck.appattest-environment` do build e precisa ser igual ao `apple_attest_environment`
  do escopo.
* `sdk/ios/Sources/Sentomaru/Exports.swift`: o `@_exported import SentomaruCore` só quando o módulo existe (SwiftPM);
  no pod os dois módulos viram um só. Sem mudança de comportamento no SDK.
* Ordem no iOS: uma fila por engine, na ordem de chegada (como o executor do Android); respondem na hora, antes da
  fila, o `ConfigurationError` da validação de `initialize`, `collectSignals`, `scaffoldInfo` e método não implementado;
  mensagens de erro do plugin
  iguais às do Android. Argumento de tipo errado no canal = `InvalidRequest:PARAMS` (Android: `ChannelError`).
* Sem prova em aparelho: testes do lado iOS só no simulador, com chaves em software e App Attest e servidor falsos.

## 0.17.0 (2026-10-27, D-14b: leitor de assets selados; não publicado)

* Novo `SentomaruSealed.load(chaveDoPubspec)` (`Future<Uint8List>`), `SentomaruSealed.string(chave)` (`null` para chave
  ausente) e `SentomaruSealed.configure(allowPlainFallback:, plainStringsKey:)`, para os arquivos que o controle
  `asset-encryption` da CLI sela (formato selado v1, `contracts/devsecops/cli-v1.md`). Decifração no lado Android, pelo
  módulo novo `br.com.ebees.sentomaru:sealed` do SDK (AES-256-GCM e HKDF-SHA256 do `javax.crypto`), pelo canal
  (`sealedLoad`, `sealedString`, `sealedConfigure`), numa thread própria; sem criptografia em Dart. O plugin traduz a
  chave do `pubspec.yaml` para o caminho canônico (`assets/flutter_assets/` + chave).
* Falhas tipadas `SentomaruSealedException` (`SentomaruSealedError.notSealed`, `integrity`, `formatUnsupported`, os
  códigos do contrato), que **não** estende `SentomaruException`. Chave mal formada → `ArgumentError` antes do canal.
  No iOS, `UnsupportedError`. Falta de memória na leitura e chamadas pendentes quando o engine desliga → `channelError`.
* `allowPlainFallback` (D-14x10) desligado por padrão: sem `header.bin` no pacote, lê o arquivo em claro (só para
  `flutter run` e testes; ligar só com `kDebugMode`); num pacote selado não tem efeito. Arquivo ausente nesse modo →
  `SentomaruException` com `details` `AssetNotFound`. `plainStringsKey` é a chave do arquivo de strings em claro (o
  cabeçalho a dá num pacote selado; um pacote sem selagem não tem cabeçalho).
* Classe nova `SentomaruFlutterSealed` com `-keepnames` nas regras de consumidor: o marcador que a CLI procura no DEX
  (`sealed-reader-missing` sem ele). Prova só que o leitor está linkado, não que o app o chama.
* Dependência nativa nova: o AAR `sealed` do SDK, construído do código-fonte como os outros (sem dependência externa).
* Ofuscação de dados, não sigilo (D-14x1). Sem prova em aparelho (D-14d) e sem o controle na CLI (D-14c): nada disso
  entra na ficha até lá.

## 0.16.0 (2026-10-26, C-03a: pinning da chave do servidor no Dart antes do envio; não publicado)

* Novo `SentomaruPins.fromProfileSection(secao)` (seção `network-pinning` v1 do perfil `protect`, mesmas regras de
  estrutura da CLI, `FormatException` com o caminho do campo; sem conferência de expiração passada nem do teto de 180
  dias, que são da CLI) e `dio.addSentomaruPinning(pins, {context, onBadCertificate})` →
  `SentomaruPinningInstall.installed` (Android) ou `unsupportedPlatform` (outras plataformas: a linha não faz nada).
  `addSentomaru(..., pins:)` instala o mesmo antes do interceptor.
* A conferência é uma `HttpClient.connectionFactory`: para um host fixado com o pin-set ativo, handshake TLS, SHA-256
  do SPKI da folha (leitor ASN.1 mínimo, conferido com o `openssl` para RSA 2048, EC P-256 e EC P-384) e socket
  entregue ao `HttpClient` só se o pino casar; senão o socket é fechado antes de qualquer byte da requisição
  (`SentomaruErrorCode.pinningRefused`, `details` `pin_mismatch`). Proxy (`proxy`) e `http` (`cleartext`) para host
  fixado são recusados antes de conectar. Expiração como no Android (meia-noite local, `agora <= expiração`), falha
  aberta depois dela; `http` segue recusado.
* Novo `SentomaruErrorCode.pinningRefused`, acrescentado no fim (ordinais antigos iguais; só Dart, sem código nativo).
* Eventos locais `SentomaruTransportEvent` em `pins.events` (`pin_failure` com `pin_mismatch`, `tls_untrusted` ou
  `tls_other`, host da seção, sequência própria), sem PII e sem envio (D-07x9).
* **Desvio da spec, registrado:** a linha põe um `IOHttpClientAdapter` novo, carregando o `createHttpClient`, o
  `onHttpClientCreate` e o `validateCertificate` do app, em vez de envolver o existente, porque o existente pode ter um
  `HttpClient` em cache criado sem a fábrica. Outro tipo de adapter → `ArgumentError`; segunda instalação ou depois do
  `addSentomaru` → `StateError`.
* **Incompatível para quem personaliza a confiança:** com a fábrica, o `HttpClient` deixa de aplicar o `context` e o
  `badCertificateCallback` postos pelo app no `createHttpClient` (não são legíveis) às conexões https diretas, também
  nos hosts **não** fixados: um `HttpClient(context: SecurityContext(withTrustedRoots: false)...)` voltaria a confiar
  nas CAs do sistema, e um `badCertificateCallback` de desenvolvimento deixa de valer. Passe-os a
  `addSentomaruPinning(pins, context: ..., onBadCertificate: ...)` (exemplo no README); `onBadCertificate` nunca vale
  para um host da seção, nem depois da expiração.
* Com `findProxy` → `'PROXY ...; DIRECT'`, o `HttpClient` tenta a entrada seguinte depois da recusa: o host fixado vai
  direto e conferido, nunca pelo proxy. Timeout durante o handshake: o socket que chegar depois é destruído.
* Dependência nova: `crypto` (pacote do dart.dev, só Dart) para o SHA-256.
* Sem prova em aparelho (C-03b): a frase do Flutter não entra na ficha até lá.

## 0.15.0 (2026-10-24, D-06h: desafio `reattest`; não publicado)

* `challenge-required` com `challengeKind: reattest` (contrato v1.10, adaptador 4.6.0) é um tipo conhecido:
  `SentomaruServerResponseCodes.reattest`, `freshSignals`, `stepUp` e a lista fechada `challengeKinds`
  (`fresh_signals`, `step_up`, `reattest`, conferida com o `CHALLENGE_KINDS` do Kotlin pelo teste). Um tipo bem formado
  fora da lista continua passando bruto; um malformado continua nulo. `SentomaruSignalEvent.isReattestChallenge`.
* Novo `SentomaruClient.reattest({strongBox})`: a mesma reatestação da D-12e (`SentomaruReattestation.reattest`
  nativo, mesma thread, mesmos resultados e erros de `reattestIfDue`), **sem** o prazo local, porque quem decidiu foi
  o servidor. Não é fluxo novo: o nativo já tinha a chamada. No iOS, `ReattestationUnsupported` sem chamar o canal.
  Interface de plataforma: `reattest()` com padrão `UnimplementedError`; quem **implementa** `SentomaruFlutterPlatform`
  num dublê acrescenta o membro.
* Roteiro do app (guia de integração): ao receber `challenge-required` `reattest`, chama `reattest()` uma vez e repete a
  operação **uma vez** com nonce novo. Com `ReattestationCompleted`, repete uma vez, quaisquer que sejam os estados (quem
  julga é o servidor); se vier `challenge` `reattest` de novo, não reatesta outra vez nesta operação. Com
  `ReattestationNotNow` (429 do intervalo ou do teto diário) mostra "tente mais tarde" e não repete. O plugin não
  reatesta nem repete nada sozinho.
* `collectSignals()`, `collectSignalsSnapshot()`, `reattestIfDue()` e `reattestationDue()` não mudam.

## 0.14.0 (2026-10-23, D-15c: eventos de sinal e de resposta do servidor por opção; não publicado)

* Novo `SentomaruClient.signalEvents` (`Stream<SentomaruSignalEvent>`, broadcast) e `signalEventsSupported`. Eventos
  **informativos**, nunca veredito: não existe `isCompromised()`, nota nem resumo, e a decisão continua no servidor a
  cada requisição. Nada liga sozinho: enquanto ninguém escuta o stream o lado nativo não guarda evento algum, e
  `collectSignals()` sem argumento e `collectSignalsSnapshot()` devolvem o mesmo de antes.
* `kind` `signal` (só Android, `EventChannel` `sentomaru_flutter/signal_events`): as capacidades da D-05 e da D-12c de
  cada `collectSignalsSnapshot` feito enquanto o app escuta, na primeira observação e a cada mudança de estado
  (`SentomaruSignalEvents` da D-15a, uma instância nova por assinatura). Campos de vocabulário fechado: `type`,
  `capabilityId`, `capabilityVersion`, `state`, `reasonCodes` (lista permitida por capacidade), `catalogVersion`. As seis
  antigas nunca viram evento. Sem horário, `detail`, nome de pacote, caminho ou digest. Um evento com qualquer campo
  fora do vocabulário (`SentomaruSignalEventsCatalog`, conferido com o `SignalsCatalog.kt` pelo teste) é descartado
  inteiro. No iOS o stream não emite eventos `signal` e `signalEventsSupported` é `false`, sem tocar no canal.
* `kind` `server_response` (todas as plataformas): o `SentomaruDioInterceptor` passa ao cliente a resposta final 401/403
  de uma requisição que **ele assinou** (marca interna posta só depois de assinar). Só o `code` de primeiro nível (e o
  `challengeKind` junto de `challenge-required`) é lido: `challenge-required` e `proof-required` (só 401),
  `installation-suspended`, `installation-revoked`, `session-unavailable`, `policy-denied`, ou código de recusa de
  política `^[A-Z0-9_]{3,64}$` (só 403). Corpo em texto ou bytes acima de 4096 caracteres não é lido. Requisição sem
  assinatura, texto livre, `riskEvent` ou `code` aninhado não viram evento; um 3xx seguido ou um `session-expired`
  renovado gera um evento só, o da resposta que encerrou a requisição. `SentomaruRiskEvent`/`onRiskEvent` não mudam.
* `sequence` é a ordem de chegada ao stream do cliente, um contador só para os dois tipos (o número nativo não é
  repassado).
* O vocabulário dos dois tipos é conferido pelo teste com o Kotlin (`SignalsCatalog.kt` e
  `SentomaruServerResponseEvent.kt`); o leitor do corpo não é o mesmo: o Dart usa `jsonDecode` (um membro repetido
  fica com o último valor, o Kotlin recusa o corpo) e lê como está um `Map` que o Dio já decodificou.
* Vários `SentomaruClient` no mesmo engine dividem uma assinatura nativa só (o canal tem um ouvinte nativo por vez):
  cancelar o stream de um não cala o do outro. Não existe método público para injetar `server_response` no stream: o
  interceptor entrega a resposta ao cliente por um registro interno, não exportado.
* Interface de plataforma: `signalEventsSupported` e `signalEvents()` com padrão falso/vazio. Quem **implementa**
  (`implements`) `SentomaruFlutterPlatform` num dublê de teste precisa acrescentar os dois membros; quem estende não.
* Guia de uso recomendado: evento `signal` no máximo avisa e registra; `challenge-required` `step_up` pede nova
  autenticação; `installation-suspended` mostra a tela de suspensão preservando rascunhos; `installation-revoked` leva a
  nova inscrição. Sair do app só por um evento `signal` é desaconselhado (falso positivo medido), mas a escolha é do app.

## 0.13.0 (2026-10-23, D-12e: sinais de integridade do app e reatestação por opção; não publicado)

* Novo parâmetro `collectSignalsSnapshot(appIntegrity: AppIntegritySignals(expectedSignerDigests: [...]))`: acrescenta,
  depois das outras, as três capacidades `client_observed` do catálogo 1.5.0 (`app_signer_mismatch`, `installer_class`,
  `code_integrity`), coletadas no Android por `SignalsCollector.appIntegrityDetectors(expectedSignerDigests)` no executor
  de fundo do plugin. **Prazo (revisão R):** sem `rasp` a coleta continua sem prazo (as seis antigas não passam a dar
  `UNKNOWN timeout` por causa da opção; os três novos se limitam sozinhos, o `code_integrity` espera no máximo 15 ms);
  com `rasp`, o prazo é `RASP_DEADLINE_MS + APP_INTEGRITY_BUDGET_MS` (135 ms) para todas, e qualquer detector, inclusive
  os antigos, pode dar `UNKNOWN timeout`, como já acontecia com `rasp`. A lista de
  certificados esperados é do app (SHA-256 de 64 dígitos hex, com ou sem `:`, qualquer caixa; lista vazia = `UNKNOWN`
  `no_reference`); um valor que não é SHA-256 é `configurationError` antes de chamar o nativo (e o nativo também
  responde `ConfigurationError`). `code_integrity` continua sempre `UNKNOWN` do app; o servidor compara (D-12c-2).
* iOS: os três ids vêm `UNSUPPORTED`, sem chamar o canal (junto com os da D-05 quando `rasp: true`).
* Reatestação sob desafio (D-12b/D-12c), por opção: `SentomaruConfig(reattestation: SentomaruReattestationConfig(
  challengeUrl:, submitUrl:, minInterval: 24 h))` cria no `initialize` o `SentomaruReattestation` nativo (rota fora da
  allowlist, sem https, intervalo não positivo ou fracionário = `configurationError`, e nada fica guardado). Novos
  `SentomaruClient.reattestationDue()` (não bloqueia) e `reattestIfDue({strongBox})`, que roda numa **thread de
  trabalho própria do plugin**, nunca na principal nem na fila do `sign`. Resultados novos: `ReattestationCompleted`
  (`ReattestationResult`), `ReattestationNotNow` (`ReattestationWait`: `rateLimited`, `verifierUnavailable`,
  `unavailable`, `notDue`, `unknown`), `ReattestationRefused(code, status)` e, no iOS, `ReattestationUnsupported`. As
  regras de nova tentativa, espera e intervalo são as do SDK Android (`contracts/sdk/sdk-api-v1.md` §2.5). Sem
  `reattestation` na configuração: `invalidRequest`. Resposta nativa malformada = `channelError`.
* `EnrollmentTransport.reattest` (Android): os dois passos saem pelas regras da inscrição (host da allowlist em https,
  sem redirect, um envio); a resposta vai ao SDK com status, corpo (vazio acima de 16 KiB) e `Retry-After` só em
  segundos; falha de transporte = `IOException` ("agora não" no SDK).
* **Sem mudança sem os parâmetros novos:** `collectSignals()` (mesmo método, sem argumentos, as seis capacidades) e
  `collectSignalsSnapshot()`/`collectSignalsSnapshot(rasp: true)` (mesmos argumentos no canal, mesmos coletores e
  prazos, mesmo cabeçalho); `initialize` sem `reattestation` manda o mesmo mapa. O ExampleApp e a J-04 continuam iguais.
* `SentomaruFlutterPlatform.collectSignalsSnapshot` ganhou `appIntegrity`, e a interface ganhou `reattestationDue()` e
  `reattestIfDue()`: quem **implementa** (`implements`) a interface de plataforma em testes precisa acrescentar o
  parâmetro e os métodos (quem estende herda o `UnimplementedError`).
* Novos exports: `AppIntegritySignals`, `SentomaruReattestationConfig`, `ReattestationOutcome` e subclasses,
  `ReattestationResult`, `ReattestationWait`.
* Evidência: testes Dart (`app_integrity_test.dart`: cada estado dos três ids, estados desconhecidos lidos como
  `UNKNOWN`, recusa da lista, cabeçalho com os 15 sinais em 3083 de 4096 caracteres, iOS, cada resultado e cada falha
  da reatestação, configuração) e JVM (`AppIntegrityCollectorTest`: coletores com e sem a lista, nenhuma falha de
  plataforma vira `NOT_DETECTED`; `ReattestationReplyTest`: `SentomaruReattestation` real com dublês de Keystore e das
  rotas; `EnrollmentTransportTest`: `reattest` em TLS real). O caso do `sample/integration_test` foi escrito e **ainda
  não rodou em aparelho**.

## Sem versão nova (2026-10-23, catálogo 1.6.0: `code_integrity` comparado no servidor, D-12c-2)

* A cópia do catálogo segue o contrato 1.6.0: só `version` muda (a cópia do plugin não guarda descrição nem
  `limitations`). Nenhuma coleta muda.

## Sem versão nova (2026-10-23, catálogo 1.5.0: três ids do cliente, D-12c)

* A cópia do catálogo segue o contrato 1.5.0: `version` passa a `1.5.0` e entram os ids `client_observed`
  `app_signer_mismatch`, `installer_class` e `code_integrity` (`appIntegrityCapabilityIds`), que o SDK Android coleta só
  por opção. O plugin **não** os coleta (a D-12e faz isso); `collectSignals()` e `collectSignalsSnapshot()` não mudam.

## Sem versão nova (2026-10-22, catálogo 1.4.0: `app_identity_mismatch`, D-13a)

* A cópia do catálogo (`SentomaruSignalsCatalog`) segue o contrato 1.4.0: `version` passa a `1.4.0` (o
  `catalogVersion` que um build novo do plugin manda; o servidor aceita qualquer versão) e entra o id `server_verified`
  `app_identity_mismatch`, que o servidor põe a partir do gate 10a da atestação de chave. Como os outros ids de servidor,
  ele sai de `serverVerifiedIds` e é descartado de `SignalsSnapshot.toMap`. Nenhuma coleta muda; o 0.12.0 publicado
  continua mandando `1.3.0`.

## Sem versão nova (2026-10-22, catálogo: `budgetMs` de `root_artifacts`)

* O catálogo 1.3.0 publicado antes de 22/10 (plugin 0.12.0 e o HML na API  de homologação) tem `budgetMs` 10 em
  `root_artifacts`; o do repositório desde o #48 tem 11 (medição D-05c no aparelho de referência), com `updatedAt`
  `2026-10-22T00:00:00Z`. A versão do catálogo não subiu porque `budgetMs` não viaja no snapshot nem é conferido pelo
  servidor; a cópia do catálogo no plugin (`SentomaruSignalsCatalog`) não guarda `budgetMs` e não muda.

## 0.12.0 (2026-10-21, D-05e: snapshot de sinais no plugin e sinais da D-05 por opção; não publicado)

* Novo `SentomaruClient.collectSignalsSnapshot({bool rasp = false})` → `Future<SignalsSnapshot>`. O plugin monta o
  snapshot no formato do servidor (`contracts/sdk/signals-observation-schema-v1.json`): `SignalsSnapshot.toJson()` é o
  valor do cabeçalho `x-sentomaru-signals`. `catalogVersion` vem do catálogo (`SentomaruSignalsCatalog.version`,
  1.3.0); `collectedAt` e `durationMs` vêm do coletor nativo (relógio monotônico; duração negativa vira 0); estado no
  nome do servidor (`SignalState.wireName`, `NOT_DETECTED`); `source` `client_observed`; `observedAt` em UTC; `detail`
  como mapa de texto, sem valores nulos. As capacidades `server_verified` do catálogo (`play_integrity_failed`,
  `build_unregistered`) são descartadas, lidas do catálogo (`SentomaruSignalsCatalog.serverVerifiedIds`) e não de uma
  lista própria. Resposta nativa sem `collectedAt` válido, sem `durationMs`, com observação sem `observedAt` ou com id
  repetido é `channelError` (nada é inventado).
* `rasp: true` pede ao Android `SignalsCollector.defaultDetectors() + raspDetectors()` com
  `deadlineMs = SignalsCollector.RASP_DEADLINE_MS`, no executor de fundo do plugin (com prazo o coletor recusa a
  thread principal): `debugger_attached`, `app_debuggable`, `dev_settings_enabled`, `root_artifacts`,
  `emulator_indicated`, `hook_framework_java`. Sinais declarados pelo app, consultivos; nenhuma política padrão os usa.
* `collectSignals()` sem argumento **não mudou**: mesmas seis capacidades, mesmo método do canal sem argumentos, mesmo
  tipo de retorno. O ExampleApp e a J-04 continuam nele.
* **O plugin não depende de `signals-rasp`.** Quem quer a checagem de pacotes de gerenciador de root do
  `root_artifacts` declara `br.com.ebees.sentomaru:signals-rasp` no `android/app/build.gradle(.kts)` do próprio app.
  Sem ele o manifesto mesclado não ganha `<queries>` e `root_artifacts` nunca dá `NOT_DETECTED` (`UNKNOWN` com
  `partial=root_package`, ou `DETECTED` por outro indício). Conferido no manifesto mesclado do `sample/`.
* iOS (sem lado nativo): `collectSignalsSnapshot(rasp: true)` devolve os seis ids da D-05 como `UNSUPPORTED`, sem chamar
  o canal; as seis antigas não entram. Sem `rasp`, snapshot vazio.
* Novos exports: `SignalsSnapshot`, `SentomaruSignalsCatalog`, `SignalCapability`; `SignalState.wireName`.
* `SentomaruFlutterPlatform.collectSignalsSnapshot({bool rasp})` acrescentado: quem **implementa** (`implements`) a
  interface de plataforma em testes precisa acrescentar o método (quem estende herda o `UnimplementedError`).
* Evidência: testes Dart (catálogo comparado com `signals-catalog-v1.json`; JSON validado contra
  `signals-observation-schema-v1.json` com as fixtures do catálogo; canal com e sem `rasp`; respostas malformadas; iOS)
  e JVM (`SignalsSnapshotReplyTest`: coletor escolhido e resposta do canal). O teste em aparelho
  (`sample/integration_test`) ganhou o snapshot com `rasp`, ainda não rodado em aparelho.

## 0.11.0 (2026-10-21, D-04d: a rotação reinscreve a mesma instalação)

* `rotate` assina, com a chave atual, a prova de que a chave nova é da mesma instalação (contrato v1.6): o servidor
  mantém o código `INS-…`, o nome, as etiquetas e a suspensão, e encerra a chave antiga. `reset()` + `enroll()`
  continua criando uma instalação nova.
* Novo `SentomaruErrorCode.reenrollmentRefused` (nativo `ReenrollmentRefused`, de `401 predecessor-invalid`): a
  instalação atual não pode ser reinscrita (quarentenada, já substituída, outro subject/tenant ou prova inválida).
  Rotacionar de novo não resolve: chame `reset()` e depois `enroll()` (instalação nova, sem nome, etiquetas nem
  suspensão). Acrescentado no fim do enum (ordinais antigos iguais).
* Resposta perdida: se a rotação pendente já foi enviada e o app chama `rotate` com desafio **novo**, o plugin reenvia
  primeiro o corpo congelado; o servidor devolve o grant original (mesmo com o desafio expirado) e a `rotate` termina
  com ele. Só quando o servidor prova que não aceitou aquele corpo (`challenge-invalid`, `enrollment-revoked`, `409
  enrollment-conflict`) a pendência é descartada e a rotação segue com o desafio novo; qualquer outra recusa (4xx
  genérico, proxy, corpo ilegível) ou erro de rede mantém a pendência.
* Mapeamento de recusas do transporte: `409 enrollment-conflict` passa a `ServerRejected:CONFLICT` (era `INVALID`);
  `EXPIRED` e `REVOKED` só vêm dos códigos exatos do Sentomaru (`challenge-invalid`/`challenge-expired`,
  `enrollment-revoked`/`installation-revoked`); um 410 sem código passa a `INVALID`. O registro local ganhou a marca
  `sent` na rotação pendente (leitura tolerante; um `InstallationStore` próprio deve persistir).
* Limite conhecido: rotacionar zera as contagens das regras de resposta automática da instalação; a suspensão já
  gravada é copiada.

## 0.10.0 (2026-10-21, D-04b: reinscrição depois de atualizar o app)

* Novo `SentomaruClient.reenrollmentReason()` → `Future<ReenrollmentReason?>`. `ReenrollmentReason.appUpdated` quando o
  `versionCode` do app é diferente daquele com que a chave em uso foi atestada (atualização **ou** rebaixamento); `null`
  quando é igual, quando a instalação não está `enrolled`, quando a versão não pôde ser lida, ou quando a instalação foi
  inscrita antes desta versão (sem versão guardada: desconhecida, nunca força reinscrição; a próxima inscrição ou rotação
  grava). `ReenrollmentReason.unknown` cobre um motivo que um SDK nativo mais novo mande.
* Não é um estado novo: `state()` continua `enrolled` e `sign` continua funcionando. O plugin não pede desafio sozinho;
  o app pede um desafio ao seu backend e chama `rotate(challenge)` (a chave atual segue assinando até o grant novo) ou
  `reset()` + `enroll(challenge)`. Os dois gravam a versão atual. Exemplo:
  `if (await client.reenrollmentReason() != null) await client.rotate(await pedirDesafio());`
* A reinscrição cria uma instalação nova no servidor (`installationId` novo, como toda rotação): o Console mostra outra
  instalação. Ligar a nova à anterior depende do servidor (fora deste plugin).
* Peça um desafio **novo** a cada vez que `reenrollmentReason() != null`. Com o mesmo desafio de uma rotação
  interrompida, a `rotate` reenvia a pendência congelada (o servidor devolve o grant original; outro corpo levaria 409
  `enrollment-conflict`): o grant é recuperado, a versão guardada continua a antiga e a consulta continua pedindo. Com
  desafio novo, chave e atestação novas gravam a versão atual. Chame `reenrollmentReason()` uma vez no cold start, não
  em volta de cada requisição; se a rotação falhar, tente no próximo cold start.
* `versionCode` zero ou negativo conta como desconhecido.
* A versão guardada é lida de forma tolerante: só inteiro positivo; qualquer outro valor vira desconhecido (nunca
  `KeyInvalidated`). Voltar a um SDK anterior descarta o campo na próxima escrita (a instalação volta a ser "sem versão").
* `SentomaruFlutterPlatform.reenrollmentReason()` acrescentado: quem **implementa** (`implements`) a interface de
  plataforma em testes precisa acrescentar o método (quem estende herda o `UnimplementedError`).
* SDK Android: `SentomaruClient.reenrollmentReason()`, `enum ReenrollmentReason { APP_UPDATED }`,
  `InstallationRecord.versionCode` e `PendingRotation.versionCode` (gravados no registro local), parâmetro
  `appVersionCode` do construtor (`@JvmOverloads`; `initialize` lê `PackageInfo.longVersionCode`). Regra de consumidor
  nova para `ReenrollmentReason`. Os construtores de `SentomaruClient`, `InstallationRecord` e `PendingRotation` têm
  `@JvmOverloads` (Java antigo compila), mas parâmetros com padrão acrescentados mudam o construtor sintético do Kotlin:
  **recompile** o código Kotlin que usa o SDK (não troque só o AAR). Um `InstallationStore` próprio deve persistir
  `versionCode`; sem isso a consulta nunca pede reinscrição.
* Evidência: testes JVM (`ReenrollmentTest` no SDK, inclusive a leitura tolerante `StoredVersionCode`; `ReenrollmentReplyTest` no plugin) e Dart (canal de métodos e
  cliente). A leitura real do `PackageManager` e o `AtomicFile`/`org.json` do armazenamento não têm teste JVM
  (stubs do android.jar; trazer `org.json` só para teste mudaria o lock de dependências): a parte pura
  (`StoredVersionCode`) é testada; o resto fica para o aparelho (D-04c).

## 0.9.2 (2026-10-19, motivo da espera da renovação)

* `renewSession()` recusado com `RenewalBackoff` agora traz em `details` o código da falha que começou a espera, no
  mesmo formato do código de `serverRejected`: `details: 'ServerRejected:SUSPENDED'` numa suspensão,
  `'NetworkUnavailable'`, `'ServerRejected:UNAVAILABLE'` etc. nas demais. Antes `details` vinha `null`: quando a
  renovação silenciosa do `sign` (`renewIfDue`) já tinha falhado por suspensão, o `renewSession()` explícito do app caía
  na espera e o app não distinguia "suspenso" de "indisponível". `details` só é `null` se a falha não teve código
  (exceção inesperada do transporte, que não é `SentomaruException`). A decisão (espera / sem renovação possível) e o
  código saem de uma leitura só, sob a trava do cliente (`SentomaruClient.renewalGate()`): uma falha nova de outra
  thread não cai entre as leituras, então `details` é sempre o da falha que gerou a recusa.
* `details` é uma pista sobre a última falha, não o estado atual do servidor: liberada dentro da janela, a instalação
  continua aparecendo "suspensa" até a espera acabar e a próxima renovação dar certo.
* Recusa por grant de outra chave na resposta da renovação fica registrada como `InvalidRequest:PARAMS` (o mesmo código
  que `renew` lança; não há erro mais específico).
* O código continua `renewalBackoff` (nenhum código novo, nenhum valor de enum novo); só `details` muda. O lado Dart não
  mudou: `SentomaruException.fromPlatformException` já repassa `details` do canal.
* SDK Android: `SentomaruClient.renewalGate()` (`RenewalGate(backingOff, canRenewNow, lastFailure)`, uma leitura
  consistente) e `SentomaruClient.lastRenewalFailure(): String?`, só leitura: o `SentomaruError.code` da última renovação
  que falhou, válido só enquanto `renewalBackingOff()` é verdadeiro (fora disso `null`). Guardado junto com o instante da
  falha e limpo em todos os pontos em que a espera é limpa (sucesso, `reset()`, perda do grant).
* O interceptor Dio não mudou (continua o desvio aceito do 0.9.1).
* Evidência: testes unitários JVM (`OkHttpTransportTest`; no plugin `RenewalRefusalTest` e `RenewSessionReplyTest`, que
  monta a resposta de `handleRenewSession` a partir de um `SentomaruClient` real depois de um `renewIfDue` suspenso) e
  Dart (canal de métodos). A chamada `result.error` em si (looper principal) não é exercitada nos testes JVM.

## 0.9.1 (2026-10-19, suspensão na renovação)

* `403 {"code":"installation-suspended"}` (contrato v1.5) na renovação nativa da sessão deixa de virar
  `invalidRequest` (`InvalidRequest:PARAMS`, sem o código do servidor): passa a `serverRejected` com
  `details: 'ServerRejected:SUSPENDED'`, no padrão de `ServerRejected:REVOKED`. O grant é mantido (não reinscreve).
* Espera depois de falhas SUSPENDED seguidas: **5 s → 15 s → 60 s** (`SUSPENDED_RENEWAL_BACKOFF_STEPS`), não 60 s fixos:
  liberada logo pelo operador, a instalação renova no próximo "Tentar de novo" sem reabrir o app. O degrau volta a 5 s
  com sucesso, `reset()`, perda do grant (`session-unavailable`) ou falha não-SUSPENDED (essa mantém 60 s). É uma troca
  do cliente: no máximo 3 renovações nos primeiros 20 s da suspensão, 4 em 80 s e depois 1/min (≈60/h, mesmo teto das
  falhas comuns; com 5 s fixos seriam até 720/h). Em troca, depois de uma suspensão longa a recuperação pode esperar até
  60 s. Só renova quando a renovação é pedida (grant na margem ou `session-expired`).
* `reset()` e a perda do grant agora limpam a espera da renovação (antes ficava a espera antiga).
* Na inscrição, o mesmo `403 installation-suspended` agora vira `ServerRejected:SUSPENDED` (antes `ServerRejected:INVALID`).
* Novo código `RenewalBackoff` → `SentomaruErrorCode.renewalBackoff`: `renewSession()` recusado por estar dentro da
  espera da última falha (antes `invalidRequest`/`InvalidRequest:PARAMS`, indistinguível de "não dá para renovar").
  Sem `renewalUrl` ou sem inscrição continua `InvalidRequest:PARAMS`, mesmo com espera pendente. `renewalBackoff` é o
  **último** valor do enum (depois de `unknown`): os índices dos valores antigos não mudam. Quem faz `switch` exaustivo
  sobre `SentomaruErrorCode` precisa tratar o novo valor.
* Desvio aceito: o interceptor Dio continua engolindo a falha da renovação (SUSPENDED, `RenewalBackoff` ou outra) e
  devolve o `403 session-expired` original, sem o motivo. Para saber o motivo, chame `SentomaruClient.renewSession()`
  direto e trate o código (é o que faz o binder do ExampleApp).
* SDK Android: o interceptor OkHttp (`addSentomaru`) também mapeia `403 installation-suspended` da renovação para
  `ServerRejected(SUSPENDED)` (antes falha genérica de 60 s); `SentomaruClient.renewalBackingOff()` e
  `EnrollmentError.RenewalBackoff` acrescentados.
* Só o 403 com `code` exatamente `installation-suspended`: outros 403, corpo sem `code`, não-JSON ou outro status mantêm
  o mapeamento anterior; `session-unavailable` continua `enrollmentRequired`.
* SDK Android: `EnrollmentError.Rejection.SUSPENDED` (acrescentado no fim do enum). Quem faz `when` exaustivo sobre
  `Rejection` precisa tratar o novo valor.
* Evidência: testes unitários JVM (`EnrollmentTransportTest`, `RenewalRefusalTest`, `OkHttpTransportTest`) e Dart (canal
  de métodos e interceptor Dio).

## 0.9.0 (2026-10-17, J-04r)

* Renovação assinada da sessão (grant): `SentomaruConfig(renewalUrl: …)` (rota pública do consumidor, https em
  `allowedHosts`). O código nativo renova o grant antes do fim da vida (10 min no servidor, margem de `min(2 min, vida/5)`), com pedido
  assinado pela chave da instalação e **sem nova atestação**; falha mantém o grant atual (a requisição segue e o
  servidor decide) e espera 60 s antes de tentar de novo. O interceptor do Dio, ao receber `session-expired` de uma
  requisição assinada, renova e reenvia **uma única vez** (respeitando a espera de 60 s). `session-unavailable` na
  renovação (instalação revogada, cadeia acima de 7 dias, aparelho sem hardware onde a política exige) apaga o vínculo:
  `state()` vira `enrollmentRequired` e o app reinscreve (`reset` + `enroll`). `SentomaruClient.renewSession()` e o
  método de canal `renewSession`. Sem `renewalUrl`, nada muda. Acréscimo, sem quebra.
* Evidência: testes unitários (Dart e JVM). O gate em aparelho da J-04r é Android/OkHttp (SDK); o caminho Dio segue
  sem prova em aparelho.

## 0.8.0 (2026-10-17, G-03c)

* `SentomaruRoutes` / `SentomaruRoute` e o parâmetro `routes:` de `dio.addSentomaru`: a seção `network-signing` do
  perfil da CLI assina, sem etiqueta por requisição, as chamadas cujo host e caminho casam com uma rota (operação
  declarada prevalece; fora de `allowedHosts` ou antes do `initialize`, recusada). Acréscimo, sem quebra.
* Regra R8 de consumidor: `-keepnames` de `SentomaruFlutterPlugin` (a CLI `sentomaru protect` procura a classe).
* Evidência: testes unitários e de transporte real em loopback (redirecionamentos 307/308 reassinados com a operação
  da rota, 302 sem herdar). **Sem prova em aparelho para o Dio**: o gate em aparelho da G-03c é só Android/OkHttp.

## 0.7.0 (2026-10-16, C-09, revisão do #146)

* `SentomaruCapabilityMismatch.operationObserveOnly` saiu do enum de desencontros: operação só em Observe virou
  `SentomaruCapabilityWarning.operationObserveOnly`, entregue por `onWarning` (nível separado do `onMismatch`), e
  continua marcada. Quem tratava esse valor em `onMismatch` passa a tratá-lo em `onWarning`.
* `scopeMismatch` não existe: a rota de capacidades não expõe o escopo (ver guia §4).

## 0.6.0 (2026-10-16, C-09, issue #143)

* `SentomaruCapabilities.fetch` (sem seguir redirecionamento) e `SentomaruCapabilityGate`: o app lê a rota de
  capacidades do backend (Sentomaru.AspNetCore 4.x, `GET /integrity/capabilities`, opt-in: `enabled` e as operações
  protegidas com `enforced`) e só marca as operações que o backend protege. Com o backend desligado, ele registra o
  desencontro e não marca (`SentomaruMismatchPolicy.degrade`, o padrão), em vez de transformar a chamada num 503.
  Operação só em Observe é avisada e continua marcada. Só acréscimos: assinatura, vetores e API existentes não mudam.
* README: ponto único sobre sujeito e tenant (nunca o fator de decisão; o backend deriva da sessão) e uso seguro do
  `onRiskEvent` (só atrito, nunca decisão).

## 0.5.0 (2026-10-16, J-01f2)

* Os sinais (`x-sentomaru-signals`) passam a ser **assinados** pelo núcleo nativo (H3): antes eram anexados depois da
  assinatura e o servidor os tratava como não assinados.
* `x-sentomaru-operation-id` (cabeçalho ou `extra['sentomaru_operation_id']`): id da operação de negócio, igual em cada
  nova tentativa, assinado; o servidor responde o primeiro veredito numa nova tentativa (RETRY-01). Formato
  16–64 `[A-Za-z0-9-]`, validado no núcleo.
* `SentomaruFlutterPlatform.sign` ganhou `optionalHeaders` (com padrão): implementações próprias da plataforma precisam
  aceitar o parâmetro.
* **Atenção ao atualizar (mudança de comportamento):** com os sinais assinados, o servidor deixa de rebaixar um
  `NOT_DETECTED` do cliente para `UNKNOWN` (regra H3). Uma política com `equals NOT_DETECTED` ou `not_equals DETECTED`
  num sinal do cliente pode decidir diferente para o mesmo aparelho. A política padrão não tem regras assim (as dela
  são `equals DETECTED` e presença de sinais); confira as políticas próprias antes de publicar o app.

## 0.4.0 (2026-10-15, C-04b)

* `SentomaruConfig.playIntegrityCloudProjectNumber` (opcional): liga o token consultivo do Play Integrity na inscrição
  (SDK Android `com.google.android.play:integrity:1.6.0`). Qualquer falha inscreve sem o token; nada muda para quem
  não configura o campo. Contrato: the Sentomaru Play Integrity API contract.

## 0.3.0 (2026-10-10, renomeação de contrato) — BREAKING

Mapa de nomes aprovado (sem marcas de terceiros), aplicado como versão nova de contrato, sem aliases.
Tabela completa: the rename migration table of the vendor.

* `SentomaruThreatEvent` → `SentomaruRiskEvent`; campo `threatScore` (int, padrão 0) → `riskIndex` (`int?`, sem
  padrão: ausência ≠ sem risco); novo `riskBand` (`String?`).
* Chave JSON lida na resposta: `threatEvent` → `riskEvent`; `threatScore` → `riskIndex`. A chave antiga é ignorada.
* Callback `onThreatEvent` → `onRiskEvent` (em `SentomaruDioInterceptor` e `dio.addSentomaru`).
* O evento é consultivo e só existe se o backend consumidor o incluir; o servidor Sentomaru não o emite.
* `x-sentomaru-signals` sai como um único valor ASCII imprimível: caracteres acima de 0x7E viram `\uXXXX` (JSON válido), caractere de controle ou valor com mais de 4096 caracteres (`maxSignalsHeaderLength`) é recusado antes do envio com `SentomaruException(invalidRequest, details: HEADER_VALUE)` em vez de um 400 opaco do servidor. Novo `encodeSignalsHeader`.

## 0.2.0 (2026-10-10, hardening) — BREAKING

### Mudanças incompatíveis
* `minSdk 28` no plugin (sem `tools:overrideLibrary`). O app hospedeiro precisa declarar `minSdk = 28`.
* O SDK nativo não vem mais em binários (`android/m2` removido). Antes de compilar o host:
  `cd <Sentomaru>/sdk/android && ./gradlew publishAllPublicationsToLocalRepoRepository`
  (ou `-Psentomaru.sdkRepo=<dir>` / `SENTOMARU_SDK_REPO`).
* `SentomaruDioInterceptor(client)` exige `dio:`; instale com `dio.addSentomaru(client)`. A forma antiga
  `dio.interceptors.add(SentomaruDioInterceptor(client))` não compila mais (antes ela deixava de seguir redirects
  em silêncio).
* `SentomaruClient(config: ...)` removido: o cliente só fica inicializado depois de `initialize()` aceito pelo nativo.
* `SignedMessageHeaders.operationId` e `clientEpoch` removidos (nunca existiram no perfil assinado; SDK-NET-4 não
  implementado).
* Novos códigos: `notInitialized`, `configurationError`; `ServerRejected:<MOTIVO>` e `InvalidRequest:<PARTE>` mapeados
  por prefixo (motivo em `details`).

### Comportamento
* Operação declarada com cliente não inicializado no isolate → `notInitialized`, nunca enviada sem assinatura.
* Operação declarada para host fora da allowlist → `hostNotAllowed`, nunca enviada sem assinatura.
* Redirects: fora da allowlist não seguidos; http recusado; 301/302/303 → GET sem corpo e sem assinatura; 307/308
  reassinados; `Authorization`/`Cookie` caem quando o host muda; no máximo 5 saltos; os saltos não passam pelos
  outros interceptors do app.
* Escopo ausente (`organization/app/environment`) → `configurationError` (Dart e nativo), nunca `ebees/example-app/dev`.
* Enrollment nativo: sem redirect, sem retry silencioso; respostas HTTP → `serverRejected` com motivo; corpo do
  servidor nunca repassado.
* Sinais: sem os stubs `mock_location_detected`, `accessibility_bot_detected`, `virtual_sandbox_detected`;
  `observedAt` obrigatório; `capabilityId` duplicado recusado.

### Migração — ExampleApp
1. `android/app/build.gradle.kts`: `minSdk = 28` (hoje `flutter.minSdkVersion`).
2. Build do SDK a partir do código antes do `flutter build` (local e CI), ver acima.
3. Trocar `interceptors.add(SentomaruDioInterceptor(c))` por `dio.addSentomaru(c)`.
4. Tratar `notInitialized` (aguardar `initialize()` antes de operações protegidas; em isolate de fundo inicializar o
   cliente daquele isolate) e `configurationError`/`serverRejected`.
5. Requisição sem operação declarada segue sem assinatura por desenho; a proteção vem de o servidor exigir prova
   nas rotas protegidas.

## 0.0.1

* Scaffold (P2 Task 0). Sem funcionalidade de produto.
