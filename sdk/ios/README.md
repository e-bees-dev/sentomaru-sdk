# sdk/ios

SDK Swift do Sentomaru para iOS (SwiftPM, iOS 15+; macOS 13+ só para os testes). Mesmo protocolo do SDK
Android: inscrição com App Attest, sessão, assinatura RFC 9421 do perfil `sentomaru-p0`, renovação, rotação e reset.
Sem dependência externa (Foundation, CryptoKit, Security, DeviceCheck).

**Estado:** núcleo do SDK com testes no host macOS. O `swift test` não usa iPhone nem objeto real da Apple (atestação
ou asserção emitida por um aparelho); a evidência de aparelho (um iPhone 13; perfil, "Objetos reais") foi conferida só offline, nos vetores (`app-attest-device-d10a.json`). Nenhum
iPhone foi inscrito contra o servidor. O plugin Flutter iOS (`sentomaru_flutter` 0.18.0; sinais desde 0.19.0) compila estes fontes
no seu pod por links simbólicos (`sdk/flutter/sentomaru_flutter/ios/Classes/SDK`, um por arquivo): arquivo novo aqui
precisa do link lá (o teste `ios_sdk_sources_test.dart` do plugin falha sem ele). No pod os dois módulos viram um só, por
isso o `@_exported import SentomaruCore` só existe quando o módulo existe (`#if canImport`).

## Módulos

- `SentomaruCore`: perfil (`Profile`), `Content-Digest` (RFC 9530), regras de mensagem, base de assinatura,
  `MessageSigner`, `EnvelopeCodec` e `SentomaruError`. Sem Keychain, sem rede.
- `Sentomaru`: `SentomaruConfig`, `SentomaruClient`, chave no Secure Enclave, App Attest, Keychain, transporte
  `URLSession` e sinais (`SignalsCollector`). Reexporta o `SentomaruCore`.

## Uso

```swift
let config = try SentomaruConfig(organization: "org", app: "app", environment: "hml",
                                 allowedHosts: ["api.consumidor.example"],
                                 enrollmentUrl: "https://api.consumidor.example/v1/org/app/hml/installations",
                                 renewalUrl: "https://api.consumidor.example/v1/org/app/hml/sessions")
let client = try SentomaruClient.live(config: config)
let transport = SentomaruTransport(allowedHosts: config.allowedHosts)

// O desafio vem do backend do consumidor.
let grant = try await client.enroll(challenge, send: transport.enroll)

// Requisição do app: assinada no último passo, com renovação antes quando devida. Com `signals:` o snapshot de
// sinais vai assinado em x-sentomaru-signals; sem ele (padrão), nenhum snapshot.
let session = SentomaruURLSession(client: client, transport: transport, signals: SignalsCollector())
let (data, response) = try await session.data(for: request, operation: "checkout")
```

`SentomaruClient.live(config:)` usa `SecureEnclaveKeys`, `KeychainInstallationStore` e
`DeviceCheckAppAttestService`; devolve o mesmo cliente para o mesmo escopo. O mesmo escopo com outra configuração
(hosts, `enrollmentUrl`, `renewalUrl` ou carência) falha com `InvalidRequest:PARAMS`. O construtor recebe as quatro
portas (`InstallationKeys`, `InstallationStore`, `AppAttestService` e o relógio) para testes.

**`send` não pode chamar o cliente.** As operações do cliente passam por uma fila única, não reentrante: `enroll`,
`rotate` e `renew` seguram a fila enquanto esperam o `send`. Um `send` que chame o mesmo cliente (por exemplo,
`sign` ou `state()`) espera para sempre. O `send` só entrega a mensagem assinada e devolve a resposta;
`SentomaruTransport.enroll` e `.renew` já fazem isso.

| Chamada | O que faz |
|---|---|
| `state()`, `sessionId()`, `retiredKeys()` | `notEnrolled`, `enrolled`, `enrollmentRequired`, `keyInvalidated`; sessão atual; chaves aposentadas na carência |
| `enroll(challenge, send:)` | Gera a chave no Secure Enclave, atesta com App Attest e envia o corpo v1.7 (`attestationFormat: "apple-app-attest"`) |
| `rotate(challenge, send:)` | Chave nova com prova da anterior, mesma instalação; reenvio idempotente do mesmo corpo |
| `sign(method:targetURI:operation:body:optional:)`, `signRequest(_:)` | Mensagem assinada (`sig1`, `ecdsa-p256-sha256`, assinatura P1363 de 64 bytes) |
| `needsRenewal()`, `canRenewNow()`, `renewalBackingOff()`, `lastRenewalFailure()`, `renewalGate()` | Mesmas regras da J-04r: margem `min(120 s, vida/5)`, espera de 60 s, degraus 5/15/60 s em `SUSPENDED` |
| `renew(send:)`, `renewIfDue(send:)`, `markGrantStale()` | Renovação assinada com asserção App Attest no corpo (abaixo) |
| `reset()` | Apaga registro, chaves do escopo e estado de renovação |
| `SentomaruURLSession.signed(_:operation:)`, `.data(for:operation:)` | Assina um `URLRequest`, com o snapshot de sinais em `x-sentomaru-signals` quando criado com `signals:`; reenvia uma vez depois de `403 session-expired` |
| `SignalsCollector().snapshot(rasp:appIntegrity:)`, `SignalsSnapshot.json()`, `.headerValue()` | Sinais do aparelho no formato do cabeçalho (abaixo) |

## Chave da requisição: só Secure Enclave

A chave P-256 da instalação é criada no Secure Enclave (`SecureEnclave.P256.Signing.PrivateKey`, CryptoKit). O
Keychain guarda só o blob que o próprio Secure Enclave cifra; a chave privada nunca sai dele. Sem Secure Enclave
(simulador, Mac sem o chip), `generate` lança `SentomaruError.unsupported(.SECURE_ENCLAVE)` e nada é criado. Não há
chave em software como alternativa silenciosa: a chave em software existe só nos testes (`SoftwareKeys`, efêmera).

## App Attest

`AppAttestService` é uma porta; a de produção é `DeviceCheckAppAttestService`. Com `isSupported == false` a inscrição
falha com `unsupported(.APP_ATTEST)` e não envia nada. O app precisa da capacidade App Attest e do entitlement
`com.apple.developer.devicecheck.appattest-environment` igual ao `apple_attest_environment` do escopo.

- Inscrição: `clientDataHash = SHA-256(attestationChallenge ‖ SPKI)`; `keyId` de 32 bytes e `attestationObject` de 1 a
  32 768 bytes conferidos antes do envio.
- O `keyId` App Attest é gravado no registro antes do `attestKey`. Uma nova tentativa (resposta perdida, processo
  morto) atesta a mesma chave em vez de deixar uma órfã. Só depois de `serverUnavailable` (`NetworkUnavailable`) a
  chave é reaproveitada; depois de sucesso ou de outra falha, a próxima tentativa gera outra, como manda a Apple.
- Renovação: corpo exatamente `{"appAssertion":"<base64 do CBOR>"}`, com `clientData =
  "sentomaru-app-assertion-v1\n" ‖ sessionId ‖ "\n" ‖ nonce ‖ "\n" ‖ base64url(SHA-256(SPKI))`. O contador da asserção
  é do App Attest; o servidor exige que ele suba.
- Chave App Attest inválida numa asserção (`keyInvalidated`): o grant é apagado e a chamada lança
  `enrollmentRequired`; o app reinscreve (`reset` + `enroll`).

**Asserção na renovação:** vem do contrato v1.11 (com `authData` real). O servidor desta árvore exige a asserção na renovação
de instalação iOS com chave App Attest gravada. Só provado contra os vetores e o servidor falso de `swift test`: o SDK
ainda não foi reexecutado contra o servidor com essa asserção. Os vetores
estão fixados em `Tests/SentomaruTests/Fixtures/app-attest-assertion-v1.json` (SHA-256 `03921955…`); o teste compara
a cópia com o arquivo do repositório quando ele existir.

## Keychain

Itens genéricos com `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, `kSecAttrSynchronizable = false`, no data
protection Keychain. Serviços: `br.com.ebees.sentomaru.installation` (registro, conta = escopo) e
`br.com.ebees.sentomaru.keys` (blob da chave, conta = alias). Registro ilegível ou de outra versão vira
`keyInvalidated`.

**Desinstalar o app não apaga o Keychain.** No iOS, itens do Keychain costumam sobreviver à desinstalação (é
comportamento da Apple, não provado aqui em aparelho). Reinstalado no mesmo aparelho, o app pode encontrar a
instalação anterior. Para começar do zero, o app chama `reset()` na primeira execução, por exemplo com um marcador em
`UserDefaults`, que a desinstalação apaga.

## Sinais

Sem sinais, uma operação listada em `sensitiveOperations` da política sai `challenge` por `SIGNALS_MISSING`, mesmo num
aparelho limpo (prova num iPhone: inscrição 201, renovação 200, `criar_demanda` 401
`challenge-required`). O `SignalsCollector` coleta as seis capacidades do catálogo 1.0.0, as que a
política padrão lê, com os mesmos ids, versões, ordem e formato JSON do SDK Android:

| Capacidade | iOS | Estados |
|---|---|---|
| `debug_attached` | `P_TRACED` do processo (`sysctl` `KERN_PROC_PID`); detalhe `debugger_connected` | `DETECTED`, `NOT_DETECTED`; `ERROR` se o `sysctl` falhar |
| `emulator_detected` | build de simulador (`targetEnvironment(simulator)`); detalhe `matched_indicators` | `DETECTED` no simulador, `NOT_DETECTED` no aparelho |
| `root_indicated` | só no aparelho: caminhos conhecidos de jailbreak (com e sem raiz, como `/var/jb`), escrita fora do sandbox, biblioteca de hooking carregada (`dyld`); detalhe `jb_path`, `sandbox_write`, `hooking_library` (booleanos, nunca o caminho); resultado guardado 60 s (abaixo) | `DETECTED`, `NOT_DETECTED`; `UNKNOWN` (`reason=simulator`) no simulador, que enxerga o disco do Mac |
| `app_signing_digest` | o iOS não expõe o certificado de assinatura ao app | `UNSUPPORTED` |
| `installer_source` | não há pacote instalador no iOS | `UNKNOWN` (`reason=not_applicable`) |
| `os_version` | `ProcessInfo.operatingSystemVersion`; detalhe `platform` (`ios`) e `release` (`18.1.0`) | `DETECTED` |

Com `snapshot(rasp: true)` e/ou `snapshot(appIntegrity: true)` os ids RASP e de integridade do app saem `UNSUPPORTED` (não há
checagem iOS para eles), como o plugin Flutter já fazia. Fora de iPhone/iPad e simulador, `emulator_detected` e
`root_indicated` saem `UNKNOWN` (`reason=not_ios_device`): o host macOS do `swift test`, app Mac Catalyst e app de
iPhone/iPad rodando num Mac com Apple silicon (`isiOSAppOnMac`). No Mac existem `/bin/bash` e `/usr/sbin/sshd`, então
tratá-lo como aparelho daria `root_indicated` sempre `DETECTED` (revisão R, M1).

**Envio assinado (desligado por padrão).** Como o interceptor OkHttp do Android, o `SentomaruURLSession` não coleta
sozinho: o padrão é `signals: nil` (sem snapshot, a não ser o que o app puser). Com
`SentomaruURLSession(client:transport:signals: SignalsCollector())` ele coleta de novo a cada assinatura (o reenvio
depois de renovar também), depois da renovação e logo antes de assinar, e põe o JSON em `x-sentomaru-signals`, que
entra na assinatura (H3, `Profile.optionalHeaders`). Um `x-sentomaru-signals` posto pelo app prevalece. Política com
`sensitiveOperations` exige o snapshot: sem ele, `SIGNALS_MISSING`. O plugin Flutter usa o coletor em
`collectSignals()`, e o app põe o resultado no cabeçalho, que o interceptor assina. Quem assina por `client.sign(...)` direto passa `optional: ["x-sentomaru-signals":
try SignalsCollector().snapshot().headerValue()]`. O JSON é ASCII imprimível (o resto vai como `\uXXXX`) e um valor
acima de 4096 bytes é `InvalidRequest:HEADER_VALUE`, nunca cortado. O servidor marca `STALE` uma observação com mais de
300 s: colete por requisição, não guarde o snapshot.

**Custo e cache de `root_indicated` (revisão R, M3).** No aparelho, as checagens de jailbreak (21 caminhos, uma
tentativa de escrita fora do sandbox, que o sistema registra como violação de sandbox, e a lista de imagens do `dyld`)
rodam no máximo uma vez a cada 60 s por processo (`RootCheckCache`, compartilhado por todo `SignalsCollector()`). A
observação guardada mantém o `observedAt` da checagem real, nunca carimbado de novo: pode ficar até 60 s antes do
`collectedAt` do snapshot. Isso está dentro do frescor do servidor, porque o `SignalsValidator` marca `STALE` por
`observedAt` de cada observação (mais de 300 s) e não por `collectedAt`. Uma regra de política com `maxSignalAgeSeconds`
compara só o `collectedAt`, que é sempre a hora desta coleta: uma regra com `maxSignalAgeSeconds` menor que 60 **não**
garante essa idade ao `root_indicated`, que pode ter até 59 s. E um jailbreak ou hook carregado depois da última
checagem pode passar sem ser visto por até 60 s. O TTL é fixo. Medido no host macOS (Mac do autor, Apple silicon, build
debug do `swift test`, `SENTOMARU_BENCH=1 swift test --filter testRootCheckCostOnTheHost`; sem a variável ou como root o teste é pulado; mesmas checagens com o disco e o `dyld` reais): sem cache, mediana
de cerca de 11 ms por coleta (máximo de 16 ms em 20); com cache, cerca de 0,013 ms. Não medido em iPhone.

**Limites.** Os sinais são `client_observed` e evadíveis: um processo instrumentado (Frida, tweak de jailbreak) muda
qualquer valor antes da assinatura, e a assinatura prova só que o snapshot saiu do processo que guarda a chave.
`NOT_DETECTED` quer dizer "não detectado nesta coleta", nunca aparelho íntegro. Jailbreak escondido (rootless com
ocultação) não é visto. Sem consulta de esquemas de URL (`cydia://`): pediria UIKit, a thread principal e
`LSApplicationQueriesSchemes` no app. Não é um detector de depurador nativo além do `P_TRACED`. Roda na thread que
chama e nunca lança: uma checagem que falha custa só a sua capacidade. O `durationMs` vem do relógio de parede (`Date`),
não de um relógio monotônico: uma mudança de hora durante a coleta pode distorcê-lo. Nenhuma API de motivo
obrigatório da Apple (`PrivacyInfo.xcprivacy` inalterado): `fileExists`, `sysctl` `KERN_PROC_PID`, `dyld` e
`Date`.

**Catálogo 1.7.0.** Os ids, versões e estados são os do catálogo, e o `catalogVersion` do snapshot é `1.13.0` (o 1.13.0 só acrescentou `location_mock` e `call_active`, Android; o 1.8.0 a 1.11.0 só acrescentaram ids e indicadores Android (sinais de aparelho, de tela e de toque injetado); o 1.12.0 declara `ios` em `screen_shared`, opt-in por `snapshot(screen: true)`). O
`supportedPlatforms` declara `ios` (com `minIosVersion` `15.0`) exatamente nas quatro capacidades que este coletor
responde com valor num iPhone/iPad: `debug_attached`, `emulator_detected`, `root_indicated` e `os_version`, cujas
`limitations` descrevem o iOS. `app_signing_digest` (sempre `UNSUPPORTED`) e `installer_source` (sempre `UNKNOWN`
`reason=not_applicable`) seguem só `android`: são enviados para a política padrão ver as seis, mas não medem nada aqui.
`SignalsTests.testIosPlatformIsDeclaredExactlyWhereTheCollectorHasAValue` cruza o catálogo com o coletor. O servidor
não muda: as seis capacidades presentes bastam para a política padrão
não dar `SIGNALS_MISSING` (teste do servidor, sobre o snapshot de referência
`verification/sdk/vectors/ios-signals-snapshot-v1.json`, conferido pelo `swift test`). Esse vetor é sintético: o coletor
com um ambiente falso de aparelho limpo e hora fixa, não um snapshot de iPhone real. O teste do servidor usa o
`ApiJson.Options` da API, mas não passa pelo endpoint nem pela verificação da assinatura (`SignalsSigned` fixo).

## Limites

Corpo até 65 536 bytes; vida da assinatura até 60 s; só `https` em host de `allowedHosts`; sem seguir redirect;
`httpBodyStream` recusado (o corpo precisa estar em bytes para o `Content-Digest`); corpo vazio sai sem corpo (GET).
O transporte lê a resposta até 16 KiB e corta a leitura no byte seguinte; espera 15 s por requisição e 30 s no total.
Um `403 session-expired` marca o grant como vencido antes de renovar.
Não espelhados do Android: reinscrição depois de atualizar o app, reatestação e Play Integrity.

## Testes

```sh
cd sdk/ios && swift test
```

- Vetores cross-SDK `verification/sdk/vectors/sdk-vectors-v1.json`: todos os 81 (43 positivos, 38 negativos), com a
  contagem exata conferida; envelopes byte a byte iguais aos do `core-signed-v1.json` (Kotlin).
- Negativos: algoritmo, chave, relógio, corpo, parâmetros.
- Fluxo com fakes (servidor que confere assinatura, corpo, prova da chave anterior e asserção; App Attest falso).
- Keychain num arquivo de keychain criado pelo teste, com serviço aleatório, apagado no fim; o Secure Enclave do host
  quando houver.
- Sinais: cada estado de cada detector com ambiente falso, ids/versões/estados contra o catálogo, JSON igual ao
  snapshot de referência, escape ASCII, limite de 4096, coletor real no host e o cabeçalho assinado pelo
  `SentomaruURLSession` conferido com a chave da instalação.

**Não provado:** sinais num iPhone real (jailbreak não testado em aparelho nenhum) e o caminho Swift direto contra o
servidor; o SDK contra o servidor com a asserção na renovação, simulador, data protection Keychain com entitlement; iPhone e App Attest
real só na evidência offline (acima). O job `sdk-ios` do CI roda no runner `ios-pr`, só em pull request que mexa em `sdk/ios/`,
`verification/sdk/vectors/` ou `verification/attestation/vectors/` e em `workflow_dispatch` (nunca em push ou
agendado), e ainda não rodou.

## Sinal `screen_shared` no iOS (opt-in, catálogo 1.12.0)

`SignalsCollector().snapshot(screen: true)` acrescenta `screen_capture` (`UNSUPPORTED`: o iOS não dá callback de captura por tela) e `screen_shared`, lido de `UIScreen`: indicador `secondary_display` (mais de uma tela) e `screen_recording` (alguma tela com `isCaptured`: gravação, espelhamento ou AirPlay). **Só na thread principal** (UIKit): em outra thread, ou fora de iPhone/iPad (simulador, Mac), o estado é `UNKNOWN` (`partial`), nunca `NOT_DETECTED`. Só códigos fixos, sem nome de tela nem app. Consultivo: o SDK nunca bloqueia nada. O plugin Flutter repassa `screen:` (`collectSignalsSnapshot(screen: true)`, lido na thread principal, que fica presa até o prazo de 135 ms).

## Chave transacional com presença humana

`TransactionSigner` assina uma operação por vez com uma chave P-256 do Secure Enclave cujo uso exige a pessoa a cada vez
(`.biometryCurrentSet`, ou `.userPresence` com biometria ou senha do aparelho) e devolve o valor de `x-sentomaru-tx-signature`
(`sentomaru-tx-v1.<nonce>.<assinatura>`, mesmos bytes e mesmo vetor do Android e do servidor). O app coloca o valor na requisição,
junto do `x-sentomaru-operation-id` (mesmo valor em todo retry), e `SentomaruClient.sign(..., optional:)` o cobre pela assinatura
RFC 9421 (o servidor recusa o cabeçalho não coberto). O alias vem de `SentomaruClient.installationAlias()`.

- **Reinscrição em duas fases (Shield #5 da revisão cruzada de 4/11).** `stageKey(biometricOnly:)` cria a chave nova sob o rótulo provisório `<alias>.tx.pending` e devolve a SPKI para o `POST transaction-keys`; a chave que assina (`<alias>.tx`) **não é tocada**. O app chama `commitKey()` só depois do `201` do servidor (a nova substitui a antiga) e `abortKey()` se o servidor recusar ou a chamada for abandonada. Antes, a criação apagava a chave antiga antes de o servidor aceitar a nova, e um erro de rede deixava o app sem chave. `commitKey()` sem chave provisória é `notEnrolled`; `discard()` apaga as duas. No Flutter: `createKey()` só prepara, `commitKey()` e `abortKey()` fecham (`txKeyCreate`, `txKeyCommit`, `txKeyAbort`), com os mesmos códigos fechados `Transaction:<CASE>` da ponte Android; nenhum código novo.
- Cancelar o prompt é `TransactionError.cancelled`, recuperável: nada é gasto e a chave da instalação não é tocada.
  `keyInvalidated` (nova biometria cadastrada, com `biometryCurrentSet`) pede nova chave.
- **Limite:** Secure Enclave userPresence protege a chave no aparelho, mas a Apple não atesta o controle de acesso; o servidor não consegue provar presença. A inscrição `transaction-keys` de uma instalação iOS aceita só a classe `advisory-ios` (sem cadeia de atestação, `attestationStatus: "unattested"`): a assinatura é verificada (formato, bytes, nonce), mas é evidência consultiva e **nunca satisfaz** `requiresUserPresenceSignature` (`403 tx-key-auth-not-hardware-enforced`). Não há promessa de presença para iOS. Não provado em aparelho (o prompt biométrico não foi exercitado).


## Cadeia de prova offline

`SentomaruClient.sealOfflineOperation(permit:operationDigest:)` sela uma operação feita sem cobertura, com os mesmos bytes e os mesmos vetores
do servidor (`contracts/sdk/offline-proof-chain-v1.md`, `contracts/sdk/offline-proof-chain-v1-vectors.json`). O `permit` vem de
`OfflinePermit.parse(_:)` sobre a resposta `201` de `offline-permits`; o pedido do permit é `offlinePermitRequest(targetURI:)` (assinado, operação
`offline_permit`, corpo vazio). Selar não faz chamada de rede, não precisa de grant vivo e só precisa da chave da instalação. Online, com o grant
renovado, `reconcileOfflineChainRequest(targetURI:permit:seals:)` devolve o pedido assinado (operação `offline_reconcile`) que o backend do
consumidor encaminha; o veredito volta ao consumidor, nunca ao app. Permit vencido, lote cheio e digest que não tem 32 bytes são `OfflineError`,
nunca um selo; a falha de gravação do estado não consome número de sequência.

**O que o iOS expõe, e o limite:**
- Relógio monotônico: `CLOCK_MONOTONIC` (`mach_continuous_time`: conta o sono, recomeça no boot). É ajustado pelo NTP (partes em 10^4), muito abaixo da tolerância de deriva do permit.
- Contador de boot: o iOS **não tem** equivalente público ao `BOOT_COUNT` do Android. O SDK lê o `sysctl kern.bootsessionuuid` (UUID novo a cada boot, independente do relógio de parede) e o converte num contador que ele mesmo guarda no Keychain (`ThisDeviceOnly`). O contador conta os boots **vistos pelo SDK**: dois boots sem nenhum selo no meio contam como um (só o crescimento importa ao servidor). Sem o sysctl, todos os selos levam `0xFFFFFFFF` (indisponível) e o servidor só aplica a regra de parede; trocar de disponível para indisponível no meio de um permit é `OfflineError.clockUnavailable`.
- Não provado em aparelho: o `sysctl` num iPhone real, o contador de boot após um reinício real e o relógio de parede alterado pela pessoa. Os testes usam relógio e chave de software, e o `sysctl`/`CLOCK_MONOTONIC` só foram exercitados no Mac. A cadeia não prova que o conteúdo é verdadeiro e não protege a cauda (contrato, seção 1).
