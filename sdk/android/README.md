# sdk/android

SDK Kotlin/Android: chave individual, assinatura RFC 9421, atestação Key Attestation, sinais, interceptor OkHttp e
transporte `HttpURLConnection` (S2).
Estado: **P2 completo** (`core`, `signer`, `signals`, `sdk`, `sample-app`, `app-lab`); depois dele, `signals-rasp`,
`perf-app` (medições em aparelho) e os módulos da CLI `sentomaru protect` (`protect`, `protect-runtime`, `protect-gate-app`) e o hospedeiro do gate de aparelho dos sinais de tela (`screen-gate-app`).
Contrato da API: [contracts/sdk/sdk-api-v1.md](../../contracts/sdk/sdk-api-v1.md). Veja [entrada do projeto](../../README.md).

## Módulos

| Módulo | Tipo | Conteúdo |
|---|---|---|
| `core` | JAR (JVM) | Kotlin/JVM puro (sem Android): `SignatureBase.build`, `ContentDigest.sha256`, `SignatureParams`, `FrozenRequest`, `MessageSigner`, `EnvelopeCodec` e erros `SentomaruError`. Vetores SDK-VEC em `verification/sdk/`. |
| `signer` | AAR (Android) | `KeystoreSigner`: gera chave EC P-256 no `AndroidKeyStore` com `setAttestationChallenge`, devolve cadeia DER e assina em P1363 de 64 bytes. Suporte tipado a StrongBox. |
| `signals` | AAR (Android) | `SignalsCollector`: coleta as capacidades `client_observed` do catálogo `contracts/sdk/signals-catalog-v1.json` (1.13.0; o 1.13.0 acrescentou `location_mock` e `call_active` (Android, por opção em `SignalsCollector.sessionDetectors(...)`); o 1.12.0 acrescentou `screen_shared` no iOS (`UIScreen`), sem mudar a coleta Android; o 1.11.0 acrescentou o indicador `injected_touch` ao `synthetic_input`; o 1.10.0 trouxe os sinais de tela (`screen_capture`, `screen_shared`); o 1.9.0 o `known_malware`; o 1.8.0 acrescentou os 4 sinais consultivos de aparelho, por opção; o 1.7.0 só acrescentou `ios` em `supportedPlatforms` de `debug_attached`, `emulator_detected`, `root_indicated` e `os_version`, com o texto do iOS nas `limitations`, sem mudar a coleta Android; o 1.6.0 só reescreveu o texto do `code_integrity`, que o servidor passou a comparar; o 1.5.0 trouxe as 3 de integridade do app; o 1.4.0 acrescentou o id `server_verified` `app_identity_mismatch`, nunca coletado pelo SDK): as 6 padrão e, por opção, as 6 RASP e as 3 de integridade do app (ver "O que os sinais medem"). Compatível com JSON Schema Draft-2020-12. |
| `signals-rasp` | AAR (Android) | Opção RASP consultiva: só o `<queries>` dos gerenciadores de root (`SignalsCatalog.ROOT_MANAGER_PACKAGES`) e a classe marcadora que o `root_artifacts` procura. Fora do `sdk` e do plugin Flutter. |
| `sdk` | AAR (Android) | Fachada principal: `SentomaruClient`, `AndroidInstallationStore` (chaves atômicas e isoladas de backup), rotação de 7 dias, `SentomaruInterceptor` (OkHttp) e `SentomaruUrlConnection` (`HttpURLConnection`). |
| `sample-app` | APK (Android) | App sintético de laboratório para testes ponta a ponta e ciclo de vida (`E2EInstrumentedTest`, `LifecycleInstrumentedTest`); `JavaUrlConnectionSample.java` mostra a chamada `HttpURLConnection` em Java e alimenta o build R8 do CI. Nunca publicado. |
| `app-lab` | APK (Android) | App de teste que hospeda testes instrumentados de atestação local. |
| `perf-app` | APK (Android) | App de medição, nunca publicado: custo dos detectores (`RaspCostInstrumentedTest`), da integridade do app (`AppIntegrityCostInstrumentedTest`) e dos eventos (`SignalEventsCostInstrumentedTest`), latência e a matriz RASP no emulador (`RaspMatrixInstrumentedTest`). |
| `protect`, `protect-runtime`, `protect-gate-app` | JVM / JAR / APK | CLI `sentomaru protect` (`contracts/devsecops/cli-v1.md`), o runtime que ela injeta no AAB e o app mínimo do portão em emulador. Não fazem parte do SDK. |

`generate(alias, challenge, strongBox)` retorna a cadeia ou lança `StrongBoxUnavailableError`; `generateResult(...)` devolve `GenerationResult.Generated`/`StrongBoxUnavailable` sem exceção.

## Assinatura de rede numa linha

`OkHttpClient.Builder().addSentomaru(client, SentomaruRoutes.of(listOf("api.example"), listOf(SentomaruRoutes.Route("/v1/pedidos/*", "concluir_pedido"))))`:
requisição sem operação declarada cujo host e caminho casam com uma rota é assinada como essa operação (a seção
`network-signing` do perfil da CLI, `contracts/devsecops/cli-v1.md`). Operação declarada (cabeçalho ou
`SentomaruOperation`) prevalece; rota em host fora de `allowedHosts` → `HostNotAllowed`, nunca sai sem assinatura.
Regras de rota em `contracts/sdk/sdk-api-v1.md` §4. A regra R8 `-keepnames` de `SentomaruRoutes` deixa a CLI achar o
transporte no DEX do app.

**O desafio e a inscrição não passam por esse cliente.** Um cliente com `addSentomaru` (ou `SentomaruUrlConnection`)
assina todo pedido a um host de `allowedHosts` com a chave da instalação, então, sem concessão (`grant`), o pedido não
sai: `SentomaruException` com `NotEnrolled` (nenhum registro) ou `EnrollmentRequired` (registro sem concessão, como no
meio de uma inscrição). Isso vale também para as rotas de desafio, inscrição e renovação do backend do app
(`SentomaruEnrollmentControllerBase` no adaptador), que são justamente quem cria a concessão. Use outro `OkHttpClient`, sem o interceptor, nessas três chamadas, e o cliente com `addSentomaru` para o
resto. Achado no teste de step-up do laboratório (`RaspLabStepUpInstrumentedTest`, item 16): a primeira versão usava um
cliente só e falhava na inscrição com `EnrollmentRequired` logo depois do 201 do desafio. Evidência: leitura de
`SentomaruInterceptor` e `SentomaruClient.signRequest` e o teste de aparelho; não há teste JVM só deste caso.

## HttpURLConnection (S2)

`SentomaruUrlConnection.send(client, routes, "POST", url, bodyBytes, headers)` (Java: método estático; sobrecargas com
`SentomaruOperation operation` e `SentomaruUrlConnection.Opener opener`) faz a troca inteira e devolve a conexão final
já respondida: o chamador lê `getResponseCode()` e `getInputStream()`/`getErrorStream()`. Mesmas regras do
`addSentomaru` (operação por cabeçalho, parâmetro ou rota; allowlist; https; URI canônica; `application/json` exato;
corpo congelado até 64 KiB; sinais e `x-sentomaru-operation-id` assinados; renovação J-04r; redirects seguidos pelo SDK,
no máximo 5, com `setInstanceFollowRedirects(false)`). Regras comuns aos dois transportes em `SentomaruWire` (interno).

- O corpo é `byte[]`: sem streaming nem corpo de tamanho desconhecido. É enviado bufferizado, não por
  `setFixedLengthStreamingMode`: no JDK um corpo em streaming transforma a resposta 401 em `HttpRetryException`.
- `Host`, `Content-Length` e `Transfer-Encoding` nos cabeçalhos → `InvalidRequest:HEADER_NAME`; o mesmo nome em duas
  grafias → `InvalidRequest:HEADER_VALUE`; corpo em GET/HEAD → `InvalidRequest:METHOD` (o JDK viraria POST).
- A URL precisa estar na forma canônica (como o `HttpUrl` do OkHttp a imprime: caminho ao menos `/`, sem porta padrão),
  senão `InvalidRequest:TARGET_URI` num host permitido.
- `Opener` abre cada salto (padrão `url.openConnection()`): é onde o app põe timeouts, `SSLSocketFactory` ou pinning. Uma
  conexão para outra URL é recusada (`HostNotAllowed`).
- Um 403 cujo corpo o SDK leu para procurar `session-expired` volta como conexão delegadora com o mesmo status,
  cabeçalhos e corpo inteiro (não é `HttpsURLConnection`).
- Os métodos são os da plataforma: o `HttpURLConnection` do JDK recusa PATCH.
- Uma chamada direta por `url.openConnection()` não é assinada. Evidência: testes JVM com a implementação do JDK
  (`UrlConnectionTransportTest`, `UrlConnectionJavaTest`), sem aparelho e sem a implementação do Android.
- R8: `-keepnames` de `SentomaruUrlConnection` (só o nome; a classe sai de um app minificado que não a chama). O CI
  confere num build R8 real do `sample-app` (`check_r8_names.py --expect android-sdk-urlconnection`).

## Operação idempotente e sinais assinados (J-01f2)

```kotlin
val request = Request.Builder().url(url)
    .header("x-sentomaru-operation", "concluir_demanda")
    .header("x-sentomaru-operation-id", operationId) // gerado pelo app uma vez por operação; repetido nas novas tentativas
    .post(body).build()
```

O interceptor assina `x-sentomaru-signals` (H3) e `x-sentomaru-operation-id` quando presentes, depois dos componentes
base e nessa ordem; um id malformado é recusado antes do envio (`InvalidRequest:HEADER_VALUE`).

## Versões fixadas

Gradle 9.8.1 (wrapper com `distributionSha256Sum`), Android Gradle Plugin 9.4.1 (Kotlin embutido; KGP 2.2.10, o declarado pelo AGP), JDK 17, compileSdk/targetSdk 36, minSdk 28 (necessário para `setIsStrongBoxBacked`/`StrongBoxUnavailableException`), build-tools 36.0.0. Testes: JUnit 4.13.2, `androidx.test:runner` 1.7.0, `androidx.test.ext:junit` 1.3.0.

## Build e testes

```bash
export JAVA_HOME=~/java/jdk-17 ANDROID_HOME=~/Android/Sdk
cd sdk/android
./gradlew :core:test :sdk:testDebugUnitTest :signals:testDebugUnitTest :signer:testDebugUnitTest :sample-app:assembleDebug  # sem aparelho
./gradlew :signals:lintDebug :signals-rasp:lintDebug :signals-rasp:testDebugUnitTest  # API oculta é erro; <queries> = catálogo
./gradlew :sample-app:assembleRelease && python3 ../../verification/devsecops/check_r8_names.py --expect android-sdk-urlconnection sample-app/build/outputs/apk/release/sample-app-release-unsigned.apk
./gradlew :signer:testDebugUnitTest            # JVM: conversor DER<->P1363 (vetores + JDK SunEC)
./gradlew :app-lab:connectedDebugAndroidTest   # aparelho conectado (adb); instala, roda e desinstala os APKs
```

Conferir que nada ficou instalado: `adb shell pm list packages br.com.ebees.sentomaru` (vazio); se preciso, `adb uninstall br.com.ebees.sentomaru.lab` e `adb uninstall br.com.ebees.sentomaru.lab.test`. Relatório: `app-lab/build/reports/androidTests/connected/`. Não versionar `local.properties`, APKs, keystores nem saídas que identifiquem o aparelho (serial/IMEI).

## Interoperabilidade com o host (aparelho real)

`app-lab/src/androidTest/.../DeviceBridge.kt` é uma ponte só de laboratório, fora da biblioteca `signer`: cada `am instrument -w -r -e class br.com.ebees.sentomaru.lab.DeviceBridge -e sentomaruOp generate|sign|delete ...` executa um passo e devolve o resultado em `INSTRUMENTATION_STATUS` (código 7). Sem `sentomaruOp` o teste retorna cedo (cláusula de guarda, sem `Assume`), então `connectedDebugAndroidTest` continua verde. `sign` usa `KeystoreSigner.useExisting(alias)` para vincular a chave gerada numa chamada anterior (outro processo); falha de keystore → `IllegalStateException`, chave que não é EC P-256 → `IllegalArgumentException` (este ramo não tem teste: exigiria criar chave não P-256 no aparelho). Quem dirige a ponte é `verification/android/run_device.py` via `python3 verification/run_p0.py --device` (instruções em [verification/README.md](../../verification/README.md#interoperabilidade-em-aparelho-real-p0b-task-5-opt-in)); ele monta os APKs (`assembleDebug`, `assembleDebugAndroidTest`), instala, roda e desinstala. Resultado em SM-A055M/Android 15: `hardwareStatus=hardware` com raízes de produção; a assinatura P1363 do aparelho é verificada em Python (`cryptography`) e pelo host .NET (NSign), o que dá a verificação independente que faltava no teste instrumentado.

## O que os sinais medem

Os sinais são **observação local** (`source: client_observed`), coletados pelo próprio app no aparelho. São evadíveis: um app adulterado, um hook (Frida/Xposed) ou root oculto pode alterar ou suprimir qualquer valor antes da coleta terminar. Quando presente, o cabeçalho `x-sentomaru-signals` entra na assinatura RFC 9421 feita com a chave atestada da instalação (H3, ver "Operação idempotente e sinais assinados" acima): a assinatura prova que o snapshot saiu do processo que guarda a chave e não mudou no caminho, **não** que os valores são verdadeiros (um processo instrumentado assina o valor forjado do mesmo jeito). Nunca são autorização; `NOT_DETECTED` significa "não detectado nesta coleta", não "ambiente limpo".

Padrão (`SignalsCollector()` e `defaultDetectors()`, exatamente as seis do catálogo 1.0.0): `debug_attached`, `emulator_detected`, `root_indicated`, `app_signing_digest`, `installer_source`, `os_version`; limitações de cada um em `SignalsCatalog.kt`. **Não medido:** localização simulada, bots de acessibilidade, sandbox/clonagem, anti-hooking. Os stubs `mock_location_detected`, `accessibility_bot_detected` e `virtual_sandbox_detected` (que sempre respondiam `NOT_DETECTED`) foram removidos em 2026-10-10 (hardening R6). `observedAt` é o instante em que cada detector rodou nessa coleta; o coletor e o snapshot recusam `capabilityId` duplicado.

**Sinais RASP (por opção, desde o catálogo 1.3.0).** `SignalsCollector()` e `defaultDetectors()` continuam com as seis
acima, sem mudança (a J-04 mede esse caminho), e o manifesto do `signals` não declara nada. Optar = depender do
artefato `signals-rasp` **e** usar `raspDetectors()`:

```kotlin
// build.gradle.kts: implementation("br.com.ebees.sentomaru:signals-rasp:<versão>")
val collector = SignalsCollector(
    detectors = SignalsCollector.defaultDetectors() + SignalsCollector.raspDetectors(),
    deadlineMs = SignalsCollector.RASP_DEADLINE_MS, // 100 ms, medido em aparelho (p95 frio 84 ms no SM-A055M)
)
val snapshot = collector.snapshot(context) // fora da thread principal
```

`raspDetectors()`: `debugger_attached` (JDWP), `app_debuggable` (`FLAG_DEBUGGABLE`), `dev_settings_enabled`
(`ADB_ENABLED`, `DEVELOPMENT_SETTINGS_ENABLED`), `root_artifacts` (caminhos de `su` e de gerenciadores, `test-keys`,
`Build.TYPE` diferente de `user`, pacotes de `SignalsCatalog.ROOT_MANAGER_PACKAGES`, `/proc/self/mountinfo`),
`emulator_indicated` (lista revista de `Build.*`, arquivos do QEMU/goldfish, acelerômetro ausente) e
`hook_framework_java` (classes do Xposed/Substrate e quadros num stack trace controlado; só a camada Java). Estados:
DETECTED se algum indício; NOT_DETECTED só se todas as verificações rodaram e nada acharam; UNKNOWN se alguma não rodou
(acesso negado, leitura falhou, classe ou método ausente; detalhe `partial`); ERROR só para exceção inesperada no
próprio detector. `detail` leva só códigos fixos (`indicators=su_path,build_type`, `partial=mountinfo`), nunca caminho,
pacote, propriedade ou identificador. Sem permissão nova, sem API oculta (lint) e sem processo.

- **`signals-rasp`.** Só o `<queries>` dos pacotes de gerenciador de root (nunca `QUERY_ALL_PACKAGES`) e a classe
  marcadora `RootManagerQueries`. Sem ele os pacotes ficam invisíveis ao app: `root_artifacts` dá
  `partial=root_package` (verificação não rodou), nunca "não instalado", e por isso nunca NOT_DETECTED. Um
  gerenciador com nome de pacote aleatório não aparece mesmo com ele. O app não deve remover esse `<queries>` no
  merge do manifesto (`tools:node="remove"`) mantendo o artefato: o marcador continua e todo pacote passa a ler como
  ausente. Quem usa os sinais RASP precisa declarar o `signals-rasp`: o app de exemplo e, com o plugin Flutter
  0.12.0, o próprio app hospedeiro no `android/app/build.gradle(.kts)`. O plugin não depende do artefato.
- **Prazo (`deadlineMs`).** O coletor recusa a thread principal (`snapshot` lança `IllegalStateException` antes de
  rodar qualquer detector) e mede cada detector com relógio monotônico. O prazo não é preemptivo: os detectores rodam
  em ordem na thread de quem chama e nenhum é interrompido, então um detector travado segura a coleta; só os
  seguintes viram UNKNOWN `timeout=skipped`. O que termina depois do prazo vira UNKNOWN `timeout=overrun` mesmo que
  tenha detectado algo (descarte deliberado, literal da especificação). Com `defaultDetectors() + raspDetectors()`
  os sinais RASP vêm por último e são os pulados num prazo apertado.
- **Falha de detector.** Nos dois modos, um detector que lança (inclusive `Error`, como `AbstractMethodError` de um
  `PlatformEnvironment` compilado antes dos sinais RASP; nunca `VirtualMachineError`) sai como ERROR sem `detail`, e a
  coleta segue.
- **Testes.** JVM: cada indício e cada falha por dublê, propriedade (falha nunca dá NOT_DETECTED), recusa da thread
  principal (`SignalsCollectorDeadlineTest`) e snapshot com as 12 capacidades ≤ 3 KiB. O teste com StrictMode
  (`perf-app`, `SignalsStrictModeInstrumentedTest`) só roda em aparelho. Limitações de cada sinal no
  catálogo; o custo em aparelho é medido no `perf-app` (`perf-app`, `RaspCostInstrumentedTest`, rodado por
  `python3 verification/run_d05c_cost.py --device`) e as fixtures
  adversariais ficam na matriz `verification/rasp/matrix-v1.json`, com a camada JVM
  no CI e a de emulador medida num AVD com KVM pelo `RaspMatrixInstrumentedTest` do `perf-app`
  (`python3 verification/run_d05d_emulator.py --emulator`; build não depurável com `-Psentomaru.d05dRelease=true`).
  O que pode e o que não pode ser dito sobre esses sinais consta na ficha de alegações do Shield Android, mantida pela operação do Sentomaru e não distribuída neste repositório.
- **`budgetMs` de `root_artifacts`.** O catálogo 1.3.0 publicado antes do ajuste (plugin Flutter 0.12.0 e
  versões antigas da API) tem `budgetMs` 10 em `root_artifacts`; o do repositório atual tem 11 (medição em aparelho no
  SM-A055M) e `updatedAt` `2026-10-22T00:00:00Z`. A versão não subiu porque `budgetMs` não viaja no snapshot nem é
  conferido pelo servidor.

## Sinais consultivos de aparelho por opção (catálogo 1.8.0; `known_malware` no 1.9.0)

Nada disto liga sozinho: `defaultDetectors()`, `raspDetectors()` e `appIntegrityDetectors()` não mudam. Os quatro são
**evidência**, nunca motivo de negação sozinhos (nenhuma política padrão os cita), e nenhum nome de serviço, teclado,
pacote ou aparelho sai do SDK. `known_malware` (catálogo 1.9.0, ficha de dado aprovada) está abaixo.

```kotlin
val collector = SignalsCollector(
    detectors = SignalsCollector.defaultDetectors() + SignalsCollector.deviceThreatDetectors(
        riskyAccessibilityPackages = listOf("com.exemplo.servico.de.risco"),
        knownInputMethodPackages = listOf("com.google.android.inputmethod.latin"),
    ),
    deadlineMs = SignalsCollector.RASP_DEADLINE_MS + SignalsCollector.DEVICE_THREAT_BUDGET_MS,
)
// só nas telas marcadas (pagamento, login), nunca no app todo:
override fun dispatchTouchEvent(ev: MotionEvent): Boolean {
    ObscuredTouchMonitor.shared.onTouch(ev)
    return super.dispatchTouchEvent(ev)
}
```

- `a11y_risk`: serviços de acessibilidade ativos (`AccessibilityManager`) contra a **lista de risco** do escopo. `result=none`
  (NOT_DETECTED), `listed` (DETECTED: algum ativo está na lista) ou `unlisted_present` (UNKNOWN: há serviços e nenhum está
  na lista; não são julgados, o leitor de tela de um usuário com deficiência é o caso comum). Lista vazia nunca dá `listed`.
- `overlay`: toques `ACTION_DOWN` das telas marcadas (`ObscuredTouchMonitor.shared.onTouch`) com `FLAG_WINDOW_IS_OBSCURED` ou
  `FLAG_WINDOW_IS_PARTIALLY_OBSCURED`. Janela de coleta = tempo desde a leitura anterior, que zera a contagem.
  `obscured` (DETECTED, `obscured` e `touches` em `detail`), `clear` (NOT_DETECTED) ou `no_touches` (UNKNOWN: nada medido).
- `ime_untrusted`: teclado padrão (`Settings.Secure.DEFAULT_INPUT_METHOD`) contra a lista de teclados conhecidos. `known`
  (NOT_DETECTED), `unknown` (DETECTED, sinal fraco: teclado de terceiros é comum), `no_reference` (UNKNOWN: sem lista) ou
  `partial=input_method` (UNKNOWN: não leu).
- `synthetic_input`: dispositivo de entrada virtual (`InputDevice.isVirtual`) com fonte de toque, mouse, caneta ou touchpad.
  `indicators=virtual_pointer` (DETECTED). Cliques feitos por serviço de acessibilidade ainda não são vistos.

- `known_malware` (catálogo 1.9.0): apps instalados **visíveis ao SDK** contra a lista assinada de malware Android
  conhecido (par pacote + SHA-256 do certificado de assinatura; [contrato](../../contracts/sdk/malware-list-v1.md)). O app
  carrega a lista na `MalwareListStore.shared` (ou numa própria, passada em `deviceThreatDetectors(..., malwareLists = ...)`)
  com `store.update(json, chavePublicaX509)`; o SDK não faz rede. `matched` (DETECTED, `matches` até 9 e `listVersion`),
  `clear` (NOT_DETECTED: nenhum app **visível** bateu, não "aparelho limpo"), `no_reference` (UNKNOWN: sem lista válida com
  entrada em vigor) ou `partial=packages|certificates` (UNKNOWN). Nunca sai pacote nem hash. O manifesto do SDK declara
  `<queries>` com intent de launcher (cobertura parcial, sem `QUERY_ALL_PACKAGES`); o app pode ampliar no manifesto dele.

## Proteção e sinais de tela por opção (catálogo 1.10.0)

Em `Application.onCreate`:

```kotlin
ScreenShield(setOf("com.exemplo.PagamentoActivity", "com.exemplo.LoginActivity")).install(this)
val detectors = SignalsCollector.screenDetectors()
```

- `ScreenShield` **muda o comportamento do app**, só nas `Activity` listadas (`listed_only`): `FLAG_SECURE` (sem captura nem
  miniatura em "recentes") e, na API 33+, `setRecentsScreenshotEnabled(false)`. Uma tela que precise de captura (suporte,
  acessibilidade) não deve estar na lista. `FLAG_SECURE` não impede câmera externa, hook nem leitura de memória.
- `screen_capture` (API 34, `Activity.ScreenCaptureCallback`, permissão `DETECT_SCREEN_CAPTURE`): capturas feitas com uma tela
  listada à frente. `captured` (DETECTED, `captures` até 9), `none` (NOT_DETECTED: havia tela listada à frente e nada foi
  capturado) ou `no_screens` (UNKNOWN: nenhuma tela listada à frente na janela). UNSUPPORTED abaixo da API 34.
- `screen_shared`: `indicators` entre `presentation_display` (display de apresentação), `secondary_display` (outro display
  visível além do padrão) e `screen_recording` (API 35, `WindowManager.addScreenRecordingCallback`, permissão
  `DETECT_SCREEN_RECORDING`). Abaixo da API 35 o `screen_recording` não é medido (`partial`) e, sem display achado, o estado
  é UNKNOWN, nunca NOT_DETECTED. Display virtual sem a flag pública (típico de compartilhamento por `MediaProjection`) não
  aparece; o pacote que criou o display não é lido (exigiria API oculta).
- As duas permissões são de proteção *normal* (sem diálogo) e **não** vêm no manifesto do módulo `signals` (Shield #2): o app que instala o `ScreenShield` as declara no próprio manifesto. Sem elas, `screen_capture` fica `no_screens` e o indicador `screen_recording` não é medido (UNKNOWN, nunca NOT_DETECTED). Host que só lê sinais (Flutter, React Native) não herda permissão alguma; `verification/sdk/check_merged_manifest.py` confere o manifesto mesclado do host.
- Prova em aparelho e custo medido: pendentes (A05m, na janela expressa). Até lá: implementado e testado em JVM.

## Sinais de contexto de sessão: `location_mock` e `call_active` (opt-in, catálogo 1.13.0)

```kotlin
val detectors = SignalsCollector.sessionDetectors()   // fora de todas as outras listas; SESSION_BUDGET_MS = 6 (provisório)
```

- `location_mock`: o SDK **não pede** permissão de localização nem inicia pedido de localização. Só lê `getLastKnownLocation` quando o app
  **já tem** `ACCESS_FINE_LOCATION` ou `ACCESS_COARSE_LOCATION`, e só vale fix de até 10 minutos. `result`: `mock_flagged` (DETECTED, a marca de
  provedor simulado da plataforma), `clean` (NOT_DETECTED, *daquele* fix), `no_permission`, `no_fix`, `partial` (UNKNOWN). Nunca coordenada,
  provedor, precisão ou hora. Esses módulos **não** declaram permissão de localização no manifesto.
- `call_active`: lê só `AudioManager.getMode()`; sem `READ_PHONE_STATE`. `result`: `cellular` e `communication` (DETECTED), `none`
  (NOT_DETECTED, no instante da leitura), `partial` (UNKNOWN). Nunca número, contato, duração ou app. Um app com `MODIFY_AUDIO_SETTINGS` muda
  o modo sem chamada (falso positivo).
- Os dois são declarados pelo app e evadíveis; alimentam `deviceSignals.mockLocation` e `sessionSignals.callActive` da API de Fraude
  (`contracts/fraud/api-v1.md`, "Declared mock location and active call"). Implementados e testados em JVM por duplos; **prova em aparelho pendente**.

Eventos informativos: tipos `accessibility_risk`, `overlay`, `ime_untrusted`, `synthetic_input` e `known_malware`, só com códigos fixos.
`budgetMs` provisório: a medição em aparelho (como a dos demais sinais) é um passo à parte, com janela expressa.

## Integridade do app por opção (catálogo 1.5.0; comparação no servidor desde o 1.6.0)

Nada disto liga sozinho: `SignalsCollector()`, `defaultDetectors()` e `raspDetectors()` não mudam, o `SentomaruClient`
não reatesta por conta própria e o servidor deixa a reatestação desligada até o operador ligar o escopo.

**Sinais.** `SignalsCollector.appIntegrityDetectors(expectedSignerDigests)` devolve três detectores declarados
(`client_observed`, evadíveis como os sinais RASP; limites em `SignalsCatalog.kt`):

```kotlin
val collector = SignalsCollector(
    detectors = SignalsCollector.defaultDetectors() + SignalsCollector.appIntegrityDetectors(listOf(SIGNING_CERT_SHA256)),
    deadlineMs = SignalsCollector.RASP_DEADLINE_MS + SignalsCollector.APP_INTEGRITY_BUDGET_MS,
)
val snapshot = collector.snapshot(context) // fora da thread principal
```

- `app_signer_mismatch`: todos os digests de `apkContentsSigners` (vários assinantes) ou de `signingCertificateHistory`
  (linhagem de rotação inteira) contra a lista esperada (hex, com ou sem `:`; outra forma lança na construção).
  DETECTED `result=mismatch` se algum não é esperado; NOT_DETECTED `result=match` só se todos foram lidos e são
  esperados; UNKNOWN `no_reference` (lista vazia) ou `unreadable` (leitura falhou ou voltou vazia). `detail` só com
  `result`, `signers` e `unexpected` (contagens), nunca o digest. A lista é configuração do próprio app: um APK
  reassinado com o SDK corrigido devolve `match`; o sinal forte para app inscrito é o `app_identity_mismatch` do servidor.
- `installer_class`: sinal de valor, nunca NOT_DETECTED. DETECTED com `class` e `initiator` (`play` só para
  `com.android.vending`, `none` sem instalador, `other`); UNKNOWN `class=unknown` no Android 9/10 (sem
  `InstallSourceInfo`) ou em falha. Mapeamento provisório até a medição em aparelho de adb e do instalador do sistema.
  **Toda leitura bem-sucedida é DETECTED:** uma contagem de DETECTED (a contagem em sombra da 0045, um relatório) é
  quantas leituras deram certo, nunca uma taxa de risco; só a classe no `detail` diz algo.
- `code_integrity`: o agregado `apk-code-sha256-v1` (`ApkCodeDigests`, mesmo algoritmo e vetores do servidor) sobre todo
  `classes*.dex` e `lib/<abi>/*.so` de `sourceDir` + `splitSourceDirs`. O SDK **nunca** decide: sempre UNKNOWN, com
  `reason=not_compared` + `algorithm`, `aggregate`, `files`; `timeout` (o hash frio continua em segundo plano);
  `partial` + `cause` (`apk_list`, `apk_unreadable`, `entry_unreadable`, `duplicate_entry`, `no_code_files`,
  `too_many_files`, `too_large`, `executor`, `hash_failed`); `main_thread`. O catálogo não declara DETECTED nem
  NOT_DETECTED, então o servidor lê um estado limpo forjado como UNKNOWN. O hash roda numa thread de fundo de baixa
  prioridade (`CodeDigestCache.shared`: uma thread daemon criada no primeiro hash e mantida no processo, um hash por
  vez; o app pode passar o próprio executor); cada coleta espera no máximo `CodeIntegrityDetector.DEFAULT_WAIT_MS`
  (15 ms) e o resultado fica em memória por `lastUpdateTime` + caminhos e tamanhos dos APKs (um processo novo calcula
  de novo). Só ficam o agregado e as recusas que os mesmos APKs sempre dão; `apk_unreadable`, `entry_unreadable` (E/S)
  e um hash que lançou valem 30 s e a coleta seguinte calcula de novo.
  A comparação com os `codeDigests` registrados é do servidor (catálogo 1.6.0): a política vê NOT_DETECTED
  `match`, DETECTED `mismatch` ou UNKNOWN com motivo do servidor, nunca o estado que o SDK declarou. Numa instalação
  por splits (base + `split_config.*`), o agregado só casa com um registro cuja lista seja a união desses APKs.
- Testes: JVM com dublês de cada estado e falha (`AppIntegrityDetectorsTest`, `CodeIntegrityTest` com zips reais e os
  vetores `contracts/shield/code-digests-v1-vectors.json`, splits, cache, espera e interrupção). Snapshot com as 15
  capacidades ≤ 4 KiB (limite do cabeçalho).
- Custo em aparelho (`perf-app` `AppIntegrityCostInstrumentedTest`,
  `python3 verification/run_d12d_cost.py --device`): no SM-A055M, p95 quente abaixo de 0,6 ms em cada sinal; hash de
  um APK grande (58 MiB de código, o teto do APK gordo) ~110 ms de CPU por processo novo, em segundo
  plano, então a primeira chamada de cada processo sai `reason=timeout` (p95 de 19,4 ms, acima do `budgetMs` 15 no
  frio) e o agregado fica pronto ~120–160 ms depois; chave da reatestação ~56 ms quente e ~75 ms fria no p50 (TEE, sem
  StrongBox no aparelho; só os passos de Keystore). Limites no relatório.

**Reatestação (`SentomaruReattestation`, contrato `contracts/api/reattestation-v1.md`).**

```kotlin
val reattestation = SentomaruReattestation(client, "https://api.example/reattest/challenge", "https://api.example/reattest")
// numa thread de trabalho, por exemplo logo depois de uma renovação bem-sucedida:
when (val outcome = reattestation.reattestIfDue { signed -> consumer.forward(signed) /* ReattestationAnswer(status, body, retryAfter) */ }) {
    is ReattestationCompleted -> outcome.result      // o que o servidor gravou (consultivo)
    is ReattestationNotNow -> outcome.retryAfter     // agora não: tente depois, nunca em laço
    is ReattestationRefused -> outcome.code          // ex.: reattestation-disabled, session-expired (renove antes)
}
```

Os dois passos (`reattest_challenge` com `{}`, depois `reattest` com `{challengeId, publicKey, attestationChain}`) são
assinados pela chave atual sobre o grant atual; a chave nova é gerada no Keystore com o desafio, a cadeia é lida e a
chave é apagada (alias `sentomaru.v1.<escopo>.reattest`; se apagar falhar, a chave órfã nunca assina e é removida
pela próxima reatestação ou pelo `reset()`, e a falha de apagar nunca esconde a da geração). O corpo fica congelado por desafio:
uma nova tentativa manda os mesmos bytes. `429` = "agora não" com `Retry-After` (1 h sem cabeçalho), sem nova
tentativa. Toda espera de "agora não" fica entre 60 s e 24 h (um `Retry-After: 0` espera 60 s).
`403 reattestation-disabled`, `reattestation-unsupported` e `installation-suspended` esperam 24 h antes de pedir de
novo (nenhuma cobra orçamento no servidor, mas cada uma é um pedido assinado). `503 verifier-unavailable` e `409 replay` ganham **no máximo uma** nova tentativa, assinada de novo (outro
nonce), depois de `max(Retry-After, 2 s)` e só se couber em 30 s e na validade do desafio (margem de 10 s); depois,
"agora não" (um segundo `replay` é recusa). Cada tentativa gasta o orçamento da instalação no servidor, o mesmo das
avaliações e renovações. Rede ou outro 5xx: "agora não", sem nova tentativa. `403 session-expired` marca o grant como
vencido (`markGrantStale`). Depois de `Completed`, `due()` fica falso por `minInterval` (24 h, o padrão do servidor;
1 h quando o resultado traz `revocation_unchecked`), só em memória. `due()` não bloqueia (campo volátil, sem trava):
pode ser chamado na thread principal enquanto uma reatestação roda; o fluxo longo usa uma trava própria. O desafio só
é recusado localmente 60 s depois do `expiresAt` (relógio do aparelho pode estar adiantado), conferido antes e depois de
gerar a chave. Respostas 200/201 com mais de 4096 caracteres não são lidas (`unexpected-answer`). O fluxo recusa a
thread principal (`IllegalStateException`).
Testes: `ReattestationTest` (dublês de cada resposta do contrato, no máximo dois envios por passo).

## Eventos de sinal por opção

`SentomaruSignalEvents` entrega ao app eventos **informativos** dos sinais que o próprio app coleta. Não é veredito:
quem controla o processo suprime ou inventa eventos, e a decisão continua no servidor, em cada requisição.

```kotlin
val signalEvents = SentomaruSignalEvents()
signalEvents.addListener(mainExecutor) { event -> /* avisar e registrar no app, no máximo */ }
val collector = SignalsCollector(detectors = SignalsCollector.defaultDetectors() + SignalsCollector.raspDetectors(),
    deadlineMs = SignalsCollector.RASP_DEADLINE_MS).apply { events = signalEvents }
```

- Um evento na primeira observação de cada capacidade e a cada mudança de estado, guardado só em memória. Nenhuma
  coleta, thread, alarme ou serviço novo, nada em disco, nada enviado.
- Só os sinais RASP e os de integridade do app. As seis do catálogo 1.0.0 ficam fora (`installer_source` e
  `app_signing_digest` levam pacote e digest no `detail`).
- Campos: `kind` (`SIGNAL`), `type` (`debugger`, `debuggable_build`, `developer_options`, `root_artifacts`, `emulator`,
  `hook_framework_java`, `app_signer`, `code_integrity`, `installer_class`), `capabilityId`, `capabilityVersion`,
  `state`, `reasonCodes` (só da lista `SignalsCatalog.EVENT_REASON_CODES`), `catalogVersion` e `sequence` local.
- Não há horário de parede, `detail`, identificador, pacote, caminho nem digest. Não há `isCompromised()`, nota ou resumo.
- Ouvinte que lança exceção, ou executor que recusa, não afeta a coleta nem os outros ouvintes.
- O executor não deve bloquear: um executor direto roda o ouvinte dentro da coleta e atrasa o snapshot.
- Coletas concorrentes na mesma instância podem entregar eventos intercalados; ordene por `sequence`. O estado guardado
  é o do último snapshot observado.
- Uma capacidade que estoura o prazo da coleta uma vez gera DETECTED, UNKNOWN (`timeout`) e DETECTED de novo: cada
  mudança é um evento.
- A lista de códigos existe só no SDK (não está no JSON do catálogo, no servidor, no plugin Flutter nem no Console).
- Sem `events`, o `SignalsCollector` é o de antes.

## Eventos de resposta do servidor por opção

O mesmo `SentomaruSignalEvents` entrega, a quem pedir, um `SentomaruServerResponseEvent` com o código fechado que o
consumidor devolveu a uma requisição **assinada**. Não é veredito nem sugestão de resposta: é o resultado real da
política como o consumidor repassou (o degrau das regras nunca chega ao app).

```kotlin
signalEvents.addServerResponseListener(mainExecutor) { event ->
    // event.code == "challenge-required" && event.challengeKind == "step_up" -> pedir reautenticação, por exemplo
    // event.isReattestChallenge -> reattestation.reattest(...) uma vez e repetir a operação uma vez
}
val http = OkHttpClient.Builder().addSentomaru(client, routes, signalEvents).build()
```

- Códigos: `challenge-required` (401, com `challengeKind` quando vier: um de `ServerResponseCodes.CHALLENGE_KINDS`,
  `fresh_signals`, `step_up` ou `reattest`, ou outro token `^[a-z][a-z0-9_]{0,31}$` de um servidor mais novo;
  malformado fica nulo), `proof-required` (401),
  `installation-suspended`, `installation-revoked`, `session-unavailable`, `policy-denied` (401 ou 403) e código de
  recusa da política `^[A-Z0-9_]{3,64}$` (só 403). Qualquer outro status ou código não vira evento.
- Lido só o membro `code` do topo do corpo JSON (e o `challengeKind` ao lado de `challenge-required`), em no máximo
  4096 caracteres espiados com `peekBody`: o app recebe o mesmo corpo. Outros membros, texto livre, `riskEvent`,
  `code` aninhado ou repetido, JSON malformado ou corpo maior não viram evento. Campos: `kind` (`SERVER_RESPONSE`, enum próprio do evento; o `Kind` dos eventos de sinal segue só `SIGNAL`),
  `code`, `challengeKind`, `httpStatus`, `sequence` (o mesmo contador dos eventos de sinal).
- Só a resposta da operação assinada: requisição sem operação, salto sem assinatura depois de um 301/302/303 e
  `addSentomaru` sem `events` não geram evento. Cada resposta é um evento (duas recusas seguidas, dois eventos).
- Só no transporte OkHttp nesta fase (o `SentomaruUrlConnection` não emite). O `SentomaruRiskEvent` do plugin Flutter
  não muda.
- **Desafio `reattest`.** A política pode exigir uma reatestação recente aprovada pelo servidor antes de uma
  operação. Com `event.isReattestChallenge`, o app chama `SentomaruReattestation.reattest` (ignora o prazo local: quem
  decidiu foi o servidor) uma vez e repete a operação **uma vez** com nonce novo; o servidor confere na nova avaliação.
  Com `ReattestationCompleted`, repete uma vez, quaisquer que sejam os estados; se for desafiado de novo, não reatesta
  outra vez nesta operação. Com `ReattestationNotNow` (429 do intervalo ou do teto diário) mostra "tente mais tarde" e
  não repete. O SDK não reatesta nem repete nada sozinho; `collectSignals()` e `reattestIfDue` não mudam. O caso
  `reattest-challenge` do `raspLab` (`RaspLabReattestChallenge`, `-e reattestChallenge true`) faz esse roteiro.

## Falha de pino, evento local por opção

Quando o app foi protegido pela `sentomaru protect` com a seção `network-pinning` (
release `cli-v0.5.0`; [contrato](../../contracts/devsecops/cli-v1.md)),
quem recusa o handshake é a plataforma (`network_security_config`). O SDK só dá nome à recusa, num evento **local**
: nada é gravado nem enviado ao servidor, nada é repetido nem desligado.

```kotlin
signalEvents.addTransportListener(mainExecutor) { event ->
    // event.type == "pin_failure"; event.reason: "pin_mismatch" | "tls_untrusted" | "tls_other"; event.host
}
val http = OkHttpClient.Builder().addSentomaru(client, routes, signalEvents).build()
// HttpURLConnection: SentomaruUrlConnection.send(client, routes, method, url, body, headers, operation, signalEvents, opener)
```

- **Hosts fixados.** A CLI grava no `<application>` a meta-data `br.com.ebees.sentomaru.pinning.hosts`
  (nomes separados por vírgula, sem espaço, na ordem do perfil) só quando o DEX tem o transporte do SDK. O
  `SentomaruClient.initialize` lê pelo `PackageManager` uma vez; `client.pinnedHosts` mostra o que foi lido. Valor fora
  do formato (item vazio, espaço, maiúscula, IP, porta, mais de 16 hosts, host repetido) vale como nenhum host; o SDK
  aceita também nome de um rótulo só (`localhost`), que a CLI nunca grava. Cliente
  construído direto (sem `initialize`) não tem hosts.
- **Classificação**, só na cadeia de causas da exceção (no máximo 16 elos): `pin_mismatch` quando uma
  `CertificateException` tem a mensagem do teste de pino da plataforma (`Pin verification failed`,
  `NetworkSecurityTrustManager.checkPins` no AOSP; a prova por versão está no relatório de pinagem); `tls_untrusted` para outra
  `CertificateException` (CA desconhecida, vencido, nome errado), `CertPathValidatorException` ou
  `SSLPeerUnverifiedException` (nome conferido pelo OkHttp, `CertificatePinner` do próprio app); `tls_other` para outra
  `SSLException` (protocolo, alerta, conexão cortada no handshake). Refinamento da spec, que punha todo
  `SSLHandshakeException` em `tls_untrusted`: sem falha de certificado na cadeia, nada diz que o par não era confiável. Falha sem TLS (DNS, recusa, tempo esgotado) não é evento.
- **Onde:** toda troca do `addSentomaru(client, routes, events)` (assinada ou não, host dentro ou fora de
  `allowedHosts`, salto de redirecionamento, renovação J-04r) e do `SentomaruUrlConnection.send` com `events` (os
  saltos e a renovação). Chamada fora do transporte do SDK é recusada pela plataforma do mesmo jeito, sem evento.
- **Campos:** `kind` (`TRANSPORT`, enum próprio), `type` (`pin_failure`), `reason` e `host` (o nome como está na
  meta-data) e `sequence` (o mesmo contador dos eventos de sinal e de resposta). Sem URL, caminho, porta, endereço,
  certificado, pino, texto da exceção nem horário. O vocabulário (`TransportEventCodes`) fica no SDK, fora do catálogo
  de sinais, que não muda.
- **Comportamento igual sem a meta-data, sem `events` ou sem ouvinte:** a exceção chega ao app sem mudança em todos os
  casos; o evento é só um aviso a mais.
- **Limites:** casamento exato do nome (um subdomínio coberto por `includeSubdomains` é fixado pela plataforma, mas não
  gera evento: a meta-data não leva o sinalizador), só em ASCII (host internacionalizado, só na forma punycode); o
  host é o da troca que o SDK fez (o `addSentomaru` desliga os redirecionamentos do OkHttp; religá-los depois pode dar
  o nome do primeiro host da cadeia); a mensagem da plataforma é a única marca do pino e pode mudar numa
  versão do Android (vira `tls_untrusted`); quem controla o processo suprime ou inventa o evento; não vale para WebView,
  Cronet nem o Dart (no Flutter o evento é do plugin, C-03a). No `SentomaruUrlConnection`, `events` leva só o evento de
  transporte (o de resposta do servidor segue só no OkHttp).
- **Testes:** JVM `PinFailureTest` (classificação e meta-data), `PinFailureTransportTest` (handshake TLS real com
  MockWebServer; a recusa da plataforma é imitada por um `TrustManager` de teste com a mesma exceção), `TransportEventsTest`
  (`signals`); instrumentado `PinnedHostsInstrumentedTest` (`sample-app`, leitura da meta-data pelo `PackageManager`),
  só compilado nesta fatia. A recusa real da plataforma foi provada: no emulador API 34 e 28 e
  no SM-A055M, `pin_mismatch` na chave não fixada pelo OkHttp e pelo `SentomaruUrlConnection`.

## Limites (laboratório)

- `setUserAuthenticationRequired(false)` só para rodar os testes sem interação; política de autenticação do usuário é decisão de produto pendente.
- `SHA256withECDSAinP1363Format` não é documentado na tabela de algoritmos da plataforma (`java.security.Signature`, developer.android.com, 2026-10-07) e está ausente (`NoSuchAlgorithmException`) no aparelho testado (Android 15); fallback de runtime mantido. O AndroidKeyStore assina em DER e `EcdsaSignatureFormat` converte para P1363; no teste instrumentado a verificação tenta o algoritmo P1363 da plataforma e, ausente, usa a conversão inversa da mesma classe (correção cruzada nos testes JVM com o provedor SunEC). A verificação independente foi feita na Task 5 (`run_p0.py --device`): a mesma assinatura do aparelho é verificada em Python (`cryptography`) e pelo host .NET (NSign).
- O teste da extensão de atestação (`1.3.6.1.4.1.11129.2.1.17`) só verifica presença e o challenge por busca de bytes (fumaça). Confiança na cadeia, raiz Google, `rootOfTrust` e nível de segurança é decidida apenas pelo verificador do servidor (Task 5).
- StrongBox: ausência é resultado tipado, não falha; não há garantia de StrongBox.
- `generate`/`generateResult` apagam a chave existente sob o alias antes de gerar; falha na geração perde a chave anterior e desvincula a instância (`sign` lança `IllegalStateException`). `KeystoreSigner` não é thread-safe.
- Testes condicionados a StrongBox (`t5b` exige StrongBox; `t7` e `t8` exigem ausência) não usam `Assume`: quando a condição não vale, retornam cedo e aparecem como **passed** no relatório; a evidência do salto é a linha `Log.i` `SKIP t5b|t7|t8: ...` (tag `SentomaruLab`) no logcat do teste (`app-lab/build/outputs/androidTest-results/connected/`).
- Sem execução em background, rotação de chave, persistência de alias de produto ou integração Flutter.

## Dependências e gates

- Lockfiles (`gradle.lockfile` por módulo, todas as configurações) e `gradle/verification-metadata.xml` (SHA-256 de todos os artefatos, sem verificação PGP) versionados desde o P2 Task 0; warnings Kotlin são erro. Regenerar: `./gradlew dependencies --write-locks` e `./gradlew --write-verification-metadata sha256 <tarefas>`. O classpath do `buildscript` é verificado por checksum, não bloqueado por lockfile.
- Jobs de CI `sdk-core` e `sdk-android-unit` rodam as tarefas sem aparelho.
- C-04b: `com.google.android.play:integrity:1.6.0` no módulo `sdk` (token consultivo do Play Integrity na inscrição,
  ligado por `SentomaruConfig.playIntegrityCloudProjectNumber`; qualquer falha inscreve sem o token). Contrato:
  `contracts/api/play-integrity-v1.md`.

## Gates P1 (antes de sair do laboratório)

- Política de autenticação do usuário por operação (substituir `setUserAuthenticationRequired(false)`).

## Chave transacional com presença humana (só Android, sem servidor ainda)

`SentomaruTransactionSigner` gera uma segunda chave EC P-256 (`<alias da instalação>.tx`) que o Keystore só libera depois de uma autenticação do usuário por uso, e produz o valor de `x-sentomaru-tx-signature`. Contrato: `contracts/api/transaction-keys-v1.md`.

- **A promessa é presença humana na assinatura**, não que a pessoa viu o valor.
- O app implementa `TransactionAuthenticator` com o `BiometricPrompt` (`CryptoObject(signature)`), declara `USE_BIOMETRIC` e a dependência `androidx.biometric`; o SDK não traz nenhuma. O prompt roda **fora** do interceptor: `signer.sign(operationId, bodyBytes, authenticator, onSigned = { request.header(...) }, onError = ...)`. No `onAuthenticationError` passe `errorCode` a `BiometricErrors.map(...)`.
- `TransactionError.Cancelled` e as demais com `recoverable` repetem a chamada sem custo; nada do registro, da chave da instalação ou do grant muda.
- `enroll(challengeUrl, enrollUrl, send = { signed -> ... })` faz o fluxo todo (desafio, chave nova, envio) pelas rotas do consumidor que repassam à API privada, como a reatestação; recusa do servidor apaga a chave nova. Fora da thread principal.
- O servidor ainda não verifica nada (fatia b): até lá a API ignora ou recusa o cabeçalho. Sem prova em aparelho.

## Toque injetado em telas marcadas (catálogo 1.11.0)

`synthetic_input` (1.1.0) ganha o indicador `injected_touch`: um `ACTION_DOWN` numa tela que o app marca (a mesma chamada `ObscuredTouchMonitor.onTouch` do `overlay`) veio com a flag de evento de acessibilidade (API 33) ou com id de dispositivo virtual. Sem coordenada, pressão, hora nem contagem; qual das duas marcas disparou não é enviado. **Tecnologia assistiva também gera o indicador** (falso positivo por desenho, e pode ser dado sensível): só evidência. Sem toque em tela marcada, nada é dito. Android Auto e monitor externo não são distinguíveis com certeza no cliente (RAT-02): o servidor decide por regra de política; o cliente nunca bloqueia.

