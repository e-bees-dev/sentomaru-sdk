# sdk/flutter

Adapter Flutter para os SDKs Android e, desde 0.18.0, iOS (`sdk/ios`): integração com transporte e ciclo de sessão RFC 9421.

## Componentes

- `sentomaru_flutter/`: Plugin Flutter para Android com ponte nativa tipada (`SentomaruFlutterPlugin`), cliente Dart (`SentomaruClient`) e interceptor HTTP para Dio (`SentomaruDioInterceptor`).
- `sample/`: Aplicativo Flutter sintético com host Android (`minSdk 28`). É o build que compila o módulo Kotlin do plugin no CI e hospeda o teste em aparelho (`integration_test/plugin_test.dart`).
- `sentomaru_flutter/ios/`: lado iOS (pod CocoaPods, iOS 15+) sobre o SDK Swift, por links simbólicos para `sdk/ios/Sources`. O `sample/ios/` (iOS 15.0) compila o pod e roda os testes XCTest do plugin no simulador (`RunnerTests`); requisitos (App Attest, entitlement de ambiente) no README do plugin.

## Declaração de Cobertura de Transporte (Decisão E6 / FLT-3)

Apenas instâncias de `Dio` configuradas explicitamente com o interceptor `SentomaruDioInterceptor`:
```dart
final dio = Dio()..addSentomaru(sentomaruClient); // liga também o tratamento de redirects
```
possuem cobertura e proteção de assinatura RFC 9421. Requisições originadas de outras instâncias de `Dio`, ou de `HttpClient` nativo / `package:http` sem o interceptor, trafegam sem assinatura (fora da cobertura). Múltiplas instâncias de `Dio` compartilhando o mesmo `SentomaruClient` são suportadas com total isolamento.

## Pinning no Dart (0.16.0, C-03a)

`dio.addSentomaruPinning(SentomaruPins.fromProfileSection(perfil['controls']['network-pinning']))` confere a chave da
folha de um host fixado depois do handshake e antes de qualquer byte da requisição, só no `Dio` em que a linha foi
instalada e só no Android. Proxy e `http` para host fixado são recusados. Detalhes e limites no README do plugin; prova
em aparelho pendente (C-03b).

## Execução sem Biometria e sem Activity (Decisão E4 / FLT-4 / FLT-8)

O cliente Dart e o interceptor Dio executam operações criptográficas no Android Keystore sem prompt biométrico (`setUserAuthenticationRequired(false)`), e o plugin usa o `applicationContext`, não uma Activity. Verificado em aparelho: chamadas a partir de isolate de fundo (`BackgroundIsolateBinaryMessenger`). **Não verificado:** WorkManager real e execução sem nenhuma Activity (a instrumentação abre a Activity); cada isolate precisa chamar `initialize()` no seu próprio `SentomaruClient`.

## O que os sinais medem

`collectSignals()` devolve as observações locais do SDK Android e, desde 0.19.0, do SDK iOS (`client_observed`, evadíveis, assinadas só quando vão em `x-sentomaru-signals` pelo interceptor, nunca autorização; no iOS `app_signing_digest` sai `UNSUPPORTED` e `installer_source` `UNKNOWN`, ver `sdk/ios/README.md`): `debug_attached`, `emulator_detected`, `root_indicated`, `app_signing_digest`, `installer_source`, `os_version`. Localização simulada, bots de acessibilidade e sandbox **não** são medidos. Uma observação sem `observedAt` válido ou com `capabilityId` duplicado é recusada (`channelError`); o Dart nunca preenche `observedAt` com a hora atual.

Desde 0.12.0 `collectSignalsSnapshot({rasp})` devolve o snapshot pronto para o cabeçalho `x-sentomaru-signals` (`toJson()`, catálogo 1.3.0 no 0.12.0 e 1.7.0 no código atual, ids `server_verified` descartados, inclusive o `app_identity_mismatch`) e, com `rasp: true`, acrescenta os seis sinais RASP por opção; `collectSignals()` não mudou. Desde 0.15.0 o tipo `reattest` do `challenge-required` é conhecido (`isReattestChallenge`) e `client.reattest()` faz a reatestação sem o prazo local; o app repete a operação uma vez. A checagem de pacotes do `root_artifacts` exige que o **app** declare `br.com.ebees.sentomaru:signals-rasp` (o plugin não depende dele); sem isso a capacidade nunca dá `NOT_DETECTED`. Detalhes no README do plugin.

Desde 0.13.0 `collectSignalsSnapshot(appIntegrity: AppIntegritySignals(expectedSignerDigests: [...]))` acrescenta por opção os três sinais de integridade do app (`app_signer_mismatch`, `installer_class`, `code_integrity`; iOS: `UNSUPPORTED`) e `SentomaruConfig(reattestation: ...)` liga `reattestIfDue()` (reatestação sob desafio, numa thread de trabalho nativa; iOS: `ReattestationUnsupported`). Sem os parâmetros novos nada muda.

Desde 0.14.0 `SentomaruClient.signalEvents` entrega por opção eventos informativos: `signal` (só Android, das coletas de `collectSignalsSnapshot` feitas enquanto o app escuta; iOS: nenhum, `signalEventsSupported` falso) e `server_response` (o código fechado de uma resposta 401/403 a uma requisição que o interceptor Dio assinou). Não são veredito; `collectSignals()` não mudou.

## Build do plugin (SDK a partir do código, sem binários versionados)

O plugin consome `br.com.ebees.sentomaru:{core,signals,sdk,sealed,signer}:0.2.0-rc.1` de um repositório Maven local gerado do código-fonte; não há AAR/JAR no git (`verification/check_no_binaries.py` reprova). Antes de compilar um app hospedeiro (ExampleApp ou `sample/`):

```bash
cd sdk/android && ./gradlew publishAllPublicationsToLocalRepoRepository   # -> sdk/android/build/repo
```

Num checkout via pub `git:` o caminho padrão (`../../../android/build/repo` relativo ao plugin) também existe; em outro layout use `-Psentomaru.sdkRepo=<dir>` ou `SENTOMARU_SDK_REPO`. O host precisa de `minSdk 28` (sem `overrideLibrary`). Combinação verificada: host AGP 8.11.1 / KGP 2.2.20 (template Flutter 3.41.9) com o SDK compilado por AGP 9.4.1 / KGP 2.2.10.

## Comportamento sem inicialização e redirects

- Cliente Dart não inicializado neste isolate (boot, isolate de fundo/WorkManager, hot restart): operação declarada é recusada com `SentomaruErrorCode.notInitialized` e não é enviada; requisição sem operação passa sem cabeçalhos Sentomaru (fora da cobertura).
- Hosts da allowlist: redirects automáticos do Dio ficam desligados; com `addSentomaru` o interceptor segue só para host permitido em https (301/302/303 → GET sem corpo e sem assinatura; 307/308 reassinado; `Authorization`/`Cookie` caem se o host muda). Fora da allowlist o 3xx volta ao chamador.
- Escopo ausente (`organization/app/environment`) é `configurationError`, nunca um padrão.

## Teste em aparelho (plugin real)

`sample/integration_test/plugin_test.dart` roda com o plugin, canal e Keystore reais: `ConfigurationError` nativo, `notInitialized`, estado, `notEnrolled`, sinais reais (= catálogo), enrollment até `NetworkUnavailable`, reinicialização de cliente Dart preservando o estado nativo e chamada a partir de isolate de fundo (`BackgroundIsolateBinaryMessenger`). O caso de integridade do app (os 15 sinais com `appIntegrity`, cabeçalho ≤ 4 KiB, agregado do código numa segunda coleta, rota de reatestação fora da allowlist recusada e o fluxo na thread de trabalho até `notEnrolled`) foi escrito e **ainda não rodou em aparelho**; não cobre reatestação com servidor. Só usa `adb install`, `am instrument` e `adb uninstall`:

```bash
cd sdk/flutter/sentomaru_flutter/sample && flutter build apk --debug && cd android
./gradlew app:assembleAndroidTest && ./gradlew app:assembleDebug -Ptarget=$(pwd)/../integration_test/plugin_test.dart
adb install -r ../build/app/outputs/apk/debug/app-debug.apk
adb install -r ../build/app/outputs/apk/androidTest/debug/app-debug-androidTest.apk
adb shell am instrument -w -r br.com.ebees.sentomaru.sentomaru_flutter_sample.test/androidx.test.runner.AndroidJUnitRunner
adb uninstall br.com.ebees.sentomaru.sentomaru_flutter_sample.test; adb uninstall br.com.ebees.sentomaru.sentomaru_flutter_sample
```

Não cobre: WorkManager real, hot restart real do engine nem ausência real de Activity (a instrumentação abre a Activity).
