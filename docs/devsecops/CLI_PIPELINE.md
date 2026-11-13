# `sentomaru protect` no pipeline de CI do cliente

Como rodar a CLI de proteção pós-build do Sentomaru DevSecOps (G-03) no CI do app, com o relatório guardado como
artefato e o job reprovado pelo código de saída. Contrato: [`contracts/devsecops/cli-v1.md`](../../contracts/devsecops/cli-v1.md);
arquitetura: [ADR 0001](adr-0001-post-build.md). Integração do backend e do app: [guia de integração da API](../api/INTEGRATION_GUIDE.md).

## Estado hoje (30/10/2026)

| O quê | Estado |
|---|---|
| `--dry-run` (validar artefato, perfil e compatibilidade; gravar o relatório; **não altera o binário**, não usa rede) | **contratual** (G-03b1) |
| Execução real com **AAB** (G-03e1, G-03e2) | **disponível**: confere o direito do módulo e abre a corrida na API (`SENTOMARU_BUILDER_TOKEN`, `SENTOMARU_API`), injeta o runtime (`runtime-injection`), assina com `--sign openbao` (chave no seu OpenBao, §3d), `--sign keystore` (senhas só pelo ambiente) ou sai sem assinatura (`--sign none`), registra o resultado; `sentomaru protect register --report …` refaz um registro que falhou |
| Assinatura de rede (`network-signing`, G-03c) | **disponível**: **uma linha no app** com os `hosts` e `routes` do perfil (§2b); a CLI não muda o binário para a rede, confere que o app embute o transporte do SDK (sem ele, `app-incompatible`) e o registra no relatório |
| Conferência da ofuscação do build (`build-obfuscation`, D-08) | a partir da `cli-v0.5.0` (publicada em 30/10/2026; no código da CLI desde a D-08f, 27/10/2026); com a `cli-v0.4.0` o perfil sai 4 (`control-not-available`): a CLI só **lê** o artefato e relata se o R8 renomeou o SDK, se o Dart saiu com `--obfuscate` e se o app é `debuggable` (`status: checked`, nunca reprova por falta de ofuscação, só avisa; §2c). R8 e `--obfuscate` são do seu build ([guia](../shield/BUILD_OBFUSCATION.md)) |
| Pinning da chave do servidor (`network-pinning`, D-07) | a partir da `cli-v0.5.0` (publicada em 30/10/2026; no código da CLI desde a D-07f, 27/10/2026); com a `cli-v0.4.0` o perfil sai 4 (`control-not-available`): num AAB, a CLI gera o `network_security_config` com os pinos SHA-256 do SPKI, o backup e a expiração do perfil, sem mudar o código do app nativo; no Flutter, a parte Dart é uma linha no app (§2d). Antes de fixar, leia [onde pode fixar e como rodar a chave](../shield/NETWORK_PINNING.md) |
| Cifragem de assets (`asset-encryption`, D-14) | a partir da `cli-v0.5.0` (publicada em 30/10/2026; no código da CLI desde a D-14e, 30/10/2026); com a `cli-v0.4.0` o perfil sai 4 (`control-not-available`): num AAB, a CLI troca os arquivos de `assets/` do `base` marcados no perfil (e um JSON de strings) por arquivos selados que o app lê por chamada explícita do SDK ou do plugin; até **1 MiB por arquivo** (maior sai 5, `asset-too-large`, também no `--dry-run`). É ofuscação de dados, **não sigilo**: a chave vai no próprio app e quem conhece o esquema público recupera os arquivos ([segredo não vai no app](../shield/NO_SECRETS_IN_APP.md); limites no [contrato](../../contracts/devsecops/cli-v1.md#asset-encryption-d-14)) |
| Proteção de telas (`ui-shield`, G-10) | a partir da `cli-v0.6.0` (publicada em 8/11/2026; a `cli-v0.6.1`, também, é a versão atual; no código da CLI desde a G-10c, 5/11/2026); com a `cli-v0.5.0` o perfil sai 4 (`control-not-available`): num AAB, a CLI só edita o manifesto (três `meta-data` no provider do runtime e, se faltar e o perfil pedir, a permissão `HIDE_OVERLAY_WINDOWS`); quem protege as telas é o runtime injetado, e exige `runtime-injection`. Tem linha no relatório de proteção (gerador 1.0.14) |
| O que ainda falta na execução real | APK de entrada na CLI publicada (G-03b3 está no código, sem release: hoje `control-failed`); plugin Gradle (G-03h) |
| Injeção do runtime num AAB em laboratório (`--lab-unregistered` com `SENTOMARU_LAB=1`) | **fora do contrato**, só laboratório (G-03b2): saída `*.lab.aab`, sem registro, nunca para distribuição. Não use no pipeline do app. A partir da `cli-v0.5.0` (D-16-lab-gate), a execução real registrada recusa `SENTOMARU_LAB=1` (saída 2, `usage`) |
| Distribuição da CLI (pacote verificado) e Action | **publicada** (G-03f, G-01): release **`cli-v0.6.1`** (8/11/2026; antes `cli-v0.6.0`, do mesmo dia, `cli-v0.5.0`, de 30/10/2026, e `cli-v0.4.0`, de 20/10/2026) com o zip reproduzível, `SHA256SUMS`, o statement in-toto e a assinatura, pela chave `shield-cli-release-hml-g1` pinada no [contrato da distribuição](../../contracts/devsecops/cli-distribution-v1.md); quem baixa é o chamador (desde a `cli-v0.5.0`, do bucket S3 público, com `curl` e sem token; o release do GitHub é o espelho), e o verificador do cliente e a Action (§1a, §3b) conferem antes de extrair. Construir do repositório (§1b) continua possível.<br>Distribuição de HML, assinada pelo OpenBao HML, sem release de produção por ora (D-PRD2); uma futura chave de produção exigirá novo pino e nova chave pública. |
| Portões de política (G-02) | **disponível** (§3c): sem perfil válido, sem SBOM CycloneDX válido ou com dependência vulnerável conhecida (OSV), a build falha; não usa a CLI nem a credencial |
| `SENTOMARU_BUILDER_TOKEN` e `SENTOMARU_API` | **só na execução real**. O `--dry-run` não lê nenhum dos dois; os exemplos deste guia são o portão de compatibilidade (`--dry-run`) e não levam a credencial |

Os exemplos deste guia são o **portão de compatibilidade** (`--dry-run`): o job falha se o artefato, o perfil ou o
app não comportam a proteção pedida, sem alterar o binário. A execução real de um AAB, assinada no seu OpenBao, está
na §3d; o APK (G-03b3) está no código e ainda não saiu em release. A assinatura de rede é uma linha no app (§2b), não uma mudança no binário.

## 1. Obter a CLI

### 1a. Distribuição verificada (G-03f)

Cada release `cli-v<versão>` traz o zip da CLI, `SHA256SUMS`, `statement.json` (in-toto, assinado com a chave de
release do cofre) e `signature.sigstore.json`. Desde a `cli-v0.5.0` o canal principal é o bucket S3 público
`https://sentomaru-cli-releases-hml.s3.sa-east-1.amazonaws.com/cli/v<versão>/` (leitura sem conta nem token, sem
listagem), com os quatro arquivos e os dois verificadores do commit da release; o release `cli-v<versão>` do GitHub é o
espelho no repositório público: o GitHub Release exige o `GITHUB_TOKEN` do workflow (limite do `download_cli.py`), o bucket não exige token. O verificador do cliente confere tudo **antes**
de extrair: cosign e chave iguais aos pinos, repositório/ref/workflow/versão assinados, tipo de build da CLI,
`SHA256SUMS` — e só então extrai ([contrato](../../contracts/devsecops/cli-distribution-v1.md)). O **pino da chave**
(`SENTOMARU_RELEASE_KEY_SHA256`) vem por um canal diferente do que serve os arquivos (contrato com o Sentomaru, Console).
A versão atual é `cli-v0.6.1` (publicada em 8/11/2026); a §1b fica para quem prefere construir do repositório.

**Quais tags existem onde.** As versões citadas neste guia (`cli-v0.6.1` e anteriores) são as do repositório de origem, onde o release
é construído e assinado. No repositório público `e-bees-dev/sentomaru-sdk` só existem as tags que alguém criou lá: confira com
`git ls-remote --tags https://github.com/e-bees-dev/sentomaru-sdk.git` e use a tag e a versão que ele listar em `SENTOMARU_REF` e
`SENTOMARU_CLI_VERSION`; não assuma que `cli-v0.6.1` esteja lá. Uma tag sozinha não basta: o download pela Action (`download_cli.py`, `GET /releases/tags/cli-v<versão>`) exige um **release publicado** com os quatro arquivos, e uma tag sem release dá `cli-download-failed:http-404`. Confira também a página Releases do repositório; `SENTOMARU_CLI_VERSION` exige a tag `cli-v<versão>` **com release publicado**.

**Por que o verificador espera `e-bees-dev/Sentomaru`.** O statement assinado de cada release registra o repositório onde o
workflow rodou e assinou, e o verificador compara esse campo com `--expect-repository` (`expect-repository` na Action). Esse é o repositório
de origem, `e-bees-dev/Sentomaru`, e não o `sentomaru-sdk` que você clona: os dois nomes são certos, cada um no seu papel.

<!-- pipeline: install-release -->
```bash
# Bucket S3 público do release (sem conta nem token). A chave pública de release veio junto com o pino, por outro
# canal (contrato com o Sentomaru, Console), e fica no seu repositório em .sentomaru/release-key.pub.
: "${SENTOMARU_CLI_VERSION:?defina SENTOMARU_CLI_VERSION}"
: "${SENTOMARU_RELEASE_KEY_SHA256:?defina o pino da chave de release (canal independente)}"
base="https://sentomaru-cli-releases-hml.s3.sa-east-1.amazonaws.com/cli/v${SENTOMARU_CLI_VERSION}"
mkdir -p sentomaru-dist sentomaru-verify
for f in "sentomaru-protect-${SENTOMARU_CLI_VERSION}.zip" SHA256SUMS statement.json signature.sigstore.json; do
  curl -fsSL --proto '=https' "$base/$f" -o "sentomaru-dist/$f"
done
for f in verify_cli.py verify_release.py; do
  curl -fsSL --proto '=https' "$base/$f" -o "sentomaru-verify/$f"
done
cp .sentomaru/release-key.pub sentomaru-verify/release-key.pub
# The verifiers come from the same channel as the zip: their digests are pinned per version (contract table).
# These are the pins of 0.6.1; for another version use its row of contracts/devsecops/cli-distribution-v1.md.
[[ "$SENTOMARU_CLI_VERSION" == 0.6.1 ]] || { echo "use the verifier pins of ${SENTOMARU_CLI_VERSION} (contract table)"; exit 1; }
printf '%s  %s\n' 443b68e437f42400a43e0881797ee7dff1b7e56f2351eb62e51720086f4c237b sentomaru-verify/verify_cli.py 66192c65c6eb256be60a84f1c4ce3bd6ade97a4ffef6986a036c762fd91263b2 sentomaru-verify/verify_release.py | sha256sum -c -
curl -fsSL https://github.com/sigstore/cosign/releases/download/v3.1.3/cosign-linux-amd64 -o sentomaru-verify/cosign
chmod +x sentomaru-verify/cosign
python3 sentomaru-verify/verify_cli.py --dist sentomaru-dist --version "$SENTOMARU_CLI_VERSION" \
  --key sentomaru-verify/release-key.pub --key-sha256 "$SENTOMARU_RELEASE_KEY_SHA256" \
  --cosign sentomaru-verify/cosign --cosign-sha256 4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71 \
  --dest sentomaru-cli
export PATH="$PWD/sentomaru-cli/sentomaru-protect-${SENTOMARU_CLI_VERSION}/bin:$PATH"
sentomaru protect --version --json
```

O `verify_cli.py` e o `verify_release.py` vêm do mesmo canal do zip (o bucket, ou uma tag do espelho, que é mutável):
por isso o pino deles **vale para a versão** — cada release lista os SHA-256 nas notas e o [contrato](../../contracts/devsecops/cli-distribution-v1.md)
mantém uma tabela por versão, append-only. O bloco acima traz os pinos da 0.6.0 e recusa outra versão; o CI do
Sentomaru confere que eles são os dos arquivos do repositório. A chave de
release é salva com o nome neutro `release-key.pub` (o bucket não a serve: ela vem com o pino, e o `verify_cli.py`
confere o arquivo contra o pino); o pino dela (`SENTOMARU_RELEASE_KEY_SHA256`) **nunca** vem do
mesmo canal. A conferência é feita numa cópia privada dos quatro arquivos (diretório 0700): trocar um arquivo no meio
não muda o que é extraído.

#### Rotação da chave de release

Quando o Sentomaru trocar a chave (nova versão `-g2`, ou a futura chave de produção): (1) o aviso chega pelo canal do
contrato, com o **novo pino**; (2) troque `SENTOMARU_RELEASE_KEY_SHA256` (e, se mudar, o caminho da chave pública
salva como `release-key.pub`); (3) releases antigos continuam verificáveis com o pino antigo, releases novos só com o
novo. Uma chave retirada por comprometimento é anunciada e o pino dela deve sair de todos os jobs. Nunca aceite um
pino novo que chegue junto com os arquivos do release.

### 1b. Construir a CLI a partir do repositório

Requisitos: JDK 17 e um Android SDK com `build-tools` e `platforms;android-36` (o mesmo ambiente que já compila o app;
a CLI em si roda só na JVM). A CLI roda **só no ambiente do cliente** (D-C1): o binário do app nunca sai da máquina.

O repositório de distribuição `e-bees-dev/sentomaru-sdk` é **público**: o `git clone` abaixo não pede credencial. Os
exemplos de CI das seções 3 e 4 clonam sem credencial.

<!-- pipeline: install -->
```bash
# O repositório de distribuição é público: o clone não pede credencial. No CI, os blocos das seções 3 e 4 também servem.
# Revisão fixa do Sentomaru (um SHA de main; o operador indica qual)
: "${SENTOMARU_REF:?defina SENTOMARU_REF}"
git clone https://github.com/e-bees-dev/sentomaru-sdk.git sentomaru-src
git -C sentomaru-src checkout "$SENTOMARU_REF"
(cd sentomaru-src/sdk/android && ./gradlew --no-daemon -q :protect:installDist)
export PATH="$PWD/sentomaru-src/sdk/android/protect/build/install/sentomaru/bin:$PATH"
sentomaru protect --version --json
```

`sentomaru protect controls --json` lista os controles desta versão (id, versão, etapa, ordem e o vocabulário de
mudanças).

## 2. Perfil de proteção no repositório do app

Um arquivo versionado junto do app, por exemplo `.sentomaru/protect-profile.json`, segundo o esquema
[`protect-profile-v1.schema.json`](../../contracts/devsecops/protect-profile-v1.schema.json). O `scope` é o escopo
do app no Sentomaru (o Console mostra o seu); `enrollmentUrl` é a rota de inscrição do **seu** backend.

<!-- pipeline: profile -->
```json
{
  "schemaVersion": "1",
  "kind": "protect",
  "profileId": "meu-app-prod-protect",
  "scope": { "organization": "minha-org", "app": "meu-app", "environment": "prod" },
  "controls": {
    "runtime-injection": { "version": "1", "enrollmentUrl": "https://api.example.invalid/integrity/v1/minha-org/meu-app/prod/installations" },
    "network-signing": { "version": "1", "hosts": ["api.example.invalid"],
                         "routes": [{ "path": "/v1/pedidos/*", "operation": "concluir_pedido" }] }
  }
}
```

JSON estrito (sem comentários, sem chaves repetidas, até 1 MiB). Um campo desconhecido numa seção de controle é
recusado (`profile-format`).

### 2b. Assinatura de rede: uma linha no app (G-03c)

A seção `network-signing` do perfil é a mesma tabela que o app passa ao transporte do SDK, **numa linha**, onde o
cliente HTTP é montado. Requisição sem operação declarada cujo host e caminho casam com uma rota é assinada (RFC 9421)
como essa operação; uma operação declarada no código continua valendo e prevalece. Em `routes`, um segmento `*` casa
exatamente um segmento não vazio; o resto compara sem diferenciar maiúsculas e já decodificado; uma barra final é
ignorada; a porta é ignorada; **a primeira rota que casa vence** (ponha a rota literal antes da rota com `*`). A
instalação recusa `hosts` que não estejam nos hosts permitidos do cliente.

Android (OkHttp, SDK `br.com.ebees.sentomaru:sdk`):

```kotlin
val http = OkHttpClient.Builder().addSentomaru(sentomaru, SentomaruRoutes.of(listOf("api.example.invalid"),
    listOf(SentomaruRoutes.Route("/v1/pedidos/*", "concluir_pedido")))).build()
```

Android com `HttpURLConnection` (SDK desde a S2, usável de Java): a tabela montada uma vez e cada chamada protegida por
`SentomaruUrlConnection.send`, que devolve a conexão já respondida (corpo `byte[]` até 64 KiB, sem streaming):

```java
HttpURLConnection conn = SentomaruUrlConnection.send(sentomaru, routes, "POST", url, bodyBytes, headers);
```

Flutter (Dio, plugin `sentomaru_flutter`), com a seção lida do mesmo perfil:

```dart
dio.addSentomaru(sentomaru, routes: SentomaruRoutes.fromProfileSection(profile['controls']['network-signing']));
```

Uma rota cujo host não está nos hosts permitidos do cliente, ou com o cliente ainda não inicializado, **não é enviada**
(erro tipado), nunca sai sem assinatura. São cobertos os clientes OkHttp e Dio em que a linha foi instalada e, no
`HttpURLConnection`, as chamadas feitas por `SentomaruUrlConnection.send` (uma chamada direta por `url.openConnection()`
não é assinada); WebView, Cronet e afins continuam fora. Na corrida, a CLI confere só que o SDK ou o plugin está
**linkado** (uma classe definida no DEX do app; `status: checked`, `evidence.transport`: `android-sdk`,
`android-sdk-urlconnection` e/ou `flutter-plugin`; o segundo a partir da CLI 0.4.0; versões anteriores informam
só `android-sdk` para um app com o SDK) e avisa
`network-signing-install-line`: que a linha foi chamada com estas rotas não aparece no binário. `SentomaruUrlConnection`
só aparece num app minificado (R8) se o app a chama; sem R8 aparece em todo app com o SDK. Quem recusa uma chamada
protegida sem assinatura é o servidor (modo `Enforce` da operação). A evidência em aparelho é só Android/OkHttp; o Dio tem só testes unitários e de transporte real em loopback, sem aparelho; o `HttpURLConnection` tem só testes JVM contra servidor TLS em loopback, com a implementação do JDK e não a do Android (`UrlConnectionTransportTest`, `UrlConnectionJavaTest`) e a conferência do nome num build R8 do app de laboratório, ainda sem aparelho.
Mudança de comportamento: um perfil com `network-signing` em `--dry-run` num app sem o SDK ou o plugin passou a sair 5
(`app-incompatible`); antes saía 0.
Mudança de comportamento (G-06): o `--dry-run` num app que já traz o provider do Sentomaru (protegido duas vezes)
passou a sair 5 (`app-incompatible`), como a execução real; antes saía 0.

### 2c. Conferência da ofuscação do build (D-08f)

A partir da `cli-v0.5.0` (publicada em 30/10/2026); com a `cli-v0.4.0` o perfil sai 4 (`control-not-available`). O perfil
de exemplo da §2 não traz a seção, que é opcional. Para o relatório dizer se o build passou pelo R8 e pelo `--obfuscate`, acrescente ao perfil a seção fechada
`"build-obfuscation": { "version": "1" }` (sem outros campos). A CLI não ofusca nada: R8 e `--obfuscate` são do seu
build (como ligar sem quebrar o SDK e como guardar o mapeamento: [BUILD_OBFUSCATION.md](../shield/BUILD_OBFUSCATION.md)).
No relatório, `status: checked`, `changes: []` e as evidências `sdkProbeRenamed`, `sdkNamesKept`, `dartObfuscated` e
`debuggable` ([contrato](../../contracts/devsecops/cli-v1.md#build-obfuscation-d-08)). Falta de ofuscação **não** muda
o código de saída: vira aviso (`build-obfuscation-sdk-not-renamed`, `build-obfuscation-dart-not-obfuscated`,
`build-obfuscation-debuggable`). Uma execução real só com essa seção sai 6 (`nothing to apply`): ela entra junto da
`runtime-injection`. Medido nos apps de exemplo (D-08e): tamanho,
arranque e fração renomeada, não de resistência.

### 2d. Pinning da chave do servidor (D-07f)

A partir da `cli-v0.5.0` (publicada em 30/10/2026); com a `cli-v0.4.0` o perfil sai 4 (`control-not-available`). O perfil
de exemplo da §2 não traz a seção, que é opcional. A seção `network-pinning` v1
([contrato](../../contracts/devsecops/cli-v1.md#network-pinning-d-07),
[exemplo](../../contracts/devsecops/examples/protect-profile-network-pinning-v1.example.json)) lista os hosts, os pinos
**aceitos hoje** (`pins`), pelo menos um pino de **backup** ainda não servido (`backupPins`) e a `expiration` (no máximo
180 dias depois da data UTC da execução; a CLI avisa abaixo de 30). Num AAB, a execução real aplica a seção (`applied`)
com ou sem a `runtime-injection`; o `--dry-run` a planeja (`planned`) e dá as mesmas saídas 4 e 5. Avisos que o job deve
ler no `report.json`: `network-pinning-expiration-near`, `network-pinning-host-unsigned`,
`network-pinning-dart-line` (app Flutter: a parte Dart depende da linha `addSentomaruPinning` no app, que a CLI não vê)
e `network-pinning-cleartext-blocked` (o app permite http, e os hosts fixados passam a recusá-lo). App que já declara
`android:networkSecurityConfig` sai 5 (`network-security-config-present`): a v1 não mescla.

Antes de pôr a seção num pipeline, confira no [guia](../shield/NETWORK_PINNING.md) se o host pode ser fixado (a chave do
certificado é sua, não da CDN), como guardar o backup e como rodar a chave sem deixar o app em campo sem acesso. Um
build fixado errado só se corrige com outro build (não há desligamento remoto).

## 3. GitHub Actions

<!-- pipeline: github-actions -->
```yaml
name: sentomaru-protect
on:
  push:
    branches: [main]
  pull_request:

jobs:
  protect-dry-run:
    runs-on: ubuntu-24.04
    env:
      SENTOMARU_REF: ${{ vars.SENTOMARU_REF }}
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
      - uses: actions/setup-java@cf277c60eb25467037889841efdb72551f06f6c3 # v4
        with:
          distribution: temurin
          java-version: "17"
      - name: Build the app bundle
        run: ./gradlew --no-daemon bundleRelease
      - name: Build the Sentomaru CLI from a pinned revision
        run: |
          : "${SENTOMARU_REF:?defina a variável SENTOMARU_REF}"
          yes | "$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager" --licenses >/dev/null
          "$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager" --install "platforms;android-36" >/dev/null
          # The distribution repository is public: the clone needs no token.
          git clone https://github.com/e-bees-dev/sentomaru-sdk.git sentomaru-src
          git -C sentomaru-src checkout "$SENTOMARU_REF"
          (cd sentomaru-src/sdk/android && ./gradlew --no-daemon -q :protect:installDist)
          echo "$PWD/sentomaru-src/sdk/android/protect/build/install/sentomaru/bin" >> "$GITHUB_PATH"
      - name: sentomaru protect (dry run, compatibility gate)
        run: |
          sentomaru protect --input app/build/outputs/bundle/release/app-release.aab \
            --profile .sentomaru/protect-profile.json --out build/sentomaru --dry-run
      - name: Keep the report
        if: always()
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4
        with:
          name: sentomaru-protect-report
          path: build/sentomaru/report.json
          if-no-files-found: warn
```

O passo da CLI reprova o job por qualquer saída diferente de 0 (o shell do Actions usa `-e`); o relatório sobe mesmo
assim (`if: always()`). `SENTOMARU_REF` (variável) vem
do operador do Sentomaru: é a revisão do repositório público de distribuição, e o clone não precisa de token. Para usar a CLI publicada (§1a), o download do release pede o `GITHUB_TOKEN` do workflow (ver §1a). Para um APK em vez do AAB, acrescente `--sign none`
(no `--dry-run` nada é assinado; a escolha é obrigatória para APK pelo contrato).

### 3b. Com a Action (G-01)

A Action `e-bees-dev/sentomaru-sdk/actions/protect` é uma casca sobre a CLI: verifica a distribuição (a mesma conferência da
§1a), roda `sentomaru protect`, guarda o relatório como artefato e falha com o código de saída da CLI. Fixe-a por SHA
de commit (o operador indica o SHA revisado). Ela precisa do pino da chave e da distribuição: já baixada pelo chamador (`distribution`, o exemplo abaixo) ou baixada
pela própria Action (veja "Download pela Action", depois do exemplo). O SHA abaixo
é um commit do `main` (o gate do guia falha no `main` quando um SHA citado não é ancestral do `main`; num PR, só avisa).

<!-- pipeline: github-action -->
```yaml
name: sentomaru-protect
on:
  push:
    branches: [main]
  pull_request:

jobs:
  protect-dry-run:
    runs-on: ubuntu-24.04
    env:
      SENTOMARU_CLI_VERSION: ${{ vars.SENTOMARU_CLI_VERSION }}
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
      - uses: actions/setup-java@cf277c60eb25467037889841efdb72551f06f6c3 # v4
        with:
          distribution: temurin
          java-version: "17"
      - name: Build the app bundle
        run: ./gradlew --no-daemon bundleRelease
      - name: Download the CLI release (public S3 bucket, no token)
        run: |
          : "${SENTOMARU_CLI_VERSION:?defina a variável SENTOMARU_CLI_VERSION}"
          base="https://sentomaru-cli-releases-hml.s3.sa-east-1.amazonaws.com/cli/v${SENTOMARU_CLI_VERSION}"
          mkdir -p "$RUNNER_TEMP/sentomaru-dist"
          for f in "sentomaru-protect-${SENTOMARU_CLI_VERSION}.zip" SHA256SUMS statement.json signature.sigstore.json; do
            curl -fsSL --proto '=https' "$base/$f" -o "$RUNNER_TEMP/sentomaru-dist/$f"
          done
          # neutral name; the key came with its pin through another channel and lives in the repository
          cp .sentomaru/release-key.pub "$RUNNER_TEMP/release-key.pub"
      - name: sentomaru protect (dry run, compatibility gate)
        uses: e-bees-dev/sentomaru-sdk/actions/protect@<SHA-DO-RELEASE>
        with:
          distribution: ${{ runner.temp }}/sentomaru-dist
          version: ${{ vars.SENTOMARU_CLI_VERSION }}
          key: ${{ runner.temp }}/release-key.pub
          key-sha256: ${{ vars.SENTOMARU_RELEASE_KEY_SHA256 }}
          expect-repository: e-bees-dev/Sentomaru  # the private builder that signs the releases (not the public distribution repo); explicit, whatever the Action's default
          input: app/build/outputs/bundle/release/app-release.aab
          profile: .sentomaru/protect-profile.json
          out: build/sentomaru
          dry-run: "true"
```

**Download pela Action (G-05).** O repositório de distribuição `e-bees-dev/sentomaru-sdk` é público, então o `GITHUB_TOKEN` padrão do seu workflow basta (o script de download exige um token, mesmo para release público). O chamador pode omitir `distribution` e o passo "Download the CLI release" acima: a Action baixa o release
`cli-v<version>` num diretório novo e o verifica **do mesmo jeito** (cosign e chave pinados, repositório/ref/workflow/versão
assinados, `SHA256SUMS`); o baixado é não confiável até passar. O pino da chave continua vindo por outro canal, e a
chave pública continua no repositório do chamador:

```yaml
      - name: sentomaru protect (dry run, compatibility gate)
        uses: e-bees-dev/sentomaru-sdk/actions/protect@<SHA-DO-RELEASE>  # use the reviewed SHA of this guide
        with:
          token: ${{ github.token }}   # the default workflow token is enough: the distribution repository is public
          version: ${{ vars.SENTOMARU_CLI_VERSION }}
          key: .sentomaru/release-key.pub
          key-sha256: ${{ vars.SENTOMARU_RELEASE_KEY_SHA256 }}
          input: app/build/outputs/bundle/release/app-release.aab
          profile: .sentomaru/protect-profile.json
```

Limites, sem rodeio: o repositório de distribuição é público, então o token padrão do workflow basta; o bucket S3 público e
`distribution`, como no exemplo acima, seguem sendo o canal principal. Falha de
download aparece na saída `verify-error` como `cli-download-failed:<motivo>`, antes de a CLI rodar. O caminho real do
release do GitHub ainda **não foi exercitado** (o CI do Sentomaru usa um servidor local que imita a API); o contrato
traz os motivos de erro e os limites ([contrato](../../contracts/devsecops/cli-distribution-v1.md)).

`dry-run` fica `"true"` neste exemplo (portão de compatibilidade); a execução real de um AAB (`dry-run: "false"`, `sign:
keystore|openbao` com `extra-args`) segue a §3d. A credencial vai só no `env:` do passo que assina. Nunca a ponha no
`env:` do job nem no `GITHUB_ENV`: eles a entregariam a todos os passos, inclusive a Actions de terceiros. A Action guarda
`build/sentomaru/report.json` como artefato `sentomaru-protect-report` mesmo quando o passo falha. O Sentomaru roda esta
Action de verdade no próprio CI (job `devsecops-cli-dist`): dry run num AAB real, distribuição adulterada recusada
antes da CLI, controle indisponível com saída 4. Desde 30/10/2026 esse job roda no PR que muda a CLI protect ou as
ferramentas dela (grupo `cli_dist`), em toda execução completa e na noturna.

### 3c. Portões de política (G-02)

A Action `e-bees-dev/sentomaru-sdk/actions/policy-gate` **reprova a build** sem perfil de proteção válido, sem SBOM
CycloneDX válido ou com dependência vulnerável conhecida acima da severidade escolhida
([contrato](../../contracts/devsecops/policy-gate-v1.md)). Roda antes da `actions/protect`, como passo próprio, e não
precisa da CLI nem da credencial. O SBOM é o da build do app (por exemplo o plugin `org.cyclonedx.bom` do Gradle, que
gera `build/reports/bom.json`); o portão confere o que a build declara, não o binário. Com `osv-api: "true"` só as
package URLs dos componentes vão para a API do OSV, **inclusive as de bibliotecas internas** (nomes e versões); o
app, o perfil e o SBOM não saem. Para que nada saia, prepare uma base OSV no job e use `osv-api: "false"` (abaixo). Fixe
a Action por SHA de commit (o operador indica o SHA revisado). O SHA abaixo é o commit com a versão final da Action; o merge
é por merge commit, então ele passa a fazer parte do `main` (o gate avisa no PR e falha no `main` se não for).

<!-- pipeline: policy-gate -->
```yaml
name: sentomaru-policy-gate
on:
  push:
    branches: [main]
  pull_request:

jobs:
  policy-gate:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
      - uses: actions/setup-java@cf277c60eb25467037889841efdb72551f06f6c3 # v4
        with:
          distribution: temurin
          java-version: "17"
      - name: SBOM of the build (CycloneDX Gradle plugin, configured in the app)
        run: ./gradlew --no-daemon cyclonedxBom
      - name: sentomaru policy gate
        uses: e-bees-dev/sentomaru-sdk/actions/policy-gate@<SHA-DO-RELEASE>
        with:
          profile: .sentomaru/protect-profile.json
          profile-sha256: ${{ vars.SENTOMARU_PROFILE_SHA256 }}
          sbom: build/reports/bom.json
          min-severity: high
          exceptions: .sentomaru/policy-exceptions.json
          out: build/sentomaru-policy
```

**Fixe o perfil** (`profile-sha256`): o SHA-256 do arquivo de perfil aprovado, numa variável do repositório que só
quem aprova perfis altera (fora do PR). Um PR que muda o perfil reprova o portão (`profile-digest-mismatch`, saída 3)
até o pino ser atualizado; sem o pino, o portão não confere o perfil e só avisa `profile-not-pinned`. Confira antes
que a variável não está vazia (uma variável ausente vira entrada vazia e desliga a conferência). O pino é o SHA-256,
em hex minúsculo, do arquivo **como o portão o lê**: se o pipeline reescreve o perfil antes (escopo ou host vindos de
variáveis), é o do arquivo reescrito. Ao aprovar um perfil novo, quem aprova atualiza a variável. O pino só protege se
o mesmo PR não puder tirar o `profile-sha256` do workflow: exija revisão em `.github/workflows/` (CODEOWNERS e proteção
de branch). O repositório de exemplos faz assim, com um JSON app → SHA-256 em `SENTOMARU_PROFILE_PINS`, um passo que
falha sem pino e um caso provocado fora do pino.

O passo reprova o job pelo código de saída do portão (0 passa; 3 perfil; 4 SBOM; 5 dependência vulnerável ou
exceção vencida; 6 base de vulnerabilidades inacessível, **falha fechada**) e guarda `build/sentomaru-policy/policy-report.json`
como artefato `sentomaru-policy-report` mesmo quando falha (com mais de um passo no mesmo job, dê um `report-name`
distinto a cada um: no `upload-artifact` v4 dois artefatos com o mesmo nome colidem). O arquivo de exceções é
opcional; cada exceção tem `id` (ou um alias, como o CVE), `reason` e `expires` (`AAAA-MM-DD`, válida até o fim do dia
em UTC, no máximo 180 dias à frente), e uma vencida volta a reprovar. Componente sem package URL reprova (saída 4); o
portão nunca aprova o que não conferiu. Sem rede, prepare uma
base OSV no job e use `osv-api: "false"` com `osv-db` e `osv-db-sha256` (o digest sai de `policy_gate.py --hash-db
<dir>`). No GitLab ou em outro CI, rode `tools/devsecops/policy_gate.py` do mesmo SHA, com as dependências de
`tools/devsecops/policy-gate.requirements.lock`. O Sentomaru roda esta Action de verdade no próprio CI (job
`devsecops-policy-gate`): SBOM limpo aprovado, dependência vulnerável reprovada com saída 5.

### 3d. Execução real com a chave no seu OpenBao (G-03e2)

Protege o AAB de verdade: confere o direito do módulo, injeta o runtime, **assina o AAB com a chave de upload no seu
OpenBao** (Transit RSA não exportável, a chave nunca sai do cofre) e registra a corrida. A identidade do job é o
OIDC do GitHub (`id-token: write`), trocada por um token do OpenBao num papel `auth/jwt` preso ao seu repositório e
workflow; nenhum segredo de assinatura no GitHub. Preparação da chave, do papel e do certificado de upload
(`sentomaru protect openbao-certificate`): [doc da G-03e2](g03e2-openbao-sign.md). A credencial do Sentomaru
(`shield-builder` do escopo) entra como segredo do Environment do job; o endereço da API, como variável.

<!-- pipeline: github-actions-signed -->
```yaml
name: sentomaru-protect-release
on:
  push:
    branches: [main]

permissions:
  contents: read
  id-token: write

jobs:
  protect:
    runs-on: ubuntu-24.04
    environment: release
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
      - uses: actions/setup-java@cf277c60eb25467037889841efdb72551f06f6c3 # v4
        with:
          distribution: temurin
          java-version: "17"
      - name: Build the app bundle
        run: ./gradlew --no-daemon bundleRelease
      # The CLI installed and verified as in §1a (or built as in §1b), on PATH.
      - name: sentomaru protect (real run, signed in your OpenBao)
        env:
          SENTOMARU_BUILDER_TOKEN: ${{ secrets.SENTOMARU_BUILDER_TOKEN }}
          SENTOMARU_API: ${{ vars.SENTOMARU_API }}
        run: |
          sentomaru protect --input app/build/outputs/bundle/release/app-release.aab \
            --profile .sentomaru/protect-profile.json --out build/sentomaru \
            --sign openbao --openbao-addr https://bao.example.com --openbao-role app-release \
            --openbao-transit transit/app-upload --openbao-key .sentomaru/upload.pem \
            --openbao-audience https://bao.example.com
      - name: Keep the report
        if: always()
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4
        with:
          name: sentomaru-protect-report
          path: build/sentomaru/report.json
          if-no-files-found: warn
```

O AAB protegido e assinado fica em `build/sentomaru/<nome>.protected.aab`, pronto para o Play Console (certificado de
upload: o `upload.pem` gerado no cofre). **Play App Signing:** num app novo, o certificado do cofre é registrado no
primeiro envio; num app que já usa Play App Signing, peça a troca da chave de upload no Play Console; num app legado
sem Play App Signing, inscreva-o antes (a chave do cofre não é exportável e não vira chave de assinatura migrável).
O app instalado pela loja é assinado pela chave do Google: `output.signingCertSha256` é o de upload, e as restrições
por SHA-256 (Sign-In, Maps, Play Integrity, App Links e a atestação do Sentomaru) usam o certificado do App Signing.
Saída 7 com `signer-unavailable` é o OpenBao inacessível ou o login
recusado (papel, audiência, CA); `sign-failed` é a chave fora da regra (exportável, não RSA) ou um certificado de
outra chave. Uma falha de registro (saída 8) deixa o artefato pronto e o relatório com `closing`:
`sentomaru protect register --report build/sentomaru/report.json` refaz o registro.

## 4. GitLab CI

<!-- pipeline: gitlab-ci -->
```yaml
stages:
  - build
  - protect

build-app:
  stage: build
  image: $ANDROID_BUILD_IMAGE
  script:
    - ./gradlew --no-daemon bundleRelease
  artifacts:
    paths:
      - app/build/outputs/bundle/release/app-release.aab

sentomaru-protect:
  stage: protect
  image: $ANDROID_BUILD_IMAGE
  needs: [build-app]
  script:
    - ': "${SENTOMARU_REF:?defina a variável SENTOMARU_REF}"'
    - git clone https://github.com/e-bees-dev/sentomaru-sdk.git sentomaru-src
    - git -C sentomaru-src checkout "$SENTOMARU_REF"
    - (cd sentomaru-src/sdk/android && ./gradlew --no-daemon -q :protect:installDist)
    - export PATH="$PWD/sentomaru-src/sdk/android/protect/build/install/sentomaru/bin:$PATH"
    - sentomaru protect --input app/build/outputs/bundle/release/app-release.aab --profile .sentomaru/protect-profile.json --out build/sentomaru --dry-run
  artifacts:
    when: always
    paths:
      - build/sentomaru/report.json
```

`ANDROID_BUILD_IMAGE` é a imagem que já compila o app (JDK 17, Android SDK com `platforms;android-36`).
`SENTOMARU_REF` é uma variável comum; o repositório de distribuição é público e o clone não usa token.

### Conferir recibos e exportações: `sentomaru verify`

`sentomaru verify receipt|audit-export` roda os verificadores de terceiros do Sentomaru (Python 3 e `openssl` na máquina; exit 0 válido,
1 inválido, 2 não foi possível verificar). Confiança: o Python, o `openssl` e os scripts só são usados se forem de root ou do seu usuário e
estiverem em diretórios que outros usuários não gravam. `SENTOMARU_PYTHON`, `SENTOMARU_OPENSSL`, `SENTOMARU_VERIFY_DIR` e o ambiente do
processo são **confiados como estão**: a checagem protege contra outros usuários, não contra código do mesmo usuário (um `openssl` falso
indicado em `SENTOMARU_OPENSSL` num diretório seu passa). O `openssl` não vem do `PATH` e roda com ambiente mínimo. Detalhes em
[`contracts/devsecops/cli-v1.md`](../../contracts/devsecops/cli-v1.md).

Se o `verify` sair com `verify-unavailable: the verifier … writable by group or others (mode 0775)`, a causa quase sempre é o `umask 002`
(runner de CI, conta compartilhada): o `unzip` da distribuição cria diretórios 775 e arquivos 664, e o launcher recusa qualquer nó
gravável por grupo ou outros. A regra não é afrouxada; a mensagem nomeia o nó e o modo. Três saídas: `chmod go-w` no nó nomeado (e nos
diretórios acima dele que forem seus); extrair a distribuição com `umask 022`; ou apontar `SENTOMARU_VERIFY_DIR` para um diretório que você
criou com modo 0700 e que contém `verify_receipt.py` e `verify_audit_export.py`. Os diretórios acima do caminho também contam: `/usr/local`
com dono `root:staff` e modo 2775 (Debian e Ubuntu; Homebrew em Intel) é gravável pelo grupo e faz o `python3` de lá ser recusado, e a mensagem do launcher diz isso. Nesse caso
não mude o diretório do sistema: indique `SENTOMARU_PYTHON` (e, para o `openssl`, `SENTOMARU_OPENSSL`) para um binário que fique em
caminho de dono único, por exemplo `/usr/bin/python3` ou `/usr/bin/openssl`. Entradas relativas ou vazias no `PATH` nunca são
procuradas; a mensagem de "nenhum Python confiável" lista as que foram ignoradas.

## 5. Ler o relatório e as saídas

`build/sentomaru/report.json` tem sempre os mesmos membros, também nas recusas: `reportVersion`, `runId`,
`startedAt`, `dryRun`, `cli`, `profile` (id e sha256), `input` (tipo, sha256, pacote, `versionCode`, `minSdk`,
`targetSdk`, certificado de assinatura, módulos), `output` (nulo no dry run), `controls` (cada controle com
`status: "planned"` e as mudanças que faria), `signing`, `registration`, `warnings` e `errors`. Nada de segredo, chave,
token nem conteúdo do app além de nomes e digests.

| Saída | Códigos | O que fazer |
|---|---|---|
| 0 | — | compatível; confira `warnings` |
| 1 | `internal-error` | falha inesperada da CLI: reporte com o `runId` |
| 2 | `usage`, `output-unwritable` | opção errada ou `--out` sem escrita (também na execução real, com o token); a partir da `cli-v0.5.0`, a execução real com `SENTOMARU_LAB=1` no ambiente (`detail` `lab-gate-registered`): tire a variável do pipeline |
| 3 | `input-format`, `input-signature`, `input-too-large`, `min-sdk-unsupported` | o artefato de entrada foi recusado (APK/AAB inválido, assinatura de entrada inválida, acima de 512 MiB, `minSdk` < 28) |
| 4 | `profile-format`, `control-not-available`, `control-version-unsupported`, `control-prerequisite`, `scope-mismatch` | corrija o perfil |
| 5 | `permission-missing`, `app-incompatible` | o app não comporta o perfil (ex.: falta `INTERNET`, ou o app já está protegido) |
| 6 | `control-failed` | um controle falhou ao aplicar (execução real) |
| 7 | `sign-failed`, `signer-unavailable` | assinatura (execução real, G-03e) |
| 8 | `credential-missing`, `entitlement-denied`, `registry-unavailable`, `register-failed` | credencial, direito do módulo ou registro (execução real, G-03e) |

No `--dry-run` só as saídas 0 a 5 aparecem na prática: 6, 7 e 8 dependem da execução real.

## 6. O que vem depois

| Fatia | Muda neste pipeline |
|---|---|
| G-03b3 | APK de entrada na execução real (`runtime-injection` e `ui-shield`; código em `main`, sem release; `network-pinning` e `asset-encryption` seguem só AAB) |
| G-03f | **publicada** (§1a): `cli-v0.6.1`, pelo bucket S3 público com o espelho no GitHub (antes `cli-v0.6.0`, `cli-v0.5.0`, `cli-v0.4.0`, `cli-v0.3.1` e `cli-v0.3.0`); cada versão nova é um release `cli-v<versão>` com uma linha nova na tabela de pinos do contrato |
| G-01 | **disponível** (§3b): Action fixada por SHA, sobre o release `cli-v0.6.1` |
| G-02 | **disponível** (§3c): `actions/policy-gate` reprova sem perfil, sem SBOM válido ou com dependência vulnerável conhecida |

Os exemplos deste guia são conferidos no CI (pelo CI do Sentomaru) **por
análise estática, sem rodar num runner** (a Action em si roda de verdade no job `devsecops-cli-dist`, grupo `cli_dist`): YAML válido, os mesmos SHAs de ação do CI do Sentomaru, toda chamada
`sentomaru protect` com `--dry-run`, `--input`, `--profile` e `--out`, só opções que a CLI atual aceita, e nenhuma
opção de laboratório nem credencial da execução real em lugar nenhum do bloco. Rodar o pipeline de verdade é com o
cliente.

## Substituir `<SHA-DO-RELEASE>`

Os exemplos fixam a Action por SHA de commit completo (40 caracteres hexadecimais), nunca por branch ou tag móvel. Troque `<SHA-DO-RELEASE>` pelo SHA do commit do release que você verificou: `git ls-remote https://github.com/e-bees-dev/sentomaru-sdk.git refs/tags/cli-v<versão> 'refs/tags/cli-v<versão>^{}' | tail -n 1 | cut -f1` (com tag anotada a última linha é o commit apontado, `^{}`; com tag leve só existe a primeira, que já é o commit), e confira que é o mesmo commit que o release informa.
