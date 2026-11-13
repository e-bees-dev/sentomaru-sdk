# `sentomaru protect` — distribuição da CLI v1 (G-03f) e Action (G-01)

Como a CLI do contrato [`cli-v1.md`](cli-v1.md) chega ao cliente e como ele confere o que baixou antes de usar.
Mesmo modelo de confiança do Shield ([release-verification-v1](../shield/release-verification-v1.md)): um statement
in-toto assinado por uma chave do cofre, conferido sem conta nem acesso ao sistema do Sentomaru.

Distribuição de HML, sem release de produção por ora; uma futura chave de produção exigirá novo pino e nova chave
pública. A versão atual, a data e os pinos de cada release estão nas notas do release `cli-v<versão>`.

## Arquivos de um release `cli-v<versão>`

| Arquivo | Conteúdo |
|---|---|
| `sentomaru-protect-<versão>.zip` | a árvore `installDist` (launcher `bin/sentomaru`, JARs com o runtime DEX embutido e, em `lib/verify/`, os dois verificadores de terceiro do Trust usados por `sentomaru verify`) sob `sentomaru-protect-<versão>/`; entradas em ordem, horário fixo (1980-01-01), modos 0755 em `bin/` e 0644 no resto. Reconstruível bit a bit a partir do commit |
| `SHA256SUMS` | `<sha256>  sentomaru-protect-<versão>.zip` |
| `statement.json` | in-toto Statement v1, `predicateType` SLSA Provenance v1, `buildType` `https://e-bees.com.br/sentomaru/devsecops/cli-dist/v1`; sujeitos: o zip e o `SHA256SUMS`; `externalParameters.workflow` (`repository`, `ref`, `path`), `internalParameters` (`versionName` = `build` de `--version --json`, `buildNumber`, `contractVersion`, `runtimeSdk`, `runtimeDexSha256`), `resolvedDependencies` (commit e arquivos de trava do Gradle). **Item 36 (8/11/2026):** `internalParameters.runner` = `{environment, os, arch}` (`RUNNER_ENVIRONMENT` = `github-hosted` ou `self-hosted`, `RUNNER_OS`, `RUNNER_ARCH`; nunca o nome da máquina) e, em `resolvedDependencies`, uma entrada por arquivo de trava (`--material`, `uri` = `git+https://github.com/<repo>@<commit>#<caminho>`, `digest.sha256`), depois da entrada do commit. Statements sem `runner` (builds locais e releases anteriores) não dizem nada sobre o runner; um verificador deve ler isso como "não declarado", nunca como hospedado. `verification/check_release_claims.py` exige as flags em toda chamada do empacotador nos workflows. O `verify_cli.py` lê o campo (item 36, parte do verificador, 8/11/2026): forma fechada (`runner-shape`), `--require-runner` recusa a ausência (`runner-not-asserted`), `--expect-runner-environment` recusa outra classe (`runner-environment`) ou a ausência; sem as flags, um statement sem `runner` passa mas escreve `cli-notice: runner-not-asserted` no stderr (nunca em silêncio) e um com `runner` escreve `cli-notice: runner environment=… os=… arch=…`. É a afirmação do empacotador, assinada pela chave de release, não de terceiro. |
| `signature.sigstore.json` | bundle Sigstore v0.3 de **assinatura de mensagem** sobre os bytes do statement (`cosign sign-blob`, sem log de transparência) |

O empacotador escreve num `--out` novo **ou vazio** (um diretório vazio existente é aceito) e recusa um com arquivos.

## Verificação pelo cliente

`tools/devsecops/verify_cli.py` (stdlib + cosign; copie junto com `tools/shield/verify_release.py`, que ele carrega do
mesmo diretório):

```bash
python3 verify_cli.py --dist sentomaru-dist --version 0.2.0 \
  --key release-key.pub --key-sha256 <pin obtido por outro canal> \
  --cosign ./cosign --cosign-sha256 4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71 \
  --dest sentomaru-cli
```

Antes de tudo, os quatro arquivos são copiados para um diretório privado (0700) e só essa cópia é conferida, hasheada
e extraída: um arquivo trocado em `--dist` durante a conferência não muda nada. Ordem: `verify_release.py` (cosign e chave iguais aos pinos; bundle de assinatura de mensagem sobre o statement;
statement estrito; cada arquivo com digest de um sujeito; `repository` = `e-bees-dev/Sentomaru`, `ref` =
`refs/heads/main`, `workflow` = `.github/workflows/cli-release.yml`, `versionName` = `--version`) → `buildType` da CLI
(um statement de outro produto assinado pela mesma chave é recusado) → `SHA256SUMS` igual ao zip → extração num
`--dest` novo, recusando caminho absoluto, `..`, link, nome repetido, fora do prefixo e acima de 256 MiB. Saída 0 com
o caminho do launcher; 1 com `cli-invalid: <código>` e nada extraído. **O pino da chave vem de outro canal** (contrato
com o cliente, Console, este repositório): um pino tirado do mesmo lugar dos arquivos não prova nada. Sem
`--version` correto não se sabe qual release se tem (rollback): a versão é obrigatória e assinada.

**Os verificadores vêm do mesmo canal do zip.** `verify_cli.py` e `verify_release.py` são baixados do bucket
(desde a `cli-v0.5.0`) ou do repositório por uma tag (mutável). Por isso **o pino vale para a versão**: cada release `cli-v<versão>` lista nas notas os SHA-256
dos dois verificadores, os mesmos desta tabela, que é **append-only** (uma linha por versão, nunca removida; a linha
de uma versão a publicar acompanha os arquivos até a publicação; a de uma publicada nunca muda). Quem verifica confere o pino da versão que vai instalar antes de rodar os scripts, e o CI confere que a
linha da versão do código da CLI (`BUILD` do `Main.kt`, que pode ser uma versão a publicar) é a dos arquivos do
repositório, e que os guias trazem a linha da release publicada.

| Versão | `tools/devsecops/verify_cli.py` | `tools/shield/verify_release.py` |
|---|---|---|
| 0.3.0 | `56e0f2f73fdefe644e79c6e6b847ad064dc9e960d9c8199428c68f2084b893c4` | `12e20abc162831c1dfca9f160fd95becc7ed5bb8ef98b5bcbba6d796cf0234aa` |
| 0.3.1 | `a5a8df9e6d39710267abbfdac6223eada67d551255c8cf7bb4dbb4f245bedae5` | `12e20abc162831c1dfca9f160fd95becc7ed5bb8ef98b5bcbba6d796cf0234aa` |
| 0.4.0 | `a5a8df9e6d39710267abbfdac6223eada67d551255c8cf7bb4dbb4f245bedae5` | `12e20abc162831c1dfca9f160fd95becc7ed5bb8ef98b5bcbba6d796cf0234aa` |
| 0.5.0 | `a5a8df9e6d39710267abbfdac6223eada67d551255c8cf7bb4dbb4f245bedae5` | `106682c3f9a1e0195d1fb12ae6c6e60a7452008eed34bdddf1b496e100b74b0c` |
| 0.6.0 | `a5a8df9e6d39710267abbfdac6223eada67d551255c8cf7bb4dbb4f245bedae5` | `66192c65c6eb256be60a84f1c4ce3bd6ade97a4ffef6986a036c762fd91263b2` |
| 0.6.1 | `443b68e437f42400a43e0881797ee7dff1b7e56f2351eb62e51720086f4c237b` | `66192c65c6eb256be60a84f1c4ce3bd6ade97a4ffef6986a036c762fd91263b2` |

**Linha 0.6.1 (publicada em 8/11/2026, run 42526346854, commit `c4cfa8d6`):** o `verify_cli.py` (`443b68e4…`) lê a classe do runner assinada (item 36: `runner-shape`, `--require-runner`, `--expect-runner-environment`, aviso `cli-notice: runner-not-asserted` no stderr); o `verify_release.py` é o da 0.6.0 (`66192c65…`) e os controles são os da 0.6.0. O zip publicado tem SHA-256 `4ec358940ac289bf45a82ff6e01581468391f131c8ece3bc72e77b8863dd0113` (digest do ativo no release `cli-v0.6.1` do GitHub). A linha 0.6.0 acima não muda (bytes publicados). A linha 0.6.1 é fixa desde a publicação.

A linha 0.5.0 é a da release `cli-v0.5.0`, **publicada** em 30/10/2026 (escrita na D-08f, 27/10/2026, e fixa desde a publicação). O `verify_cli.py` não mudou; o
`verify_release.py` mudou em 30/10/2026 (gerador do relatório de proteção 1.0.5): copia o cosign uma vez para o
diretório privado (0700), confere o pino na cópia e executa a cópia, então um binário trocado em `--cosign` depois da
conferência não roda (TOCTOU, M-3 da R da D-16b); de novo na 1.0.6 (R da D-16f, M-5): a cópia tem teto de 512 MiB
(`cosign-size`) e uma falha de escrita dela é `cosign-copy`. Os arquivos publicados na `cli-v0.5.0` têm esses pinos.
Ela fica sem marca na tabela porque a tabela é append-only e o workflow de release procura a linha exata; o que diz
qual versão está publicada é o "Estado" no topo deste documento.

Controles que cada versão lista em `controls --json` (append-only, a partir da 0.4.0: a linha de uma versão publicada
nunca muda; a de uma versão **a publicar** acompanha o código até a publicação). O CI confere que a linha da versão do
código é o `Controls.all` e que o perfil de exemplo do guia só usa controles da versão fixada nele.

| Versão | Controles |
|---|---|
| 0.4.0 | `runtime-injection`, `network-signing` |
| 0.5.0 | `runtime-injection`, `network-signing`, `build-obfuscation`, `asset-encryption`, `network-pinning` |
| 0.6.0 | `runtime-injection`, `network-signing`, `build-obfuscation`, `asset-encryption`, `network-pinning`, `ui-shield` |
| 0.6.1 | `runtime-injection`, `network-signing`, `build-obfuscation`, `asset-encryption`, `network-pinning`, `ui-shield` |

A linha 0.5.0 ganhou `network-pinning` na D-07f (27/10/2026), antes da publicação (a `cli-v0.5.0` saiu em 30/10/2026 com a linha completa); quem
construiu a CLI do repositório entre a D-08f e a D-07f viu a lista sem `network-pinning`.
A D-16-lab-gate (27/10/2026) mudou o comportamento do código da 0.5.0, também antes da publicação, sem mudar as
linhas 0.5.0 das duas tabelas (os verificadores e a lista de controles são os mesmos): a execução real registrada com
`SENTOMARU_LAB=1` passou a sair 2 (`usage`, `lab-gate-registered`); a mudança está registrada no
[contrato da CLI](cli-v1.md#invocação). Quem construiu a CLI do repositório antes dela tem uma 0.5.0 que aceitava o gate
numa corrida registrada.
A linha 0.6.0 é a da release `cli-v0.6.0`, **publicada** em 8/11/2026 (escrita na G-10c, 5/11/2026, antes da publicação, e fixa desde então): o `verify_cli.py` é byte a byte o da 0.5.0 e o `verify_release.py` só trocou os exemplos do cabeçalho por valores neutros (6/11/2026, antes da publicação; nenhuma linha de código mudou), por isso o pino dele é novo; a lista de controles ganha `ui-shield`, que sai do gate de laboratório.
A linha 0.5.0 ganhou `asset-encryption` na D-14e (30/10/2026), também antes da publicação, na ordem das etapas
(`harden/20`, entre `build-obfuscation` e `network-pinning`); quem construiu a CLI do repositório antes dela viu a
lista sem `asset-encryption`, e o controle só existia com `SENTOMARU_LAB=1`.

A chave pública é salva pelo cliente com o nome neutro `release-key.pub` (o arquivo no repositório é
`contracts/devsecops/keys/shield-cli-release-hml-g1.pub`); o pino dela vem de outro canal.

| Chave | Ambiente | Criada | SHA-256 do PEM (pino) |
|---|---|---|---|
| `shield-cli-release-hml-g1` | HML | 16/10/2026 | `ec993b125a12b1779ee6c6e38d96fb0a96e5bbd70177d06cd7067b8f1c3c91a3` |

## Rotação da chave de release

Uma chave nova (`-g2`, ou a futura chave de produção) entra por PR com o PEM novo e o seu pino neste contrato; a
antiga continua publicada para verificar releases antigos. O cliente recebe o **novo pino** pelo canal do contrato,
troca `SENTOMARU_RELEASE_KEY_SHA256` (e a chave salva como `release-key.pub`), e releases novos só verificam com o pino
novo. Uma chave retirada por comprometimento é removida e anunciada: o pino dela sai de todos os jobs. Um pino que
chegue junto com os arquivos do release nunca é aceito.

## Action (G-01)

`actions/protect/action.yml`, composite, sem lógica própria: verifica a distribuição com `verify_cli.py`, roda
`sentomaru protect` com as entradas (`input`, `profile`, `out`, `dry-run` padrão `"true"`, `sign`, `extra-args`),
guarda `<out>/report.json` como artefato (sempre) e falha com o código de saída da CLI; publica `exit-code` e `code` (primeiro erro do relatório) também quando a CLI recusa, e com `fail: "false"` só publica sem falhar o passo. Uma
distribuição que não verifica falha **antes** de a CLI rodar. Fixe a Action por SHA de commit (`uses:
e-bees-dev/sentomaru-sdk/actions/protect@<sha>`). A execução real (`dry-run: "false"`: AAB com `sign: openbao`, G-03e2,
`keystore` ou `none`) exige `SENTOMARU_BUILDER_TOKEN` e `SENTOMARU_API` no ambiente do job; a entrada APK (G-03b3) está no código, sem release.

### Download dentro da Action (G-05)

`distribution` é opcional. Informada, a Action verifica esse diretório como sempre (o chamador baixou). **Vazia**, o primeiro
passo roda `tools/devsecops/download_cli.py` e baixa `sentomaru-protect-<version>.zip`, `SHA256SUMS`, `statement.json` e
`signature.sigstore.json` do release `cli-v<version>` de `release-repository` (padrão `e-bees-dev/sentomaru-sdk`) pela API REST do
GitHub (`release-api-url`, padrão `https://api.github.com`: https, ou loopback nos testes), para um diretório novo em
`$RUNNER_TEMP`, e o `verify_cli.py` roda sem alteração sobre ele.

- **Token:** entrada `token`, com leitura dos releases de `release-repository`; vai por variável de ambiente (nunca na linha de
  comando, nunca impresso) e só ao host da API, nunca ao destino do redirecionamento (a URL assinada do arquivo). O
  repositório de distribuição é público e o `GITHUB_TOKEN` padrão do workflow do cliente basta (o script exige um token, mesmo para release público).
  Sem o token, o caminho continua sendo o bucket S3 público com `distribution` (CLI_PIPELINE §1a).
- **Sem confiança nova:** o baixado é não confiável até o `verify_cli.py` passar. O pino da chave (`key`, `key-sha256`) vem por
  outro canal; a Action não busca chave no release. `expect-*` e os pinos do cosign não mudam.
- **Limites do download:** versão `^[0-9]+\.[0-9]+\.[0-9]+$` (mais estrita que a do verificador, que aceita `-prerelease`),
  repositório `dono/nome`, nomes dos arquivos fixos pela versão (outros nomes do release são ignorados), até 128 MiB por
  arquivo, corpo truncado recusado, destino preexistente recusado.
- **Erro:** `cli-download-failed:<motivo>` (`version`, `repository`, `url`, `token`, `dest-exists`, `http-<status>`, `network`,
  `release-malformed`, `missing-<zip|sha256sums|statement|signature>`, `redirect`, `too-large`, `truncated`, `io`), publicado na saída
  `verify-error` como qualquer recusa de verificação, antes de a CLI rodar.
- **Provado:** testes do script contra um servidor local e a Action no job `devsecops-cli-dist` contra stand-ins loopback.
  **Não provado:** o release real do GitHub (token real, URL assinada).

