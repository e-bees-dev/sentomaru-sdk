# Proveniência da corrida `sentomaru protect` — statement `protect-run/v1` (D-16d)

A CLI não assina nada além do artefato (e não deve: a chave do statement é do ambiente do cliente, D-C1). Depois de uma
corrida **registrada**, o CI que chama a CLI (a Action do G-01 ou o passo do próprio cliente) monta um statement in-toto
com [`tools/devsecops/protect_provenance.py`](../../tools/devsecops/protect_provenance.py) (stdlib) e o assina **com a
chave do cliente**. Com ele, o relatório de proteção da corrida (`kind: protect-run`,
[protection-report-v1.md](../shield/protection-report-v1.md)) pode ser gerado e conferido por terceiro com o
`tools/shield/protection_report.py` 1.0.2. Desenho: an internal design note,
item 6, decisões D-16x11 e D-16x3.

Isto cobre a parte "proveniência (com o artefato de entrada e o de saída)" da G-03e. **Não muda a CLI** (o
`report.json` já tem tudo) e **não cria papel nenhum no OpenBao do Sentomaru**: quem assina é o cliente (OpenBao dele,
por identidade federada, ou chave local). Registrar a corrida como build do Shield continua fora (desvio do
[contrato da CLI](cli-v1.md), "Medição": o `buildId` é o `runId`).

## Quando

Só depois de `report.json` dizer `registration.status: registered`. A ferramenta recusa, antes de escrever qualquer
coisa (saída 1, `provenance-invalid: <código>` no stderr). Os códigos são os do gerador quando a situação é a mesma;
`input-mismatch` e `vocabulary` são só da ferramenta (no gerador, a mesma situação sai `report-json` ou
`subject-shape`). A ferramenta recusa tudo o que faria o gerador recusar todo relatório da corrida pela forma do
`report.json` ou pelo vocabulário, para o cliente não assinar um statement que nunca vira relatório:

| Código | Quando |
|---|---|
| `dry-run` | `dryRun: true` (o `--dry-run` não registra nem escreve artefato) |
| `lab-run` | `report.json` com `lab` (corrida `--lab-unregistered`, nunca registrada) |
| `run-errors` | `errors` não vazio |
| `not-registered` | `registration.status` diferente de `registered` (uma corrida cujo fechamento falhou passa a valer depois do `sentomaru protect register`) |
| `report-json` | `report.json` fora da forma do [contrato da CLI](cli-v1.md), "Saída e relatório" (membros de topo exatamente os do `skeleton`, `versionCode` de 1 a 2 100 000 000, `package` com a forma de pacote Android) |
| `vocabulary` | um valor que o relatório copia (`--repository`, `--ref`, `--workflow-path`, `--invocation-id`, o builder, `profile.id`, o escopo, `input.package`, os nomes dos subjects) tem palavra que o relatório proíbe (`certif…`, `seguro`, `secure`, `aprovado`, `garantido`, `nível SLSA`… ; a mesma expressão `TOKEN` do gerador, conferida pelo teste). Um app ou repositório com esse nome não gera relatório de proteção |
| `output-mismatch` | o SHA-256 do `--output` não é `output.sha256` (a mesma conferência do `protect register`) |
| `input-mismatch` | o SHA-256 do `--input` não é `input.sha256` |
| `sbom-shape` | `--input-sbom` que não é CycloneDX 1.6 |
| `out-exists` / `io` | `--out` já existe (nunca sobrescreve); arquivo ausente, link ou não regular |

Saída 2: uso (`--output` que não termina em `.protected.aab`, `--input` que é o próprio AAB protegido, nomes repetidos,
argumento fora da forma).

## Forma

in-toto Statement v1, SLSA Provenance v1, `buildType` `https://e-bees.com.br/sentomaru/devsecops/protect-run/v1`,
serializado com chaves ordenadas e `\n` final (mesmas entradas, mesmos bytes):

| Campo | Valor |
|---|---|
| `subject[]` | `<nome>.protected.aab` (o `--output`), `report.json`, o AAB de entrada **só se o cliente o publica** (`--input`; senão o digest dele fica só em `report.json` e no relatório, `buildFacts.inputSha256`) e o SBOM do build de entrada, se o cliente tiver (`--input-sbom`, CycloneDX 1.6, nome `*.json`); em ordem de nome |
| `externalParameters.workflow` | `repository`, `ref`, `path` (é onde o `verify_release.py` lê `--expect-repository`, `--expect-ref` e `--expect-workflow-path`) |
| `externalParameters.profileSha256` | `profile.sha256` do `report.json` |
| `externalParameters.runId` | `runId` do `report.json` |
| `externalParameters.profileRevision` | `{profileId: profile.id, scope: "<organization>/<app>/<environment>"}`: é onde o `check_expectations` do `verify_release.py` lê `--expect-scope`. Sem `digest`: o perfil `protect` não é perfil do Shield e não tem revisão no registro |
| `internalParameters.buildNumber` | `input.versionCode` em texto (para `--expect-build-number`, contra rollback). **Sem `versionName`**: o `report.json` não o tem, então `--expect-version` não funciona no `protect-run` |
| `internalParameters.cliBuild`, `contractVersion`, `runtimeDexSha256` | `cli.build`, `cli.version` e `cli.runtime.dexSha256` do `report.json` |
| `resolvedDependencies` | o commit do app (`git+https://github.com/<repository>@<ref>`, `gitCommit`) e o zip da CLI usado (`https://e-bees.com.br/sentomaru/devsecops/cli-dist/v1#sentomaru-protect-<build>.zip`, `sha256` = a linha do `SHA256SUMS` da release) |
| `runDetails.builder.id` | padrão `https://github.com/<repository>/<workflow-path>@<ref>` (`--builder-id` troca) |
| `runDetails.metadata.invocationId` | a URL da execução do CI (`--invocation-id`); nenhum horário (D-16x12) |

Nada de segredo, token, chave ou conteúdo do app: só nomes, digests e os campos acima. O gerador confere que o
statement e o `report.json` assinado dizem a mesma coisa (`report-json` se não), e recusa o `report.json` de corrida
que não seja registrada pelas mesmas regras da tabela acima.

## Assinatura (pelo cliente)

Na forma que o `verify_release.py` exige (assinatura de mensagem Sigstore v0.3, sem log de transparência):

```bash
python3 tools/devsecops/protect_provenance.py --report out/report.json --output out/app.protected.aab \
  --repository "$GITHUB_REPOSITORY" --ref "$GITHUB_REF" --workflow-path .github/workflows/protect.yml \
  --commit "$GITHUB_SHA" --cli-zip-sha256 <linha do SHA256SUMS> \
  --invocation-id "$GITHUB_SERVER_URL/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID/attempts/$GITHUB_RUN_ATTEMPT" \
  --out publicado/statement.json
cosign sign-blob --yes --key <chave do cliente> --use-signing-config=false --tlog-upload=false \
  --bundle publicado/signature.sigstore.json publicado/statement.json
```

Publica-se `statement.json`, `signature.sigstore.json`, o AAB protegido, `report.json` (e o AAB e o SBOM de entrada,
se entraram como subject) e o PEM público da chave, cujo **pino o cliente entrega a quem confere por outro canal** (o
Sentomaru não tem como dizer que a chave é do cliente: o relatório traz `keyName: null` e as linhas `client-key` e
`key-not-published` em `notVerified`).

## Prova (D-16d)

`verification/shield_release/test_protect_run_report.py`: um AAB de exemplo protegido de verdade pela CLI compilada no
mesmo job (`runtime-injection`, `network-signing`, `build-obfuscation`), registrada num **registro falso** (servidor
HTTP stdlib do lado do teste, `buildId` fixo de teste), statement desta ferramenta assinado com chave efêmera e
relatório gerado e conferido; mais uma corrida sintética com ouro e as recusas. Roda no job `devsecops-cli-dist` do CI,
passo "Protection report of a protect run (D-16d, zero skips)", com o cosign fixado e a CLI compilada no mesmo job
(entrou com a correção da revisão R; a primeira prova de CI é o run do PR que a levar). A adoção pela Action do G-01 (passo opcional de proveniência) fica para depois.
