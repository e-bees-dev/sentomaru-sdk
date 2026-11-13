# `sentomaru protect` — contrato da CLI v1 (G-03a)

Contrato da CLI de proteção pós-build do Sentomaru DevSecOps (G-03). Recebe um APK ou AAB **já compilado** e devolve o
artefato protegido, com relatório, sem alterar o código-fonte do app (dentro dos limites abaixo), **exceto a
assinatura de rede**, que é uma linha no app (`network-signing`, G-03c, decisão do fornecedor de 16/10/2026). Decisão D-C1 (fornecedor,
16/10/2026): **a CLI roda só no ambiente do cliente** (máquina ou CI). Nenhum serviço do Sentomaru recebe, altera ou
guarda o binário; só metadados (digests, ids, versões) saem da máquina. Arquitetura: [ADR 0001](../../docs/devsecops/adr-0001-post-build.md).
Esquema do perfil: [`protect-profile-v1.schema.json`](protect-profile-v1.schema.json).
Distribuição da CLI e Action: [`cli-distribution-v1.md`](cli-distribution-v1.md) (G-03f, G-01).

**Compatibilidade:** são acréscimos da v1 um **controle novo** (seção nova no perfil) e um **campo novo no relatório**
(consumidores ignoram campos desconhecidos). Um campo novo dentro de um controle existente é uma **versão nova desse
controle** (`version: "2"`), porque a seção é fechada. Remover ou mudar o sentido de um campo, um código de erro ou um
código de saída é v2 do contrato.

## Invocação

```text
sentomaru protect --input <app.apk|app.aab> --profile <protect-profile.json> --out <dir>
                  [--dry-run] [--report <path>] [--json]
                  [--sign keystore --keystore <path> --key-alias <alias>]                       (G-03e)
                  [--sign openbao --openbao-addr <url> --openbao-role <role> --openbao-transit <mount>/<key>
                   --openbao-key <cert.pem> [--openbao-cacert <pem>] [--openbao-audience <aud>]]   (G-03e2)
                  [--sign none]
sentomaru protect openbao-certificate --openbao-addr <url> --openbao-role <role> --openbao-transit <mount>/<key>
                  --common-name <cn> --out <cert.pem> [--years 30] [--openbao-cacert <pem>] [--openbao-audience <aud>]
sentomaru protect --version [--json]
sentomaru protect controls [--json]   # controles desta versão: id, versão, etapa, ordem
sentomaru verify receipt|audit-export [opções do verificador]   # conferência de terceiro do Trust (abaixo)
sentomaru scope plan|apply|check --manifest <sentomaru-scope.yaml> [--api <url>] [--policy <policy.json>] [--expect <módulo,…>] [--allow-unknown] [--json] [--admin-token-stdin]   # onboarding de escopo (seção "sentomaru scope")
sentomaru policy study (--scope <org>/<app>/<env> --operations <op,op,...> --sensitive-operations <op,op,...> |
                         --manifest <sentomaru-scope.yaml>)
                  [--presence-operations <op,op,...>] [--location-sensitive-operations <op,op,...>]
                  [--version <v>] [--description <texto>] [--out <path>]   # política de estudo (abaixo)
```

- **`sentomaru policy study` (acréscimo, não é parte de `protect`; ativação de módulos em cliente novo, Fase D,
  spec de 10/11/2026 §8):** monta a política shadow (toda regra em `observe`) que cobre o catálogo de sinais
  (`contracts/sdk/signals-catalog-v1.json`) e as operações declaradas, do modelo
  [`contracts/policy/templates/study-v1.json`](../policy/templates/study-v1.json) — nunca um JSON escrito à mão. Sem
  rede, sem a API do Sentomaru: lê o modelo embutido na própria CLI e escreve em stdout ou em `--out`. `--scope` e
  `--manifest` são **mutuamente exclusivos** e um dos dois é obrigatório. Com `--scope`, `--operations` e
  `--sensitive-operations` são obrigatórios (`--sensitive-operations`, uma decisão do negócio, nunca um padrão
  silencioso) e `--sensitive-operations` precisa ser um subconjunto de `--operations`. Com `--manifest`, organização/app/ambiente
  e a lista de operações sensíveis vêm de `policy.sensitiveOperations` no manifesto do `sentomaru-scope.yaml` (Fase C;
  seção "`sentomaru scope`" abaixo); o manifesto precisa declarar
  `policy.template: study` (qualquer outro valor, ou a ausência da seção `policy`, é erro de uso) e `policy.operations`,
  se ausente ou vazio, usa a própria lista de sensíveis. Um manifesto malformado sai com **4** (`manifest-format`), igual
  ao leitor de `sentomaru scope`. Nos dois modos, `--presence-operations`/`--location-sensitive-operations` (para as
  regras `user_presence`/`fraud_location_mock`) são opcionais e, se omitidos, usam a lista de operações sensíveis — o
  manifesto não carrega essas duas, só a linha de comando. Saída: **0** gerado; **2** erro de uso (falta um argumento
  obrigatório, `--scope` e `--manifest` juntos, uma lista vazia, um id de operação fora do formato de slug com `_` opcional,
  um dos grupos citando uma operação que não está nas operações, ou um manifesto sem `policy`/com `policy.template`
  diferente de `study`); **4** manifesto malformado. "Pronto" (spec §8): com as listas do ExampleApp prod este comando reproduz
  `docs/api/examples/policy-exampleapp-prod-estudo-1.0.0.json`, a menos de id, versão e descrição. O resultado, nos dois modos,
  satisfaz o contrato que `sentomaru scope apply --policy` confere numa política `study` (mesmo escopo; `policyId`/`version`
  presentes; `enforcementMode: shadow`; `sensitiveOperations` igual ao do manifesto, como conjunto).

- **`sentomaru verify` (acréscimo, não é parte de `protect`):** `receipt` confere um recibo de conclusão
  (o recibo de conclusão assinado do Sentomaru) e `audit-export` confere uma exportação assinada da trilha ou um
  dossiê (e o dossiê de evidências). Não há lógica
  nova: a CLI executa, com `python3 -I`, os mesmos `verify_receipt.py` e `verify_audit_export.py` que um terceiro rodava a partir de
  `tools/trust/` (biblioteca padrão e `openssl`; a distribuição os traz sem alteração em `lib/verify/`), repassa os argumentos depois
  do nome, imprime o que eles imprimem e devolve o código de saída deles: **0** válido, **1** inválido (a única linha de stdout é o
  código do motivo), **2** erro de uso. Não usa rede nem a API do Sentomaru, não lê `SENTOMARU_API` nem credenciais. Se o verificador
  não puder rodar (sem Python 3 confiável, sem o script na distribuição, sem `openssl`, mais de 120 s) ou terminar com saída que não é a do
  contrato (código fora de 0/1/2, `0` sem a linha `ok` ou o resumo JSON, `1` sem uma única linha de motivo), a saída é **2** com uma
  linha `verify-unavailable: …` em stderr, nunca 0 nem 1. `SENTOMARU_PYTHON` troca o interpretador (padrão: o primeiro `python3` de um diretório absoluto do `PATH`). Confiança, em
  POSIX: o interpretador e o script são resolvidos (links seguidos) e é o caminho resolvido que se executa; cada um precisa ser arquivo
  regular, de root ou do usuário atual, sem escrita por grupo ou outros, e **cada diretório acima** (pelo caminho dado e pelo
  resolvido) precisa ser de root ou do usuário atual e sem escrita por grupo ou outros (um diretório com sticky bit de root, como
  `/tmp`, é aceito acima do arquivo); um link de outro usuário é recusado; caminho relativo nunca é procurado. A JVM não consegue
  abrir o arquivo uma vez e passar o descritor ao filho, então validar e executar seguem sendo dois passos: o que fecha a janela é
  que ninguém além do dono e de root escreve em nenhum diretório do caminho. **Windows:** não há dono nem modo para conferir; a CLI
  recusa (`verify-unavailable`) a menos que `SENTOMARU_VERIFY_ALLOW_UNCHECKED=1`, e então nada é conferido. O `openssl` que decide a
  assinatura **nunca** vem do `PATH`: os scripts o procuram em `/usr/bin`, `/bin`, `/opt/homebrew/bin` e `/usr/local/bin` (ou em
  `SENTOMARU_OPENSSL`, que substitui a lista), com as mesmas regras de confiança, e só aceitam a resposta se ele sair com 0 **e** escrever
  `Verified OK`; um controle negativo (os mesmos bytes mais um byte, com a mesma assinatura) precisa falhar, senão o resultado é
  `openssl-misbehaves` (exit 2). **O que isto não cobre:** `SENTOMARU_PYTHON`, `SENTOMARU_OPENSSL`, `SENTOMARU_VERIFY_DIR` e o ambiente do processo são confiados como
  vêm de quem roda a CLI. A checagem protege contra **outros usuários** (e contra um diretório gravável por eles), não contra código do
  **mesmo** usuário: um `openssl` falso esperto, num diretório do próprio usuário, indicado em `SENTOMARU_OPENSSL`, passa nas regras
  acima. O `openssl` roda só com `PATH`, `LC_ALL` (e `SYSTEMROOT` no Windows): `OPENSSL_CONF`, `OPENSSL_MODULES` e o resto do ambiente
  não chegam a ele. Os dois canais de saída são lidos juntos (um verificador verboso não trava) e, no tempo esgotado, os
  processos filhos também são encerrados. Os códigos de saída de `protect` (seção
  "Erros e códigos de saída") não mudam. Os verificadores de bootstrap (`verify_cli.py`, `download_cli.py`, `verify_sdk.py`,
  `verify_release.py`) continuam scripts à parte: servem para conferir a própria CLI antes de ela existir na máquina.

- **Credencial:** toda execução real (sem `--dry-run`) exige a credencial `shield-builder` do escopo do perfil, em
  `SENTOMARU_BUILDER_TOKEN` (nunca em argumento nem em arquivo do relatório), e o endereço da API em `SENTOMARU_API`.
  A CLI confere o direito do módulo (B-06) **antes** de alterar qualquer coisa e, ao fim, registra a corrida em
  `platform.protect_run` (não é um build do Shield): metadados e digests, nunca o binário. Não há modo real sem rede na v1. `SENTOMARU_API` é https
  (http só para endereço de loopback, em teste local).
- **Registro (G-03e):** a execução real **abre** a corrida em `POST /v1/{org}/{app}/{env}/devsecops/runs` (`runId`,
  `profileId`, `profileSha256`, `cliVersion`) antes de ler a entrada: a rota é do módulo `devsecops`, então abrir é a
  conferência do direito (403 `module-*` → `entitlement-denied`; credencial de outro escopo → `scope-mismatch`;
  credencial recusada ou de outro tipo → `credential-missing`; API inacessível, 429 ou 5xx → `registry-unavailable`).
  Ao fim **fecha** em `POST …/runs/{runId}/close` com o resultado: `protected` (digests de entrada e saída, `signed`,
  `signingCertSha256`) ou `failed` (o código do erro e, se a entrada já foi lida, o digest dela). O fechamento **não**
  passa pela porta do módulo: uma corrida admitida pelo direito sempre registra o resultado (só quem abriu fecha). O
  `buildId` do relatório é o `runId`. Uma corrida fechada é imutável (nem apagada); reabrir ou refechar com a mesma
  declaração é idempotente. Uma corrida aberta há mais de 24 h é fechada como `failed`/`run-expired`, de forma
  preguiçosa: na próxima abertura ou fechamento de uma corrida do mesmo escopo. Uma corrida legítima que passe de 24 h
  perde o fechamento: `close` devolve 409 `run-closed` e `protect register` dá `register-failed`.
  Digests e `signed` são **declaração** de quem tem a credencial `shield-builder`, não prova de que o artefato foi
  protegido: o servidor não vê o binário (D-C1).
- **Listagem (G-08):** `GET /v1/{org}/{app}/{env}/devsecops/runs?limit=&before=` devolve `{ "runs": [...] }` das corridas
  do escopo, da mais nova para a mais antiga (`openedAt`, depois `runId`), na mesma forma do registro. Cada linha traz também `profileSha256` e `cliVersion` (a versão de `build` que a CLI declarou ao abrir; o Console mostra a coluna "CLI"), declarados como o resto da linha. `limit` vai de 1 a
  100 (padrão 50); `before` e `beforeRun` são o `openedAt` e o `runId` da última linha vista, copiados sem truncar, e
  paginam para trás sem perder linhas de mesmo instante (`beforeRun` exige `before`). Só leitura, sessão de operador com
  `policy.read`, como as leituras do Shield (a credencial `shield-builder` não lista), sem porta do módulo: o histórico continua legível com o módulo
  desligado. Parâmetro de cursor inválido ou `limit` fora da faixa: 400 `run-query` (um `limit` que não é inteiro recebe o 400 do próprio framework). As linhas são declaração de quem tem a credencial, como acima.
- **Refazer o registro:** se o fechamento falhar (`register-failed`, `registry-unavailable`), o relatório guarda o
  fechamento em `closing` e `sentomaru protect register --report <report.json>` o reenvia (mesma credencial e API);
  antes, confere o escopo e o `runId` do relatório, aceita só as chaves de um fechamento `protected` e exige que o
  único `*.protected.aab` ao lado do relatório tenha o SHA-256 declarado. O relatório é atualizado no lugar, e só os
  erros de registro (`register-failed`, `registry-unavailable`) saem de `errors`.
- **`--dry-run`:** valida entrada, perfil e compatibilidade e calcula tudo o que mudaria; grava só o relatório
  (`output.sha256` e as medições ficam `null`); **não faz chamada de rede** (sem direito, registro, assinatura nem
  medição). Devolve os mesmos códigos de saída de uma execução real **para as saídas 2 a 7**; não pode produzir a 8
  nem `scope-mismatch` (precisam da credencial e da rede), então o portão do CI não cobre esses casos.
- **`--report`:** caminho do relatório; padrão `<out>/report.json`. `--json` faz `--version` e `controls` saírem em
  JSON (formato estável) para a Action (G-01).
- **Assinatura (G-03e):** padrão por tipo de artefato: **APK** sai assinado (v2/v3; `--sign none` só com aviso,
  porque um APK sem assinatura não instala); **AAB** sai sem assinatura por padrão, para o cliente assinar com a chave
  de upload (o Play Console exige o AAB assinado com ela) ou assina por `--sign keystore|openbao` (assinatura JAR, a
  do AAB). `--sign openbao`: chave no OpenBao **do cliente**, por identidade federada do CI (D-02b). Opções de
  assinatura sem `--sign` → `usage`. **APK sem `--sign`** → `usage` (é preciso escolher `keystore` ou `none`; `openbao` só vale para AAB). Rotação de chave v3 (linhagem) fica fora da v1.
- **Estado da implementação (G-03e1):** `--sign keystore` assina o **AAB** (assinatura JAR SHA-256 pelo signer do
  JDK; antes do registro a CLI confere, com `JarFile` em verificação, que **todas** as entradas estão assinadas pelo
  mesmo certificado); as senhas vêm só do ambiente: `SENTOMARU_KEYSTORE_PASSWORD` e, se a chave tiver outra,
  `SENTOMARU_KEY_PASSWORD`. Uma execução real com **APK** de entrada (G-03b3) aplica `runtime-injection` e `ui-shield`
  (DEX `classesN.dex` e manifesto binário; saída `<entrada>.protected.apk`, alinhada como o `zipalign` e assinada pelo
  apksig, v2/v3 habilitados e v1 desligado; a assinatura de entrada é descartada, com o aviso `input-signature-removed`).
  `--sign openbao` com APK → `usage` (o assinador do OpenBao assina um pacote JAR, não um APK); um controle que ainda só edita
  AAB (`network-pinning`) responde `control-failed`. **Estado:** código em `main` desde a G-03b3, ainda sem release: a
  `cli-v0.6.1` publicada executa só AAB. `network-signing` (G-03c) não muda o binário: confere que o app embute o transporte de
  assinatura do SDK e o registra no relatório (ver o controle).

- **`--sign openbao` (G-03e2):** a assinatura JAR SHA-256 do AAB é feita por uma chave **RSA não exportável** do
  Transit do OpenBao **do cliente** (`--openbao-transit <mount>/<key>`): o signer do JDK monta a assinatura e cada
  operação RSA é uma chamada `sign` do Transit (`sha2-256`, prehashed, PKCS#1 v1.5). A chave nunca sai do cofre; a CLI
  recusa (`sign-failed`) uma chave exportável, com backup em claro ou que não seja RSA, e um `--openbao-key`
  (certificado X.509 em PEM) cuja chave pública não seja a da chave do Transit. Identidade: o token federado do CI
  (D-02b) em `SENTOMARU_OPENBAO_JWT`, ou o OIDC do GitHub Actions (`ACTIONS_ID_TOKEN_REQUEST_*`, `permissions:
  id-token: write`) com a audiência `--openbao-audience` (padrão: o endereço). Login em `auth/jwt` com
  `--openbao-role`; o token da sessão é revogado ao fim. JWT e token só em memória (nunca argv, log, relatório ou
  arquivo). Só https, verificado por `--openbao-cacert` quando dado (senão as raízes do sistema), sem redirecionamento.
  Política mínima do papel: `read` em `<mount>/keys/<key>` e `update` em `<mount>/sign/<key>/sha2-256`. OpenBao
  inacessível, TLS recusado, login recusado ou 403 (papel ou política sem permissão na chave) → `signer-unavailable`
  (7); 404 (a chave não existe) e outro 4xx, chave fora da regra, resposta acima de 256 KiB ou assinatura que não
  confere → `sign-failed` (7); 5xx → `signer-unavailable`. `--openbao-cacert` ou `--openbao-key` ausentes ou que não são
  certificados (o de `--openbao-key` tem de ser RSA) → `usage` (2), **antes** de abrir a corrida. Pela precedência, a corrida já está aberta (direito conferido) e
  fecha como `failed`.
- **`openbao-certificate`:** gera o certificado autoassinado X.509 v3 da chave do Transit (validade padrão de 30 anos,
  `--years` de 1 a 50), assinado **no cofre**, para cadastrar como certificado de upload no Play Console e para passar
  em `--openbao-key`. Nunca sobrescreve um arquivo (criação exclusiva); imprime só o caminho e o SHA-256 do
  certificado. Saídas: 0 gerado; 2 `usage` (argumentos, `--out` já existente) ou `output-unwritable` (`--out` sem
  escrita); 7 `signer-unavailable`/`sign-failed` (as mesmas regras do `--sign openbao`); 1 `internal-error`.
- **Play App Signing (`--sign openbao` e `keystore`):**
  - **app novo:** o certificado do cofre (`openbao-certificate`) é registrado como certificado de upload no primeiro
    envio ao Play Console;
  - **app que já usa Play App Signing:** o dono pede a **troca da chave de upload** no Play Console (Integridade do
    app → Assinatura do app) e envia o certificado do cofre;
  - **app legado sem Play App Signing:** a chave não exportável do cofre **não pode** virar chave de assinatura do
    app migrável para o Google (exigiria exportá-la). Inscreva o app no Play App Signing antes e use o cofre só para a
    chave de upload;
  - quem instala pela loja recebe o APK assinado pela **chave de assinatura do Google**, não pela de upload:
    `output.signingCertSha256` é o certificado de **upload**. As restrições por SHA-256 (Google Sign-In, Maps, Play
    Integrity, App Links/`assetlinks.json` e a atestação do Sentomaru, digests do escopo) usam o certificado do **App
    Signing**, lido no Play Console.

> **Não contratual (G-03b2; mantido na G-03e1 só para o gate em aparelho):** `--lab-unregistered`, aceito só com
> `SENTOMARU_LAB=1` no ambiente, aplica `runtime-injection` (e, desde a D-07b, `network-pinning`, liberado na D-07f e aplicado aqui do mesmo jeito, e desde a D-14c, `asset-encryption`, liberado na D-14e e aplicado aqui do mesmo jeito; `network-signing` e, desde a D-08d, `build-obfuscation` continuam recusados com `control-failed`) a um AAB sem credencial, sem conferência de direito e sem
> registro, com `--sign none`. A saída se chama `<nome>.lab.aab`, o relatório traz `"lab": true`, o aviso
> `lab-unregistered` e `registration.status = "not-registered"`. Serve só para laboratório e testes; nunca para
> distribuição. Sai quando o gate em aparelho (the vendor's run g03b2 device gate check) usar um registro local.
> Desde a D-16-lab-gate, o gate (`SENTOMARU_LAB=1`) só vale no `--dry-run` (que não registra) e com `--lab-unregistered`:
> numa execução real registrada a CLI o recusa (saída 2, `usage`, `detail` `lab-gate-registered`, ver abaixo).

**Mudança de comportamento na D-16-lab-gate, ainda CLI 0.5.0 (registrada; nenhuma versão de controle muda):** a 0.5.0
ainda não tinha sido publicada, então a recusa entra na mesma versão (a linha 0.5.0 da tabela de controles do
[contrato da distribuição](cli-distribution-v1.md) foi completada antes da publicação). Uma execução real (sem
`--dry-run` e sem `--lab-unregistered`) com `SENTOMARU_LAB=1` no ambiente (valor exato `1`) sai **2 (`usage`)** com o
`detail` estável **`lab-gate-registered: SENTOMARU_LAB=1 needs --lab-unregistered`**, depois de ler o perfil e o seu
`scope` e **antes** da credencial, do direito e da abertura da corrida (nenhuma requisição chega à API, nenhum artefato
em `<out>`; o relatório da recusa é gravado como nas outras). Antes (`cli-v0.4.0` e o código da 0.5.0 até esta fatia),
a corrida seguia com o gate e era registrada como qualquer outra; o servidor, que recebe só digests, não distinguia uma
corrida com o gate (D-16x5). Motivo: o gate muda o comportamento de um controle (o teto do `asset-encryption`, 4 MiB em
vez de 1 MiB), e uma corrida registrada só pode ter o comportamento da CLI distribuída. Outros valores
(`SENTOMARU_LAB=0`, `true`) não são o gate e não mudam nada. O `--dry-run` e a execução de laboratório seguem como antes.

## Entrada

| Item | Regra | Código |
|---|---|---|
| Artefato | um APK (assinado v2/v3, ou só v1 com aviso) ou um AAB. `.apks`, `.xapk`, splits soltos → recusados | `input-format` |
| Assinatura de entrada | APK: a assinatura existente tem de ser válida (`apksig`); AAB: se assinado, a assinatura JAR tem de ser válida | `input-signature` |
| Tamanho | até 512 MiB (limite de memória da v1, com ZIP64); acima | `input-too-large` |
| `minSdk` do app | ≥ 28 (o do SDK) | `min-sdk-unsupported` |
| AAB com módulos de recurso dinâmico | só o módulo `base` recebe o runtime; os outros seguem intactos e o relatório lista cada um | — |
| Perfil | JSON segundo o esquema v1; campo desconhecido dentro de uma seção de controle é **recusado** | `profile-format` |
| Escopo | `scope` do perfil tem de ser o da credencial | `scope-mismatch` |

### Entrada IPA (G-03g1, só `--dry-run`)

Um `--input` com extensão `.ipa` é só inspecionado e exige `--dry-run`; sem ele, `usage`. O perfil ainda é lido e validado (escopo e
formato), mas nenhum controle é avaliado (`controls` vazio e o aviso `ipa-controls-not-evaluated`). `input` traz `kind` `ipa`, `sha256`,
`bundleId`, `shortVersion`, `buildVersion`, `minimumOsVersion`, `executable`, `frameworks` (nomes em `Frameworks/`),
`sentomaruFramework` (há um `Sentomaru*.framework`; SDK compilado dentro do app, como o pod do Flutter, não é visto, e o aviso
`ipa-sdk-framework-absent` diz isso) e `hasProvisioningProfile` (só a presença). Recusas: `input-format` (não é zip, nenhum ou mais de um
`Payload/*.app`, `Info.plist` ausente, ilegível ou sem `CFBundleIdentifier`, nome de entrada inseguro), `input-too-large`. Não lê a assinatura
nem o perfil de provisionamento e não grava artefato.

## Perfil de proteção (`protect-profile` v1)

Uma seção por **controle de perfil**, cada uma com a própria versão (costura da onda 1: um controle novo entra como
seção nova, sem versão nova da CLI nem da Action). É o mesmo objeto que o Shield registra (D-01), com
`kind: "protect"`. Assinatura e registro **não** são seções: são opções da invocação.

```json
{
  "schemaVersion": "1",
  "kind": "protect",
  "profileId": "exampleapp-hml-protect",
  "scope": { "organization": "ebees", "app": "exampleapp", "environment": "hml" },
  "controls": {
    "runtime-injection": { "version": "1", "enrollmentUrl": "https://api.example/v1/ebees/exampleapp/hml/installations" },
    "network-signing":   { "version": "1", "hosts": ["api.example"],
                           "routes": [{ "path": "/v1/demandas/*", "operation": "concluir_demanda" }] }
  }
}
```

Versões são inteiros em texto (`"1"`, `"2"`) em todo o contrato: perfil, controle, relatório. O runtime embutido é o
da versão da CLI (`cli.runtime.sdk` no relatório); o perfil não escolhe versão de SDK. Uma seção de controle
desconhecido precisa de `version` numérica (senão `profile-format`); com ela, a CLI responde `control-not-available`.
Exceção no esquema: a seção `network-pinning` já é fechada por ele (D-07a, ver [`network-pinning`](#network-pinning-d-07));
a CLI a conheceu só atrás do gate de laboratório da D-07b à D-07e, e desde a D-07f (código da CLI 0.5.0) a conhece sem
ele. As seções `build-obfuscation` (D-08a, ver [`build-obfuscation`](#build-obfuscation-d-08)) e `asset-encryption`
(D-14a, ver [`asset-encryption`](#asset-encryption-d-14)) também são fechadas pelo esquema; a CLI conhece
`build-obfuscation` sem o gate desde a D-08f, e `asset-encryption` só atrás dele da D-14c à D-14e, e sem ele desde a
D-14e (código da CLI 0.5.0).

## Controles

Cada controle declara `id`, `version`, `stage`, `order` (dentro da etapa), pré-requisitos, **o que muda no binário**
(com um id estável por tipo de mudança) e a evidência que gera (seção do relatório D-16). Ordem de aplicação: por
etapa `inject` → `instrument` → `harden`, e dentro da etapa por `order`; depois assinatura e registro.

| Controle | Fatia | Etapa / ordem | Muda no binário | Pré-requisitos |
|---|---|---|---|---|
| `runtime-injection` | G-03b (onda 1) | inject / 10 | DEX do runtime acrescentado (dependências realocadas para pacote próprio, exceto os tipos de rede que o app compartilha); `ContentProvider` de inicialização declarado no manifesto, `exported=false`, no processo principal; permissões que o runtime precisa e o app não declara → recusa. **Sem recursos**: o runtime não traz `res/` (não há mescla de `resources.arsc`). Preserva `versionCode`, `versionName`, `targetSdk` e as permissões do app. AAB: edita o manifesto e o DEX do módulo `base` (formato protobuf) e valida com `bundletool` | permissão ausente → `permission-missing`; DEX acima do limite de métodos sem multidex → `app-incompatible`; app que já declara o provider do Sentomaru em `<application>` (protegido duas vezes) → `app-incompatible`, também no `--dry-run` (G-06) |
| `network-signing` | G-03c (onda 1) | instrument / 10 | **Nada** (decisão do fornecedor, 16/10/2026: sem reescrita de DEX). A assinatura RFC 9421 é o transporte do SDK que o app liga **numa linha**, com os `hosts` e `routes` do perfil: Android `OkHttpClient.Builder().addSentomaru(client, SentomaruRoutes.of(hosts, routes))`, Flutter `dio.addSentomaru(client, routes: SentomaruRoutes.fromProfileSection(secao))`; Android com `HttpURLConnection` (S2, CLI 0.4.0): a tabela montada uma vez e cada chamada por `SentomaruUrlConnection.send(client, routes, método, url, corpo, cabeçalhos)`. Requisição sem operação declarada cujo host e caminho casam com uma rota é assinada como essa operação; operação declarada (cabeçalho ou etiqueta) prevalece. **Casamento:** as rotas são tentadas **na ordem do perfil e a primeira que casa vence** (rota literal antes de uma rota com `*` que também a cobriria); `*` casa exatamente um segmento não vazio; o resto compara sem diferenciar maiúsculas e já decodificado (percent-encoding); uma barra final é ignorada; **a porta é ignorada**; o host com um ponto final (`api.example.`) conta como o mesmo host e então é recusado pela lista de hosts do cliente. A instalação é **recusada** se `hosts` não estiver contido nos hosts permitidos do cliente; uma rota com o cliente não inicializado, num host fora da lista, ou com URI não canônica **não é enviada** (erro tipado). A CLI confere, só lendo o DEX do módulo `base`, que uma `class_def` **define** `Lbr/com/ebees/sentomaru/sdk/transport/SentomaruRoutes;`, `Lbr/com/ebees/sentomaru/sdk/transport/SentomaruUrlConnection;` (S2) ou o plugin `Lbr/com/ebees/sentomaru/sentomaru_flutter/SentomaruFlutterPlugin;` (nomes preservados pelas regras R8 do SDK e do plugin, conferidas num build R8 real no CI); sem nenhum → `app-incompatible`. Isso prova que o **SDK ou o plugin está linkado**, não que a tabela está em uso (as regras do SDK mantêm `SentomaruRoutes` em qualquer app com o SDK; o registrador gerado do Flutter sempre referencia o plugin). `SentomaruUrlConnection` só tem o nome preservado (`-keepnames`): num app minificado ela só existe se o app a chama; sem R8 existe em todo app com o SDK. Relatório: `status: checked`, `changes: []`, evidência `transport` (lista separada por vírgula, nesta ordem, dos valores encontrados: `android-sdk`, `android-sdk-urlconnection` (acréscimo da S2, CLI 0.4.0), `flutter-plugin`) e `check: dex-class-defined`, com o aviso `network-signing-install-line` | `runtime-injection` (ausente → `control-prerequisite`) |
| `build-obfuscation` | D-08 (onda 2; seção do perfil fechada na D-08a) | harden / 10 | **Nada**: só lê o artefato e relata se o R8 renomeou o SDK, se nomes do SDK ficaram, se o Dart foi compilado com `--obfuscate` e se o app é `debuggable` (`status: checked`, ver [`build-obfuscation`](#build-obfuscation-d-08)). No código da CLI (`Controls.all`) desde a D-08f; está na release `cli-v0.5.0` (publicada em 30/10/2026) (de D-08d a D-08e, só com `SENTOMARU_LAB=1`) | — |
| `integrity-manifest` | D-12 (onda 2) | harden / 90 | manifesto de integridade embutido (sempre por último no endurecimento) | — |
| `asset-encryption` | D-14 (onda 2; seção do perfil fechada na D-14a) | harden / 20 | arquivos de `assets/` do módulo `base` marcados no perfil (e um arquivo JSON de strings) trocados por arquivos selados com AES-256-GCM em `assets/sentomaru/sealed/`; os originais saem do pacote; o app lê pelo SDK ou pelo plugin, por chamada explícita (ver [`asset-encryption`](#asset-encryption-d-14)). No código da CLI (`Controls.all`) desde a D-14e, depois da prova em aparelho, adversarial e no emulador (D-14d); está na release `cli-v0.5.0` (publicada em 30/10/2026) (da D-14c à D-14d, só com `SENTOMARU_LAB=1`) | o leitor do SDK ou do plugin linkado (ausente → `app-incompatible`) |
| `dex-obfuscation` | D-21a (onda 2) | harden / 30 | ofuscação de DEX | — |
| `network-pinning` | D-07 (onda 2; seção do perfil fechada na D-07a) | harden / 40 | `network_security_config` com pinos SHA-256 do SPKI, pino de backup e expiração, gerado como recurso XML do módulo `base` e ligado no `<application>`; com o SDK no app, uma meta-data com os hosts fixados (ver [`network-pinning`](#network-pinning-d-07)). No código da CLI (`Controls.all`) desde a D-07f, depois da prova em aparelho e emulador (D-07e/C-03b); está na release `cli-v0.5.0` (publicada em 30/10/2026) (da D-07b à D-07e, só com `SENTOMARU_LAB=1`) | — |
| `ui-shield` | G-10 (HU-05, onda épicos; seção do perfil fechada na G-10a) | harden / 50 | **só o manifesto**: três `meta-data` no provider de inicialização do `runtime-injection` (`UI_SHIELD_MODE`, `UI_SHIELD_ACTIVITIES`, `UI_SHIELD_HIDE_OVERLAY`) e, se o perfil pede e o app não declara, `<uses-permission android:name="android.permission.HIDE_OVERLAY_WINDOWS"/>` antes de `<application>`. O DEX do app não é reescrito; quem protege as telas é o runtime injetado (ver [`ui-shield`](#ui-shield-g-10)). Está em `Controls.all` desde a G-10c (código da CLI 0.6.0; entra na release `cli-v0.6.0`, a publicar), sem depender do gate; `controls --json` o lista por último. Ainda não tem linha no relatório de proteção (BPR/D-16): a corrida registrada com ele aplicado não gera relatório até essa linha existir | `runtime-injection` (ausente → `control-prerequisite`) |

**O que `network-signing` afirma (aceito pelo dono, 17/10/2026):** só que o SDK ou o plugin de assinatura está
linkado no app. A CLI **não afirma** que o app chama a linha de instalação, nem com quais rotas: isso não aparece no
binário. A garantia de que uma chamada protegida sem assinatura não produz efeito é do **servidor** (operação em modo
bloqueante no adaptador do consumidor).

**Mudança de comportamento na G-03c (registrada; a versão do controle segue `"1"`):** `network-signing` mudou de desenho
(antes previa reescrita de DEX). A **execução real** nunca o aplicou (respondia `control-failed`), mas o **`--dry-run`**
o aceitava sem olhar o app e respondia `planned`, saída 0. Desde a G-03c, o `--dry-run` confere o app: sem o SDK ou o
plugin a saída é **5 (`app-incompatible`)**, e com eles o controle sai `checked`. Um pipeline que usava o `--dry-run`
com essa seção num app sem o SDK passa a falhar, que é o objetivo do portão.

**Mudança de comportamento na G-06 (registrada; a versão do controle segue `"1"`):** o `--dry-run` de
`runtime-injection` respondia `planned`, saída 0, para um app que já declara o provider do Sentomaru; só a execução
real o recusava. Desde a G-06, o `--dry-run` recusa com **5 (`app-incompatible`)**, a mesma resposta da execução real
de um AAB. Num APK já protegido, a execução real também passa a sair 5 em vez de 6 (`control-failed`, APK não
suportado), porque a recusa vem antes. Um APK sem proteção continua `planned` no `--dry-run` e, na execução real, é protegido
(G-03b3) quando os controles do perfil editam APK; com `network-pinning` sai 6.

Os controles das ondas 2–4 não existem nesta versão: pedidos, dão `control-not-available`; versão de controle que
esta CLI não tem → `control-version-unsupported`. O `build-obfuscation` (D-08d) saiu do gate na D-08f, o
`network-pinning` (D-07b) na D-07f e o `asset-encryption` (D-14c) na D-14e: os três estão no código da CLI
(`Controls.all`) e estão na release `cli-v0.5.0` (publicada em 30/10/2026); o `ui-shield` (G-10a) saiu do gate na G-10c e está no código da CLI 0.6.0 (release `cli-v0.6.0` a publicar); nenhum controle fica só atrás do gate (`Controls.laboratory` vazio).

### `network-pinning` (D-07)

Contrato da seção v1 fechado na D-07a (26/10/2026). Desenho:
an internal design note; decisão de arquitetura em
[ADR 0002](../../docs/devsecops/adr-0002-network-pinning.md). Exemplo validado pelos testes:
[`examples/protect-profile-network-pinning-v1.example.json`](examples/protect-profile-network-pinning-v1.example.json)
(a data do exemplo é ilustrativa e vence; os testes da CLI que dependem dela usam relógio fixo).

**Estado da implementação (D-07f, 27/10/2026):** o controle está no código da CLI (`Controls.all`); entra na release
`cli-v0.5.0`, **publicada em 30/10/2026** ([distribuição](cli-distribution-v1.md)). Nesse código ele roda no `--dry-run` (com ou
sem `SENTOMARU_LAB`), na execução real (sem o gate: desde a D-16-lab-gate a execução real registrada recusa
`SENTOMARU_LAB=1` com saída 2, `usage`) e na execução de laboratório, e `controls --json` o lista. O código do controle
não lê o gate: no `--dry-run` a saída e o relatório são os mesmos com ou sem ele. Da D-07b à D-07e
ele ficou só atrás do gate de laboratório (`SENTOMARU_LAB=1`), até a prova em aparelho e emulador (D-07e/C-03b; os relatórios de
aparelho e de emulador ficam com a operação do Sentomaru). A release `cli-v0.4.0`, a anterior, ainda válida: com
ela o perfil com a seção sai 4 (`control-not-available`). Não há recusa por nome de ambiente: o `environment` do perfil
é do app do cliente. Sem a seção, o artefato é o de antes; no relatório só muda `cli.build` (`0.5.0` desde a D-08f).
O guia do cliente (onde pode fixar, rotação, Flutter, limites, chave vazada) é entregue pela operação do Sentomaru.

**Mudança de comportamento na D-07f, ainda CLI 0.5.0 (registrada; a versão do controle segue `"1"`):** a 0.5.0 ainda não tinha sido
publicada, então a liberação entra na mesma versão (a linha 0.5.0 da tabela de controles do
[contrato da distribuição](cli-distribution-v1.md) foi completada antes da publicação). Em relação à `cli-v0.4.0`:

- `controls --json` muda **mesmo sem perfil**: lista `runtime-injection`, `network-signing`, `build-obfuscation` e
  `network-pinning` (a 0.4.0 lista só os dois primeiros; o código da 0.5.0 antes da D-07f, os três primeiros).
- Um perfil com a seção `network-pinning` respondia `control-not-available` (saída 4) sem `SENTOMARU_LAB=1`; agora é
  validado (saída 4 `profile-format` pelas regras abaixo), conferido contra o app (saída 5) e, válido, aplicado num AAB
  (`applied`) ou planejado no `--dry-run` (`planned`, saída 0). Com `"version"` diferente de `"1"` a resposta passa de
  `control-not-available` para `control-version-unsupported` (as duas são saída 4).
- Sem a seção `network-pinning`, o artefato gerado é o de antes, byte a byte (regressão da D-07b); no relatório só muda
  `cli.build`.

```json
"network-pinning": {
  "version": "1",
  "expiration": "2027-03-31",
  "domains": [
    { "host": "lab-pin.sentomaru.com.br", "includeSubdomains": false,
      "pins":       ["sha256/<base64 de 32 bytes>"],
      "backupPins": ["sha256/<base64 de 32 bytes>"] }
  ]
}
```

**Campos** (seção fechada: campo desconhecido ou ausente, aqui ou num domínio, é `profile-format`):

- **`expiration`** (obrigatória): data `AAAA-MM-DD` que existe no calendário. Vira o atributo `expiration` do
  `<pin-set>`; depois dela o app volta à confiança do sistema (falha aberta por desenho). Regra da CLI, em dias de
  calendário contados sobre a data UTC da execução (`hoje`): aceita `hoje ≤ expiration ≤ hoje + 180` (a data de hoje e
  o 180º dia são aceitos; `hoje − 1` e `hoje + 181` são recusados) e avisa quando `expiration − hoje < 30` (de `hoje`
  a `hoje + 29`). **Conferido no AOSP na D-07b** (`XmlConfigSource.parsePinSet` e
  `NetworkSecurityTrustManager.checkPins`, `frameworks/base`, ramo `main`, lidos em 26/10/2026): a data é lida com
  `SimpleDateFormat("yyyy-MM-dd")`, não leniente, no **fuso padrão do aparelho**, e os pinos deixam de ser conferidos quando
  `System.currentTimeMillis() > expiração`; ou seja, o `<pin-set>` deixa de valer às **00:00 locais do dia da expiração**
  (o próprio dia já não é fixado). Uma `expiration` igual a `hoje`, aceita pela regra da CLI, gera um pin-set que já não
  vale no aparelho (com o aviso `network-pinning-expiration-near`). Essa conferência não muda a regra da CLI.
- **`domains`**: de 1 a 16 domínios, sem host repetido.
- **`host`**: nome DNS exato, em minúsculas, com pelo menos dois rótulos, até 253 caracteres; sem curinga, porta, ponto
  final, esquema, caminho nem IP (o último rótulo começa por letra).
- **`includeSubdomains`**: booleano, obrigatório e explícito.
- **`pins`**: chaves **aceitas hoje** (a servida e, numa rotação, a próxima a ser servida). **`backupPins`**: chaves
  aceitas e **ainda não servidas** em nenhum certificado, guardadas fora do servidor até a ativação. Cada lista tem pelo
  menos 1 pino, sem repetição; um pino não pode estar nas duas listas; o domínio tem no máximo 16 pinos no total. A
  CLI **não consegue** saber se um backup está mesmo fora de uso (regra do runbook de rotação, D-07c).
- **Pino**: `sha256/` + base64 padrão (com `+` e `/`, não o de URL) do SHA-256 do `SubjectPublicKeyInfo` em DER, 51
  caracteres (`^sha256/[A-Za-z0-9+/]{43}=$`, que só cabe em 32 bytes), o mesmo formato do `pinning` do perfil do Shield.
  A CLI decodifica de forma estrita: o último caractere tem de deixar zerados os 2 bits que sobram (base64 canônico),
  senão `profile-format`.
  No XML gerado o prefixo sai (`<pin digest="SHA-256">` só com o base64). A v1 é de chaves de **folha** com chave
  controlada pelo dono do host (no Flutter só a folha é vista).
- **Pré-requisitos:** nenhum; não depende de `runtime-injection`. Os hosts **não** precisam estar em
  `network-signing.hosts`.

O esquema confere a estrutura. São só da CLI: a expiração passada ou acima do teto (o esquema não tem relógio), o pino
nas duas listas, o total acima de 16 e o host repetido (o esquema não compara listas) e o pino em base64 não canônico.
O padrão de `expiration` limita mês e dia sozinho; o dia que o mês não tem (`2027-02-30`) só é recusado pelo esquema num
validador que afirma `format: date` (como o do portão de política) e, sempre, pela CLI.

**Códigos e avisos, a partir da D-07b** (nenhum código de erro novo; `detail` sem dados do app; da D-07b à D-07e, sem
`SENTOMARU_LAB=1`, o controle inteiro respondia `control-not-available`; desde a D-07f vale com ou sem a variável):

| Condição | Saída | `code` | `detail` / aviso |
|---|---|---|---|
| campo desconhecido ou ausente na seção | 4 | `profile-format` | `network-pinning.<campo>` |
| `expiration` mal formada, já passada ou a mais de 180 dias | 4 | `profile-format` | `network-pinning.expiration` |
| `domains` vazia, com mais de 16 itens ou host repetido | 4 | `profile-format` | `network-pinning.domains` |
| campo desconhecido ou ausente num domínio | 4 | `profile-format` | `network-pinning.domains.<campo>` |
| host inválido | 4 | `profile-format` | `network-pinning.domains.host` |
| `includeSubdomains` ausente ou não booleano | 4 | `profile-format` | `network-pinning.domains.includeSubdomains` |
| pino mal formado ou repetido em `pins`; `pins` vazia; mais de 16 pinos no domínio | 4 | `profile-format` | `network-pinning.domains.pins` |
| pino mal formado ou repetido em `backupPins`; domínio sem backup; pino também em `pins` | 4 | `profile-format` | `network-pinning.domains.backupPins` |
| `version` que esta CLI não tem | 4 | `control-version-unsupported` | `network-pinning <versão>` |
| o app já declara `android:networkSecurityConfig` (sem mescla na v1) ou a meta-data `br.com.ebees.sentomaru.pinning.hosts` (inclui o AAB já protegido por este controle) | 5 | `app-incompatible` | `network-security-config-present` |
| `resources.pb` ausente, sem pacote ou com mais de um, pacote com id diferente de `0x7f` ou tabela sem id livre; mais de um tipo `xml`; tipo ou entrada sem id; `resources.pb` acima de 32 MiB (ou sem memória para lê-lo); o app já tem o recurso `xml/sentomaru_network_security_config` (ou o `_debug`, que a plataforma leria como `debug-overrides`) ou a entrada `base/res/xml/sentomaru_network_security_config.xml` | 5 | `app-incompatible` | `resource-table-unsupported` |
| `resources.pb` que não é um `ResourceTable` legível | 3 | `input-format` | `unreadable resource table` |
| `android:usesCleartextTraffic` é uma referência a recurso (não um literal que possa ser copiado para o `base-config`) | 5 | `app-incompatible` | `cleartext-attribute-unsupported` |
| APK de entrada com `network-pinning` (execução real) | 6 | `control-failed` | o controle só edita AAB; `runtime-injection` e `ui-shield` editam APK desde a G-03b3 (código em `main`, sem release) |
| expiração a menos de 30 dias | 0 | — | aviso `network-pinning-expiration-near` |
| host fixado fora de `network-signing.hosts` (ou sem essa seção) | 0 | — | aviso `network-pinning-host-unsigned` |
| app Flutter (a classe do plugin no DEX do `base`) | 0 | — | aviso `network-pinning-dart-line` |
| o app permite cleartext e os hosts fixados passam a recusar http | 0 | — | aviso `network-pinning-cleartext-blocked` |

A precedência é a do contrato: a validação do perfil (saída 4) vem antes da compatibilidade com o app (saída 5), e o
`--dry-run` dá as mesmas saídas 2 a 7 da execução real.

**O que muda no binário, a partir da D-07b** (AAB, módulo `base`; os módulos dinâmicos não mudam): um recurso
`res/xml/sentomaru_network_security_config.xml` em XML proto do aapt2, com um `<domain-config
cleartextTrafficPermitted="false">` por domínio (`<domain includeSubdomains>`, `<pin-set expiration>` com `pins` e
`backupPins`, `<trust-anchors><certificates src="system"/>`), sem `<debug-overrides>`, `overridePins` nem
`src="user"`, e um `<base-config cleartextTrafficPermitted>` só quando o app declara `android:usesCleartextTraffic`
(o valor é copiado, porque com a configuração presente a plataforma ignora o atributo); a entrada do recurso na
tabela (`resources.pb`), com ids novos sem renumerar os existentes; o atributo `android:networkSecurityConfig` no
`<application>`; e, só quando o DEX do `base` define uma classe do transporte do SDK Android (`SentomaruRoutes` ou
`SentomaruUrlConnection`, as mesmas da `network-signing`), a meta-data `br.com.ebees.sentomaru.pinning.hosts` com os
hosts (só os nomes, na ordem do perfil, separados por vírgula, sem espaço), para o evento local de falha de pino do SDK
(D-07d). Detalhes da geração (D-07b): o tipo `xml` é reaproveitado se existe, senão é criado com o primeiro `type_id`
livre (1 a 255); a entrada recebe o primeiro `entry_id` livre do tipo, com uma configuração padrão e
`FileReference{path, PROTO_XML}`; o atributo entra antes do primeiro atributo `android:` de resource id maior, com a
referência como o aapt2 a liga (`@xml/…`, `type_flags` 1); o XML gerado é o que o `aapt2 compile` dá para o mesmo texto
sem espaços (teste de ouro); a entrada nova vem logo depois de `base/resources.pb` no ZIP, com hora fixa. Alvos das
`changes`: `base/res/xml/sentomaru_network_security_config.xml`, `xml/sentomaru_network_security_config`,
`@xml/sentomaru_network_security_config` e o nome da meta-data. Risco registrado: o "primeiro id livre" pode reaproveitar
um id que o encolhimento de recursos tirou da tabela mas que ainda aparece no DEX (constante `R` inlinada) ou num
`public.xml`; esse código passaria a ler o recurso novo. A spec fixa essa regra; a prova em aparelho (D-07e) e uma
regra `max + 1` ficam como alternativa se aparecer o caso. Ids de `changes` (vocabulário fechado): `res.xml.added`,
`resources.entry.added`, `manifest.network-security-config.set` e `manifest.meta-data.added`. Relatório: `status:
applied` (`planned` no `--dry-run`) e evidência `{ "domains": "<n>", "expiration": "<AAAA-MM-DD>", "sectionSha256":
"<hex>", "cleartextBase": "absent|true|false" }`, com `sectionSha256` o SHA-256 da seção em JSON canônico (RFC 8785,
JCS), também no `--dry-run`. Aviso `network-pinning-cleartext-blocked` quando `usesCleartextTraffic="true"` ou, sem o
atributo, com `targetSdk` (ou, sem ele, o `minSdk`, como no Android) abaixo de 28. Sem a seção no perfil, o artefato e
o relatório são os de hoje, byte a byte: o artefato é comparado por teste com uma cópia do gravador anterior ao refator
(`PreviousInjector`, em cinco AABs de fixture), e o relatório foi conferido à mão na D-07b (sem `runId` e `startedAt`).

**Limites:**

- Vale para o que usa o `TrustManager` padrão da plataforma (OkHttp com ou sem a linha do Sentomaru,
  `HttpURLConnection`, Retrofit, o lado Java/Kotlin de um app Flutter). Não vale para WebView, Cronet com pilha própria,
  código com `TrustManager` próprio nem para o Dart: no Flutter, o `HttpClient` do `dart:io` não lê o
  `network_security_config`, e a parte Dart depende de uma linha no app (C-03a), que não aparece no binário.
- Não resiste a quem controla o processo (Frida, hooks no `TrustManager`, reempacotar sem o recurso) e não protege um
  build depois que uma chave fixada vaza, até a expiração dele. Atrasar o relógio do aparelho mantém o pin-set;
  adiantá-lo o desliga.
- Sem kill switch remoto e sem modo "só reportar": os freios são o pino de backup, a expiração e a atualização do app.
- Fixar um host atrás de uma CDN que gere a chave (Cloudflare com Universal SSL, CloudFront/ACM) quebra o app quando a
  chave muda; a CLI não vê a borda.
- O `pinning` do perfil do Shield (D-01, the Shield registry contract) continua declarativo: a geração vem do
  perfil `protect`.

**Mudança de comportamento na D-07a (registrada):** antes, `network-pinning` era uma seção de controle desconhecido
para o esquema (bastava `version`); agora é fechada. Um perfil com `"network-pinning": {"version": "1"}` passava no
portão de política e passa a falhar com `profile-invalid`. A CLI responde `control-not-available` nos dois casos.
Não é v2 do contrato porque nada do que mudou teve sentido: o controle nunca existiu na CLI, que sempre respondeu
`control-not-available` a essa seção, e nenhum perfil do repositório (exemplos, fixtures, guias) a trazia antes da
D-07a (conferido por busca em 26/10/2026). É o acréscimo de um controle novo, com a seção fechada desde a primeira
versão, como pede a regra de compatibilidade.

### `build-obfuscation` (D-08)

Contrato da seção v1 fechado na D-08a (26/10/2026). Desenho:
an internal design note (itens 1 e 2, decisões D-08x1 a D-08x7). O guia de
build do cliente é entregue pela operação do Sentomaru. Exemplo validado pelos testes:
[`examples/protect-profile-build-obfuscation-v1.example.json`](examples/protect-profile-build-obfuscation-v1.example.json).

**O controle não ofusca** (D-08x1). R8 e `--obfuscate` são passos do compilador, no build do cliente; depois do build
não há mais o que eles precisam. A CLI só **lê** o artefato e relata o que encontrou, para o relatório (D-16). Ofuscar
DEX depois do build é a D-21a (`dex-obfuscation`), fora deste controle.

**Estado da implementação (D-08f, 27/10/2026):** o controle está no código da CLI (`Controls.all`); entra na release
`cli-v0.5.0`, **publicada em 30/10/2026** ([distribuição](cli-distribution-v1.md)). Nesse código ele roda no `--dry-run`, com ou sem
`SENTOMARU_LAB`, e na execução real (sem o gate, que ela recusa desde a D-16-lab-gate), e `controls --json` o lista. Da D-08d à D-08e ele ficou só atrás do gate de laboratório
(`SENTOMARU_LAB=1`), até a medição (D-08e). A release
`cli-v0.4.0`, a anterior, ainda válida: com ela o perfil com a seção sai 4 (`control-not-available`).

**Mudança de comportamento na D-08f, CLI 0.5.0 (registrada; a versão do controle segue `"1"`):**

- `cli.build` passa de `0.4.0` para `0.5.0` (`--version --json`, relatório e abertura da corrida no registro).
- `controls --json` muda **mesmo sem perfil**: lista `runtime-injection`, `network-signing` e `build-obfuscation`
  (antes, só os dois primeiros). Quem compara essa saída com um valor gravado vê a diferença.
- Um perfil com `"build-obfuscation": {"version": "1"}` respondia `control-not-available` (saída 4) sem
  `SENTOMARU_LAB=1`; agora é validado e conferido (`checked`, saída 0 no `--dry-run`, com os avisos da tabela abaixo).
  Com `"version"` diferente de `"1"` a resposta passa de `control-not-available` para `control-version-unsupported` (as
  duas são saída 4).
- Sem a seção `build-obfuscation`, o artefato gerado é o de antes; no relatório só muda `cli.build` (a comparação, D-08d, está
  registrada pela operação).

```json
"build-obfuscation": { "version": "1" }
```

**Campos:** só `version`. A seção é fechada e não tem opção: qualquer campo é uma versão nova do controle. O controle
**não falha** por falta de ofuscação (D-08x5): só relata e avisa.

**Evidência, a partir da D-08d** (`status: checked`, `changes: []`, também no `--dry-run`; os valores são texto, como
nos outros controles):

| Evidência | Como | Valores |
|---|---|---|
| `sdkProbeRenamed` | com o SDK no app, a classe de sonda `Lbr/com/ebees/sentomaru/sdk/AndroidInstallationStore;` **não** está definida com esse nome no DEX do `base` (o critério de the vendor's check r8 names check) | `true`, `false`, `unknown` (app sem o SDK, ou algum DEX do `base` pulado: acima do limite ou malformado) |
| `sdkNamesKept` | todas as classes de um conjunto fixo estão definidas com o nome de origem: `SentomaruRoutes` (mantida pelas regras do SDK) e, quando a seção `asset-encryption` está no perfil, o marcador do leitor (`SentomaruSealed` ou `SentomaruFlutterSealed`, ver [`asset-encryption`](#asset-encryption-d-14)). `SentomaruUrlConnection` não entra: some num app minificado que não a chama | `true`, `false`, `unknown` (app sem o SDK, ou algum DEX do `base` pulado) |
| `dartObfuscated` | app Flutter (`base/lib/<abi>/libapp.so` no AAB, `lib/<abi>/libapp.so` no APK): leitura dos bytes de cada `libapp.so`. Todo arquivo precisa ser um snapshot Dart legível: ELF little-endian inteiro (a tabela de seções termina dentro do arquivo) com o símbolo `_kDartIsolateSnapshotData`, que existe com e sem `--obfuscate`; senão `unknown`. `false` quando **todo** `libapp.so` tem a lista fixa de identificadores Dart do plugin (`SentomaruClient`, `SentomaruConfig`, `SignalObservation`) ou **todo** tem o marcador do framework `WidgetsFlutterBinding` (todo app Flutter o alcança pelo `runApp`; o `--obfuscate` o renomeia). `true` só quando **nenhum** tem nenhum desses nomes **e** o DEX define a classe do plugin. Lista, símbolo e marcador validados com builds reais com e sem a opção (D-08b, D-08d) e iguais aos de the vendor's check dart obfuscation check | `true`, `false`, `unknown` (sem `libapp.so`: não é Flutter, ou é build de debug; arquivo que não é snapshot legível: vazio, truncado, não ELF, sem o símbolo; ou a heurística não decide: lista parcial sem o marcador, ABIs que discordam, app sem o plugin, mais de 16 `libapp.so`, um acima de 512 MiB ou mais de 1 GiB lidos no total, entrada que não descompacta) |
| `debuggable` | `android:debuggable` do `<application>` no manifesto do `base`: ausente ou `false` literal (booleano, ou inteiro 0) é `false`; `true` literal, inteiro diferente de 0, ou um valor que não é literal (referência a recurso), conta como `true` (só aviso); com o atributo repetido ou dois `<application>`, `true` se qualquer ocorrência for | `true`, `false` |

"App sem o SDK" é o DEX do `base` sem nenhuma classe sob `Lbr/com/ebees/sentomaru/sdk/` nem a classe do plugin. Se a
D-08b mostrar que a heurística do Dart erra em algum exemplo, `dartObfuscated` fica sempre `unknown` na v1 (D-08x5),
sem mudar a versão do controle (o valor já existe).

**Códigos e avisos, a partir da D-08d** (nenhum código de erro novo):

| Condição | Saída | `code` | `detail` / aviso |
|---|---|---|---|
| campo desconhecido na seção | 4 | `profile-format` | `build-obfuscation.<campo>` |
| `version` que esta CLI não tem | 4 | `control-version-unsupported` | `build-obfuscation <versão>` |
| APK de entrada com `network-pinning` (execução real) | 6 | `control-failed` | o controle só edita AAB; `runtime-injection` e `ui-shield` editam APK desde a G-03b3 (código em `main`, sem release) |
| execução real só com `build-obfuscation` (nada a aplicar) | 6 | `control-failed` | `nothing to apply` |
| execução de laboratório (`--lab-unregistered`) com a seção | 6 | `control-failed` | `build-obfuscation: not applicable by this build` (como a `network-signing`) |
| `sdkProbeRenamed` = `false` | 0 | — | aviso `build-obfuscation-sdk-not-renamed` |
| `dartObfuscated` = `false` | 0 | — | aviso `build-obfuscation-dart-not-obfuscated` |
| `debuggable` = `true` | 0 | — | aviso `build-obfuscation-debuggable` |

**Pré-requisitos:** nenhum. **Limites (escritos no relatório e na ficha):**

- `sdkProbeRenamed` mede se o R8 renomeou o **SDK**, não se o **app** foi ofuscado: uma regra `-keep` larga do cliente
  sobre `br.com.ebees.sentomaru.**` dá `false` com o app ofuscado, e um app que ofusca o SDK pode manter o próprio
  código com o nome de origem.
- `dartObfuscated` é uma heurística sobre nomes do plugin e do framework, não uma prova sobre o código Dart do app; um
  app Flutter que não chama `runApp` (sem o marcador mesmo sem `--obfuscate`) e não alcança os tipos do plugin daria
  `true` errado.
- Nada disso mede resistência a engenharia reversa (D-08x7): R8 renomeia identificadores e remove código morto; não
  cifra strings, não esconde fluxo de controle e não protege o nativo; `--obfuscate` renomeia identificadores Dart, e
  literais, rotas e nomes de canal de plataforma continuam legíveis.
- O mapeamento do cliente fica no ambiente dele: a CLI não lê, não pede e não guarda `mapping.txt` nem símbolos Dart
  (D-08x3).

**Mudança de comportamento na D-08a (registrada):** antes, `build-obfuscation` era uma seção de controle desconhecido
para o esquema (bastava `version`, e campos a mais passavam); agora a seção é fechada e só aceita `version`. O perfil
`{"version": "1"}` continua aceito; um perfil com outro campo passa a falhar no portão de política com
`profile-invalid`. A CLI responde `control-not-available` nos dois casos. Não é v2 do contrato pelo mesmo motivo da
D-07a: o controle nunca existiu na CLI e nenhum perfil do repositório trazia a seção (conferido por busca em
26/10/2026).

### `asset-encryption` (D-14)

Contrato da seção v1 e do formato selado v1 fechados na D-14a (26/10/2026). Desenho:
an internal design note (itens 7 a 13, decisões D-14x1 a D-14x10);
decisão de arquitetura em [ADR 0003](../../docs/devsecops/adr-0003-asset-encryption.md). Exemplo validado pelos testes:
[`examples/protect-profile-asset-encryption-v1.example.json`](examples/protect-profile-asset-encryption-v1.example.json)
(junta um caminho de app nativo e um de app Flutter só para mostrar as duas formas, como a spec; um app real tem uma).
Vetores compartilhados pela CLI, pelo SDK e pelo plugin: [`sealed-v1-vectors.json`](sealed-v1-vectors.json), gerados por
the vendor's gen sealed vectors check e conferidos por the vendor's reference reader (com um
leitor de referência independente).

**É ofuscação de dados, não sigilo** (D-14x1). A chave de cada arquivo é derivada, no aparelho e sem rede, de valores que
estão no pacote e de uma constante pública do formato. Quem tem o APK e conhece o esquema (que é público) recupera os
arquivos. O controle só tira os arquivos marcados do pacote em claro.

**Estado da implementação (D-14b e D-14c, 27/10/2026):** o leitor (D-14b): o módulo `sdk/android/sealed` e o plugin
Flutter 0.17.0 (não publicado) leem o formato selado v1, conferidos contra todos os casos de `sealed-v1-vectors.json` e
os da RFC 5869 em teste de JVM; os marcadores sobrevivem a um build R8 real (the vendor's check r8 names check).
O controle na CLI (D-14c, liberado na D-14e, 30/10/2026): está no código da CLI (`Controls.all`); entra na release
`cli-v0.5.0`, **publicada em 30/10/2026** ([distribuição](cli-distribution-v1.md)). Nesse código ele roda no `--dry-run` (com ou sem
`SENTOMARU_LAB`), na execução real (sem o gate: desde a D-16-lab-gate a execução real registrada recusa
`SENTOMARU_LAB=1` com saída 2, `usage`, `lab-gate-registered`) e na execução de laboratório (`--lab-unregistered`), e
`controls --json` o lista. Da D-14c à D-14d ele ficou só atrás do gate de laboratório (`SENTOMARU_LAB=1`, não
contratual), até a prova em aparelho (aparelho de referência), o teste adversarial, o revisor independente e a parte do emulador da
D-14d (relatório de aparelho e emulador com `status`
`device-and-emulator-done`, guardado pela operação) e a revisão R. A release `cli-v0.4.0`, a anterior, ainda válida: com ela o perfil com a
seção sai 4 (`control-not-available`). Diferente da `network-pinning`, o código do controle **lê** o gate, só para o
limite por arquivo (abaixo, "Limites"): 1 MiB sem ele, o teto do formato (4 MiB) com ele; como a execução real
registrada recusa o gate, uma corrida registrada sempre tem o limite de 1 MiB. Sem a seção, o artefato é o de antes,
byte a byte; no relatório só muda `cli.build` (`0.5.0` desde a D-08f). Num APK, o `--dry-run` confere e planeja com os
caminhos na raiz do APK (sem `base/`, sem `assets.pb`); a execução real de um APK com a seção responde `control-failed`
(saída 6, a regra do APK para um controle que só edita AAB, o `network-pinning`), **depois** da compatibilidade (um APK que o controle recusa sai 5, por exemplo
sem o leitor); com o gate, a execução real sai antes, 2 (`usage`, `lab-gate-registered`).

**Mudança de comportamento na D-14e, ainda CLI 0.5.0 (registrada; a versão do controle segue `"1"`):** a 0.5.0 ainda não tinha sido
publicada, então a liberação entra na mesma versão (a linha 0.5.0 da tabela de controles do
[contrato da distribuição](cli-distribution-v1.md) foi completada antes da publicação). Em relação ao código da 0.5.0
antes dela:

- `controls --json` muda **mesmo sem perfil**: lista `runtime-injection`, `network-signing`, `build-obfuscation`,
  `asset-encryption` e `network-pinning`, na ordem das etapas (a `cli-v0.4.0` lista só os dois primeiros).
- Um perfil com a seção `asset-encryption` respondia `control-not-available` (saída 4) sem `SENTOMARU_LAB=1`, sem ler a
  seção; agora é validado (saída 4 `profile-format`; `"version"` diferente de `"1"` passa a
  `control-version-unsupported`), conferido contra o app (saída 5) e, válido, aplicado num AAB (`applied`) ou planejado
  no `--dry-run` (`planned`, saída 0).
- Sem a seção `asset-encryption`, o artefato gerado é o de antes, byte a byte; no relatório só muda `cli.build`.
- O relatório de proteção (the Sentomaru protection report contract) tem a linha do controle desde a D-16f (catálogo
  2, decisão do fornecedor em 30/10/2026): numa corrida registrada da 0.5.0, o gerador confere a marca v1 e os tamanhos das
  entradas seladas no AAB de saída (e os arquivos marcados no de entrada, quando publicado), não o conteúdo, e
  acrescenta a `notVerified` as linhas `asset-key-in-app` ("ela não protege segredo: a chave vai no próprio app") e
  `sealed-content` (o conteúdo cifrado não é conferido).

Os testes da CLI (`AssetEncryptionTest`) cifram com a fonte de aleatoriedade de teste e comparam com os vetores, e leem a
saída (o AAB e os APKs que o `bundletool build-apks` gera dele) com o próprio leitor do `sdk/android/sealed`.

```json
"asset-encryption": {
  "version": "1",
  "assets": ["assets/regras/tabela.json", "assets/flutter_assets/assets/dados/catalogo.bin"],
  "strings": "assets/sentomaru-strings.json"
}
```

**Campos** (seção fechada: campo desconhecido ou ausente é `profile-format`):

- **`assets`** (obrigatória): de 1 a 64 caminhos, sem repetição. Cada um é um **caminho canônico**: o nome de um arquivo
  do módulo `base` como o `bundletool` o mostra, sem o prefixo `base/`. Forma (esquema): começa por `assets/`; segmentos
  só de `A-Z`, `a-z`, `0-9`, `.`, `_`, `-`, `@`, `+` e `~`, nenhum vazio, nenhum igual a `.` ou `..`; de 8 a 512
  caracteres; fora de `assets/sentomaru/` (o diretório do formato). Isso exclui curinga, barra dupla ou final, espaço,
  `%`, parênteses, letra acentuada, controle e `#` (os diretórios com targeting do AAB, `#tcf_…`/`#lang_…`, mudam de nome
  nos APKs gerados). O alfabeto fechado e o teto de 512 são decisão da D-14a (a spec só pede "bem formado"): mantêm o
  caminho igual em ZIP, AAD e nome do `.bin` sem regra de normalização Unicode. Alargar depois é aditivo; estreitar não
  seria. A CLI confere a forma inteira do texto (casamento total, sem o `$` que aceita uma quebra de linha final). No Flutter, o caminho é `assets/flutter_assets/` + a chave do `pubspec.yaml`
  (`assets/dados/catalogo.bin` vira `assets/flutter_assets/assets/dados/catalogo.bin`); o app chama o plugin com a
  chave do `pubspec.yaml`.
- **`strings`** (opcional; `null` ou ausente → sem strings): caminho canônico, na mesma forma, de um asset JSON que é um
  objeto plano `{"chave": "valor"}` em UTF-8, com chaves `^[a-z0-9_.]{1,64}$`, valores texto e até 1024 entradas. É
  selado como os outros, conta nos limites de quantidade e tamanho e não pode repetir um caminho de `assets`. O app lê
  por `string("chave")`. É a forma de "strings marcadas no perfil" sem reescrever código: o cliente tira a string do
  código e a põe nesse arquivo.
- **Limites** (D-14x5, com a emenda da D-14e): 64 arquivos contando o de `strings`; até **1 MiB por arquivo**
  (1 048 576 bytes) e 32 MiB na soma (33 554 432 bytes), medidos sobre o arquivo em claro. Arquivo maior é recusado na
  hora do build (fase de compatibilidade, também no `--dry-run`), com `asset-too-large`; não há leitor em fluxo. Motivo
  (decisão do fornecedor, conservadora, D-14e): o leitor guarda o arquivo inteiro na memória e o pico medido na D-14d ficou
  acima de 3× o tamanho em claro (no emulador, a medida precisa da leitura de 4 MiB deu de 3,0× a 4,0×; para 1 MiB é
  extrapolação, não medida; campo `cost.livePeakPreciseNote` do relatório de aparelho). O teto do **formato** continua 4 MiB (os leitores recusam tamanho declarado acima
  disso; `readerLimits` nos vetores); só com o gate de laboratório (`SENTOMARU_LAB=1`, não contratual) a CLI aceita até
  esse teto, para a prova da D-14d selar o canário de 4 MiB; o gate vale no `--dry-run` e na execução de laboratório,
  nunca numa corrida registrada (D-16-lab-gate).
- **Pré-requisito no app:** o DEX do `base` define o marcador do leitor: no Android
  `Lbr/com/ebees/sentomaru/sdk/sealed/SentomaruSealed;`, no Flutter `Lbr/com/ebees/sentomaru/sentomaru_flutter/SentomaruFlutterSealed;`
  (a `SentomaruFlutterPlugin` existe em versões do plugin sem leitor e não serve). Como na `network-signing`, isso
  prova só que o leitor está **linkado**, não que o app o chama. Sem pré-requisito de `runtime-injection`.

O esquema confere a forma. São só da CLI: `strings` repetindo um caminho de `assets`, mais de 64 arquivos contando
`strings` (o esquema não compara campos) e tudo o que precisa do AAB (existência, tamanho, targeting, arquivos do motor,
JSON de strings).

**Códigos e avisos, a partir da D-14c** (nenhum código de erro novo; `detail` sem dados do app; da D-14c à D-14d, sem o
gate, o controle inteiro respondia `control-not-available`; desde a D-14e vale com ou sem o gate). O primeiro da ordem define a saída; os outros vão em `errors[]` quando
detectáveis sem efeito, como no resto do contrato:

| Fase | Condição | Saída | `code` | `detail` / aviso |
|---|---|---|---|---|
| validação do perfil (sem artefato) | campo ausente; caminho fora da forma (inclui `#`, curinga, `..`, `assets/sentomaru/`) ou repetido; mais de 64 arquivos contando `strings`; `strings` fora da forma ou repetindo um caminho de `assets` | 4 | `profile-format` | `asset-encryption.<campo>` (`assets` ou `strings`) |
| validação do perfil | campo desconhecido (o primeiro em ordem de nome) | 4 | `profile-format` | `asset-encryption.<nome>` quando o nome é curto e simples (`^[A-Za-z0-9_-]{1,64}$`); senão `asset-encryption.unknown-field` (o `detail` vai para o relatório e não carrega texto livre do perfil) |
| validação do perfil | `version` que esta CLI não tem | 4 | `control-version-unsupported` | `asset-encryption <versão>` |
| compatibilidade (lê o AAB), nesta ordem | `versionCode` ausente no manifesto do `base`, ou `versionCodeMajor` presente (o leitor usa `PackageInfo.longVersionCode`, que só é igual ao `versionCode` sem ele) | 5 | `app-incompatible` | `version-code-missing` |
| | algum nome sob `base/assets/sentomaru/` já existe (protegido duas vezes) | 5 | `app-incompatible` | `sealed-present` |
| | nenhum dos dois marcadores do leitor definido no DEX do `base` | 5 | `app-incompatible` | `sealed-reader-missing` |
| | `base/assets.pb` acima de 8 MiB ou que não é um `Assets` do `bundletool` legível (lido neste passo; o `--dry-run` também) | 3 | `input-format` | `assets.pb above 8 MiB` ou `unreadable assets.pb` |
| | algum diretório do caminho (de `assets/` até o pai do arquivo) tem variante com targeting: um diretório citado em `base/assets.pb` com targeting não vazio (o `bundletool` cita ali todo diretório de `assets/` com arquivos, quase sempre com targeting vazio, que não conta) ou uma entrada `base/assets/…` cujo segmento, sem o sufixo `#…`, é esse diretório (`assets/textures#tcf_astc/` para `assets/textures/`). Vem antes de `asset-missing`, porque o arquivo pode existir só na variante | 5 | `app-incompatible` | `asset-targeted` |
| | caminho ausente no `base` | 5 | `app-incompatible` | `asset-missing` |
| | arquivo lido pelo motor do Flutter ou pela plataforma sem passar pelo leitor: qualquer arquivo **direto** em `assets/flutter_assets/` (sem subdiretório: `AssetManifest*`, `FontManifest.json`, `NativeAssetsManifest.json`, `NOTICES*`, `kernel_blob.bin`, snapshots e o que vier em versões novas do Flutter); qualquer arquivo sob `assets/flutter_assets/shaders/`, `assets/flutter_assets/fonts/` ou `assets/flutter_assets/packages/`; qualquer arquivo citado no `FontManifest.json` do `base` (com um `FontManifest.json` acima de 8 MiB ou que não se lê como JSON estrito, a CLI não sabe quais são: **todo** caminho sob `assets/flutter_assets/` é recusado assim); qualquer arquivo terminado em `.ttf`, `.otf` ou `.ttc` (sem diferenciar maiúsculas); qualquer arquivo sob `assets/dexopt/` (perfis de base lidos pelo `ProfileInstaller`) | 5 | `app-incompatible` | `asset-engine-managed` |
| | algum arquivo acima de 1 MiB em claro (1 048 576 bytes; com o gate de laboratório, acima do teto do formato, 4 MiB), pelo tamanho declarado no ZIP e de novo pelos bytes descomprimidos | 5 | `app-incompatible` | `asset-too-large` |
| | cada arquivo dentro do limite, mas a soma acima de 32 MiB (D-14e: antes vinha com `asset-too-large`) | 5 | `app-incompatible` | `assets-total-too-large` |
| | JSON de strings que não é UTF-8, não é objeto plano de textos, tem chave fora do padrão ou repetida, ou mais de 1024 entradas | 5 | `app-incompatible` | `strings-invalid` |
| aviso | sempre que aplicado | 0 | — | `asset-encryption-read-line` (Android e Flutter: o app precisa ler pelo SDK ou pelo plugin) |
| controles (só a execução real) | APK de entrada com controle só de AAB | 6 | `control-failed` | a regra para um controle que só edita AAB (`network-pinning`); vem **depois** da compatibilidade, como nos outros controles (um APK que o controle recusa dá 5 também na execução real) |

A lista de `asset-engine-managed` é uma recusa larga de propósito (conferida no APK de release do exemplo do plugin,
Flutter 3.41.9, que traz `NativeAssetsManifest.json` na raiz): os assets do app ficam em subdiretórios de
`assets/flutter_assets/` (a chave do `pubspec.yaml`), e o que fica na raiz é do motor. `assets/flutter_assets/packages/`
guarda fontes e assets de pacotes (incluindo os ícones do Material) que o motor e os pacotes leem sem passar pelo
plugin. O `--dry-run` dá as mesmas saídas 2 a 7.

#### Formato selado v1

Notação: `HKDF` = HKDF-SHA256 (RFC 5869, saída de 32 bytes, sal vazio = 32 bytes zero); `AEAD` = AES-256-GCM, nonce
de 96 bits, tag de 128 bits **no fim** do texto cifrado (a convenção do `javax.crypto`); `‖` = concatenação; textos
(`info`, AAD, caminhos) em UTF-8; `package` é o atributo `package` do manifesto do `base` (na CLI) e
`context.packageName` (no leitor), que são o mesmo `applicationId`; `versionCode` é o `android:versionCode` do manifesto
(na CLI) e `PackageInfo.longVersionCode` (no leitor), em decimal sem zeros à esquerda, iguais porque a CLI recusa
`versionCodeMajor`. Tudo por `javax.crypto` (Conscrypt no Android, JCA na CLI), sem dependência nova
(D-14x9); o HKDF é implementado sobre `HmacSHA256` e testado com os casos da RFC 5869 que estão nos vetores.

- **`K_fmt`**, a constante do formato v1, é `SHA-256("Sentomaru sealed assets format v1 public constant")` (ASCII),
  `d49d16621c97d973d3d27ade53b09e223c5a07297beb57df176fe4827a498921`. **É pública por desenho**: está em todo leitor
  que o cliente distribui. Serve só para a chave não estar em texto no pacote e para o `kek` mudar por app e versão.
- A cada corrida a CLI tira do `SecureRandom` o `dek` (32 bytes), o `salt` (16 bytes) e um nonce de 12 bytes por
  arquivo e para o cabeçalho.
- `kek = HKDF(ikm = K_fmt, salt = salt, info = "sentomaru-sealed-v1|" ‖ package ‖ "|" ‖ versionCode)`.
- **`assets/sentomaru/sealed/header.bin`**: `"SNTS"` (4 bytes) ‖ versão `0x01` (1) ‖ `salt` (16) ‖ nonce (12) ‖
  `AEAD(kek, dek ‖ caminho canônico de strings ou nada, aad = "header|v1|" ‖ package ‖ "|" ‖ versionCode)`.
- **Por arquivo:** `k_i = HKDF(ikm = dek, salt = vazio, info = "asset|" ‖ caminho)`; entrada
  `assets/sentomaru/sealed/<sha256(caminho) em hex minúsculo>.bin` = `"SNTA"` (4) ‖ versão `0x01` (1) ‖ tamanho do
  arquivo **em claro**, antes da compressão (u32 big-endian, 4) ‖ nonce (12) ‖ `AEAD(k_i, deflate(claro), aad = "asset|v1|"
  ‖ package ‖ "|" ‖ versionCode ‖ "|" ‖ caminho)`. `deflate` é DEFLATE cru (RFC 1951, sem cabeçalho zlib nem gzip),
  feito **antes** de cifrar para o pacote não crescer; os bytes comprimidos não são contratuais (qualquer fluxo válido
  serve), o resto é exato. O nome não revela o caminho, mas o caminho **não fica oculto**: quem conhece os caminhos
  (código do app, `AssetManifest.bin` do Flutter) calcula o hash.
- **Fora da autenticação:** o magic, a versão e o tamanho declarado (u32) dos `.bin`, e o magic e a versão do
  `header.bin`. O `salt` do cabeçalho entra no `kek` (trocá-lo falha na tag) e os nonces entram no GCM. O tamanho
  declarado é conferido depois de abrir: o fluxo descomprimido tem de ter exatamente esse tamanho.
- O arquivo original é **removido** do `base`, para um `assets.open`/`rootBundle.load` esquecido falhar alto
  (`FileNotFoundException`) em vez de devolver bytes cifrados. As entradas novas saem em ordem fixa por nome.
- A CLI zera os arrays próprios (`dek`, `kek`, cada `k_i`, o conteúdo do cabeçalho e os bytes comprimidos) depois da
  escrita, também quando ela falha, no melhor esforço da JVM (cópias dentro do JCA, da `SecretKeySpec`, do `Deflater` e
  do coletor de lixo ficam fora do alcance); nenhum deles vai para relatório, log, `stderr` ou OpenBao.
- **Saída não reproduzível com a seção:** `dek`, `salt` e nonces mudam a cada corrida, logo `output.sha256` também. Sem a
  seção a saída continua a de hoje, byte a byte. Para os vetores e o teste de ouro há uma fonte de aleatoriedade
  injetável **só em teste** (seam interno, passado a cada chamada, sem estado mutável no controle), nunca por argumento
  nem variável de ambiente da CLI.

**Consequências:** um arquivo selado copiado para outro app, outra versão ou outro caminho não abre (AAD com pacote,
`versionCode` e caminho); arquivo corrompido, trocado por outro selado ou copiado de outro build falha na tag
(`integrity`), mas **quem tem o APK forja um arquivo com tag válida** (deriva o `kek` de `K_fmt`, do `salt` e do pacote, abre
o `dek` e sela o que quiser): a tag não é evidência de adulteração contra quem reempacota o app; **sem** vínculo ao certificado de
assinatura na v1 (com Play App Signing o certificado instalado é o do Google, que a CLI não vê; errar o vínculo deixaria
o app sem os arquivos, D-14x4); atualizar o app gera `dek` novo e não há nada a migrar.

#### Leitura (SDK Android e plugin Flutter, a partir da D-14b)

- **Android** (módulo `sdk/android/sealed`, sem rede): `SentomaruSealed.open(context, caminho): InputStream`,
  `bytes(context, caminho): ByteArray` e `string(context, chave): String?` (`null` para chave ausente). Erros tipados
  `SentomaruSealedException` com `not-sealed`, `integrity` ou `format-unsupported`. **Flutter:**
  `SentomaruSealed.load(chaveDoPubspec)` (`Future<Uint8List>`) e `SentomaruSealed.string(chave)`, decifrando no lado
  Android do plugin (sem criptografia em Dart); no iOS, `UnsupportedError`.
- **Ordem das conferências** (o leitor de referência de `test_sealed_vectors.py` e os casos negativos dos vetores):
  sem `header.bin` → `not-sealed`; menos de 5 bytes, magic diferente de `SNTS` ou versão diferente de 1 →
  `format-unsupported`; fora de 81 a 593 bytes (o máximo cabe um caminho de strings de 512 bytes) ou tag que não
  confere → `integrity`; arquivo do caminho ausente (num pacote selado, nunca cai para o claro) → `not-sealed`; menos de 5
  bytes, magic diferente de `SNTA` ou versão diferente de 1 → `format-unsupported`; fora de 37 a 4 198 437 bytes
  (37 + 4 MiB + 4 KiB de folga do DEFLATE; a CLI nunca grava mais), tamanho declarado acima de 4 MiB, tag que não
  confere, fluxo DEFLATE inválido, com bytes depois do fim ou com tamanho diferente do declarado → `integrity`;
  `string()` sem arquivo de strings no cabeçalho → `not-sealed`, e JSON de strings que não é UTF-8 ou não é objeto de
  textos depois de aberto → `integrity`. Os tamanhos são conferidos **antes** de decifrar; a descompressão **para** em
  tamanho declarado + 1 byte (nunca expande um fluxo além disso). Os limites estão em `readerLimits` nos vetores; cada
  regra tem um caso negativo, e os casos que trocam o conteúdo levam tag válida, para falharem pela regra que nomeiam. As regras de recurso (tamanho
  antes de decifrar, corte da descompressão) têm `probe` nos vetores: o código de erro sozinho não as prova, e os testes
  de cada leitor as conferem por instrumentação, como o leitor de referência.
- **Preguiçosa:** nada roda no arranque (sem `ContentProvider`, sem trabalho em `Application`); a primeira chamada lê o
  cabeçalho e deriva o `kek`; o `dek` fica na memória do processo; o claro nunca vai para disco. `open()` devolve o
  arquivo inteiro já decifrado em memória (o GCM só entrega o claro depois de validar a tag), não streaming.
- **Desenvolvimento sem a CLI (D-14x10):** `SentomaruSealed.configure(allowPlainFallback = true)` lê o arquivo em claro
  pelo caminho canônico **só** quando o pacote não tem `header.bin`. Desligada por padrão; o guia manda ligar só com
  `BuildConfig.DEBUG`/`kDebugMode`. Com `header.bin` presente a opção não tem efeito (nem um `header.bin` que falha
  abre caminho para o claro: o erro é o do cabeçalho). Sem cabeçalho não há caminho do arquivo de strings; o segundo
  parâmetro, opcional, dá esse caminho para o `string()` em claro (`plainStringsPath`, caminho canônico, no Android;
  `plainStringsKey`, chave do `pubspec.yaml`, no Flutter); sem ele, `string()` num pacote sem selagem é `not-sealed`.
  Arquivo ausente nesse modo falha como o `AssetManager` (`FileNotFoundException`; no Flutter, `SentomaruException`
  com `details` `AssetNotFound`), não com um código do contrato. Decisão da D-14b, aditiva.
- **Leitores incompatíveis** (um arquivo lido por eles não pode ser selado): `file:///android_asset/` em WebView,
  `AAssetManager` no nativo, `AssetFileDescriptor`/`MediaPlayer`/`SoundPool`, `Typeface.createFromAsset`,
  `Image.asset`/`rootBundle` no Flutter.
- Regras de consumidor: `-keep` da API pública do leitor e `-keepnames` do marcador do plugin, para os marcadores
  sobreviverem ao R8 do cliente (conferido num build R8 real na D-14b).

**O que muda no binário, a partir da D-14c** (AAB, módulo `base`; os outros módulos não mudam): as entradas dos
caminhos marcados saem; entram `base/assets/sentomaru/sealed/header.bin` e um `.bin` por arquivo, em ordem fixa por
nome. Isso exige uma operação nova no editor de AAB da CLI: remover uma entrada existente; acrescentar depois de uma
entrada removida põe a entrada nova no lugar dela, isto é, antes da seguinte que sobrevive (sem nenhuma, no fim do
arquivo); remover o que foi acrescentado na mesma corrida, remover duas vezes ou acrescentar um nome existente e não
removido é `internal-error` (defeito do controle). O controle ancora as entradas novas na última entrada
`base/assets/…` **na ordem do ZIP** (removida ou não): elas ficam juntas, em ordem de nome, logo depois dela (no lugar
dela quando é selada), isto é, depois da última entrada de assets do arquivo, que não é necessariamente a última por
nome nem o fim do diretório `base/assets/` quando o ZIP não está ordenado. **`base/assets.pb`** (decisão da
D-14c): o `bundletool` lista ali cada diretório de `assets/` com arquivos diretos e recusa um diretório listado que fica
sem nenhum ("Targeted directory … is empty"); quando o AAB tem o arquivo, o controle tira da lista os diretórios de
targeting vazio cujos únicos arquivos diretos eram os selados e acrescenta `assets/sentomaru/sealed` com targeting vazio,
como o `bundletool build-bundle` o escreveria; o resto do arquivo não muda. `bundletool validate` e `build-apks` no fim,
como hoje. Ids de `changes` (vocabulário fechado): `asset.sealed` e `asset.removed` (alvo: o `sha256` do caminho
canônico, nunca o caminho nem o conteúdo), `sealed.header.added` (alvo: `base/assets/sentomaru/sealed/header.bin`) e,
acréscimo da D-14c, `assets-config.updated` (alvo: `base/assets.pb`, quando o AAB o tem). A ordem em `changes` é:
`sealed.header.added`, depois `asset.sealed` e `asset.removed` de cada arquivo na ordem do perfil (`assets`, depois
`strings`), e `assets-config.updated` por último. Relatório: `status: applied` (`planned` no
`--dry-run`, com os mesmos `changes`) e evidência `{ "files": "<n>", "bytesIn": "<soma em claro>", "bytesOut": "<soma
dos .bin e do cabeçalho>", "strings": "<entradas ou 0>", "format": "v1", "sectionSha256": "<hex>" }`, com
`sectionSha256` o SHA-256 da seção em JSON canônico (RFC 8785, JCS), também no `--dry-run`. A seção é hasheada como
está no perfil: `"strings": null` e a ausência de `strings` dão hashes diferentes. No `--dry-run` não há cifragem e
`bytesOut` é `"unknown"` (as evidências são sempre texto).

**Ordem com outros controles:** `build-obfuscation` (10) → `asset-encryption` (20) → `dex-obfuscation` (30, D-21a) →
`network-pinning` (40) → `integrity-manifest` (90). Um manifesto de integridade embutido (G-03d) que um dia cubra
assets verá os selados, não os claros.

**Interação com a D-12:** o algoritmo `apk-code-sha256-v1` só cobre `classes*.dex` e `lib/<abi>/*.so`; selar assets
**não muda** os `codeDigests` e o `code_integrity` não vê os selados (nem os claros, antes). Não há sinal novo
(D-14x7): a tag GCM, conferida na leitura, só pega corrupção, troca e cópia entre builds; não é evidência contra quem
reempacota o app, e nenhum veredito sai dela. O leitor está no
DEX do SDK que o app já linka; a CLI não acrescenta DEX neste controle.

**O que o controle afirma (só depois da D-14d):** "os arquivos de `assets/` marcados no perfil não aparecem em claro
no AAB nem nos APKs gerados dele (conferido com `unzip` e `apktool`); são lidos pelo app com AES-256-GCM, com uma chave
própria de cada artefato protegido (gerada a cada corrida da CLI), que não está gravada em texto no pacote mas pode ser
derivada por quem conhece o esquema; o custo no arranque e na primeira leitura está medido".

**O que não afirma:**

- sigilo contra quem tem o APK: tudo o que o app usa para chegar à chave está no APK ou no SDK público (o revisor
  independente da D-14d recuperou os dois arquivos marcados em 4 min 37 s só com o APK e o esquema público; está na
  ficha como limite);
- nada contra quem controla o processo: Frida ou um SDK corrigido lê o retorno da decifração em claro;
- que um arquivo selado não foi adulterado: quem tem o APK sela um arquivo novo com tag válida (ver "Consequências");
- nada sobre strings no DEX ou no Dart (`libapp.so`, `--dart-define`), `res/` (`strings.xml`, `raw/`), fontes e arquivos
  do motor do Flutter, asset packs e módulos dinâmicos (fora da v1, D-14x2);
- que guardar uma chave de API ou senha num arquivo selado a deixe segura: segredo de servidor não vai no app;
- cifragem "de ponta a ponta", "de nível militar", assets impossíveis de extrair, ou paráfrases.

**Mudança de comportamento na D-14a (registrada):** antes, `asset-encryption` era uma seção de controle desconhecido
para o esquema (bastava `version`); agora é fechada e exige `assets`. Um perfil com `"asset-encryption": {"version":
"1"}` passava no portão de política e passa a falhar com `profile-invalid`. A CLI respondia `control-not-available` nos
dois casos (até a D-14e). Não é v2 do contrato pelo mesmo motivo da D-07a: o controle nunca existiu na CLI e nenhum perfil do
repositório trazia a seção (conferido por busca em 26/10/2026).

### `ui-shield` (G-10)

Controle da CLI **0.6.0** (G-10c, 5/11/2026; antes era de laboratório, G-10a): está em `Controls.all`, `controls --json` o lista e o gate
(`SENTOMARU_LAB`) não muda nada para ele. Com a `cli-v0.5.0` o perfil que traz a seção sai 4 (`control-not-available`). A release `cli-v0.6.0` ainda
está a publicar. O registro no relatório de proteção (BPR/D-16) é fatia própria: até lá o gerador recusa o controle por id (`control-not-released`).

Seção do perfil (fechada; qualquer campo a mais ou a menos é `profile-format`):

```json
"ui-shield": {
  "version": "1",
  "mode": "listed_only",
  "activities": ["br.com.ebees.exampleapp.pay.PayActivity"],
  "hideOverlayWindows": true
}
```

- `mode`: `listed_only` (padrão recomendado; exige de 1 a 64 `activities`, sem repetição, cada uma um nome de classe
  binário como `br.com.app.Tela` ou `br.com.app.Tela$Interna`) ou `all_activities` (`activities` vazio; toda tela do app;
  aviso `ui-shield-all-activities`, porque um fluxo que precisa de captura, como suporte e acessibilidade, deixa de funcionar).
- `hideOverlayWindows`: se verdadeiro, o runtime chama `Window.setHideOverlayWindows(true)` (API 31+) e a CLI declara a
  permissão normal `HIDE_OVERLAY_WINDOWS` quando o app não a tem (mudança `manifest.permission.added`).
- Cada atividade listada precisa estar declarada (`<activity>` ou `<activity-alias>`) no manifesto do `base` do AAB; senão
  `app-incompatible`, também no `--dry-run`. Num APK a conferência não é feita (o leitor de manifesto do APK não lista
  atividades), mas a execução real é só de AAB, como nos demais controles que mudam o binário.
- Mudanças (vocabulário fechado): `manifest.meta-data.added` (alvo `ui-shield`) e `manifest.permission.added`
  (alvo `android.permission.HIDE_OVERLAY_WINDOWS`). Evidência do plano: `mode`, `activities` (quantidade),
  `hideOverlayWindows`, `applies: activity-lifecycle`.
- Um pacote que já traz a configuração do `ui-shield` (protegido duas vezes) → `app-incompatible`.

**O que o runtime faz** (`UiShield` em `:protect-runtime`, instalado pelo `InitProvider` quando a meta-data existe, em
`onActivityStarted`, antes do primeiro quadro): `FLAG_SECURE`; `setRecentsScreenshotEnabled(false)` (API 33+);
`setHideOverlayWindows(true)` (API 31+, se pedido); `setFilterTouchesWhenObscured(true)` na `DecorView`;
`setAccessibilityDataSensitive(ACCESSIBILITY_DATA_SENSITIVE_YES)` (API 34+). Cada chamada roda sozinha: uma janela que
recusa uma delas ainda recebe as outras. Configuração ilegível deixa o escudo desligado (nunca adivinha).

**Desvio registrado do desenho inicial (HU-05):** a ficha previa a injeção "em `onCreate` dos alvos no DEX". Esta fatia
usa o ciclo de vida de atividade no runtime e **não reescreve o DEX do app**: funciona para uma atividade que não define
`onCreate`, que herda de uma base, ou que o R8 renomeou, e não depende do `DexRoundTrip`. A consequência: as flags entram
no `onActivityStarted`, depois do `onCreate` e antes do primeiro quadro, não dentro do `onCreate`. **O dono aceitou o desvio em 2026-11-07**
(registro interno do G-10): reabrir a injeção no `onCreate` só se uma prova futura mostrar que a janela entre `onCreate` e
`onActivityStarted` deixa a tela exposta.

**O que `ui-shield` NÃO afirma:** `FLAG_SECURE` não impede câmera externa, hook, leitura de memória nem um dispositivo
com root; não prova que o app é seguro; só afeta as telas marcadas. **Limite (G10-1):** as chamadas valem para a **janela da
`Activity`** listada. `Dialog`, `DialogFragment`, bottom sheet e `PopupWindow` abrem janelas próprias sem `FLAG_SECURE`, filtro de
toque nem `setHideOverlayWindows`: um PIN digitado num diálogo de uma tela protegida continua capturável, e o app precisa pôr
`FLAG_SECURE` nessa janela por conta própria. A CLI não enxerga nem altera essas janelas. Não é o `ScreenShield` do D-20 (que também mede captura):
este só protege, e não envia sinal.

### Limites conhecidos (v1)

- **Pinning (`network-pinning`, a partir da `cli-v0.5.0`):** só para o que usa o `TrustManager` padrão da plataforma;
  fora WebView, Cronet, `TrustManager` próprio e o Dart sem a linha do plugin. Lista completa em
  [`network-pinning`](#network-pinning-d-07), "Limites", e no guia do cliente.
- **Ofuscação (`build-obfuscation`, a partir da `cli-v0.5.0`):** só conferência e relato; a CLI não ofusca nem mede
  resistência. Ver [`build-obfuscation`](#build-obfuscation-d-08), "Limites".
- **Cifragem de assets (`asset-encryption`, a partir da `cli-v0.5.0`):** ofuscação de dados com chave derivável por
  quem tem o APK (não guarda segredo); até 1 MiB por arquivo, e o app recebe o arquivo inteiro decifrado na memória; só `assets/` do `base` e um arquivo de strings; o app lê por chamada explícita do SDK ou do plugin. Ver
  [`asset-encryption`](#asset-encryption-d-14), "O que não afirma".
- **Assinatura de rede só por OkHttp e HttpURLConnection (Android) e Dio (Flutter):** o transporte do SDK cobre os
  clientes em que a linha foi instalada e, no `HttpURLConnection`, as chamadas feitas por `SentomaruUrlConnection.send`
  (S2; corpo `ByteArray` até 64 KiB, sem streaming; evidência só por testes JVM, sem aparelho). React Native/JS, Unity,
  WebView, Cronet, Ktor e Apache HttpClient não são cobertos; `notInstrumentable` fica no formato do relatório, sempre vazio nesta versão (nada é instrumentado).
- **Reempacotar muda a assinatura do app:** atualização sobre instalação existente (APK) só com a mesma chave;
  restrições por SHA-1/SHA-256 do certificado (Google Sign-In, Maps, App Links/`assetlinks.json`, Play Integrity,
  App Check) precisam do digest do certificado que assina o app **instalado**. Num AAB publicado pelo Play com Play App
  Signing, esse é o certificado do App Signing (do Google), não o de upload: `output.signingCertSha256` é o de upload
  (ver "Play App Signing" acima).
- **Apps com verificação própria de integridade ou assinatura** podem recusar o artefato reempacotado.
- O `ContentProvider` é instanciado só no processo padrão do app; inicializa depois de `attachBaseContext` e antes de
  `Application.onCreate`. A assinatura de rede não depende dele: é o cliente do SDK do app que assina, e uma rota do
  perfil com o cliente sem inicializar **não é enviada** (falha fechada, erro tipado). Apps instantâneos não são
  suportados.
- `.so` do runtime (se houver) só para as ABIs que o app já tem; alinhamento de 16 KiB de `.so` e do zip mantido
  (exigido para `targetSdk` 35+ no Play).

## Saída e relatório

`<out>/` recebe o artefato protegido (`<nome>.protected.apk` ou `.aab`) e o relatório. Nada parcial fica em `<out>`
em caso de erro (só o relatório com o erro), **exceto** na falha de registro (`registry-unavailable`,
`register-failed`): o artefato pronto fica, o relatório diz que não foi registrado e o registro pode ser refeito.

```json
{
  "reportVersion": "1",
  "runId": "<uuid>",
  "startedAt": "2026-10-16T12:00:00Z",
  "dryRun": false,
  "cli": { "version": "1", "build": "1.0.0", "runtime": { "sdk": "0.5.0" } },
  "profile": { "id": "exampleapp-hml-protect", "sha256": "..." },
  "input":  { "kind": "apk", "sha256": "...", "package": "com.example.app", "versionCode": 123,
              "signingCertSha256": "...", "modules": ["base"] },
  "output": { "sha256": "...", "signed": true, "signingCertSha256": "...", "sizeDeltaBytes": 412000 },
  "controls": [
    { "id": "runtime-injection", "version": "1", "status": "applied",
      "changes": [ { "id": "dex.added", "target": "classes3.dex" },
                   { "id": "manifest.provider.added", "target": "br.com.ebees.sentomaru.runtime.InitProvider" } ],
      "evidence": {} },
    { "id": "network-signing", "version": "1", "status": "checked", "changes": [], "notInstrumentable": [],
      "evidence": { "transport": "android-sdk", "check": "dex-class-defined" } }
  ],
  "signing": { "mode": "openbao", "status": "applied" },
  "registration": { "status": "registered", "buildId": "<uuid>" },
  "warnings": [],
  "errors": []
}
```

`controls[].status`: `applied`, `skipped` (nada a fazer no app), `not-applicable`, `failed`; em `--dry-run`, `planned`;
`checked` (acréscimo da G-03c) para um controle que só confere o app e não muda o binário (`network-signing` e, a partir
da D-08d, `build-obfuscation`), na execução real e no `--dry-run`. `cli.runtime.dexSha256` (acréscimo da G-03b2) é o SHA-256 do DEX do runtime embutido nesta versão da CLI; a evidência de `runtime-injection` repete o valor. `changes[].id` é um
vocabulário fechado por controle (lista em `controls --json`). O relatório nunca contém segredos, chaves, tokens nem
conteúdo do app além dos nomes e digests listados.

**Proveniência da corrida (D-16d):** a CLI não assina o relatório nem monta proveniência; depois de uma corrida
registrada, o CI do cliente monta o statement `protect-run/v1` com the vendor's protect provenance tool e o assina
com a chave dele ([protect-run-provenance-v1.md](protect-run-provenance-v1.md)); o relatório de proteção da corrida é o
`kind: protect-run` de [protection-report-v1.md](../shield/protection-report-v1.md). Nada muda neste contrato.

## `sentomaru scope` (Fase C, acréscimo; não é parte de `protect`)

Contrato do manifesto de onboarding `sentomaru-scope.yaml` (v1) e dos comandos que o leem. Esquema:
[`scope-manifest-v1.schema.json`](../platform/scope-manifest-v1.schema.json); exemplo:
[`examples/sentomaru-scope.example.yaml`](../platform/examples/sentomaru-scope.example.yaml) (digests sintéticos). Especificação de origem:
an internal design note, seção 7.

```text
sentomaru scope plan  --manifest <sentomaru-scope.yaml> [--api <url>] [--policy <policy.json>] [--json] [--admin-token-stdin]
sentomaru scope apply --manifest <sentomaru-scope.yaml> [--api <url>] [--policy <policy.json>] [--json] [--admin-token-stdin] [--console <url>]
sentomaru scope check --manifest <sentomaru-scope.yaml> [--api <url>] [--expect <módulo,...>] [--allow-unknown] [--json] [--admin-token-stdin]
```

- **Manifesto:** documento **fechado** (chave desconhecida é recusada, então não há onde pôr segredo), lido por um leitor estrito do
  subconjunto de YAML que o manifesto usa. Âncoras, aliases, tags, blocos `|`/`>`, vários documentos, chave repetida e tabulação são
  recusados, não adivinhados. Digest SHA-256 é `XX:XX…` com **32 pares** (a CLI converte para os 64 hexadecimais minúsculos da API); o
  App ID Apple é **sempre montado** de `teamId` + `.` + `bundleId` e um `bundleId` que já começa com o `teamId` é recusado;
  `attestEnvironment: development` só em escopo `dev`, `lab` ou `hml`. Máximo de 64 KiB.
- **Credencial:** a sessão de operador do Console, em `SENTOMARU_ADMIN_TOKEN` (64 hexadecimais) ou na primeira linha da entrada padrão
  com `--admin-token-stdin`; **nunca** em argumento (um `--admin-token` é opção desconhecida, saída 2). A CLI a manda só no cookie
  `__Host-sentomaru_session` e no cabeçalho `X-Sentomaru-Csrf` derivado dela nas escritas; nenhuma saída, erro ou arquivo a repete.
  `SENTOMARU_API` (ou `--api`) é https, ou http só em endereço de loopback (teste local). `plan` pede um papel que lê o escopo
  (`PolicyRead`); `apply` pede **SuperAdmin**, porque as rotas de escrita são `ScopesManage`.
- **`plan`:** só leitura (`GET /v1/auth/scopes`, `GET …/admin/scope`, `GET …/admin/policies`). Uma linha por item, com a marca `+`
  (acrescenta), `~` (troca), `=` (já está), `!` (conflito ou bloqueio) e `i` (informativo). `--json` devolve um objeto único com
  `items[]`. Sai com 0 quando conseguiu ler, mesmo com diferenças ou conflitos.
- **`apply`:** idempotente, usa só rotas que já existem e, **nesta ordem**: criar o escopo (`POST /v1/{org}/platform/scopes`, só se o
  operador não o enxerga; o pacote vem de `android.package`; um escopo do mesmo pacote é reaproveitado), `POST …/scope/signing-digests`
  (`active`, para cada digest que não está ativo), `PUT …/scope/apple-app`, e `POST …/policies` (**rascunho**). Antes de qualquer
  escrita confere o arquivo da política e recusa se houver conflito ou bloqueio. **Nunca aprova** uma política (a SoD não muda: a
  aprovação é de outro usuário no Console), **nunca retira** nem remove nada (um digest ativo no servidor que o manifesto não lista só é
  informado) e **não troca o pacote** de um escopo existente (`scope-conflict`). A saída diz o id do rascunho e onde abri-lo (o link
  completo só quando `--console` ou `SENTOMARU_CONSOLE_URL` dá a origem do Console).
- **Política:** `template: file` lê `policy.file` (relativo ao manifesto) ou `--policy`. `template: study` **não** gera o JSON aqui: a
  política de estudo vem do gerador da Fase D (`sentomaru policy study`) e entra por `--policy`; sem ela o `plan` mostra `!` e o `apply`
  recusa (`policy-not-generated`) antes de escrever. O arquivo precisa ser do mesmo escopo; uma política `study` precisa ser `shadow` e ter
  as mesmas `sensitiveOperations` do manifesto. Se `policyId` + `version` já existem no servidor, o item é `=`.
- **`check`:** só leitura de `GET …/admin/readiness` ([`readiness-v1.md`](../platform/readiness-v1.md); papel `Auditor`, `SecurityOperator` ou
  `SuperAdmin`) e comparação com o que o manifesto espera. Esperado, com os ids do catálogo `readiness-modules-v1.json`: `android` →
  `attestation.android`; `ios` → `attestation.ios`; `android.playIntegrity.cloudProjectNumber` → `play_integrity`; `policy` → `policy`;
  `consumer.expected.mobileGate` → `consumer.gate`; `consumer.expected.fraud` → `fraud`; `app.expected.installationResponse` → `response`;
  `notifications.telegram` → `notifications`; mais os de `--expect a,b`. Imprime **todos** os módulos (estado, motivos e próximos
  passos por código; `!` o esperado que não está `ready`, `=` o esperado que está). Saída **0** quando todo módulo esperado está
  `ready`; **4** `readiness-not-ready` quando algum não está (o `unknown` conta como não pronto, porque o servidor não o vê, a menos
  que `--allow-unknown`), inclusive um módulo esperado que o catálogo do servidor não tem. Escopo desconhecido (ou servidor sem a rota):
  `scope-unknown`, saída 4; resposta que não tem a forma do contrato: `readiness-format`, saída 8. A resposta é dado: só se imprimem ids,
  estados, motivos e códigos de próximo passo em forma fechada (`[a-z][a-z0-9_.]*`); qualquer outro texto é descartado. `--json` devolve
  `{ scope, mode: "check", ok, stale, expected, failing, missing, modules[] }`. Não chama rota de escrita nem manda CSRF.
- **Só informativo (sem rota para gravar):** `android.playIntegrity.cloudProjectNumber`, `consumer.expected`, `app.expected` e
  `notifications.telegram` são lidos e validados e aparecem como `i`; quem os usa é a Prontidão e o `scope check`
  (`consumer.expected` e `app.expected` só pedem `ready` quando a autodeclaração das fases E/F existe; até lá o módulo sai `unknown`).

| Saída | Códigos | Quando |
|---|---|---|
| 0 | — | `plan` leu; `apply` terminou; `check` encontrou todo módulo esperado `ready` |
| 2 | `usage`, `policy-not-generated` | argumentos; `--api` que não é https/loopback; `apply` de política `study` sem o arquivo |
| 4 | `manifest-format`, `policy-format`, `scope-conflict`, `scope-unknown`, `readiness-not-ready` | manifesto ou arquivo de política recusado; pacote diferente no servidor; escopo que o manifesto não consegue criar; `check`: escopo desconhecido ou módulo esperado que não está pronto |
| 5 | `permission-missing`, `scope-not-visible` | a sessão não pode ler ou escrever; o escopo existe mas o operador não o tem |
| 8 | `credential-missing`, `api-unavailable`, `apply-refused`, `readiness-format` | sem token ou token mal formado ou recusado (401); API inacessível, 429 ou 5xx; uma rota recusou (o `detail` traz o código dela) |

Prova: `ScopeCliTest` (29 testes; servidor de teste em loopback: rotas, ordem, cookie, CSRF, nada de aprovação nem retirada, idempotência, conflito,
credencial) e `verification/devsecops/test_scope_manifest_schema.py` (esquema e leitor listam as mesmas chaves).

## Erros e códigos de saída (estáveis)

| Saída | Códigos | Quando |
|---|---|---|
| 0 | — | sucesso (inclui `--dry-run`); avisos em `warnings` |
| 1 | `internal-error` | falha inesperada (sem artefato parcial) |
| 2 | `usage`, `output-unwritable` | argumentos inválidos; `<out>` sem escrita; `SENTOMARU_LAB=1` numa execução real registrada (`usage`, `detail` estável `lab-gate-registered: SENTOMARU_LAB=1 needs --lab-unregistered`, depois do perfil e antes da credencial, D-16-lab-gate) |
| 3 | `input-format`, `input-signature`, `input-too-large`, `min-sdk-unsupported` | artefato de entrada recusado |
| 4 | `profile-format`, `control-not-available`, `control-version-unsupported`, `control-prerequisite`, `scope-mismatch` | perfil recusado |
| 5 | `permission-missing`, `app-incompatible` | o app não comporta o perfil (o `detail` diz o motivo: limite de DEX, ABI, verificação própria detectada) |
| 6 | `control-failed` | um controle falhou ao aplicar (`detail` traz o id do controle) |
| 7 | `sign-failed`, `signer-unavailable` | assinatura falhou ou OpenBao inacessível |
| 8 | `credential-missing`, `entitlement-denied`, `registry-unavailable`, `register-failed` | sem credencial; módulo DevSecOps desligado para a organização (`module-disabled`, B-06); API inacessível; registro recusado |

Precedência: o primeiro erro na ordem de execução (argumentos → leitura do perfil e do seu `scope` → gate de
laboratório numa execução real (`lab-gate-registered`, saída 2, D-16-lab-gate) → credencial e direito → entrada → validação completa do perfil →
compatibilidade → controles → assinatura → registro) define a saída; os demais vão em `errors[]` quando a CLI
consegue detectá-los sem efeito. Mensagem em `stderr` e no relatório: `{"code": "<código>", "detail": "<texto sem dados do app>"}`.

## Medição (B-05)

Cada execução real tem um registro idempotente pelo `runId`: **aberto** junto com a conferência do direito (antes de
ler a entrada) e **fechado** com o resultado. Sem direito (`entitlement-denied`) não há corrida. `--dry-run` não é
medido. Controle novo não cria unidade de cobrança sem decisão do fornecedor (D-F2).

**Como está implementado (G-03e1, migração 0034):** o registro é a linha de `platform.protect_run`, e a medição deriva
dela pelo rollup (B-05): a métrica `devsecops.pipelines` conta as corridas `protected` pelo instante do fechamento.
**Desvio:** corridas `failed`, expiradas (`run-expired`, abertas há mais de 24 h) e nunca fechadas **não** são medidas
(ficam no registro, consultáveis, mas não entram no consumo). Franquia e preço seguem a decisão D-F2. Como toda
métrica derivada, a franquia de um trial (B-12a) só barra depois do rollup seguinte (até 5 min), não na mesma corrida.
**Desvio:** a corrida **não** vira um registro de build do Shield (`platform.build_protection_record` exige um perfil
de proteção do Shield, D-01, que o perfil `protect` não é): o `buildId` é o `runId`, e `shield.builds` não conta as
corridas da CLI.

## Gate (G-03, onda 1)

Apps de exemplo protegidos com o runtime injetado **sem alterar o código-fonte** e com a assinatura de rede ligada
**por uma linha** (decisão do fornecedor, 16/10/2026: a G-03 deixa de prometer "sem alterar o código" para a rede): Kotlin com
OkHttp (`addSentomaru(client, routes)`) e um app Flutter com Dio (`dio.addSentomaru(client, routes: ...)`). **A
evidência em aparelho é só Android/OkHttp; o Dio tem só testes unitários e de transporte real em loopback (sem
aparelho).** Evidência da rede em aparelho (17/10/2026, aparelho de referência, Android 15): relatório de aparelho da operação do Sentomaru: rota assinada pela tabela aceita pelo servidor, a mesma rota sem a linha recusada
pelo servidor (401) e rota fora da lista de hosts não enviada; o app Flutter em aparelho continua pendente. Instalados em aparelho com a saída assinada, inscritos e
com requisições aceitas pelo servidor; suíte de UI do exemplo igual antes e depois; tamanho e arranque medidos.
