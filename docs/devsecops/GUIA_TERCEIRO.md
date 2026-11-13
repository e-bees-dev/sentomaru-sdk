# Guia de ponta a ponta para terceiros

Do zero até a primeira requisição aceita: o app Android (Kotlin, Java ou Flutter) assina as chamadas com o SDK, o
seu backend confere a prova com o adaptador .NET, e o CI do app passa pelos portões de política e pela proteção
pós-build `sentomaru protect`. Este guia **não repete** os guias canônicos: ele dá a ordem e diz em que seção de cada
um está o detalhe. Onde os dois divergirem, vale o guia canônico.

O SDK nos três transportes, o backend, os portões e a execução real com keystore foram exercitados no HML pelo
repositório externo de exemplos, com
três apps que consomem só o que o Sentomaru publica. Os passos abaixo apontam para os arquivos dele como exemplo
pronto. A assinatura com OpenBao, o GitLab CI e o Play App Signing seguem a documentação canônica, sem exemplo
executado nesse repositório.

## Estado e limites (30/10/2026)

- **Só HML.** Não há produção do Sentomaru nem SLA. A distribuição da CLI é assinada pela chave de HML.
- **Repositório público de distribuição.** O SDK Android, o plugin Flutter e as Actions vêm de
  `e-bees-dev/sentomaru-sdk`, que é público: não há token de leitura a pedir ao operador (onde um token é exigido, o
  `GITHUB_TOKEN` do workflow basta). A CLI publicada vem do bucket S3 público ou do release do GitHub, e é sempre
  verificada antes de rodar.
- **Só Android.** O plugin Flutter não tem lado iOS.
- **Cobertura do transporte.** São assinados o OkHttp com `addSentomaru`, as chamadas feitas por
  `SentomaruUrlConnection.send` e o Dio com `addSentomaru`. Um `url.openConnection()` direto, outro cliente HTTP,
  WebView e Cronet não são. A CLI confere só que o SDK ou o plugin está linkado no app, não que a linha foi chamada
  com as rotas certas (aviso `network-signing-install-line`). Quem recusa uma chamada sem assinatura é o backend.
- **A execução real da CLI publicada (`cli-v0.6.1`) aceita AAB.** A entrada APK (G-03b3) está no código, sem release: com a CLI publicada, APK de entrada ainda responde `control-failed`.
- **O registro da build é declaração.** O Sentomaru não vê o binário: os digests e o `signed` da corrida são o que a
  CLI declarou com a credencial `shield-builder`.

## 1. O que pedir ao operador do Sentomaru

| Item | Para quê | Detalhe |
|---|---|---|
| Escopo `organização/app/ambiente` e o pacote Android | tudo é por escopo; a prova de um escopo não vale em outro | [INTEGRATION_GUIDE §2](../api/INTEGRATION_GUIDE.md#2-pré-requisitos) |
| Credencial `consumer` do escopo | o backend chama a API do Sentomaru | exibida uma vez no Console; vai para o seu cofre |
| Credencial `shield-builder` do escopo | só a execução real da CLI | secret `SENTOMARU_BUILDER_TOKEN` do CI |
| Pino da chave de release da CLI | conferir a CLI antes de rodar | por um canal diferente do que serve os arquivos; [contrato da distribuição](../../contracts/devsecops/cli-distribution-v1.md) |
| Endereço da API (`SENTOMARU_API`) | backend e execução real | https |

## 2. App: SDK e a linha de assinatura

O SDK vem do código-fonte num commit fixo (não há binário versionado nem registro público). O exemplo gera o
repositório Maven local com `scripts/sdk-repo.sh` do repositório de exemplos. Para o Flutter, o host consome o mesmo
repositório local, e o plugin entra por `git:` numa tag.

- Build do SDK e versões fixadas: [sdk/android/README.md](../../sdk/android/README.md) ("Build e testes", "Versões
  fixadas"); plugin: [sdk/flutter/README.md](../../sdk/flutter/README.md) ("Build do plugin").
- A linha que assina, com os `hosts` e `routes` do perfil: [CLI_PIPELINE §2b](CLI_PIPELINE.md#2b-assinatura-de-rede-uma-linha-no-app-g-03c).
  - Kotlin com OkHttp: `OkHttpClient.Builder().addSentomaru(sentomaru, routes)`
    (exemplo: `apps/kotlin-okhttp`).
  - Java com `HttpURLConnection`: `SentomaruUrlConnection.send(...)`. Regras do transporte (corpo `byte[]`, URL
    canônica, `Opener`, R8): [sdk/android/README.md, "HttpURLConnection (S2)"](../../sdk/android/README.md#httpurlconnection-s2)
    (exemplo: `apps/java-urlconnection`).
  - Flutter com Dio: `dio.addSentomaru(sentomaru, routes: ...)` (exemplo: `apps/flutter-dio`).
- O que o app envia e como reagir ao risco: [INTEGRATION_GUIDE §7](../api/INTEGRATION_GUIDE.md#7-o-que-o-app-envia).
- Build de release com R8 e `--obfuscate` sem quebrar o SDK, guarda do mapeamento e simbolização de crash:
  [BUILD_OBFUSCATION.md](../shield/BUILD_OBFUSCATION.md) (D-08a; o app não precisa de regra R8 para o Sentomaru).

Os três exemplos leem escopo, `enrollmentUrl`, hosts e rotas do mesmo `.sentomaru/protect-profile.json` que o CI usa,
empacotado como asset. Assim o app e a CLI não divergem.

## 3. Backend: adaptador e rotas de inscrição

1. Configurar o adaptador, a credencial no deploy e **quem é o chamador** (sujeito e tenant vêm da sua sessão, nunca
   do corpo do app): [INTEGRATION_GUIDE §3](../api/INTEGRATION_GUIDE.md#3-configurar-o-adaptador).
2. Rotas de inscrição: `POST /integrity/challenges` devolve `challengeId`, `challenge`, `attestationChallenge` e
   `expiresAt` como o Sentomaru mandou: [INTEGRATION_GUIDE §4](../api/INTEGRATION_GUIDE.md#4-rotas-de-inscrição-no-seu-backend).
   O app lê esses nomes de campo, e `expiresAt` vem com fuso.
3. Proteger a ação: [INTEGRATION_GUIDE §5](../api/INTEGRATION_GUIDE.md#5-proteger-uma-ação). Sem prova, a ação
   responde 401 `proof-required`.
4. Aceite antes de publicar o app: [INTEGRATION_GUIDE §8](../api/INTEGRATION_GUIDE.md#8-aceite-da-integração).

O backend do exemplo é o sample `integrations/samples/aspnetcore-third-party` com uma autenticação de
**demonstração** (cabeçalho `X-Demo-User`, sem senha). Isso não é modelo de login: no seu backend, o sujeito vem do seu
esquema de autenticação.

## 4. Identidade do app no escopo

A inscrição confere o pacote e o **SHA-256 do certificado** que assina o APK instalado. Cadastre esse certificado no
Console, em *Ativação de clientes → Identidade do app → Cadastrar certificado*. Sem certificado ativo, toda inscrição
nova do escopo é recusada. Com o certificado errado, a identidade do app no atestado não confere, e a inscrição também
é recusada (`app_id_mismatch`, o mesmo motivo de um pacote errado).

O certificado é o da chave que assina o binário que chega ao aparelho:

| Como o app é assinado | Certificado a cadastrar |
|---|---|
| `--sign keystore` na execução real (seção 6) | o da keystore |
| `--sign openbao` | o `upload.pem` do cofre ([CLI_PIPELINE §3d](CLI_PIPELINE.md#3d-execução-real-com-a-chave-no-seu-openbao-g-03e2)) |
| Distribuição pelo Play com Play App Signing | o certificado do App Signing no Play Console, não o de upload |

## 5. CI: obter a CLI e passar pelos portões

1. **CLI verificada.** Baixar o release `cli-v<versão>` e conferir o statement, a assinatura e o pino antes de
   extrair: [CLI_PIPELINE §1a](CLI_PIPELINE.md#1a-distribuição-verificada-g-03f). Com a Action `protect`, isso acontece
   dentro dela: [CLI_PIPELINE §3b](CLI_PIPELINE.md#3b-com-a-action-g-01). Fixe as Actions por SHA de commit, nunca por
   branch.
2. **Perfil versionado** com o mesmo escopo do Console: [CLI_PIPELINE §2](CLI_PIPELINE.md#2-perfil-de-proteção-no-repositório-do-app).
3. **Portões de política** (`policy-gate`), antes do `protect`, sem CLI nem credencial:
   [CLI_PIPELINE §3c](CLI_PIPELINE.md#3c-portões-de-política-g-02). Eles reprovam sem perfil válido, sem SBOM CycloneDX
   válido ou com dependência vulnerável conhecida (OSV). Com `osv-api: "true"`, as package URLs de todos os
   componentes vão para a API do OSV. Fixe o perfil com `profile-sha256` numa variável do repositório, fora do PR
   ([CLI_PIPELINE §3c](CLI_PIPELINE.md#3c-portões-de-política-g-02)).
4. **Portão de compatibilidade** (`--dry-run`): não altera o binário e não usa rede. Saídas e relatório:
   [CLI_PIPELINE §5](CLI_PIPELINE.md#5-ler-o-relatório-e-as-saídas).

### Provocar cada portão

Um portão só serve se reprova de verdade. O workflow `portoes-provocados.yml` do repositório de exemplos roda o
`policy-gate` com entradas ruins de propósito e confere a saída do [contrato](../../contracts/devsecops/policy-gate-v1.md):

| Caso | Entrada | Saída esperada |
|---|---|---|
| Perfil inválido ou ausente | perfil corrompido ou caminho inexistente | 3 |
| SBOM inválido | JSON que não é CycloneDX | 4 |
| Dependência vulnerável | SBOM com `log4j-core 2.14.1` (só no arquivo de prova, nenhum app compila) | 5 |
| Caso positivo | perfil e SBOM da build | 0 |

Copie a ideia para o seu repositório: uma entrada ruim por portão, e o job falha se a saída não for a esperada.

## 6. Execução real

Injeta o runtime no AAB, assina e registra a corrida no Sentomaru. Precisa de `SENTOMARU_BUILDER_TOKEN` e
`SENTOMARU_API`.

- **Com a chave no seu OpenBao** (recomendado: a chave nunca sai do cofre, e a identidade do job é o OIDC do GitHub):
  [CLI_PIPELINE §3d](CLI_PIPELINE.md#3d-execução-real-com-a-chave-no-seu-openbao-g-03e2) e
  [preparação da chave e do papel](g03e2-openbao-sign.md).
- **Com keystore** (`--sign keystore`, senhas só no `env:` do passo que assina, nunca no `GITHUB_ENV`): é o que o
  repositório de exemplos faz, com uma keystore **de teste** guardada nos secrets e o certificado dela cadastrado no escopo (seção 4). Para instalar no
  aparelho, o exemplo tira um APK universal do AAB protegido com o `bundletool` oficial (SHA-256 fixado), assinado
  com a mesma chave. Uma keystore gerada no job e descartada registra a corrida, mas o app não se inscreve, porque o
  escopo não conhece o certificado.

Pronto quando o relatório `build/sentomaru/report.json` traz `registration.status = registered` (o `buildId` é o
`runId` da corrida). Essa é a confirmação que o seu lado tem. O Console ainda não lista as corridas uma a uma: uma
corrida fechada como protegida é contada em Módulos e consumo › Consumo medido (módulo `devsecops`, métrica
`pipelines`), em até uns 7 minutos (a medição roda a cada 5 minutos e espera 2 minutos de carência). Essa aba é do
operador da plataforma (SuperAdmin); peça a ele a conferência, se precisar. Corrida que falhou não entra na conta.

## 7. Primeira requisição aceita

No aparelho, com o APK assinado pelo certificado cadastrado:

1. O app pede o desafio ao seu backend e se inscreve pelo SDK. Esperado, num aparelho com Keystore em hardware: o
   vínculo volta com `hardwareStatus` `hardware` e `attestationStatus` `verified`
   ([INTEGRATION_GUIDE §4](../api/INTEGRATION_GUIDE.md#4-rotas-de-inscrição-no-seu-backend)).
2. O app chama a ação protegida pela linha de assinatura. Esperado: HTTP 200. A mesma chamada sem prova responde 401
   `proof-required`.

Se algo recusar, o código de erro está nas respostas do adaptador:
[INTEGRATION_GUIDE §6](../api/INTEGRATION_GUIDE.md#6-respostas-do-adaptador).

## 8. Configurar com um agente de IA

Para entregar estes passos a um agente de código, use os blocos prontos de [AGENTE_IA.md](AGENTE_IA.md) (o Console
mostra os mesmos, já com o seu escopo). Nenhum segredo entra na conversa com o agente.
