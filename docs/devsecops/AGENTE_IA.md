# Configurar com um agente de IA

Instruções prontas para entregar a um agente de IA de código (Claude Code, Copilot, Cursor ou outro) que vai
configurar, no repositório do **seu** app ou backend, o pipeline do Sentomaru DevSecOps ou o uso do SDK. O Console
mostra os mesmos blocos, já com o escopo do app selecionado no lugar de `{{org}}`, `{{app}}` e `{{env}}`.

As instruções não repetem os guias. Elas apontam o agente para os guias canônicos deste repositório numa versão fixa
e dizem o que ele não pode fazer. Nenhum bloco contém segredo, e nenhum deve receber: o agente trabalha só com os
**nomes** dos secrets, e quem grava os valores é uma pessoa, no cofre ou nas configurações do CI. Tokens e senhas
nunca entram na conversa com o agente.

O repositório do Sentomaru e o feed de pacotes são privados. Para ler os guias e baixar o pacote .NET, o agente usa
uma credencial de leitura que o operador do Sentomaru concede (`contents: read`, e `read:packages` para o NuGet, com
prazo curto), como no [kit de PoC](../poc/README.md). Quem configura essa credencial é você, fora da conversa: `gh auth
login`, ou uma variável de ambiente no terminal do agente.

O CI do Sentomaru confere este arquivo:
- a versão da CLI é a release publicada (o "Estado" do
  [contrato da distribuição](../../contracts/devsecops/cli-distribution-v1.md); o código pode estar numa versão ainda a
  publicar), e os pinos são os da linha dessa release;
- os caminhos citados existem;
- cada `§` citado existe como seção no arquivo citado na mesma linha;
- os identificadores do SDK e do adaptador citados existem no código;
- só os marcadores `{{org}}`, `{{app}}` e `{{env}}` aparecem.

O que ela não confere: se o agente segue as instruções. Quem protege é o portão no CI e o servidor, não o texto.

## Pipeline (CLI `sentomaru protect` e portões de política)

<!-- agent: pipeline -->
```text
Tarefa: configurar o Sentomaru DevSecOps no CI deste repositório (app Android que gera AAB de release).
Escopo do app no Sentomaru: {{org}}/{{app}}/{{env}}.

Fontes (leia antes de escrever qualquer arquivo), no repositório público e-bees-dev/sentomaru-sdk, na tag do release que você vai usar (liste com git ls-remote --tags; cli-v0.6.1 é a do repositório de origem e pode não existir no público; confira também em Releases: SENTOMARU_CLI_VERSION exige a tag cli-v<versão> com release publicado, tag sem release dá cli-download-failed:http-404):
- docs/devsecops/CLI_PIPELINE.md §1a, §2, §3b, §3c e §5 (CLI verificada, perfil, Action, portões, saídas)
- contracts/devsecops/cli-v1.md e contracts/devsecops/cli-distribution-v1.md (contratos da CLI e da distribuição)
- contracts/devsecops/policy-gate-v1.md (portões de política)
Se não conseguir ler essas fontes, pare e me peça para autenticar o gh no seu terminal. Nunca me peça o token na
conversa. Não invente opções, rotas nem versões.

Faça, nesta ordem:
1. Crie .sentomaru/protect-profile.json (protect-profile v1, docs/devsecops/CLI_PIPELINE.md §2) com scope
   organization={{org}}, app={{app}}, environment={{env}}. Em enrollmentUrl, use a rota de inscrição do NOSSO
   backend, que eu informo. Se não souber, pergunte. Em network-signing, use os hosts e as rotas que o app chama e que
   o backend protege.
2. Crie .github/workflows/sentomaru-protect.yml seguindo o bloco "github-action" do guia, com a CLI verificada
   (docs/devsecops/CLI_PIPELINE.md §3b e §1a). Depois do build do AAB de release:
   - baixe o release cli-v0.6.1 com curl do bucket S3 público
     https://sentomaru-cli-releases-hml.s3.sa-east-1.amazonaws.com/cli/v0.6.1/ (sem token; o release do GitHub é
     o espelho); a chave pública de release fica no repositório em .sentomaru/release-key.pub, que eu entrego com o pino;
   - alternativa: omita `distribution` e este download; a Action baixa e verifica o release do repositório público
     e-bees-dev/sentomaru-sdk, com o `GITHUB_TOKEN` do workflow (docs/devsecops/CLI_PIPELINE.md §3b, "Download
     pela Action"); o pino da chave e a chave pública seguem como abaixo;
   - confira os verificadores pelos pinos da versão 0.6.1: verify_cli.py
     443b68e437f42400a43e0881797ee7dff1b7e56f2351eb62e51720086f4c237b e verify_release.py
     66192c65c6eb256be60a84f1c4ce3bd6ade97a4ffef6986a036c762fd91263b2;
   - use a Action e-bees-dev/sentomaru-sdk/actions/protect fixada pelo SHA do guia, com expect-repository
     e-bees-dev/Sentomaru (o repositório que construiu e assinou o release, campo repository do statement; não é o repositório público de distribuição), dry-run "true" e o pino da chave de release na variável SENTOMARU_RELEASE_KEY_SHA256 (o pino
     chega por outro canal: nunca o tire do mesmo download);
   - guarde report.json como artefato, inclusive quando falhar.
3. Crie .github/workflows/sentomaru-policy-gate.yml seguindo o bloco "policy-gate" do guia
   (docs/devsecops/CLI_PIPELINE.md §3c), com a Action e-bees-dev/sentomaru-sdk/actions/policy-gate fixada pelo SHA do guia. Ela confere o perfil, o SBOM
   CycloneDX (gerado pelo plugin org.cyclonedx.bom do Gradle) e as dependências vulneráveis.
4. Execução real (dry-run desligado, injeção e registro da corrida): só quando eu pedir. Ela usa os secrets
   SENTOMARU_BUILDER_TOKEN e SENTOMARU_API e a assinatura por keystore ou OpenBao (docs/devsecops/CLI_PIPELINE.md §3d).

Regras:
- Nunca grave token, senha, keystore ou pino de chave em arquivo do repositório, em log ou em argumento de comando.
  Use só os nomes dos secrets. Quem grava os valores sou eu.
- Fixe toda Action de terceiros por SHA de commit. Não use continue-on-error, || true ou fail "false".
- Não enfraqueça um portão para ele passar: não baixe min-severity, não crie nem amplie
  .sentomaru/policy-exceptions.json e não ligue nenhuma opção allow-*. Se o portão falhar, me mostre o motivo.
- Não troque osv-api sem me perguntar. Com osv-api "true", os nomes e as versões das bibliotecas do app, inclusive as
  internas, vão para a API do OSV (docs/devsecops/CLI_PIPELINE.md §3c).
- A execução real aceita só AAB (APK de entrada ainda não existe). O runtime injetado só inicializa: não escreva que
  o app passa a ter proteção em tempo de execução, anti-debug ou detecção de root.
- A CLI confere só que o SDK ou o plugin está linkado. Quem recusa a chamada sem assinatura é o backend.

Pronto quando:
- o job de --dry-run sai 0 e publica report.json;
- o portão de política fica verde;
- ao provocar cada portão num branch de teste, ele falha com a saída do guia: perfil ausente sai 3, SBOM ausente sai 4
  e dependência vulnerável sai 5.
Mostre os arquivos criados e os runs, e liste o que ficou para mim (secrets a criar, SHA a confirmar). Se não rodou
algo, diga que não rodou.
```

## SDK Android (Kotlin ou Java com OkHttp)

<!-- agent: sdk-android -->
```text
Tarefa: ligar o SDK Android do Sentomaru neste app, para que as chamadas protegidas ao nosso backend saiam assinadas
(RFC 9421).
Escopo do app no Sentomaru: {{org}}/{{app}}/{{env}}.

Fontes, no repositório público e-bees-dev/sentomaru-sdk, no SHA de main que o operador indicar:
- docs/api/INTEGRATION_GUIDE.md §4 e §7 (rotas de inscrição do backend e o que o app envia)
- contracts/sdk/sdk-api-v1.md e sdk/android/README.md (módulos, SDK 0.2.0-rc.5, API do SDK)
- sdk/flutter/README.md (como gerar o repositório Maven local do SDK)
- docs/devsecops/CLI_PIPELINE.md §2b (tabela de rotas em uma linha)
Se não conseguir ler essas fontes, pare e me peça para autenticar o gh no seu terminal. Nunca me peça o token na
conversa.

Faça:
1. Adicione br.com.ebees.sentomaru:sdk:0.2.0-rc.5. Ele não está no Maven Central: sai de um repositório Maven
   local gerado do código (./gradlew publishAllPublicationsToLocalRepoRepository em sdk/android, como no
   sdk/flutter/README.md). Se não houver um repositório combinado com o operador, pare e pergunte. minSdk 28 e
   permissão INTERNET.
2. Inicialize o cliente com SentomaruConfig: escopo {{org}}/{{app}}/{{env}}, enrollmentUrl na rota de inscrição do
   NOSSO backend e allowedHosts só com os hosts do nosso backend.
3. Faça a inscrição com o desafio que o nosso backend emite (POST /integrity/challenges, com a sessão do usuário).
4. Onde o OkHttpClient é montado, acrescente UMA linha:
   OkHttpClient.Builder().addSentomaru(sentomaru, SentomaruRoutes.of(hosts, routes))
   Use as mesmas rotas da seção network-signing do .sentomaru/protect-profile.json, se ele existir.
   Se o app usa HttpURLConnection (Java) em vez de OkHttp, troque cada chamada protegida por
   SentomaruUrlConnection.send(sentomaru, routes, method, url, body, headers), que devolve a conexão já respondida
   (docs/api/INTEGRATION_GUIDE.md §7). O corpo vai inteiro em byte[]: sem streaming. PATCH não é aceito.

Regras:
- Só são cobertos o OkHttp com essa linha e as chamadas feitas por SentomaruUrlConnection.send. Um
  url.openConnection() direto, WebView e Cronet não são: não diga que são.
- Não desligue a validação de TLS. Não aceite redirecionamento para fora de allowedHosts. Nada de chave, token ou
  credencial de workload no app.
- Os sinais do aparelho são observações e nunca valem como prova: não tome decisão de segurança no app com base neles.

Pronto quando:
- o build e os testes do app passam;
- num aparelho, o app se inscreve e uma chamada protegida sai com Signature-Input e Signature, e o backend responde 2xx;
- sem a linha, a mesma chamada é recusada pelo backend (401 com a operação em ZeroTrust).
Se você não tem aparelho para testar, diga que não testou em aparelho e deixe o teste para mim. Nunca diga que testou
algo que não rodou.
```

## Plugin Flutter (Dio, só Android)

<!-- agent: sdk-flutter -->
```text
Tarefa: ligar o plugin Flutter do Sentomaru (sentomaru_flutter) neste app, para que as chamadas protegidas do Dio ao
nosso backend saiam assinadas (RFC 9421) no Android.
Escopo do app no Sentomaru: {{org}}/{{app}}/{{env}}.

Fontes, no repositório público e-bees-dev/sentomaru-sdk, no SHA de main que o operador indicar:
- sdk/flutter/sentomaru_flutter/README.md e CHANGELOG.md (API do plugin e versão)
- sdk/flutter/README.md (dependência git e repositório Maven local do SDK Android)
- docs/api/INTEGRATION_GUIDE.md §7, §7a e §7b (o que o app envia, rota de capacidades e onRiskEvent)
- docs/devsecops/CLI_PIPELINE.md §2b (tabela de rotas em uma linha)
Se não conseguir ler essas fontes, pare e me peça para autenticar o gh no seu terminal. Nunca me peça o token na
conversa.

Faça:
1. No pubspec.yaml, adicione sentomaru_flutter como dependência git de https://github.com/e-bees-dev/sentomaru-sdk.git,
   com ref no SHA indicado pelo operador (nunca branch) e path sdk/flutter/sentomaru_flutter. O plugin não está
   publicado no pub.dev e consome o SDK Android de um repositório Maven local (sdk/flutter/README.md).
2. Inicialize o SentomaruClient com SentomaruConfig: escopo {{org}}/{{app}}/{{env}}, enrollmentUrl na rota de
   inscrição do NOSSO backend e allowedHosts só com os hosts do backend.
3. Faça a inscrição com o desafio do backend (POST /integrity/challenges) e sentomaru.enroll.
4. Onde o Dio é montado, acrescente UMA linha:
   dio.addSentomaru(sentomaru, routes: SentomaruRoutes.fromProfileSection(...))
   Use a seção network-signing do .sentomaru/protect-profile.json, se existir.
5. No início do app, leia a rota de capacidades do backend (SentomaruCapabilities, docs/api/INTEGRATION_GUIDE.md §7a).

Regras:
- O plugin é só Android: no iOS não há assinatura. Não diga que o app iOS fica protegido e não quebre o build iOS.
- Só o Dio com essa linha é coberto. Outro cliente HTTP do app não é.
- Hoje a prova do plugin é por testes, sem aparelho. Não escreva que há prova em aparelho até testarmos.
- Nada de chave, token ou credencial de workload no app. Não desligue TLS.

Pronto quando:
- flutter analyze e flutter test passam;
- num aparelho Android, o app se inscreve e uma chamada protegida é aceita pelo backend;
- sem a linha, a mesma chamada é recusada (401 com a operação em ZeroTrust).
Se você não tem aparelho para testar, diga que não testou em aparelho e deixe o teste para mim. Nunca diga que testou
algo que não rodou.
```

## Backend .NET (adaptador)

<!-- agent: backend-dotnet -->
```text
Tarefa: proteger ações deste backend ASP.NET Core com o adaptador do Sentomaru, para que aceitem só requisições
assinadas por uma instalação inscrita do nosso app.
Escopo do app no Sentomaru: {{org}}/{{app}}/{{env}}.

Fontes, no repositório público e-bees-dev/sentomaru-sdk, no SHA de main que o operador indicar:
- docs/api/INTEGRATION_GUIDE.md §2 a §8 (pré-requisitos, adaptador, quem é o chamador, credencial no deploy, rotas de
  inscrição, ações protegidas, respostas, aceite)
- integrations/samples/aspnetcore-third-party (exemplo de backend de terceiro)
Se não conseguir ler essas fontes, pare e me peça para autenticar o gh no seu terminal. Nunca me peça o token na
conversa.

Faça:
1. Adicione o pacote NuGet Sentomaru.AspNetCore 4.4.0 do feed privado https://nuget.pkg.github.com/e-bees-dev/index.json.
   A credencial do feed (read:packages) fica no nuget.config do usuário ou no secret do CI, nunca no nuget.config
   versionado. Se o feed recusar, pare e pergunte.
2. Registre AddSentomaruClient(builder.Configuration, "Sentomaru") com Org={{org}}, App={{app}}, Env={{env}},
   BaseAddress e PublicBaseUrl, sem a credencial, e um ISentomaruContextResolver que diga quem é o usuário e o tenant
   da sessão (docs/api/INTEGRATION_GUIDE.md §3, "Quem é o chamador"). Sem ele, o desafio responde 403
   caller-context-missing.
3. Exponha as rotas de inscrição (docs/api/INTEGRATION_GUIDE.md §4): POST /integrity/challenges e POST
   /integrity/v1/{{org}}/{{app}}/{{env}}/installations.
4. Marque as ações a proteger começando pelo modo Observe:
   [SentomaruIntegrity("<operação>", DeviceAssuranceLevel.Observe)]
   O padrão do atributo é ZeroTrust, que recusa quem ainda não assina. Use os mesmos nomes de operação das rotas do
   app. Proponha a troca para ZeroTrust só depois do aceite (docs/api/INTEGRATION_GUIDE.md §8c).

Regras:
- A credencial de workload (Sentomaru__WorkloadToken) chega só pelo cofre ou pelo env do deploy
  (docs/api/INTEGRATION_GUIDE.md §3, "Credencial no deploy"). Nunca em appsettings versionado, imagem, log ou teste.
- Não apague o tratamento das respostas do adaptador (docs/api/INTEGRATION_GUIDE.md §6): 401, 403, 409
  operation-replayed e 503 têm significados diferentes.
- Não aponte a produção para o HML do Sentomaru (docs/api/INTEGRATION_GUIDE.md §8b).

Pronto quando:
- o build e o teste de contrato das rotas de inscrição (docs/api/INTEGRATION_GUIDE.md §4) passam;
- em Observe, as ações registram a avaliação sem recusar ninguém;
- o aceite do docs/api/INTEGRATION_GUIDE.md §8 está preenchido, com a proposta de troca para ZeroTrust.
Se não rodou algo, diga que não rodou.
```
