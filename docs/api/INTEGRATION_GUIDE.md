# Guia de integração da API Sentomaru (C-08)

Para um terceiro que quer proteger operações do próprio backend ASP.NET Core com a prova por requisição do Sentomaru,
usando o adaptador `Sentomaru.AspNetCore` (`integrations/aspnetcore`) e o SDK no app Android. O que o produto faz e
o que não pode ser afirmado consta na ficha de afirmações da API, mantida pela operação do Sentomaru.

Os trechos C# e JSON deste guia vêm do exemplo de terceiro `integrations/samples/aspnetcore-third-party`, compilado
na solução e executado como host real pelos testes do Sentomaru (CI). O CI do Sentomaru falha se um desses trechos divergir do
arquivo de origem indicado acima dele. O trecho Kotlin do app é **ilustrativo** (marcado assim e não compilado).

## 1. Como funciona

1. O app pede um **desafio** ao seu backend (`POST <PublicBaseUrl>/integrity/challenges`, com a sessão do usuário). O
   backend, autenticado no Sentomaru com a credencial de workload, pede o desafio para o usuário que ele mesmo
   autenticou: sujeito e tenant vêm da sua sessão, nunca do corpo do app.
2. O app gera uma chave no Android Keystore com o `attestationChallenge` recebido, assina a inscrição para a **URL
   pública do seu backend** (`<PublicBaseUrl>/integrity/v1/{org}/{app}/{env}/installations`) e a envia. O backend a
   encaminha como recebeu; o Sentomaru confere a prova e a Key Attestation e devolve o vínculo (instalação, chave e
   sessão).
3. Cada requisição protegida sai do app assinada (RFC 9421) pelo SDK. No backend, o atributo `[SentomaruIntegrity]`
   encaminha a prova ao Sentomaru e só deixa a ação rodar com o veredito `allow` (ou `shadow`, quando a política está
   em sombra).

O app nunca fala com a API privada do Sentomaru; só o seu backend tem a credencial de workload.

## 2. Pré-requisitos

| Item | Quem fornece | Observação |
|---|---|---|
| Escopo `organização/app/ambiente` (ex.: `minha-org/meu-app/prod`) | operador do Sentomaru | identificadores em minúsculas; a prova de um escopo não vale em outro |
| Credencial de workload do escopo | operador, pelo Console (exibida uma vez) | vai para o seu cofre de segredos como `Sentomaru__WorkloadToken`; nunca em arquivo versionado. Rotação: procedimento da operação do Sentomaru |
| Política ativa no escopo | operador (autor e aprovador distintos) | sem política publicada, vale a política padrão embutida 2.0.0, que aceita App Attest verificado (iOS) na regra de hardware |
| Endereço da API do Sentomaru (`BaseAddress`, https) | operador | |
| URL pública do seu backend (`PublicBaseUrl`, https) | você | é a URL que o app assina; atrás de proxy, use `KnownProxies` |
| Login do usuário no seu backend | você | o desafio é emitido para o sujeito e o tenant da sua sessão (seção 4) |
| App Android com `minSdk` 28 e o SDK Sentomaru | você | contrato do SDK: `contracts/sdk/sdk-api-v1.md` |

## 3. Configurar o adaptador

<!-- source: integrations/samples/aspnetcore-third-party/SampleApp.cs#registration -->
```csharp
// Section "Sentomaru" (appsettings or environment variables Sentomaru__*). The workload token comes from the
// secret store as Sentomaru__WorkloadToken, never from a versioned file.
builder.Services.AddSentomaruClient(builder.Configuration, "Sentomaru");
builder.Services.AddSingleton<ISentomaruContextResolver, CallerContextResolver>();
builder.Services.AddControllers();
```

Configuração (sem a credencial, que vem do cofre):

<!-- source: integrations/samples/aspnetcore-third-party/sentomaru.example.json -->
```json
{
  "Sentomaru": {
    "BaseAddress": "https://sentomaru.example.invalid",
    "PublicBaseUrl": "https://api.example.invalid",
    "Org": "minha-org",
    "App": "meu-app",
    "Env": "prod",
    "Timeout": "00:00:02"
  }
}
```

`Org`, `App` e `Env` **omitidos assumem `ebees`, `exampleapp` e `prod`** (os padrões de `SentomaruClientOptions`, do
consumidor de referência): declare sempre os três do seu escopo.

Fora de `Development` o host **não sobe** (`OptionsValidationException`) com `FailOpen: true`, `BaseAddress` ou
`PublicBaseUrl` em http, sem `PublicBaseUrl` nem `KnownProxies`, ou com `Enabled: false` sem `DisabledAcknowledged:
true` (chave de desligamento deliberada, registrada em log Error a cada requisição liberada).

### Quem é o chamador

> **Ponto único (backend e app): o sujeito e o tenant que o app envia nunca são o fator de decisão.** O backend os
> deriva da **própria sessão autenticada** (ou os revalida contra ela) em toda rota que fala com o Sentomaru: desafio,
> inscrição e operações protegidas. Um valor que só o app diz (corpo, armazenamento local, padrão de build) não
> identifica ninguém. O adaptador 4.x recusa com 403 `caller-context-missing` um chamador que a sessão não identifica,
> e a API recusa com 400 `caller-context-reserved` um desafio novo para os marcadores `anonymous`/`default` (issues
> #142 e #143). O mesmo aviso está no README do plugin `sentomaru_flutter`.

O adaptador manda ao Sentomaru, em cada avaliação, o sujeito e o tenant do chamador, lidos por um
`ISentomaruContextResolver`. O resolvedor padrão (`DefaultSentomaruContextResolver`) lê as claims
`NameIdentifier`, `sub` ou `id_usuario` (ou o nome da identidade) para o sujeito, e `tenant`, `tenant_id`,
`id_varejista` ou `IdVarejista` para o tenant. **Desde o 4.0.0, quando elas faltam o adaptador recusa** (403
`caller-context-missing`, log Error, o Sentomaru não é chamado; em `Observe` a ação roda e nada é enviado). Até o
3.x ele caía em `anonymous`/`default` e juntava todos os chamadores sem claim num só par. `AllowAnonymousContext:
true` mantém marcadores (`development-anonymous`/`development-default`) **só em `Development`**: fora dele o host não
sobe. Registre um resolvedor próprio, que leia só as claims da sua sessão:

<!-- source: integrations/samples/aspnetcore-third-party/CallerContextResolver.cs#resolver -->
```csharp
/// <summary>
/// Subject and tenant from YOUR session only: the claims "sub" and "tenant". Missing claims stay empty, and the
/// adapter then refuses the request (403 caller-context-missing): it never sends a caller it does not have.
/// </summary>
public sealed class CallerContextResolver : ISentomaruContextResolver
{
    public CallerContextDto ResolveContext(HttpContext context) => new()
    {
        Subject = context.User.FindFirstValue("sub") ?? "",
        Tenant = context.User.FindFirstValue("tenant") ?? "",
    };
}
```

**Migração para 4.0.0** (de 1.0.2, 2.x ou 3.x): (1) de 1.x, as mudanças da 2.0.0 (sem allow degradado em 503,
validação de startup, token só pelo cofre); (2) de 2.x, a renomeação da 3.0.0, `DeviceTrustLevel` →
`DeviceAssuranceLevel` (sem alias); (3) para 4.0.0, toda rota protegida e as rotas de desafio exigem login (o atributo
`[Authorize]` ou o equivalente do seu backend) e o resolvedor lê as claims da sua sessão: um chamador sem elas deixa de
ser avaliado como `anonymous` e passa a ser recusado. Detalhes no README do adaptador
(`integrations/aspnetcore/README.md`).

**Ordem de deploy:** suba o consumidor para o adaptador 4.x **antes ou junto** com a API do Sentomaru que recusa os
marcadores no desafio. Instalações já inscritas com `anonymous`/`default` continuam sendo avaliadas; o Sentomaru conta
cada uma na métrica `sentomaru_reserved_caller_evaluations_total` e, no máximo uma vez por escopo por minuto,
registra um Warning e o evento de auditoria `caller.reserved.evaluated` (retenção de 30 dias, como as recusas de verificação; migração 0035).

### Credencial no deploy

A credencial de workload chega ao contêiner do backend **só** por um arquivo de ambiente que o agente do cofre
renderiza (0600, fora do repositório e da imagem). Exemplo com docker compose e vault-agent (consul-template), sem
nenhum valor de segredo. O agente roda uma vez antes do backend (`exit_after_auth`; `depends_on` com
`service_completed_successfully`), então o contêiner nunca sobe sem a credencial:

<!-- source: integrations/samples/aspnetcore-third-party/deploy/docker-compose.yml -->
```yaml
# C-09 (#142): the workload token reaches the backend container ONLY through an env file rendered by the secret
# store's agent. Nothing secret in this file, in the image or in the repository.
#
# Order: `sentomaru-render` (one-shot agent, exit_after_auth) renders the file and exits; `api` starts only after it
# completed successfully (depends_on), so the container never starts without the credential.
# Rotation: docker reads env_file when it CREATES the container. After rotating the token in the secret store, render
# again and recreate the api:  docker compose run --rm sentomaru-render && docker compose up -d --force-recreate api
services:
  sentomaru-render:
    image: hashicorp/vault:1.18.3
    command: ["agent", "-config=/agent/agent.hcl"]
    volumes:
      - ./agent.hcl:/agent/agent.hcl:ro
      - ./sentomaru.env.ctmpl:/agent/sentomaru.env.ctmpl:ro
      - ${AGENT_AUTH_DIR:-/opt/minha-api/agent-auth}:/agent/auth:ro      # role-id / secret-id of a read-only AppRole
      - ${RENDERED_DIR:-/opt/minha-api/rendered}:/rendered
    restart: "no"

  api:
    image: registry.example/minha-api:1.0.0
    depends_on:
      sentomaru-render:
        condition: service_completed_successfully
    env_file:
      - ${RENDERED_DIR:-/opt/minha-api/rendered}/sentomaru.env           # rendered by the agent, 0600, never versioned
    environment:
      ASPNETCORE_ENVIRONMENT: Production
      Sentomaru__Enabled: "true"
      Sentomaru__FailOpen: "false"
      Sentomaru__BaseAddress: https://sentomaru.example
      Sentomaru__PublicBaseUrl: https://api.minha-empresa.example
      Sentomaru__Org: minha-org
      Sentomaru__App: meu-app
      Sentomaru__Env: prod
    restart: always
```

<!-- source: integrations/samples/aspnetcore-third-party/deploy/sentomaru.env.ctmpl -->
```
{{- /* C-09 (#142): one line, from the secret store; the value is never written anywhere else. */ -}}
{{- with secret "secret/data/minha-api/sentomaru" -}}
Sentomaru__WorkloadToken={{ .Data.data.workloadToken }}
{{- end }}
```

<!-- source: integrations/samples/aspnetcore-third-party/deploy/agent.hcl -->
```hcl
# C-09 (#142): read-only AppRole; renders sentomaru.env (0600) for docker compose's env_file, then exits
# (exit_after_auth): the api container starts after it (depends_on) and reads the file once, at creation.
exit_after_auth = true

vault {
  address = "https://vault.minha-empresa.example"
}

auto_auth {
  method "approle" {
    config = {
      role_id_file_path                   = "/agent/auth/role-id"
      secret_id_file_path                 = "/agent/auth/secret-id"
      remove_secret_id_file_after_reading = false
    }
  }
}

template {
  source      = "/agent/sentomaru.env.ctmpl"
  destination = "/rendered/sentomaru.env"
  perms       = "0600"
  error_on_missing_key = true
}
```

**Rotação:** o Docker lê o `env_file` quando **cria** o contêiner. Depois de girar o token no cofre, renderize de novo
e recrie o backend (`docker compose run --rm sentomaru-render && docker compose up -d --force-recreate api`). Confira
depois do deploy que a variável está **dentro** do contêiner (`docker exec <api> printenv Sentomaru__WorkloadToken | wc
-c` maior que 1, sem imprimir o valor): um `.env` solto no servidor que o contêiner não lê deixa o adaptador sem
credencial.

## 4. Rotas de inscrição no seu backend

**Desafio.** O app chama `POST <PublicBaseUrl>/integrity/challenges` com a sessão do usuário (o cabeçalho de login do
seu app) e corpo JSON `{"publicKeyPem": null}` (a chave nasce depois, com o `attestationChallenge`). A resposta 201
é o desafio do Sentomaru, repassado como veio (`ChallengeResponseDto`):

| Campo | Conteúdo |
|---|---|
| `challengeId` | UUID; é o `keyid` da assinatura da inscrição e volta como `keyId` do vínculo (o SDK recusa um vínculo com `keyId` diferente do `challengeId`) |
| `challenge` | token aleatório (base64 de 32 bytes) que entra no corpo assinado da inscrição |
| `attestationChallenge` | 32 bytes em base64url, passados crus ao Keystore (`setAttestationChallenge`) |
| `expiresAt` | validade (120 s pelo relógio do servidor) |

Sem login a rota responde 401 sem chamar o Sentomaru; com login mas sem sujeito ou tenant, 403
`caller-context-missing`. O exemplo, sozinho, **não registra autenticação** (o login é do terceiro): rodado como está,
o desafio responde sempre 401 até você registrar o seu esquema (`AddAuthentication`) que preenche `HttpContext.User`;
os testes usam um esquema de teste.

<!-- source: integrations/samples/aspnetcore-third-party/EnrollmentController.cs#challenge -->
```csharp
[HttpPost("challenges")]
public async Task<IActionResult> Challenge([FromBody] ChallengeInput? input, CancellationToken ct)
{
    // Your authentication sets HttpContext.User; subject and tenant come from it, never from the app's body.
    if (User.Identity?.IsAuthenticated != true) return Unauthorized();
    var caller = callers.ResolveContext(HttpContext);
    if (string.IsNullOrEmpty(caller.Subject) || string.IsNullOrEmpty(caller.Tenant))
        return StatusCode(StatusCodes.Status403Forbidden, new SentomaruApiError { Code = "caller-context-missing" });
    var result = await sentomaru.IssueChallengeAsync(new ChallengeRequestDto
    {
        Subject = caller.Subject, Tenant = caller.Tenant, PublicKeyPem = input?.PublicKeyPem,
    }, ct);
    return result.Succeeded
        ? StatusCode(StatusCodes.Status201Created, result.Value)
        : StatusCode(result.StatusCode, new SentomaruApiError { Code = result.ErrorCode ?? "integrity-error" });
}
```

**Inscrição.** O app assina esta URL exata; o caminho termina em `/v1/{org}/{app}/{env}/installations`, e o prefixo
antes dele é livre (aqui, `/integrity`). A resposta 201 traz `installationId`, `keyId`, `sessionId`,
`hardwareStatus`, `attestationStatus` e `attestationReason`. Se a política **publicada** do escopo (em modo `active`)
exige hardware, a inscrição de chave em software é recusada com 422 `hardware-not-proven` **mesmo que o app não tenha
pedido hardware**; repasse ao app como está, sem tentar de novo com a mesma chave:

<!-- source: integrations/samples/aspnetcore-third-party/EnrollmentController.cs#enrollment -->
```csharp
// The app signs this exact public URL: <PublicBaseUrl>/integrity/v1/{org}/{app}/{env}/installations.
[HttpPost("v1/{org}/{app}/{env}/installations")]
public async Task<IActionResult> Enroll(CancellationToken ct)
{
    ForwardedMessageDto message;
    try
    {
        message = await SentomaruExtractor.ExtractAsync(Request, null, options.Value, ct);
    }
    catch (SentomaruBodyTooLargeException)
    {
        return StatusCode(StatusCodes.Status413PayloadTooLarge, new SentomaruApiError { Code = "body-limit" });
    }
    var result = await sentomaru.CompleteEnrollmentAsync(new EnrollmentEnvelopeDto { Request = message }, ct);
    return result.Succeeded
        ? StatusCode(result.StatusCode, result.Value)
        : StatusCode(result.StatusCode, new SentomaruApiError { Code = result.ErrorCode ?? "integrity-error" });
}
```

**No app**, `SentomaruClient.enroll(challenge) { signed -> ... }` gera a chave, monta e assina a mensagem; o bloco
recebe a `SignedMessage` (método, URL, cabeçalhos e corpo congelado), a envia ao seu backend sem alterar nada e
devolve o `EnrollmentGrant` da resposta. Exemplo mínimo com OkHttp:

<!-- illustrative: Kotlin do app, não compilado pelo CI; a API usada é a de sdk/android/sdk (SentomaruClient.enroll) -->
```kotlin
// 1. Desafio: POST https://api.example.invalid/integrity/challenges (sessão do usuário já autenticada no seu app)
val json = JSONObject(http.newCall(Request.Builder().url("$base/integrity/challenges")
    .post("{}".toRequestBody("application/json".toMediaType())).build()).execute().use { it.body!!.string() })
val challenge = EnrollmentChallenge(
    id = json.getString("challengeId"),
    token = json.getString("challenge"),
    attestationChallenge = Base64.getUrlDecoder().decode(json.getString("attestationChallenge")),
    expiresAt = Instant.parse(json.getString("expiresAt")),
)

// 2. Inscrição: o SDK gera a chave, monta e assina a mensagem; o bloco só a envia como está.
val grant = sentomaru.enroll(challenge) { signed ->
    val request = Request.Builder().url(signed.targetUri) // = SentomaruConfig.enrollmentUrl
        .method(signed.method, signed.body().toRequestBody("application/json".toMediaType()))
        .apply { signed.headers.forEach { (name, value) -> header(name, value) } }
        .build()
    http.newCall(request).execute().use { response ->
        check(response.code == 201 || response.code == 200) { "enrollment ${response.code}" }
        val g = JSONObject(response.body!!.string())
        EnrollmentGrant(g.getString("installationId"), g.getString("keyId"), g.getString("sessionId"),
            g.getString("hardwareStatus"), g.getString("attestationStatus"))
    }
}
```

A `SentomaruConfig` do app aponta `enrollmentUrl` para a rota de inscrição acima e lista o host do seu backend em
`allowedHosts`.

### Capacidades do backend (opt-in; avalie a exposição)

Uma rota do **seu** backend diz ao app o que ele verifica: se a verificação está ligada e quais operações protege,
cada uma com `enforced` (true = ZeroTrust, recusa sem prova válida; false = Observe; com dois níveis para a mesma
operação, vale o mais fraco). Ela não tem token, endereço do Sentomaru, escopo, versão nem FailOpen. O que expõe (os
nomes das operações protegidas e se bloqueiam) já está no binário do app que as assina, mas mapeá-la é decisão sua:
`MapSentomaruCapabilities(configure: o => { o.RequireAuthorization = true; o.RateLimitingPolicy = "..."; })` exige
login e aplica uma política do seu `AddRateLimiter`. A resposta é calculada uma vez e vai com `Cache-Control` (padrão
300 s; `private` quando exige login). O app a lê no início (seção 7a) e o CI do app a confere antes de publicar
(seção 8, passo 9). A resposta não traz o escopo: a checagem de escopo (o backend servir outro org/app/env) saiu do
plugin e do smoke de release para não expor o escopo a qualquer chamador; o escopo continua amarrado à
credencial de workload do backend, que só vale para o próprio escopo. Consequência: um app de HML apontando para o
backend de produção (ou o contrário) não é mais detectado pela rota; só o processo o pega, pela variável de URL do
backend que o CI do app passa ao smoke e ao build de cada ambiente (seção 8, passo 9).

<!-- source: integrations/samples/aspnetcore-third-party/SampleApp.cs#capabilities -->
```csharp
// C-09 (#143): GET /integrity/capabilities, public, no token: what this backend enforces, read by the app at
// bootstrap and by the release smoke test.
app.MapSentomaruCapabilities();
```

### Teste de contrato das suas rotas

Copie e cole na suíte de testes do seu backend (qualquer framework: cada checagem devolve `null` quando o contrato
vale, ou o motivo). Precisa de um `HttpClient` para o seu backend (anônimo na primeira checagem; autenticado como um
usuário conhecido na segunda) e, na segunda, de um jeito de ler o que o seu backend mandou ao Sentomaru (um
transporte falso do Sentomaru nos seus testes, como faz `ThirdPartySampleTests`):

<!-- source: integrations/samples/aspnetcore-third-party/ConsumerContract.cs#contract -->
```csharp
/// <summary>
/// C-09 (#142): contract checks to copy into the test suite of YOUR backend (any test framework: each returns null when
/// the contract holds, or the reason it does not). The challenge route must take subject/tenant from the authenticated
/// session, never from the body. Needs: an HttpClient to your backend (anonymous for the first check, authenticated
/// as a known user for the second), and, for the second, a way to read what your backend sent to Sentomaru (a fake
/// Sentomaru transport in your tests, as ThirdPartySampleTests does).
/// </summary>
public static class ConsumerContract
{
    private const string Body = """{"subject":"someone-else","tenant":"another-tenant"}""";

    /// <summary>Anonymous call that claims an identity in the body: 401, or 403 with code caller-context-missing.</summary>
    public static async Task<string?> ChallengeRefusesAnonymousCallerAsync(HttpClient anonymous,
        string path = "/integrity/challenges", CancellationToken ct = default)
    {
        using var content = new StringContent(Body, Encoding.UTF8, "application/json");
        using var response = await anonymous.PostAsync(path, content, ct);
        if (response.StatusCode == HttpStatusCode.Unauthorized) return null;
        if (response.StatusCode == HttpStatusCode.Forbidden &&
            await CodeAsync(response, ct) == "caller-context-missing") return null;
        return $"{path} answered {(int)response.StatusCode} to an anonymous caller; expected 401, or 403 caller-context-missing";
    }

    /// <summary>Authenticated call whose body names someone else: the challenge goes out for the SESSION caller.</summary>
    public static async Task<string?> ChallengeUsesTheSessionCallerAsync(HttpClient authenticated,
        Func<(string Subject, string Tenant)?> lastSentToSentomaru, string sessionSubject, string sessionTenant,
        string path = "/integrity/challenges", CancellationToken ct = default)
    {
        using var content = new StringContent(Body, Encoding.UTF8, "application/json");
        using var response = await authenticated.PostAsync(path, content, ct);
        if (!response.IsSuccessStatusCode) return $"{path} answered {(int)response.StatusCode} to an authenticated caller";
        var sent = lastSentToSentomaru();
        return sent == (sessionSubject, sessionTenant)
            ? null
            : $"{path} sent {sent?.Subject}/{sent?.Tenant} to Sentomaru instead of the session caller {sessionSubject}/{sessionTenant}";
    }

    private static async Task<string?> CodeAsync(HttpResponseMessage response, CancellationToken ct)
    {
        try
        {
            using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
            return doc.RootElement.TryGetProperty("code", out var code) ? code.GetString() : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
```

### Renovação da sessão (J-04r, adaptador 4.1.0)

O vínculo (grant) que a inscrição devolve vale **10 minutos**. Para o app não cair em `session-expired` numa sessão
longa, exponha uma rota pública de renovação e configure-a no app (`renewalUrl`, SDK Android e plugin 0.9.0). A rota
repassa o pedido assinado do app, como veio, com `SentomaruExtractor.ExtractAsync` e
`ISentomaruClient.RenewSessionAsync(new SessionRenewalEnvelopeDto { Request = forwarded })`, e devolve ao app a
resposta (200 com `sessionId` e `ttlSeconds`) ou o erro tal como o Sentomaru respondeu. O `context` (sujeito e tenant)
é opcional: o app renova pelo transporte nativo, sem a sessão do usuário, e quem autoriza é a chave da instalação; se
mandar, tem de ser o chamador da instalação. A renovação não exige nova atestação e é idempotente: repetir com o mesmo
vínculo devolve o mesmo vínculo novo, e o antigo vale até vencer. A cadeia termina 7 dias depois da inscrição (padrão,
`chainExpiresAt` na resposta; o vínculo novo nunca vence depois dele). Revogar um vínculo revoga a cadeia inteira.
Recusas: `proof-invalid` (401), `session-unavailable` (reinscrever: vínculo ou instalação revogados, teto da cadeia,
aparelho sem hardware onde a política **publicada** exige; nesse escopo a inscrição já recusa a chave em software com 422 `hardware-not-proven`), `operation-context`, `replay`, `rate-limited`. Repasse ao app só essas; um
401 ou 403 da credencial do seu backend (workload) e um 5xx são problema do seu lado: responda 502/503 com código próprio.

**Suspensão temporária (contrato v1.5, adaptador 4.3.0).** Uma instalação suspensa por um operador ou por uma regra de
resposta recebe `403 installation-suspended` na avaliação e na renovação, mas só quando a prova foi feita com a chave
dela. Qualquer outra chave recebe `session-unavailable`. O app **espera e tenta mais tarde; não reinscreve**: a suspensão
acaba sozinha no prazo ou quando o operador a libera. Repasse esse 403 ao app. O adaptador 4.2.0 o transformava em 502,
então atualize para o 4.3.0 **antes** de alguém suspender instalações em uso ou publicar regra `suspend`. A quarentena
(revogação) continua `session-unavailable`: reinscrever.

**Depois de atualizar o app (D-04b, plugin 0.10.0).** A evidência de build gravada na inscrição (`versionCode`
atestado) é da versão que se inscreveu. Quando o `versionCode` muda, `reenrollmentReason()` responde `APP_UPDATED`
(Flutter: `ReenrollmentReason.appUpdated`) e a instalação continua assinando. Peça um desafio novo e chame
`rotate(challenge)` (ou `reset()` + `enroll(challenge)`): a chave nova traz atestação nova. A reinscrição cria uma
instalação nova no servidor (`installationId` e código `INS-…` novos), como qualquer rotação.

> **Cuidado com laço.** Consulte `reenrollmentReason()` **uma vez no cold start** (depois do `initialize`) e, se ela
> pedir, reinscreva uma vez. Não a chame em volta de cada requisição nem repita a rotação em seguida se ela falhar ou se
> o pedido continuar: tente de novo no próximo cold start. Cada rotação gasta um desafio e cria uma instalação no
> servidor. Peça um desafio **novo** cada vez que a consulta pedir: reaproveitar o desafio de uma rotação interrompida
> só recupera o grant antigo (o servidor devolve o mesmo grant ao reenvio idêntico e recusa outro corpo com 409), e a
> consulta continua pedindo.

Nas rotas protegidas, devolva ao app o 403 do Sentomaru **com o `code`** (`session-expired`): o SDK renova e reenvia uma
vez. Em `Observe` o adaptador não bloqueia e o app não vê a recusa; a renovação antecipada do SDK cobre esse caso.

## 5. Proteger uma ação

Operação protegida (`ZeroTrust`, o padrão): a ação só roda com veredito `allow`.

<!-- source: integrations/samples/aspnetcore-third-party/OrdersController.cs#protected-action -->
```csharp
[HttpPost("{id}/concluir")]
[SentomaruIntegrity("concluir_pedido")] // ZeroTrust (default): runs only on an allow verdict
public IActionResult Complete(string id)
{
    store.Complete(id);
    return Ok(new { id, status = "concluido" });
}
```

**Nova tentativa da mesma operação.** Quando o app manda `x-sentomaru-operation-id` (assinado), a primeira admissão
roda a ação e uma nova tentativa do mesmo id, por 24 h, não roda de novo: por padrão o adaptador responde 409
`operation-replayed` ("feita ou em andamento"). Uma ação que guarda o resultado por id declara
`AllowOperationReplay = true` e devolve o que guardou:

<!-- source: integrations/samples/aspnetcore-third-party/OrdersController.cs#replay-action -->
```csharp
[HttpPost("{id}/pagar")]
[SentomaruIntegrity("pagar_pedido", AllowOperationReplay = true)]
public IActionResult Pay(string id)
{
    var operationId = HttpContext.Items[SentomaruIntegrityAttribute.OperationIdItem] as string;
    var firstAdmission = HttpContext.Items[SentomaruIntegrityAttribute.FirstAdmissionItem] as bool?;
    if (operationId is not null && firstAdmission == false)
    {
        // A retry of an operation already admitted: return what was stored, never charge again. The charge and
        // its receipt are written in one transaction (OrderStore.Charge), so no receipt means no charge: the first
        // attempt is still running, or it died before committing. Neither may be charged again here (the first
        // could still commit), so the app gets 409 and asks later; after a crash that lasts until the id expires
        // (24 h) or the app starts a new operation with a new id.
        return store.ReceiptFor(operationId) is { } stored
            ? Ok(new { id, receipt = stored })
            : Conflict(new { code = "operation-in-progress" });
    }
    return Ok(new { id, receipt = store.Charge(id, operationId) });
}
```

Regras:

- **Grave o efeito e o resultado por id na mesma transação** (no exemplo, `OrderStore.Charge`). Assim "sem resultado
  guardado" quer dizer "sem efeito", e a nova tentativa nunca aplica em dobro.
- **409 residual:** se o processo cair depois da admissão e antes de a transação confirmar, nada foi aplicado, mas o id
  continua admitido no Sentomaru (a liberação não chegou a rodar). A nova tentativa recebe 409 (`operation-in-progress`
  no exemplo) até o id vencer, em 24 h, ou até o app recomeçar a operação com um id novo. A ação não deve aplicar o
  efeito nesse caso: a primeira tentativa ainda pode estar em curso.
- Não devolva 5xx depois de aplicar o efeito: um 5xx, ou exceção não tratada, **libera** o id e a nova tentativa
  aplicaria de novo. Um 4xx mantém o id. Só um `allow` grava o id: uma recusa é reavaliada na nova tentativa.

**`Observe` não protege.** A ação sempre roda; havendo prova, o veredito vai só para o log. Use apenas em operações
conscientemente desprotegidas (por exemplo, para medir antes de ligar a proteção):

<!-- source: integrations/samples/aspnetcore-third-party/OrdersController.cs#observe-action -->
```csharp
[HttpGet("{id}")]
[SentomaruIntegrity("consultar_pedido", DeviceAssuranceLevel.Observe)] // telemetry only: NOT protected
public IActionResult Get(string id) => Ok(new { id });
```

### 5a. Proteger no gateway, sem o adaptador (D-17)

Para backend fora do ASP.NET Core, ou para proteger a borda sem mexer nele, o serviço
`integrations/gateway/Sentomaru.Gateway.Verifier/` toma as mesmas decisões do `[SentomaruIntegrity]` atrás de um gateway.
O contrato do verificador, com a lista fechada de divergências, é entregue pela operação do Sentomaru, e o exemplo de deploy
está em `integrations/gateway/envoy/`. O verificador só existe como código-fonte neste repositório, sem imagem nem
pacote publicados, e nunca rodou em HML. Só o Envoy tem exemplo e prova; o OpenResty (D-17e) não foi feito.

Antes de ligar, confira cada item. O exemplo do Envoy já cumpre os três primeiros:

1. **Vhost inteiro.** Toda rota passa pelo verificador, salvo as isenções, com método e caminho exatos. O que não está na
   tabela recebe 403 `operation-unmapped`, então declare todas as rotas do vhost.
2. **Cabeçalhos.** O gateway apaga `sentomaru-verified-*` e `sentomaru-caller-*` do cliente em toda rota, inclusive nas
   isentas, e recusa cabeçalho do perfil repetido e nome com sublinhado.
3. **Uma execução.** Sem `retry_policy`, `hedge_policy` nem `request_mirror_policies`. Depois de um 5xx do upstream, a
   nova tentativa com o mesmo operation id recebe 409 `operation-replayed`; rota que precisa repetir usa
   `allowOperationReplay` com idempotência no upstream.
4. **Rede.** O upstream e o verificador só são alcançados pelo gateway. Com o chamador `trusted-header`, o verificador
   só parte em loopback, IP privado (RFC 1918 ou `fc00::/7`) ou socket Unix; ele não prova quem alcança um IP privado, e isso fica com você.
5. **Conferência no upstream.** Trate como verificada só a requisição com `sentomaru-verified-verdict` igual a `allow` ou
   `shadow` e sem `sentomaru-verified-observed`. Confira também que o usuário da sua sessão é
   `sentomaru-verified-subject` e `sentomaru-verified-tenant`, ou autentique pela mesma credencial que o verificador leu e
   por nenhuma outra. Sem isso, a prova do usuário A pode acompanhar a sessão do usuário B.
6. **Sem o atributo.** Rota protegida no gateway não leva `[SentomaruIntegrity]` no upstream: a segunda avaliação daria
   `replay`.
7. **Credencial própria.** Crie uma credencial do tipo `gateway-verifier` para o verificador, com um único escopo, e guarde o
   token no `workloadTokenFile`. Ela só chama `POST /v1/{org}/{app}/{env}/evaluations`: em outra rota de workload a API
   responde 403 `workload-kind`, e em outro escopo 403 `workload-scope`. Todo o resto (inscrição, revogação, renovação, desafio, reatestação,
   consulta, liberação) continua com a credencial `consumer` do seu backend. Se o verificador usar uma credencial recusada, o gateway responde 503 `integrity-unavailable`.
   Um verificador já implantado com `consumer` segue funcionando até você rotacionar.

Numa rota `observe`, o verificador sempre responde 200: a passagem não dependeu do veredito, e os cabeçalhos servem só para log.

## 6. Respostas do adaptador

| Situação | Status e `code` | A ação roda? |
|---|---|---|
| Sessão sem sujeito ou tenant (ou com `anonymous`/`default`) | 403 `caller-context-missing` (sem chamar o Sentomaru; em `Observe` a ação roda e nada é enviado) | não |
| Desafio com sujeito ou tenant reservados, vindo de um adaptador antigo | 400 `caller-context-reserved` (do Sentomaru) | não (a rota de desafio) |
| Sem `Signature`/`Signature-Input` | 401 `proof-required` (sem chamar o Sentomaru; `FailOpen` não muda isso) | não |
| Prova inválida, expirada ou de outro escopo | o status e o código do Sentomaru (ex.: 401 `proof-invalid`, 403) | não |
| Veredito `deny` | 403 com o primeiro código de razão da política (ou `policy-denied`) | não |
| Veredito `challenge` | 401 `challenge-required`, com `challengeKind` desde a 4.5.0 quando a regra declara um tipo (`fresh_signals`: o app manda sinais válidos; `step_up`: o consumidor pede reautenticação, que o Sentomaru não verifica; `reattest` desde a 4.6.0: o app reatesta, o Sentomaru confere; um tipo mais novo que o adaptador sai bruto e nunca chama o gancho) | não; sim só em `step_up`, sem id de operação assinado, se o `ISentomaruChallengeHandler` do consumidor devolver `Proceed` |
| Nova tentativa de um id já admitido | 409 `operation-replayed`, salvo `AllowOperationReplay` | não (ou a sua ação, com `AllowOperationReplay`) |
| Mesmo id com outro conteúdo | 409 `operation-conflict` (do Sentomaru) | não |
| Corpo acima de 64 KiB | 413 `body-limit` | não |
| Sentomaru fora (tempo esgotado, 503, rede) | 503 (`store-unavailable` ou `integrity-unavailable`); `FailOpen` só vale em `Development` | não |
| Resposta inesperada do Sentomaru (corpo vazio ou ilegível, erro não previsto) | 500 `internal-error` | não |
| `ISentomaruClient` não registrado | 503 `integrity-unavailable` | não |
| Veredito `allow` (ou `shadow`) | o resultado da sua ação | sim |

O tempo limite de cada chamada ao Sentomaru é `Timeout` (padrão 2 s), uma chamada por requisição.

**Qual política vale.** A avaliação traz `policySource`: `published` (uma política publicada para o escopo) ou
`default` (a política embutida, quando o escopo não tem nenhuma publicada), junto de `policyId` e `policyVersion`;
`GET …/policy` traz o cabeçalho `Sentomaru-Policy-Source`. O adaptador registra um log Warning, uma vez por processo,
quando a política em vigor é a embutida: publique a sua antes de depender de regras próprias.

## 7. O que o app envia

O SDK monta e assina tudo; o app escolhe a operação e, se quiser efeito único, o id da operação.

| Cabeçalho | Valor | Assinado |
|---|---|---|
| `Signature-Input`, `Signature` | prova RFC 9421 (`ecdsa-p256-sha256`, validade de até 60 s, nonce único) | — |
| `content-type`, `content-digest` | `application/json` e o SHA-256 do corpo exato enviado | sim |
| `x-sentomaru-profile`, `x-sentomaru-org`, `x-sentomaru-app`, `x-sentomaru-environment` | perfil e escopo | sim |
| `x-sentomaru-session` | sessão do vínculo da inscrição | sim |
| `x-sentomaru-operation` | o nome da operação (o mesmo de `[SentomaruIntegrity("...")]`) | sim |
| `x-sentomaru-operation-id` (opcional) | 16–64 caracteres `[A-Za-z0-9-]`, gerado uma vez por operação e repetido nas novas tentativas | sim |
| `x-sentomaru-signals` (opcional) | observações do aparelho (catálogo `contracts/sdk/signals-catalog-v1.json`); nunca valem como prova | sim, quando presente |

Android (Kotlin, OkHttp): `OkHttpClient.Builder().addSentomaru(client)` assina as requisições aos hosts de
`SentomaruConfig.allowedHosts` (https, sem redirecionamento para fora da lista). Flutter: plugin `sentomaru_flutter`
com `dio.addSentomaru(client)`. Detalhes: `contracts/sdk/sdk-api-v1.md` e `sdk/android/README.md`. Perfil HTTP
completo: `contracts/p0-http-profile.md`.

Em vez de declarar a operação em cada requisição, o app pode passar na mesma linha a tabela de rotas do perfil da CLI
(G-03c): `addSentomaru(client, SentomaruRoutes.of(hosts, routes))` no Android e
`dio.addSentomaru(client, routes: SentomaruRoutes(...))` no Flutter (plugin 0.8.0). A requisição cujo host e caminho
casam com uma rota é assinada como essa operação ([guia da CLI](../devsecops/CLI_PIPELINE.md) §2b).

Android com `HttpURLConnection` (Java ou Kotlin, SDK desde a S2): a tabela de rotas é montada uma vez e cada chamada
protegida passa por `SentomaruUrlConnection.send`, que faz a troca inteira (renovação, assinatura, redirecionamentos
sob as mesmas regras do OkHttp) e devolve a conexão já respondida. O corpo é um `byte[]` de até 64 KiB, sem streaming;
`Host`, `Content-Length` e `Transfer-Encoding` não podem vir nos cabeçalhos. Uma chamada feita direto por
`url.openConnection()` não é assinada. A evidência é por testes JVM com o `HttpURLConnection` do JDK (`UrlConnectionTransportTest`,
`UrlConnectionJavaTest`) e, desde 20/10/2026, uma execução manual em um aparelho no HML com o `HttpsURLConnection` do Android
(relatório de aparelho da operação, app `java-urlconnection` dos exemplos: assinada aceita, host fora da allowlist recusado
antes de abrir conexão pelo contador do `Opener`, chamada direta com `401 proof-required`). Proxy, redirect e renovação
não foram exercidos em aparelho. Exemplo do app de laboratório (compilado no CI):

<!-- source: sdk/android/sample-app/src/main/java/br/com/ebees/sentomaru/sample/JavaUrlConnectionSample.java#urlconnection-routes -->
```java
this.routes = SentomaruRoutes.of(Collections.singletonList(host),
        Collections.singletonList(new SentomaruRoutes.Route("/v1/pedidos/*", "concluir_pedido")));
```

<!-- source: sdk/android/sample-app/src/main/java/br/com/ebees/sentomaru/sample/JavaUrlConnectionSample.java#urlconnection-send -->
```java
try {
    HttpURLConnection connection = SentomaruUrlConnection.send(sentomaru, routes, "POST", url,
            json.getBytes(StandardCharsets.UTF_8), Collections.singletonMap("Authorization", "Bearer " + bearer));
    int status = connection.getResponseCode();
    InputStream body = status < 400 ? connection.getInputStream() : connection.getErrorStream();
    if (body != null) body.close();
    return status;
} catch (SentomaruException refused) {
    return -1; // typed: HostNotAllowed, NotEnrolled, BodyTooLarge, InvalidRequest:...
}
```

### 7a. Flag do app e estado do backend (plugin 0.7.0)

O app não deve descobrir no primeiro 503 do usuário que o backend não verifica o que ele marca. No início, ele lê a
rota de capacidades. Com o backend desligado ele registra o desencontro e não marca nenhuma operação; uma operação que
o backend não protege também deixa de ser marcada. Essas chamadas seguem sem prova; as operações protegidas continuam
marcadas e são decididas pelo backend. É configurável com `SentomaruMismatchPolicy.keep`. Rota inacessível conta como
desconhecido e mantém a configuração do build.

<!-- source: sdk/flutter/sentomaru_flutter/test/sentomaru_capabilities_test.dart#capabilities-bootstrap -->
```dart
// Once at bootstrap: does the backend verify what this build marks? (Sentomaru.AspNetCore 4.x capabilities route)
final capabilities = await SentomaruCapabilities.fetch(dio, Uri.parse('$apiBase/integrity/capabilities'));
final gate = SentomaruCapabilityGate(
  appEnforces: enforce, // e.g. your SENTOMARU_ENFORCE build flag
  operations: const ['criar_demanda', 'concluir_demanda'],
  onMismatch: (m) => log('sentomaru capabilities mismatch: ${m.name}'), // a log, never a user-facing error
)..evaluate(capabilities);
// Per request: mark the operation only when the gate says so (backend off = plain call, the user is not blocked).
// options.extra['sentomaru_operation'] = gate.shouldMark('criar_demanda') ? 'criar_demanda' : null;
```

### 7b. O que fazer com o `onRiskEvent` no app

Hoje **nenhum componente do Sentomaru emite `riskEvent`**: o callback só dispara se o seu backend incluir esse membro
numa resposta de erro. O sinal é consultivo. Use-o só para **acrescentar atrito** a uma ação sensível (pedir que o
usuário confirme de novo) e nunca para liberar, bloquear ou pular uma verificação: a decisão é sempre do servidor, em
cada requisição.

<!-- source: sdk/flutter/sentomaru_flutter/test/sentomaru_capabilities_test.dart#risk-event -->
```dart
// Advisory only: ask the user to confirm a sensitive action again (friction), never block, never trust it as "safe".
// The server already decided this request; an absent or low event proves nothing.
return event.riskBand == 'high' || (event.riskIndex ?? 0) >= 80;
```

O relógio do aparelho precisa estar certo: a assinatura não pode ser criada mais de 30 s no futuro em relação ao
servidor.

### 7c. Sinais RASP da D-05: medir em sombra antes de qualquer regra (catálogo 1.3.0)

Seis sinais novos, **declarados pelo app** (`client_observed`) e **por opção**: `debugger_attached`, `app_debuggable`,
`dev_settings_enabled`, `root_artifacts`, `emulator_indicated` e `hook_framework_java`. O caminho padrão não muda: sem
opção o SDK manda só os seis sinais antigos. Para mandar os novos, no Android o app depende do artefato
`signals-rasp` e coleta com `SignalsCollector.defaultDetectors() + SignalsCollector.raspDetectors()` e
`deadlineMs = SignalsCollector.RASP_DEADLINE_MS` (`sdk/android/README.md`); no Flutter, `collectSignalsSnapshot(rasp:
true)` do plugin 0.12.0, com o `signals-rasp` declarado no app hospedeiro. Quando o cabeçalho `x-sentomaru-signals`
vai na requisição, ele entra na assinatura feita com a chave atestada da instalação: o servidor sabe que o snapshot
saiu do processo que guarda essa chave e não foi alterado no caminho. Não sabe se ele é verdadeiro: um processo
instrumentado (Frida, LSPosed) ou um root oculto pode trocar os valores antes da assinatura. `NOT_DETECTED` quer dizer
"não detectado nesta coleta". O que cada sinal vê, o custo medido e os contornos constam na ficha de alegações do Shield Android, mantida pela operação do Sentomaru.

Nenhum desses sinais entra na política padrão. Publique primeiro uma política em **sombra** no escopo que vai medir:
o servidor avalia as regras e devolve o que elas dariam (`evaluatedAction`), mas a recomendação
(`recommendedAction`) de um `deny` ou `challenge` continua `allow`. O exemplo abaixo usa
`challenge`, nunca `deny`, e deixa `sensitiveOperations` vazio. Com operações sensíveis listadas, um app que ainda não
manda os sinais novos ganharia `challenge` `SIGNALS_MISSING` em toda operação sensível. `dev_settings_enabled` fica de
fora de propósito: opções de desenvolvedor e ADB ligados são comuns em aparelho legítimo. O servidor conta à parte
quantas avaliações aceitas trouxeram cada estado de cada sinal, assinado ou não (`integrity.signal_observation_count`):
é esse número que decide se alguma regra sai da sombra, e essa decisão é do dono do escopo.

<!-- source: docs/api/examples/policy-rasp-shadow-example.json -->
```json
{
  "schemaVersion": "1.0.0",
  "policyId": "pol_rasp_lab_hml_shadow_v1",
  "version": "1.0.0",
  "organization": "ebees",
  "app": "rasp-lab",
  "environment": "hml",
  "enforcementMode": "shadow",
  "description": "Exemplo D-05f: sinais RASP da D-05 (declarados pelo app) medidos em sombra. Nada é recusado; o veredito real é allow.",
  "sensitiveOperations": [],
  "rules": [
    {
      "ruleId": "rule_shadow_root_artifacts",
      "name": "Sombra: indício de root declarado pelo app",
      "priority": 10,
      "action": "challenge",
      "reasonCode": "RASP_ROOT_ARTIFACTS",
      "conditions": {
        "signalRules": [{ "capabilityId": "root_artifacts", "operator": "equals", "expectedState": "DETECTED" }]
      }
    },
    {
      "ruleId": "rule_shadow_hook_java",
      "name": "Sombra: framework de hook Java declarado pelo app",
      "priority": 20,
      "action": "challenge",
      "reasonCode": "RASP_HOOK_FRAMEWORK_JAVA",
      "conditions": {
        "signalRules": [{ "capabilityId": "hook_framework_java", "operator": "equals", "expectedState": "DETECTED" }]
      }
    },
    {
      "ruleId": "rule_shadow_debugger",
      "name": "Sombra: depurador Java (JDWP) declarado pelo app",
      "priority": 30,
      "action": "challenge",
      "reasonCode": "RASP_DEBUGGER_ATTACHED",
      "conditions": {
        "signalRules": [{ "capabilityId": "debugger_attached", "operator": "equals", "expectedState": "DETECTED" }]
      }
    },
    {
      "ruleId": "rule_shadow_emulator",
      "name": "Sombra: indício de emulador declarado pelo app",
      "priority": 40,
      "action": "challenge",
      "reasonCode": "RASP_EMULATOR_INDICATED",
      "conditions": {
        "signalRules": [{ "capabilityId": "emulator_indicated", "operator": "equals", "expectedState": "DETECTED" }]
      }
    },
    {
      "ruleId": "rule_shadow_app_debuggable",
      "name": "Sombra: app em execução com FLAG_DEBUGGABLE",
      "priority": 50,
      "action": "challenge",
      "reasonCode": "RASP_APP_DEBUGGABLE",
      "conditions": {
        "signalRules": [{ "capabilityId": "app_debuggable", "operator": "equals", "expectedState": "DETECTED" }]
      }
    },
    {
      "ruleId": "rule_allow_default",
      "name": "Permitir o resto",
      "priority": 100,
      "action": "allow",
      "reasonCode": "POLICY_DEFAULT_ALLOW",
      "conditions": {}
    }
  ]
}
```

O teste `Rasp_shadow_example_policy_is_valid_shadow_and_never_denies` (teste do validador de política do Sentomaru)
confere que este arquivo passa pelo validador de publicação, está em sombra, não nega e só cita os seis sinais da D-05.
O escopo do exemplo é o do laboratório da D-05g (`ebees/rasp-lab/hml`); para usar em outro escopo, troque
`organization`, `app`, `environment` e `policyId`.

### 7d. Degraus por regra, tipo de desafio e eventos no app (D-06/D-15, adaptador 4.5.0, plugin 0.14.0; `reattest` desde o adaptador 4.6.0 e o plugin 0.15.0)

A política decide por regra se o achado é contado, desafiado ou recusado. Cada regra pode declarar `stage`:
`observe` (a regra casa, aparece em `observedRules` e é contada, mas nunca entra na recomendação) ou `enforce` (entra
na recomendação, como uma regra sem `stage` numa política `active`). Um `challenge` pode declarar `challengeKind`:
`fresh_signals` (o app manda sinais novos assinados e o Sentomaru confere) ou `step_up` (o **consumidor** pede ao
usuário que se autentique de novo; o Sentomaru não verifica o step-up nem guarda estado dele) ou, desde o contrato
v1.10, `reattest` (o app reatesta e o Sentomaru confere; abaixo). O validador recusa em
`prod` um `deny` fora de `observe` sobre sinal declarado pelo app (`client-signal-deny-prod`); fora de `prod` aceita
com aviso (`client-signal-deny`). A política padrão embutida não usa degraus.

Suba uma regra devagar: `observe` → `enforce` com `challenge` → `enforce` com `deny`, este só sobre sinal verificado
pelo servidor. O Estúdio de políticas do Console mostra o degrau, o tipo e quantas vezes cada regra casou nas últimas
24 h, 7 ou 30 dias (`integrity.policy_rule_count`, um piso: um envio perdido do contador não volta); promover cria a
versão seguinte do rascunho, que outro operador aprova. O exemplo abaixo é a escada do laboratório
(`ebees/rasp-lab/hml`): emulador só contado, root declarado pede step-up ao consumidor, identidade do app verificada
pelo servidor recusa.

<!-- source: docs/api/examples/policy-rasp-ladder-example.json -->
```json
{
  "schemaVersion": "1.0.0",
  "policyId": "pol_rasp_lab_hml_ladder_v1",
  "version": "2.0.0",
  "organization": "ebees",
  "app": "rasp-lab",
  "environment": "hml",
  "enforcementMode": "active",
  "description": "Exemplo D-06a: degraus por regra. Emulador só contado (observe); root declarado pede step-up ao consumidor; identidade do app verificada pelo servidor recusa.",
  "sensitiveOperations": [],
  "rules": [
    {
      "ruleId": "rule_observe_emulator",
      "name": "Contar: emulador declarado pelo app",
      "priority": 10,
      "action": "challenge",
      "reasonCode": "RASP_EMULATOR_INDICATED",
      "stage": "observe",
      "conditions": {
        "signalRules": [{ "capabilityId": "emulator_indicated", "operator": "equals", "expectedState": "DETECTED" }]
      }
    },
    {
      "ruleId": "rule_stepup_root_artifacts",
      "name": "Desafiar (step-up do consumidor): root declarado pelo app",
      "priority": 20,
      "action": "challenge",
      "reasonCode": "RASP_ROOT_ARTIFACTS",
      "stage": "enforce",
      "challengeKind": "step_up",
      "conditions": {
        "signalRules": [{ "capabilityId": "root_artifacts", "operator": "equals", "expectedState": "DETECTED" }]
      }
    },
    {
      "ruleId": "rule_deny_app_identity",
      "name": "Recusar: identidade do app divergente (verificada pelo servidor)",
      "priority": 30,
      "action": "deny",
      "reasonCode": "APP_IDENTITY_MISMATCH",
      "stage": "enforce",
      "conditions": {
        "signalRules": [{ "capabilityId": "app_identity_mismatch", "operator": "equals", "expectedState": "DETECTED" }]
      }
    },
    {
      "ruleId": "rule_allow_default",
      "name": "Permitir chamadas sem achado",
      "priority": 100,
      "action": "allow",
      "reasonCode": "POLICY_DEFAULT_ALLOW",
      "conditions": {}
    }
  ]
}
```

**Adaptador 4.5.0.** O 401 `challenge-required` traz `challengeKind` quando a regra declarou um tipo (sem tipo, o
corpo é o da 4.4.0; um tipo mais novo que o adaptador sai bruto e nunca chama o gancho). Só para `step_up`, e só em
`ZeroTrust`, o adaptador chama o `ISentomaruChallengeHandler` opcional do consumidor; `Proceed` roda a ação, `Refuse`
(o padrão, também sem gancho) responde o 401. O gancho é onde o consumidor guarda "reautenticou nesta sessão há X
minutos": sem isso o sinal continua DETECTED e a próxima requisição desafia de novo. O exemplo de terceiro tem um
step-up **falso**, que só confere a idade do login (`auth_time`):

<!-- source: integrations/samples/aspnetcore-third-party/StepUpHandler.cs#step-up -->
```csharp
/// <summary>
/// 4.5.0 (D-06b): a FAKE step-up for the sample. A real consumer checks its own reauthentication (a new login, a
/// confirmation it already has); Sentomaru never verifies it and keeps no step-up state. Here the session proves a recent
/// login with the claim "auth_time" (Unix seconds): within <see cref="Window"/> the operation proceeds, otherwise the
/// adapter answers 401 challenge-required with challengeKind step_up and the app asks the user to sign in again. The
/// window is what keeps the next request from being challenged again while the signal stays DETECTED.
/// </summary>
public sealed class StepUpHandler(TimeProvider clock) : ISentomaruChallengeHandler
{
    public static readonly TimeSpan Window = TimeSpan.FromMinutes(5);

    public ValueTask<SentomaruChallengeDecision> HandleAsync(SentomaruChallengeContext challenge, CancellationToken cancellationToken)
    {
        var claim = challenge.HttpContext.User.FindFirstValue("auth_time");
        var recent = long.TryParse(claim, NumberStyles.None, CultureInfo.InvariantCulture, out var seconds) &&
                     clock.GetUtcNow() - DateTimeOffset.FromUnixTimeSeconds(seconds) is var age &&
                     age >= TimeSpan.Zero && age <= Window;
        return ValueTask.FromResult(recent ? SentomaruChallengeDecision.Proceed : SentomaruChallengeDecision.Refuse);
    }
}
```

<!-- source: integrations/samples/aspnetcore-third-party/SampleApp.cs#step-up-registration -->
```csharp
// 4.5.0 (D-06b): optional step_up hook (a fake one in this sample). Without it, a step_up challenge is 401.
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton<ISentomaruChallengeHandler, StepUpHandler>();
```

**Regra do Índice de Risco (D-T1a, contrato v1.13).** Uma política pode recusar a faixa alta do Índice de Risco, por
escopo e por opção. O modelo `risk-index-v1` **não tem calibração**: os pesos são desenho, e nenhuma taxa de falso
positivo foi medida. **Comece em `observe`**, olhe a contagem da regra no Estúdio por tempo suficiente e só então
considere `enforce`. Sem a condição `riskIndex`, o índice nem é calculado e nada muda, inclusive na política padrão.

<!-- source: docs/api/examples/policy-risk-index-observe-example.json -->
```json
{
  "schemaVersion": "1.0.0",
  "policyId": "pol_integrity_lab_hml_risk_observe_v1",
  "version": "1.0.0",
  "organization": "ebees",
  "app": "integrity-lab",
  "environment": "hml",
  "enforcementMode": "active",
  "description": "Exemplo D-T1a: Índice de Risco sem calibração, só contado (observe) para medir falsos positivos antes de recusar.",
  "rules": [
    {
      "ruleId": "rule_risk_index_high",
      "name": "Índice de Risco na faixa alta",
      "priority": 900,
      "action": "deny",
      "reasonCode": "RISK_INDEX_HIGH",
      "stage": "observe",
      "conditions": {
        "riskIndex": { "model": "risk-index-v1", "band": "HIGH" }
      }
    },
    {
      "ruleId": "rule_allow_default",
      "name": "Permitir o restante",
      "priority": 1000,
      "action": "allow",
      "reasonCode": "POLICY_DEFAULT_ALLOW",
      "conditions": {}
    }
  ]
}
```

Em `observe` a regra entra em `observedRules` e em `reasonCodes` e é contada, sem mudar `recommendedAction`. Em
`enforce` a faixa alta dá `deny` com `reasonCode` `RISK_INDEX_HIGH`. A condição só aceita `deny` e esse código. Em
`prod`, a publicação recusa a regra fora de `observe` (`risk-index-deny-prod`); fora de `prod` aceita com aviso
(`risk-index-deny`). O número nunca é respondido nem gravado. Índice com prova válida:

| Chave | Sinais assinados | Índice | Faixa |
|---|---|---|---|
| Hardware atestado | limpos | 0 | baixa |
| Hardware atestado | ausentes | 22 | baixa |
| Hardware atestado | `debug_attached` | 18 | baixa |
| Hardware atestado | `root_indicated` ou `emulator_detected` | 45 | média |
| Hardware sem atestação de plataforma | `root_indicated` | 57 | média |
| Sem hardware | limpos | 40 | média |
| Sem hardware | ausentes | 62 | média |
| Sem hardware | `debug_attached` | 58 | média |
| Sem hardware | `root_indicated` ou `emulator_detected` | 85 | **alta** |
| iOS `device_attested` | limpos | 25 | baixa |
| iOS `device_attested` | ausentes | 48 | média |
| iOS `device_attested` | `debug_attached` | 43 | média |
| iOS `device_attested` | `root_indicated` ou `emulator_detected` | 70 | **alta** |

"Limpos" quer dizer os três sinais em `NOT_DETECTED`, frescos. Snapshot sem assinatura, mesmo com `DETECTED`, conta como
ausente: uma detecção que pode ter sido acrescentada no caminho não recusa ninguém. Num snapshot assinado, qualquer dos
três não observado, vencido ou em outro estado (`UNKNOWN`, por exemplo) também pontua como ausente, salvo se outro estiver
em `DETECTED` com peso maior. Nenhum desses casos chega à faixa alta. Só `root_indicated`, `emulator_detected` e `debug_attached`
entram no cálculo; os sinais da D-05 não entram. Como o sinal é declarado pelo app, quem controla o aparelho pode
omiti-lo e sair da faixa alta. A condição não pode ser combinada com `requiresHardware` na mesma regra
(`risk-index-requires-hardware`): a inscrição lê qualquer `deny` com `requiresHardware` fora de `observe` como exigência
de hardware do escopo, e a promoção da regra para `enforce` passaria a recusar inscrições (desde o contrato v1.14, a regra
em `observe` não recusa). Para exigir hardware, use uma regra separada. Faixa baixa quer dizer "nada observado nesta
coleta", nunca aparelho íntegro.

**Prioridade da regra em `observe`.** Regras em `observe` também entram em `reasonCodes`, por ordem de prioridade, e o
adaptador ASP.NET Core responde o primeiro código numa recusa. Com a regra de risco antes de uma regra imposta, a recusa
da outra regra pode sair como `RISK_INDEX_HIGH`. Dê à regra de risco uma prioridade depois das regras impostas, como o
900 do exemplo. Uma regra `deny` imposta com prioridade menor que 900 sai primeiro.

**Desafio `reattest` (D-06h, contrato v1.10, adaptador 4.6.0 e plugin 0.15.0, ainda não publicados).** A política pode exigir uma
reatestação recente aprovada pelo servidor antes de uma operação: uma regra `challenge` com `challengeKind: reattest`
e a condição `reattestationMaxAgeSeconds` (N, de 12 h a 30 dias) casa quando a última reatestação da instalação não
foi aprovada pelo servidor nos últimos N. Depois de uma aprovada, a regra deixa de casar até passarem N de novo. A
condição só existe com `challenge` + `reattest`, nunca com `deny` (uma reatestação reprovada não prova
reempacotamento), é recusada em `prod` (`reattestation-prod`) e fica inerte em instalações iOS e em escopo com a
reatestação desligada. A publicação recusa N abaixo do intervalo mínimo do escopo
(`reattestation-age-below-interval`) e a condição num escopo com a reatestação desligada
(`reattestation-disabled-scope`). O Estúdio mostra o campo só com esse tipo.

O adaptador 4.6.0 responde 401 `challenge-required` com `challengeKind: reattest` e **não** chama o
`ISentomaruChallengeHandler`: quem confere é o Sentomaru, não o consumidor. A 4.5.0 manda o tipo bruto, e a 4.4.0 ou
anterior manda o 401 sem tipo. **Pré-requisitos:** o escopo com a reatestação ligada pelo operador (desligada é o
padrão); o backend do consumidor com as duas rotas de reatestação (`reattest_challenge` e `reattest`, contrato entregue pela operação) repassando ao Sentomaru como as de inscrição; no app, o opt-in
`SentomaruReattestation` no Android ou `SentomaruConfig.reattestation` no plugin (`sdk/android/README.md`,
`sdk/flutter/sentomaru_flutter/README.md`). Sem eles, o primeiro desafio termina em `ReattestationRefused`
(`reattestation-disabled`) ou em erro de configuração. O roteiro do app (o SDK não reatesta nem repete nada sozinho):

1. Ao receber o desafio com `reattest` (`isReattestChallenge` no Android e no Flutter), chamar `reattest()` uma vez:
   `SentomaruReattestation.reattest` no Android ou `SentomaruClient.reattest()` no plugin 0.15.0. Ele ignora o prazo
   local, porque quem decide é o servidor.
2. Com `ReattestationCompleted`, repetir a operação uma vez, com nonce novo; a repetição é avaliada de novo (um
   `challenge` não fica gravado). O app não lê o estado da reatestação para decidir: se a repetição for desafiada de
   novo, ele não reatesta outra vez nesta operação e mostra a recusa. Assim não há laço.
3. Com `ReattestationNotNow` (o 429 com `Retry-After` do intervalo mínimo do escopo ou do teto de 4 reatestações em
   24 h, ou outro "agora não" do SDK: rede, verificador indisponível), mostrar "tente mais tarde" e não repetir a
   operação em laço.
4. Com `ReattestationRefused` `session-expired`, renovar a sessão (4, "Renovação da sessão") e só então tentar o
   roteiro de novo, uma vez. Com outra recusa (`reattestation-disabled`, `reattestation-unsupported`,
   `installation-suspended`), mostrar a recusa e não repetir: a ação não rodou. O `reattestIfDue` espera 24 h depois dessas recusas, mas o
   `reattest()` ignora o prazo local, então é o app que não o chama de novo.

Numa instalação nova ou reinscrita ainda não há reatestação, então a primeira operação coberta recebe o desafio. Nos
apps que usam a condição, chame `reattestIfDue` logo depois da inscrição: custa uma chave atestada (56 a 110 ms no
aparelho de referência) e evita o desafio na primeira operação. Se o operador aumentar o intervalo do escopo depois de publicar a
política, a condição continua casando e o app recebe 429 até o intervalo vencer; o runbook pede conferir N antes de
mudar o intervalo. O caso `reattest-challenge` do `raspLab` faz esse roteiro no laboratório.

**Eventos no app (por opção).** O app recebe eventos informativos dos sinais que ele mesmo coleta e, se quiser, o
código fechado que o consumidor respondeu a uma requisição assinada. No Android, `SentomaruSignalEvents`
(`collector.events = signalEvents` e `addSentomaru(client, routes, events)`, `sdk/android/README.md`); no Flutter,
`SentomaruClient.signalEvents` do plugin 0.14.0 (0.15.0 reconhece `reattest`; `signal` só no Android; `server_response` do interceptor Dio em
qualquer plataforma; `sdk/flutter/sentomaru_flutter/README.md`). O servidor não manda ao app o degrau das regras nem
uma resposta sugerida, e um evento não é veredito: quem controla o processo o suprime ou o inventa. O mapeamento
recomendado:

| Evento | O que o app faz |
|---|---|
| `signal` (qualquer estado) | no máximo avisa o usuário e registra; sair do app só por esse evento é desaconselhado (falso positivo medido: `dev_settings_enabled` DETECTED em aparelho de laboratório legítimo), mas a escolha é do app |
| `server_response` `challenge-required` com `step_up` | pede ao usuário que se autentique de novo no seu backend e repete a operação |
| `server_response` `challenge-required` com `reattest` (D-06h, plugin 0.15.0) | chama `reattest()` uma vez e repete a operação uma vez com nonce novo; se for desafiado de novo, não reatesta outra vez nesta operação; com "agora não" (429) mostra "tente mais tarde" sem repetir |
| `server_response` `challenge-required` sem tipo ou com `fresh_signals` | repete com um snapshot novo de sinais; se continuar, mostra a recusa (fora do item 5 da spec: é o que o adaptador já esperava antes da 4.5.0) |
| `server_response` `installation-suspended` | mostra a tela de suspensão preservando rascunhos |
| `server_response` `installation-revoked` | leva a uma nova inscrição |
| outro `server_response` (`proof-required`, `session-unavailable`, `policy-denied`, código da política) | mostra a recusa; a ação não rodou |

<!-- source: sdk/flutter/sentomaru_flutter/test/signal_events_test.dart#signal-events -->
```dart
/// What the app does with an event (integration guide, 7d). Informative only: the server already decided the request.
String appReaction(SentomaruSignalEvent e) => switch ((e.kind, e.code, e.challengeKind)) {
      (SentomaruSignalEventKind.signal, _, _) => 'warn_and_log', // leaving the app on a signal alone is discouraged
      (_, 'challenge-required', 'step_up') => 'reauthenticate',
      // D-06h: client.reattest() once, then the operation once with a new nonce; if challenged again, no new reattest.
      (_, 'challenge-required', 'reattest') => 'reattest_then_repeat_once',
      (_, 'challenge-required', _) => 'retry_with_fresh_signals', // no kind or fresh_signals
      (_, 'installation-suspended', _) => 'suspension_screen_keeping_drafts',
      (_, 'installation-revoked', _) => 'enroll_again',
      _ => 'show_the_refusal',
    };
```

`SentomaruRiskEvent`/`onRiskEvent` (7b) não mudam. Sem pedir os eventos, nada muda: `collectSignals()` e
`defaultDetectors()` são os mesmos.

## 8. Aceite da integração

Antes de ligar a proteção numa operação real, confira no seu ambiente (o exemplo prova o mesmo no CI do Sentomaru):

1. Desafio sem login → 401; com login → 201 para o sujeito e o tenant da sessão, nunca os do corpo.
2. Requisição sem prova a uma operação protegida → 401 `proof-required`, a ação não roda.
3. Requisição assinada e aceita → a ação roda uma vez; a mesma requisição reenviada (mesmo nonce) é recusada.
4. Nova tentativa com o mesmo `x-sentomaru-operation-id` → não aplica o efeito de novo.
5. Sentomaru inacessível → 503, a ação não roda.
6. O host não sobe em produção com `FailOpen: true`.
7. Logs sem token de workload, cabeçalhos de assinatura ou corpo.
8. Sessão sem sujeito ou tenant → 403 `caller-context-missing` (o `ConsumerContract` acima, na sua suíte).
9. App com a flag de proteção ligada só é publicado quando o backend confirma. No job de publicação do app, leia
   `GET <BACKEND_URL>/integrity/capabilities` (sem token) e falhe a publicação quando a combinação for inconsistente: o app
   marca operações (flag ligada) e o backend está com o Sentomaru desligado ou não protege uma operação que o app marca;
   uma operação só em `Observe` é aviso, ou falha se você exigir `ZeroTrust`. Use códigos de saída distintos para
   "combinação inconsistente" e "backend ilegível". A URL do backend vem de `BACKEND_URL`, variável do ambiente do
   GitHub (hml/produção) que o build do app também lê: como a rota não traz o escopo, é ela que impede um build de HML
   de apontar para o backend de produção. A operação do Sentomaru entrega um script de referência para esse job.

O CI do Sentomaru roda o exemplo deste guia como teste de host real.

### 8a. Aceite para produção

**Hoje não existe produção do Sentomaru** (decisão D-PRD2 do dono, 16/10/2026): o HML é para homologação. Quando
existir, a virada exige, além da lista acima:

1. Infraestrutura própria do Sentomaru de produção (não a de HML), com backup cifrado fora do host e restauração ensaiada
   (procedimentos da operação do Sentomaru).
2. DNS e TLS do endereço de produção, `BaseAddress` e `PublicBaseUrl` em https.
3. Política publicada para o escopo de produção (`policySource: published`), revisada por autor e aprovador distintos.
4. Credencial de workload própria do consumidor de produção, no cofre, com rotação documentada
   (procedimento da operação do Sentomaru).
5. `FailOpen: false` (padrão) e o plano de indisponibilidade do item 8b.
6. Monitoramento: taxa de recusa por código, latência do adaptador e alerta quando o Sentomaru não responde.
7. Reversão: `Enabled: false` com `DisabledAcknowledged: true` (desligamento deliberado, sem nova versão) e a volta da
   operação para `Observe`.

### 8b. Não aponte a produção para o HML do Sentomaru

Com `FailOpen: false` (correto: uma indisponibilidade nunca libera uma operação protegida sem verificação), toda
operação em `ZeroTrust` depende do Sentomaru a cada requisição. Apontar a produção do seu backend para o **HML** do
Sentomaru faz a sua produção cair junto quando o HML cair, reiniciar ou for atualizado, e mistura tráfego real com
dados de homologação. Não faça isso; em `Observe` o risco é só de log, mas a prova continua dependente do HML.

### 8c. Quando trocar `Observe` por `ZeroTrust` (proposta até a J-04)

Ainda não há dado de piloto que sustente um número (a avaliação do piloto, J-04, sai por volta de 11/11/2026). Até lá,
um critério mínimo proposto, só com o que existe hoje:

- **Em Observe, o veredito da política só aparece nos logs do seu adaptador** (`Sentomaru Observe (no protection):
  <operação> verdict <ação>`): o Sentomaru não recusa nada em Observe, então o Observatório não vê esses `deny`.
- O **Observatório** do Console (`GET …/admin/observatory?days=1|7|30`) traz a frota e as **recusas de verificação**
  (prova inválida, replay, sessão) por código. Esse número é um piso (a fila de auditoria descarta eventos quando
  cheia), as recusas ficam 30 dias e o Observatório não conta avaliações aceitas.
- **Desde a migração 0036 (J-04b)** o servidor também guarda, por 30 dias, uma linha por avaliação com o veredito, a
  instalação (pseudônima) e o tempo de avaliação no servidor, para a avaliação do piloto (J-04). Não muda nada na
  resposta nem no seu adaptador; a latência que conta para você continua sendo a medida no seu backend.

Critério:

1. Pelo menos 14 dias em `Observe` com tráfego real da operação.
2. Volume mínimo: 500 linhas `Sentomaru Observe … verdict` da operação no período.
3. Percentual de `deny` e de `challenge` sobre o total dessas linhas, por dia, estável; cada motivo revisado e nenhum
   usuário legítimo recusado sem explicação.
4. Recusas de verificação do Observatório sem salto no período (dentro dos 30 dias que ele guarda).
5. Latência adicional do adaptador medida no seu backend (p95 dentro do seu orçamento; o teto por chamada é o `Timeout`).

Troque uma operação de cada vez e mantenha o caminho de volta (`Observe`) pronto.

## 9. Proteção do binário no CI (DevSecOps)

A prova por requisição deste guia não depende de mexer no binário. Para levar a CLI de proteção pós-build
`sentomaru protect` ao pipeline do app (`--dry-run` como portão de compatibilidade e, para AAB, a execução real com
o runtime injetado; a assinatura de rede é a linha acima, que a CLI confere), veja o [guia da CLI no pipeline](../devsecops/CLI_PIPELINE.md): GitHub Actions, GitLab CI, perfil, relatório e
códigos de saída. A ordem de ponta a ponta (SDK, backend, identidade do app, portões, execução real e a primeira
requisição aceita), com o repositório de exemplos, está no [guia para terceiros](../devsecops/GUIA_TERCEIRO.md).
