# Sentomaru.Gateway.Verifier

Serviço verificador que o gateway chama antes do upstream (contrato
the Sentomaru gateway verifier contract, esquema the Sentomaru gateway verifier config contract). Versão 0.1.0,
não publicado. Exemplo Envoy em `../envoy/`.

```text
Sentomaru.Gateway.Verifier --config /etc/sentomaru/verifier.json   # ou SENTOMARU_VERIFIER_CONFIG
```

Configuração inválida: o host não sobe, imprime todos os erros e sai com 2 (contrato, seção 9).

## Arquivos

| Arquivo | O que faz |
|---|---|
| `Program.cs` | entrada; lê a configuração, sai com 2 se inválida |
| `VerifierConfig.cs` | leitura estrita e validação de partida |
| `VerifierApp.cs` | host: tabela de rotas, núcleo `SentomaruEvaluationPipeline`, respostas, ouvinte de gestão |
| `RouteTable.cs` | tabela exata de rotas e isentas (C1) |
| `TrustedHeaderCallerResolver.cs` | chamador `trusted-header` |
| `JwtCallerSettings.cs`, `JwksSource.cs`, `JwtCallerValidator.cs` | chamador `jwt`: configuração, JWKS fixo com cache e renovação limitada, validação do token (contrato, seção 11) |
| `WorkloadTokenHandler.cs` | `Bearer` de workload lido do `workloadTokenFile` |
| `VerifierMetrics.cs` | contadores com rótulos fechados (`/metrics` só na `managementPort`) |

## Credencial

Use uma credencial `gateway-verifier` só deste verificador (contrato, seção 4): um único escopo, nunca observadora,
aceita só em `POST /v1/{org}/{app}/{env}/evaluations`. Ela não inscreve, não revoga instalação nem grant, e em qualquer
outra rota de workload a API responde 403 `workload-kind`. Criação e rotação do token são feitas pela operação do Sentomaru. Uma
credencial `consumer` já implantada continua funcionando. Credencial recusada (`workload-required`, `workload-kind`,
`workload-scope`): 503 `integrity-unavailable` com log Error.

## Chamador

- `trusted-header`: o gateway autentica e injeta `sentomaru-caller-subject`/`-tenant`; exige
  `verifierReachableOnlyFromGateway: true`.
- `jwt`: o verificador valida o `Authorization: Bearer` do usuário contra o JWKS da configuração (URL https fixa ou
  chaves públicas inline; nunca `iss`, `jku`, `x5u`, `jwk` ou `x5c` do token), com `alg` só da lista assimétrica
  configurada (`none` e `HS*` nunca), `iss`, `aud` e `exp` obrigatórios, `nbf`/`iat` respeitados, tolerância de relógio
  de 0 a 120 s, `typ` conferido só com `requiredTyp` (opcional), e subject/tenant pelas claims configuradas (ASCII
  visível, até 512 caracteres). Token ausente ou inválido: 401 `authentication-required` com
  `WWW-Authenticate: Bearer error="invalid_token"`; token válido sem subject/tenant utilizável: 403
  `caller-context-missing`; JWKS indisponível: 503 `integrity-unavailable` (fail-closed). O JWKS é buscado na partida
  (prazo de 3 s, sem bloquear) e o `/health` só fica pronto com um conjunto utilizável. Sem dependência nova:
  `System.Security.Cryptography`.

```json
"caller": {
  "mode": "jwt",
  "jwks": { "url": "https://login.example.com.br/.well-known/jwks.json" },
  "algorithms": ["RS256", "ES256"],
  "issuer": "https://login.example.com.br",
  "audience": "api-pedidos",
  "clockSkewSeconds": 30,
  "unknownKidRefreshSeconds": 60,
  "subjectClaims": ["sub"],
  "tenantClaims": ["tenant"],
  "requiredTyp": "at+jwt"
}
```

## Testes

`GatewayVerifierHostTests.cs` (host, `trusted-header`, matriz atributo × verificador),
`GatewayVerifierHostTests.Jwt.cs` (modo `jwt`, regras I6), `GatewayParityTests.cs` e `GatewayParityTests.Envoy.cs`
(vetores), the vendor's run gateway check (gate Envoy com a API real).
