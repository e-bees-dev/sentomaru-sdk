# Perfil Sentomaru P0 HTTP — versão sentomaru-p0

Perfil experimental de [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html) e [RFC 9530](https://www.rfc-editor.org/rfc/rfc9530.html), exclusivamente para laboratório. Não é API v1 do produto.

## Transporte e limites

HTTP apenas em 127.0.0.1, host/porta fixados pelo runner; sem gateway/Forwarded/X-Forwarded-*. Em produção será necessário TLS e perfil de proxy confiável. Host com valor diferente do configurado é rejeitado. Body máximo 65.536 bytes; `application/json` exato; sem Content-Encoding. Headers do perfil e de assinatura devem ter valor único; múltiplas assinaturas são rejeitadas. Nonce UUID canônico, keyId/challenge/session IDs UUID canônicos. Identificadores de contexto/operation: `[a-z][a-z0-9-]{0,31}`. Não há negociação/downgrade de algoritmo nesta versão.

## Assinatura

Tag obrigatório `sentomaru-p0`, alg `ecdsa-p256-sha256`, chave pública SPKI P-256 (PEM no permit; base64 do DER em `publicKey` na chave diferida); assinatura RFC em P1363 de 64 bytes. label `sig1` é convencional; qualquer label válida única pode ser verificada. Parâmetros created, expires, nonce, keyid, alg, tag obrigatórios. Created não pode exceder relógio servidor em 30s; expires > created; expires − created ≤ 60s; servidor exige now < expires e idade ≤ 90s. Challenge expira após 120s pelo relógio do servidor.

Componentes cobertos obrigatórios, nesta ordem no cliente de referência:

```text
@method
@target-uri
content-digest
content-type
x-sentomaru-profile
x-sentomaru-org
x-sentomaru-app
x-sentomaru-environment
x-sentomaru-session
x-sentomaru-operation
```

Backend exige cobertura exata desses componentes sem parâmetros adicionais ou duplicatas; ordem de entrada pode variar. `@target-uri` inclui query e URI derivada da requisição efetiva com Host fixado. Headers têm valores ASCII canônicos; org/app/environment/operation são identificadores, profile=`sentomaru-p0`. Body é congelado antes da assinatura. `Content-Digest` aceita somente `sha-256=:BASE64:` canônico recalculado sobre bytes recebidos, sem reserializar JSON. Headers body/query/contexto alterados após assinatura falham. Não aceitar `req`, `tr`, `sf` ou `bs` nos componentes deste perfil.

### Componentes opcionais (API)

Dois cabeçalhos entram na assinatura quando o app os envia, sempre os dois casos com um único valor:

- `x-sentomaru-signals` (H3): o snapshot de sinais. Coberto pela assinatura = sinais assinados; um membro `signals` no
  envelope ao lado de um cabeçalho assinado é recusado (J-01b).
- `x-sentomaru-operation-id` (J-01f, RETRY-01): id da operação de negócio, 16–64 caracteres `[A-Za-z0-9-]`, gerado pelo
  app e **igual em cada nova tentativa** da mesma operação. Presente sem estar coberto, malformado ou repetido = sem
  prova (401 `proof-invalid`). Coberto: a primeira avaliação admitida desse id na instalação responde
  `firstAdmission: true`; uma nova tentativa (nonce novo) com o mesmo método, `@target-uri` e corpo responde o veredito
  da primeira com `firstAdmission: false`; outro conteúdo no mesmo id é 409 `operation-conflict`, sem consumir nada.
  Ids valem 24 h por instalação. Só um `allow` grava o id (uma recusa é reavaliada na nova tentativa, por exemplo
  depois de um desafio). O consumidor que não conseguiu aplicar o efeito libera o id
  (`POST /v1/{org}/{app}/{env}/installations/{id}/operations/{operationId}/release`, 204; 404 `operation-unknown`),
  e a nova tentativa volta a ser primeira admissão. Um `allow` gravado vale para o mesmo id e conteúdo mesmo que uma
  avaliação nova recusasse; o 409 `operation-replayed` do adaptador significa "feita ou em andamento".

Com esses cabeçalhos, a cobertura exigida é a lista acima mais os opcionais enviados, cada um uma vez. O servidor
confere a cobertura como conjunto (a base de assinatura segue a ordem do `Signature-Input`); os SDKs assinam os
opcionais depois dos base, sinais antes do id, e os vetores compartilhados usam essa ordem.

## Inscrição do laboratório

1. Workload sintético envia `POST /p0/enrollment-challenges` com Authorization Bearer efêmero do runner e JSON `{organization, app, environment, subject, tenant, publicKeyPem?}` (`publicKeyPem` ausente ou `null` → challenge *sem chave*, ver [Inscrição com chave diferida](#inscrição-com-chave-diferida)). Só workload autoriza inscrição; controle em laboratório equivale à decisão de backend após reautenticação, não prova MFA real. Valor desconhecido de JSON deve ser rejeitado, não virar controle de confiança.
2. Resposta 201: `{challengeId, challenge, attestationChallenge, expiresAt}`. ChallengeId (UUID) é keyId temporário; `challenge` é token aleatório do servidor para a prova HTTP; `attestationChallenge` é outro valor: 32 bytes aleatórios (base64url) passados crus a `setAttestationChallenge` (ver [p0-attestation-profile.md](p0-attestation-profile.md)). `subject/tenant` ficam registrados no servidor; não são derivados de observações do cliente.
3. Cliente envia `POST /p0/installations` assinado com keyId/challengeId, header session=challengeId e operation=`enroll`, contexto do permit e body `{challenge, requiresHardware, attestationChain?, publicKey?}` (assinado; `publicKey` só em challenge sem chave; `attestationChain` = lista base64 DER, ≤5 certs de ≤4 KiB, dentro do limite de 65.536 bytes). Não trocar a chave pública nesse request (challenge com chave: `publicKey` presente → 400 `enrollment-format`).
4. Prova válida registra instalação/keyId e sessão sintética vinculados ao permit. Resposta 201: `{installationId, keyId, sessionId, attestationStatus, hardwareStatus, attestationReason}`; sem cadeia: `notEvaluated`/`unknown`. Replay idêntico de inscrição retorna 200 enquanto a sessão do grant estiver viva (não revogada; a expiração de 10 minutos do vínculo não afeta o replay de enrollment), mesmo com o challenge já expirado, sem criar segunda instalação; contexto do permit divergente retorna 403 `enrollment-context` (checado antes do digest) e body com digest divergente retorna 409 `enrollment-conflict`. `requiresHardware:true` sem `hardwareStatus:"hardware"` comprovado retorna 422 `hardware-not-proven` (inclui o caso sem atestação: hardware não é inferido). Estados, razões e mapeamento completos: [p0-attestation-profile.md](p0-attestation-profile.md).

## Inscrição com chave diferida

Motivo: no Android Key Attestation o `attestationChallenge` é fixado na **geração** da chave; o aparelho precisa do challenge antes de ter a chave. Variante aditiva; o caminho com `publicKeyPem` no permit não muda.

1. Permit sem `publicKeyPem` (campo ausente ou `null`; string vazia continua 400 `permit-format`). Demais validações e resposta 201 `{challengeId, challenge, attestationChallenge, expiresAt}` iguais. O challenge fica *sem chave*.
2. O aparelho gera a chave com `setAttestationChallenge(attestationChallenge)` e envia `POST /p0/installations` como no passo 3 da inscrição, com `publicKey` no body assinado: **base64 padrão com padding do SPKI DER** (não PEM), P-256 de curva nomeada (parâmetros explícitos e ponto comprimido rejeitados), ≤ 2.048 caracteres, canônico (DER reexportado e seu base64 com padding iguais à entrada; sem whitespace/bytes extras). Mesma validação de curva do permit (código compartilhado).
3. A assinatura RFC 9421 é verificada com essa chave (prova de posse). Para obter a chave antes do handler, o verificador lê o body já bufferizado **somente** se: keyId é challenge sem chave ainda não vinculado, rota `/p0/installations`, header operation=`enroll`, `Content-Digest` confere com os bytes recebidos; o body é lido com as mesmas opções JSON do endpoint. Os dois leitores podem divergir em bordas (ex.: BOM UTF-8 é erro no verificador e ignorado no endpoint); divergência fecha: 401 aqui, ou 400 `enrollment-format` se o `publicKey` do endpoint ≠ chave verificada. Operações nunca usam chave do body. Body que não parseia → 401 `proof-invalid` (fecha; difere do `json-format` do caminho com chave). Nada é gravado nesta etapa.
4. Vínculo: a chave provada é gravada no challenge **junto com o consumo**, sob o mesmo lock (ponto de consumo do perfil de atestação). Primeira escrita vence; a chave nunca é trocada. Rejeições que não consomem (400, 401 de token/expiração, 403 de contexto) não vinculam. Depois do vínculo a verificação usa só a chave vinculada: assinatura com outra chave → 401 `proof-invalid` (inclusive após 422). Corrida entre dois requests com chaves diferentes antes do vínculo: ambos passam a verificação com a própria chave, o lock serializa; o primeiro consome e vincula, o perdedor recebe 401 `proof-invalid` (chave provada ≠ vinculada, checado antes de consumido/replay).
5. Replay idêntico → 200 (assinado com a chave vinculada; mesmo digest), digest divergente → 409, consumido vence expirado — regras do perfil de atestação inalteradas.
6. Atestação: sem mudança no verificador. Folha comparada com a chave vinculada (≠ → `key_mismatch`), challenge da extensão com `attestationChallenge`. Sem cadeia e `requiresHardware:false` a inscrição é aceita com `unknown`/`notEvaluated`/`no_attestation`: a confiança na chave vem **apenas** do permit autorizado pelo workload + posse do token `challenge` + prova de posse da chave. Consequência: até o consumo, quem tiver `challengeId` e `challenge` pode vincular a própria chave (o token vira credencial de vínculo por ≤120 s); o caminho com chave no permit não tem essa janela. `requiresHardware:true` só passa com `hardware` comprovado (chave na folha atestada).

Status (sem consumir, sem vincular): challenge sem chave e `publicKey` ausente/`null` → 400 `enrollment-format`; `publicKey` inválido (tipo não string, base64 inválido, PEM, > 2.048 caracteres, não P-256, não canônico) → 400 `public-key-format`; challenge com chave e membro `publicKey` presente, **inclusive `null`** → 400 `enrollment-format` (regra estrita: rejeita mesmo se igual à chave do permit; checado na etapa de formato, depois de 401/409/403); os dois primeiros são decididos antes da verificação da assinatura e antes das consultas de replay/consumo/expiração (só após digest conferido; challenge sem chave expirado e ainda retido sem `publicKey` → 400) e não alteram estado.

## Operação sintética

`POST /p0/{organization}/{app}/{environment}/operations/{operation}?channel=field` exige assinatura e sessionId vinculada à chave. Headers de escopo precisam corresponder à route e grant. Subject/tenant e escopo real derivam do grant emitido pelo workload. Body é bytes JSON sintéticos sem interpretar regras de negócio. Qualquer body válido no perfil pode ser enviado; efeito é incrementar contador em memória e devolver `{proofStatus:"valid", attestationStatus:"notEvaluated", recommendedAction:"allowLabOnly", subject, tenant}`. Resultado nunca declara app/dispositivo seguro.

Nonce de operação consumido junto com efeito sob lock após assinatura/digest/contexto válidos. Mesmo nonce/chave, mesmo que a assinatura ou sessão mudem, retorna 409 (regra só de operações; enrollment não consome nonce, ver [p0-attestation-profile.md](p0-attestation-profile.md)). Assinatura/digest inválidos não podem consumir nonce e impedir prova legítima posterior. Concorrência deve produzir exatamente um efeito. Ledger em memória cobre apenas este processo; reinício invalida todos grants/keys. Não fornece persistência em réplicas, idempotência de negócio ou API Gateway pronto.

## Controle de teste

`GET /p0/control/state` retorna `{installations, effects}` para comparar efeitos antes/depois. `POST /p0/control/sessions/{sessionId}/revoke` retorna 204 e revoga sessão. Ambos exigem workload Bearer, sem segredo hardcoded. `GET /health` retorna apenas identificação `SentomaruP0`.

Status de rejeição: 400 formato/contexto sintático, 401 ausência/erro de assinatura/workload/grant, 403 transposição de escopo/revogação, 409 replay/conflito, 413 body grande, 422 hardware não comprovado com `requiresHardware:true` (código `hardware-not-proven`; razão em `attestationReason`; ver perfil de atestação). Challenge nunca consumido e expirado/desconhecido: 401 `challenge-invalid`; formato de cadeia/body (inclui JSON bem formado com `attestationChain` de tipo errado: não lista, `null`, elemento não string): 400 `attestation-invalid` sem consumir; JSON com erro de sintaxe: 400 `json-format` sem consumir; replay após revogação com contexto divergente: 403 `enrollment-context`; replay com digest divergente, challenge consumido (inclusive após 422 de atestação — consumo também em 422, ver perfil de atestação; consumido vence expirado) ou por outro keyId: 409 `enrollment-conflict`; sessão revogada: 409 `enrollment-revoked`; replay com contexto divergente: 403 `enrollment-context`; replay idêntico: 200. Chave diferida: `publicKey` ausente/`null` em challenge sem chave ou presente (mesmo `null`) em challenge com chave → 400 `enrollment-format`; `publicKey` inválido → 400 `public-key-format`; assinatura com chave diferente da vinculada, body sem parse no caminho diferido, ou operação com keyId de challenge sem chave não vinculado → 401 `proof-invalid`. Convenção: `code` hifenizado, `attestationReason` com underscores. Respostas contêm código estável de erro, sem payload, key material ou parâmetros sensíveis.

## Bibliotecas e próximos gates

NSign 1.2.5 verifica base/assinatura em .NET; http-message-signatures 2.0.1 produz prova Python independente. Referências: [NSign](https://github.com/Unisys/NSign), [PyAuth](https://github.com/pyauth/http-message-signatures). Parsing estruturado pertence às bibliotecas. Seleção P0 ainda precisa de vetores Android/Kotlin, avaliação operacional e Key Attestation/roots/revogação reais. Este perfil não implementa detector de root/hooks/malware.
