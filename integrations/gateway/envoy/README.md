# Envoy na frente do verificador (exemplo)

Exemplo de deploy do Envoy com o `Sentomaru.Gateway.Verifier` (contrato `contracts/api/gateway-verifier-v1.md`, seções
5 e 10). É o mesmo arquivo que o gate `verification/run_gateway.py` e o teste de vetores
(`GatewayParityTests.Envoy.cs`) sobem, só com os marcadores trocados.

- `envoy.yaml`: configuração estática. Marcadores `__LISTEN_ADDRESS__`, `__LISTEN_PORT__`, `__VERIFIER_ADDRESS__`,
  `__VERIFIER_PORT__`, `__UPSTREAM_ADDRESS__`, `__UPSTREAM_PORT__`, `__JWT_ISSUER__`, `__JWT_AUDIENCE__` e
  `__JWKS_JSON__` (JWKS público, JSON numa linha, sem aspas simples).
- `envoy-image`: a imagem fixada por digest do índice multiarquitetura
  (`envoyproxy/envoy:v1.40.2@sha256:8de97e65…`). Para subir de versão, troque tag e digest juntos, depois de conferir o
  digest em mais de uma fonte (Docker Hub, registry v2, `docker pull`), e rode o gate.

## O que o exemplo garante (requisitos normativos da seção 5)

1. `ext_authz` no vhost inteiro; só `GET /health` isenta (`ExtAuthzPerRoute` `disabled: true`, casada por caminho
   **e** `:method` `GET`; a regra do `jwt_authn` sem `requires` também), repetida em `exempt` na configuração do
   verificador. `POST /health` cai na rota protegida e recebe 403 `operation-unmapped`.
2. `normalize_path`, `merge_slashes` e `path_with_escaped_slashes_action: REJECT_REQUEST`.
3. Nenhum `retry_policy`, `hedge_policy` ou `request_mirror_policies` (I1); o gate tem um caso negativo que liga
   `retry_policy` e mostra a execução dupla. Retry por cabeçalho também fica fechado: os `x-envoy-*` do cliente são
   apagados no `header_mutation` (o `x-envoy-retry-on` vale quando o Envoy acha que a requisição é interna, e com
   `use_remote_address` desligado ele decide isso pelo `x-forwarded-for` que o cliente manda, contra o
   `internal_address_config`; sem ele, como aqui, a 1.40 trata todo cliente como externo). Requisito: nunca tratar o
   cliente como interno (`internal_address_config`/`use_remote_address`) nem tirar essa remoção; o gate prova as duas
   coisas com uma cópia que trata 10.0.0.0/8 como interno, com e sem a remoção.
4. Cabeçalho do perfil repetido recusado no gateway (filtro Lua, 400 `header-repeated`; `content-type` e `content-length`
   por vírgula no valor, seção 5 do contrato).
5. Corpo inteiro até 65536 bytes (`with_request_body`, `allow_partial_message: false`), `failure_mode_allow: false`,
   `status_on_error` 503 e `local_reply_config` com os corpos `{"code":"body-limit"}` e
   `{"code":"integrity-unavailable"}`; timeout de 3 s para o verificador (acima dos 2 s de `timeoutMs`).
6. `sentomaru-verified-*`, `sentomaru-caller-*` e `x-envoy-*` do cliente apagados antes de tudo; ao verificador só vão a allowlist
   do extrator e o chamador (`authorization` e `cookie` em `disallowed_headers`); ao upstream só os
   `sentomaru-verified-*` do verificador.

7. `codec_type: AUTO`: o gate prova HTTP/1.1 (com corpo chunked) e, em HTTP/2 em texto claro, o subconjunto listado na
   seção 10 do contrato. HTTP/3 fica fora, e TLS no ouvinte é do deploy. Até 100 streams por conexão. O upstream é HTTP/1
   (trailers de HTTP/2 não passam pelos filtros de cabeçalho).
8. Nome de cabeçalho com sublinhado recusado em toda rota.

## Chamador (`trusted-header`)

O filtro `jwt_authn` é o exemplo de autenticação do gateway: valida o token do usuário (JWKS fixo, emissor e audiência
conferidos; só do cabeçalho `authorization: Bearer`, `from_headers`, nunca de `?access_token=` na query) e injeta `sentomaru-caller-subject` (claim `sub`) e `sentomaru-caller-tenant` (claim `tenant`). Troque pela
autenticação que o gateway já faz, mantendo a ordem: apagar os `sentomaru-caller-*` do cliente, autenticar, injetar.
Em produção, `remote_jwks` com URL https fixa no lugar de `local_jwks`. O token vai ao upstream (`forward: true`): o
upstream confere que o usuário da sessão dele é o `sentomaru-verified-subject`/`-tenant`, ou autentica por esse mesmo
token (contrato, seção 3).

## Chamador `jwt`

Com `caller.mode: jwt` quem valida o token é o verificador (contrato, seção 11), e o exemplo muda em quatro pontos, sem
caso próprio no gate (a decisão está no contrato, seção 11, "Gate"): tirar o filtro `jwt_authn` e a injeção de
`sentomaru-caller-*` (a remoção dos `sentomaru-caller-*` do cliente fica; o verificador não os lê nesse modo); tirar
`authorization` de `disallowed_headers` do `ext_authz`; acrescentar `www-authenticate` em `allowed_client_headers` (o
exemplo só deixa passar `content-type`); e manter o timeout para o verificador acima de `timeoutMs` +
1000 ms (uma busca do JWKS pode entrar na requisição). Se o `authorization` não chegar, ou chegar com duas linhas
juntadas, a resposta é 401 `authentication-required` (com o `WWW-Authenticate`, se ele estiver em `allowed_client_headers`):
recusa, nunca passagem. A sonda de prontidão usa o `/health` da `managementPort`, que fica 503 sem JWKS utilizável.

## Rede

O verificador escuta só onde o Envoy chega (loopback do pod, socket, IP privado ou mTLS num sidecar em loopback) e o upstream só aceita o Envoy. Sem
segredo no Envoy: a credencial de workload, do tipo `gateway-verifier` (só avaliação, um escopo), fica no `workloadTokenFile` do verificador.

O exemplo é o mínimo que o gate sobe, sem TLS e sem limites de tempo do cliente. Em produção: TLS no ouvinte, XFF
conforme a topologia (`use_remote_address`/`xff_num_trusted_hops`), `request_headers_timeout`/`request_timeout`.
