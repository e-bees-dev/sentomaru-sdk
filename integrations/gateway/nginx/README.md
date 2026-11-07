# OpenResty (nginx) na frente do verificador (exemplo)

Exemplo de deploy do OpenResty com o `Sentomaru.Gateway.Verifier` (contrato the Sentomaru gateway verifier contract,
seções 5 e 11), nos modos de chamador `jwt` e `trusted-header` (marcador `__CALLER_MODE__`). Não é o módulo de Nginx do plano (esse não existe) nem o exemplo de produção:
é o que o smoke the vendor's run nginx smoke check sobe.

- `nginx.conf`: configuração estática. Marcadores `__LISTEN_ADDRESS__`, `__LISTEN_PORT__`, `__VERIFIER_ADDRESS__`,
  `__VERIFIER_PORT__`, `__UPSTREAM_ADDRESS__`, `__UPSTREAM_PORT__`, `__AUTHN_ADDRESS__`, `__AUTHN_PORT__` (serviço de
  autenticação do gateway; sem uso no `jwt`, ponha qualquer endereço) e `__CALLER_MODE__` (`jwt` ou `trusted-header`).
- `openresty-image`: a imagem fixada por digest (`openresty/openresty:1.27.1.2-alpine@sha256:7610…`). Para subir de
  versão, troque tag e digest juntos, confira o digest em mais de uma fonte e rode o smoke.

## Por que não `auth_request` puro

O `ngx_http_auth_request_module` só devolve ao cliente os status 401 e 403 do subpedido, sem o corpo; qualquer outro
status não-2xx vira 500. O contrato (seção 2) exige o status e o `{"code": ...}` do verificador (400, 409, 413, 422,
429...), então um `auth_request` sozinho quebraria a paridade com o `[SentomaruIntegrity]`. O exemplo faz o mesmo desenho
(subpedido interno, corpo lido antes, resposta do verificador decide a passagem) com `ngx.location.capture` no
`rewrite_by_lua_block`, o `access_by_lua` que a seção 5, item 1, já prevê. Precisa do OpenResty (ou nginx com
`lua-nginx-module`); nginx puro não cumpre o contrato.

## O que o exemplo garante (seção 5)

1. Verificação no vhost inteiro; só `GET /health`, pela linha crua, é isento. `POST /health` vai ao verificador e recebe
   403 `operation-unmapped` dele.
2. Normalização: o nginx **não** normaliza o que repassa com `proxy_pass …$request_uri`. Verificador e upstream recebem a
   mesma linha crua (provado com `//`, `.` e `%2E`); quem recusa segmento `.`, `..`, `%2E`, vazio e `//` é o verificador
   (seção 2). `%2F` e `%5C` no caminho são recusados no gateway (400 `forward-format`).
3. Uma verificação, uma execução: `proxy_next_upstream off`, `max_fails=0`, sem tentativa nova para o verificador nem
   para o upstream.
4. Cabeçalho do perfil repetido (`signature`, `signature-input`, `content-type`, `content-digest`, `content-length` e todo
   `x-sentomaru-*`) recusado com 400 `header-repeated`. Nome de cabeçalho com sublinhado é **descartado** pelo nginx
   (`underscores_in_headers off`), não recusado como no Envoy; ele nunca chega a verificador nem a upstream.
5. Corpo inteiro até 65536 bytes (`client_max_body_size`, 413 `body-limit` com o corpo JSON do contrato); o Lua lê
   o corpo inteiro (um corpo chunked em pedaços pequenos que o nginx gravou em disco por causa do enquadramento é relido, no máximo 65537 bytes;
   antes dava 503 mesmo dentro do limite, achado B20). Verificador com 5xx, status fora de 200/4xx, lento (mais de 3 s) ou parado: 503 `integrity-unavailable`,
   nunca passa.
6. Ao verificador só vão a allowlist do extrator e o `authorization`; cookie e `sentomaru-caller-*` nunca. Ao upstream só
   os nove `sentomaru-verified-*` do contrato (seção 3), um valor cada: qualquer outro `sentomaru-verified-*` na
   resposta do verificador é 503. Os do cliente (`sentomaru-verified-*`, `sentomaru-caller-*`) são apagados antes de tudo.
7. Resposta de 4xx do verificador: status, `Content-Type`, corpo e `WWW-Authenticate` como vieram.

## Limites (o que este exemplo não é)

- **Chamador `trusted-header`:** o exemplo não valida token nenhum. Ele pergunta a um serviço de autenticação do gateway
  (subpedido interno `GET`, só com o `authorization`) que responde 200 com `Sentomaru-Caller-Subject` e
  `Sentomaru-Caller-Tenant`, ou 4xx com corpo (devolvido como veio); falha dele é 503. O `authorization` não vai ao
  verificador nesse modo. Provado pelos vetores com um serviço de teste que confere o ES256; o serviço real é do deploy.
- **TLS, HTTP/2, HTTP/3:** o ouvinte do exemplo é HTTP/1.1 em texto claro. Com `ssl` e `http2 on` no `listen` (certificado autoassinado de teste), os requisitos da seção 5 valem também sobre HTTP/2 nos dois modos de chamador: the vendor's run nginx tls smoke check (8 testes, 6/11/2026). **Não provado:** cadeia de certificado real, ALPN com cliente de produção, HTTP/3, carga; o exemplo continua sem TLS (é do deploy).
- **API real:** o smoke usa dublês; os 126 vetores usam o verificador real com a API em memória; the vendor's run gateway nginx check sobe a API real, o PostgreSQL, o verificador real e este OpenResty (modo `trusted-header` com um serviço de autenticação de laboratório) e roda 27 testes de `nginx_gateway_e2e.py` (os 28 de `gateway_e2e.py` menos 5 que são do Envoy, mais 4 sobre TLS + HTTP/2 com um segundo OpenResty `ssl`/`http2 on`; 3 reescritos para o comportamento do nginx: caminho não normalizado recusado pelo verificador com 403, I1 como configuração, repetido com `content-type` explícito). Resultado de 6/11/2026: 27 de 27, e o primeiro que rodou achou o defeito abaixo.
- **Repetido com caixa diferente (corrigido):** a checagem de I7 usava `get_headers(0, true)` (nomes crus), em que `Signature` e `signature` são duas chaves e não um repetido: o pedido passava ao verificador com o cabeçalho duas vezes. Agora usa nomes em minúsculas (`get_headers(0)`); `run_nginx_smoke.py` tem o teste `test_repeated_profile_headers_with_different_case_are_refused` e o E2E o cobre.
- **Cabeçalhos repetidos:** o nginx recusa dois `Content-Length` com 400 sem corpo JSON antes do Lua; o `Transfer-Encoding`
  com `Content-Length` e outras ambiguidades de enquadramento são do nginx, não do exemplo.
- **Rede:** verificador e upstream só alcançáveis pelo gateway, sem segredo no gateway (contrato, seção 5, item 6).
- **Limites de tempo do cliente:** só `client_header_timeout`/`client_body_timeout` de 10 s; ajuste ao deploy.
- **Tamanho do vhost:** um `location /` só; várias rotas isentas exigem repetir a regra do Lua e a do `exempt` do verificador.

## Gates

```bash
python3 verification/gateway/run_nginx_smoke.py
```

Precisa de Docker em execução (Colima) e da imagem de `openresty-image`. Monta o `nginx.conf` num diretório sob `$HOME`
(o Colima não enxerga `/var/folders`). O teste estático the vendor's test nginx example check não precisa de Docker.

```bash
python3 verification/gateway/run_nginx_tls_smoke.py
```

Sobe o mesmo `nginx.conf` com `listen … ssl; http2 on;` e um certificado descartável, nos modos `jwt` e `trusted-header`; confere por `curl --http2` a versão HTTP negociada (2), uma verificação e uma execução, cabeçalho de perfil repetido recusado (400 `header-repeated`), corpo até 65536 bytes (413 acima), `sentomaru-verified-*`/`sentomaru-caller-*` forjados apagados, 4xx do verificador e do serviço de autenticação devolvidos, 5xx em 503, e TLS 1.1 recusado. Trocar `http2 on` por `off` faz 15 asserções falharem (a prova de que o teste morde).

```bash
python3 verification/gateway/run_nginx_vectors.py
```

Os 126 vetores de `GatewayParityTests` pelo OpenResty (teoria explícita `…Through_the_pinned_OpenResty…`, modo
`trusted-header`, verificador real, API em memória): 126 de 126. Cinco respostas são do próprio gateway (lista fechada em
`GatewayParityTests.OpenResty.cs`): 413 `body-limit`, `%2F`/`%5C` com 400 `forward-format` (o Envoy: 400 sem corpo) e os dois
400 do analisador do nginx (espaço no alvo, `%00`). Diferença para o Envoy que o teste exige: os nomes dos cabeçalhos
vão ao verificador em minúsculas (o envelope guarda a caixa recebida).
