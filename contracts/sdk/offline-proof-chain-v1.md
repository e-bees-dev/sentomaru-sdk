# Cadeia de prova offline (`OfflineProofChain`, `v1`)

**Módulo:** Sentomaru Shield, SDK e servidor (`D-26`, HU-03 / SH-41 da avaliação do especialista; migração `0078`)
**Estado deste contrato:** escrito antes do código, junto com a ficha de dado. Decisão do fornecedor: D-ESP1 (aprovada). Itens da D-26 sem prova em aparelho até a fatia do SDK ser medida; iOS é fatia própria.
**Superfície** (mesmo envelope do D-25: o app assina, o backend do consumidor encaminha com o workload `consumer`, e **o veredito volta ao consumidor**, não ao app):
- `POST /v1/{org}/{app}/{env}/offline-permits` (emite o permit; `x-sentomaru-operation` = `offline_permit`)
- `POST /v1/{org}/{app}/{env}/offline-permits/reconciliations` (envia o lote e recebe o veredito; `x-sentomaru-operation` = `offline_reconcile`)
- SDK Android: `sealOfflineOperation(permit, operationDigest)` e `reconcileOfflineChain(permit, seals)`

## 1. O que é, e o que não é

Uma técnica em jornada de 2 h sem cobertura executa operações que o app só consegue enviar depois. O grant dura 10 minutos e a prova do envio é fresca (regra §7.1), então "agora" não vale para o que aconteceu antes. A cadeia dá ao servidor, na reconciliação, três coisas verificáveis: as operações foram seladas **em ordem**, **nenhuma do meio ou do começo foi removida**, e o **relógio de parede não andou de modo incompatível** com o relógio monotônico do aparelho.

**Limites declarados (viram texto da proposta):**
- A cadeia prova ordem e ausência de remoção feitas pelo **SDK íntegro**. **Não prova que o conteúdo é verdadeiro**: um aparelho comprometido com hook no SDK assina qualquer coisa. Isso é do RASP e da atestação, à parte.
- A **cauda** não é protegida: se as últimas seladas nunca forem enviadas, o servidor não tem como saber que existiram. Só remoção do começo e do meio é detectada.
- O servidor **não confirma a hora real** de cada item. Ele confirma que `wall` e `elapsed` andaram juntos e que o conjunto cabe na janela do permit. Quem muda o relógio e o monotônico juntos (root, kernel) não é visto.
- `Settings.Global.BOOT_COUNT` (público desde a API 24) pode ser ausente ou fixo em alguns aparelhos; a ausência é declarada (§4) e nunca vira "sem reboot".
- Não substitui o grant nem a prova do envio: a reconciliação é uma chamada assinada (perfil `sentomaru-p0`) por si só.

## 2. Permit (`offline-permits`)

Emitido **online**, por instalação, com prova fresca e **grant vivo** (`x-sentomaru-session`), como os passos do D-25. Opt-in por escopo (padrão desligado; ausente = desligado). Sem a opção, a rota responde `403` `offline-disabled` e nada é gravado.

Resposta `201`:

```json
{
  "permitId": "uuid",
  "chainSeed": "base64url, 32 bytes aleatórios do servidor",
  "issuedAt": "2026-11-05T12:00:00Z",
  "validUntil": "2026-11-06T12:00:00Z",
  "maxItems": 50,
  "driftToleranceSeconds": 120
}
```

Política por escopo (tabela, não o esquema de política; defaults e tetos fixos):

| Campo | Padrão | Teto | Observação |
|---|---|---|---|
| `enabled` | `false` | | opt-in |
| `maxAgeSeconds` (validade) | 86400 | **86400 (24 h)** | permit mais longo que o teto é recusado na configuração |
| `maxItems` | 50 | **128** | por permit (128 selos cabem nos 64 KiB do corpo encaminhado) |
| `driftToleranceSeconds` | 120 | 900 | tolerância entre `wall` e `elapsed` (§5) |

- No máximo **um permit aberto por instalação** (não reconciliado e dentro da janela de reconciliação). Outro `POST` responde `409` `permit-open`.
- A janela de reconciliação é `validUntil` + **24 h**. Depois disso o permit vira `expired` e o lote é recusado (`410` `permit-expired`); os itens que o aparelho guardou não têm mais valor de ordem para o servidor.
- Instalação revogada ou suspensa não tem grant vivo e, portanto, nem recebe permit nem reconcilia (`403`, como no D-25). Os itens guardados no aparelho perdem valor para o servidor.
- O permit **não substitui** o grant: durante a janela offline o app não tem grant válido. Na reconciliação o app já está online, **renova o grant** pelo fluxo normal (`POST /sessions`) e então envia o lote com o grant novo. O lote nunca renova o grant.

## 3. Selo (`seal`)

O app calcula o `operationDigest` (SHA-256 do payload da operação, **o payload nunca vai ao Sentomaru**). O SDK monta, para cada item, o registro em bytes fixos (big-endian, sem separadores):

```
"SMOFF1"           6 bytes ASCII
permitId           16 bytes (UUID)
seq                4 bytes, u32, começa em 0, +1 por item
bootCount          4 bytes, u32 (0xFFFFFFFF = indisponível, §4)
elapsedNanos       8 bytes, u64, SystemClock.elapsedRealtimeNanos()
wallMillis         8 bytes, u64, System.currentTimeMillis()
operationDigest    32 bytes
prevHash           32 bytes
```

- `hash = SHA-256(registro)`.
- `prevHash` do item 0 = `SHA-256("SMOFF1-seed" || permitId || chainSeed)`; o do item `n` é o `hash` do item `n-1`.
- `signature` = ECDSA P-256 com SHA-256 (DER) **sobre o registro**, feita pela **chave da instalação** (a mesma da prova de requisição, não exportável). O prefixo `SMOFF1` é a separação de domínio: um selo nunca é uma assinatura de requisição válida.
- O SDK guarda o estado da cadeia (próximo `seq`, último `hash`) por permit, em armazenamento privado do app; selar com permit vencido, com lote cheio (`maxItems`) ou sem permit gera erro tipado do SDK, nunca um selo.

## 4. Relógios

- `elapsedNanos` conta desde o boot e inclui sono profundo; zera no reboot. `wallMillis` é o relógio de parede e o usuário pode mudar.
- `bootCount` identifica o boot. Dentro de um mesmo boot os itens são comparáveis por `elapsed`; entre boots só pelo `wall`.
- `bootCount` indisponível (`0xFFFFFFFF`) em **qualquer** item: desde o contrato v1.19 (D-26, 8/11/2026) o servidor **recusa** (fail closed): o veredito é `rejected` com `offline_chain_broken`, seja um selo, todos ou uma mistura com selos legíveis. O veredito continua dizendo `bootCount: "unavailable"` e acrescenta `"offline_boot_unavailable"` em `advisories`, para o consumidor ver o motivo. O aparelho precisa de um permit novo quando voltar a ler o contador (ou reatestar); nada já gravado é reescrito, e uma reconciliação repetida devolve o veredito gravado. Antes da v1.19 (v1.16 a v1.18) o lote sem contador em todos os itens era `accepted` com a só regra de parede; essa regra continua sendo calculada, e o recuo do relógio aparece como `offline_clock_tampered` ao lado do `offline_chain_broken`.
- **Por que recusa.** Sem o contador, o servidor não confere a deriva dentro do mesmo boot nem a âncora do primeiro selo do boot (§5, regras 5 e RB-03); resta o recuo do relógio de parede e a janela `[issuedAt, recebido_em]`. Quem escolhe esse caminho é o **cliente**: o `bootCount` está dentro do registro que a chave da instalação assina, então a assinatura prova a origem, não o valor, e um app reempacotado pode assinar "indisponível" à vontade. O sentinela não é exclusivo de uma plataforma: o SDK iOS cai nele só se o `sysctl` do boot falhar e o Android quando `Settings.Global.BOOT_COUNT` não é legível. Não há medição de com que frequência cada plataforma o usa.

## 5. Reconciliação (`reconcile`)

Corpo encaminhado (JSON estrito, assinado no perfil `sentomaru-p0` com grant vivo; o corpo encaminhado vai até 64 KiB):

```json
{"permitId": "uuid", "items": [{"seq": 0, "bootCount": 7, "elapsedRealtimeNanos": 123456789, "wallClockMillis": 1793880000000,
            "operationDigest": "base64url", "prevHash": "base64url", "hash": "base64url", "signature": "base64url"}]}
```

O servidor refaz o registro de cada item com os campos recebidos e confere, **nesta ordem**, parando de somar sinais só no que a regra diz:

1. **Forma e teto.** Lote vazio, mais que `maxItems`, campo malformado: `400` `offline-format`. `permitId` desconhecido ou de outra instalação: `404` `permit-unknown`. Nada é gravado.
2. **Sequência.** `seq` deve ser `0, 1, 2, …` sem repetição nem salto. Falta no meio ou no começo: `offline_chain_gap_detected` (e o item seguinte cai na regra 3).
3. **Encadeamento.** `prevHash` do item 0 contra a semente e `prevHash` de cada item contra o `hash` do anterior; `hash` contra o `SHA-256` do registro refeito. Qualquer falha: `offline_chain_broken`.
4. **Assinatura.** Cada `signature` contra a chave pública da instalação do permit. Falha: `offline_chain_broken` (selo que a chave da instalação não assinou).
5. **Deriva.** Para cada par de itens consecutivos **do mesmo boot**: `|Δwall − Δelapsed|` (ambos em segundos) acima de `driftToleranceSeconds` é `offline_clock_tampered`. A mesma conta vale também contra o **primeiro item do boot** (`|(wall − wall₀) − (elapsed − elapsed₀)|`, mesma tolerância): passos pequenos que somam não passam (revisão B, RB-03). Entre boots (`bootCount` aumentou): `wall` não pode **retroceder** mais que a tolerância. `bootCount` que diminui, ou que repete com `elapsed` menor, é `offline_clock_tampered`. Além disso `wall` de todo item fica na janela `[issuedAt − tolerância, recebido_em + tolerância]` do **relógio do servidor**: fora dela, `offline_clock_tampered`.
6. **Orçamento.** O primeiro item selado depois de `validUntil + driftToleranceSeconds` (pelo `wall`, já checado na regra 5; a folga é a mesma tolerância do relógio, decisão registrada na revisão do fechamento, RB-11) é `offline_chain_broken` com `late`: o permit não valia mais.

A `signature` de cada item é guardada com ele (migração 0089, RB-10) e não é lida pelo papel de leitura.

Resposta `200`:

```json
{"permitId": "uuid", "status": "accepted", "itemCount": 3, "signals": [], "bootCount": "available",
 "items": [{"seq": 0, "operationDigest": "base64url"}], "advisories": []}
```

`advisories` (v1.18, aditivo; a semântica do lote sem contador mudou na v1.19, §4) lista o que o veredito **não pôde conferir**, calculado pelo servidor a partir do `bootCount` gravado, então a primeira resposta e a repetição dizem o mesmo. Hoje há um valor: `offline_boot_unavailable`, emitido quando ao menos um selo do lote tinha o contador de boot indisponível (`bootCount` é `"unavailable"` no veredito, inclusive no lote misto, que além disso é `offline_chain_broken`). **Não é um `signal`**: o aviso em si não muda `status` nem `signals`. Desde a v1.19 o lote sem contador é `rejected` pelo `offline_chain_broken` do §4 (na v1.18 um lote honesto sem contador era `accepted`). O consumidor pondera o aviso como quiser (por exemplo, tratar a cadeia como prova mais fraca). Um cliente que ignora `advisories` não é afetado.

`status` é `accepted` só com `signals` vazio; caso contrário `rejected`. **`rejected` não apaga nada**: o veredito e os `signals` ficam registrados; o consumidor decide. O servidor nunca devolve valores do aparelho em `signals` (só os três códigos). Reconciliar de novo um permit já reconciliado devolve `200` com o **veredito gravado** e nunca regrava nem reavalia (o consumidor que perdeu a resposta a recupera repetindo a chamada); o lote repetido não é comparado com o gravado.

Uma repetição depois que os itens foram apagados pela retenção (90 dias) responde `410` `permit-expired`, não uma contagem sem itens (revisão B, RB-09).

### Consulta administrativa

`GET /v1/{org}/{app}/{env}/admin/devices/{id}/offline-reconciliations` exige sessão de operador, `DevicesRead` no escopo exato e direito ao Trust. Retorna até 50 reconciliações concluídas nos últimos 90 dias, em ordem decrescente de data, com `Cache-Control: no-store`. Cada item contém `reconciledAt`, `status` (accepted/rejected), `signals` e `advisories`. Instalação inexistente ou de outro escopo recebe 404. Instalação sem reconciliações nessa janela recebe `[]`.

A consulta reaproveita os resultados persistidos sem alterar a retenção do banco. A resposta omite sementes, assinaturas, itens da cadeia, valores de relógio e identificadores de operação. `offline_boot_unavailable` informa uma verificação indisponível e permanece separado dos sinais de recusa.

## 6. Veredito para o consumidor

A resposta de `reconciliations` volta ao backend do consumidor, que a repassa ao app como quiser; o app nunca é a fonte do veredito. A resposta traz, por item, só `seq` e `operationDigest` (para o consumidor casar com o que o app lhe entregou). O consumidor, não o Sentomaru, decide se aceita operações de uma cadeia `rejected`. Sem dado pessoal. Não há rota de leitura separada nesta versão.

## 7. Falha segura e métricas

- Sem a opção habilitada, tabela indisponível ou erro de gravação: a rota recusa (`403` ou `503`) e **não** deixa o app selar operações sem permit. O app offline simplesmente não tem permit e segue sem a cadeia.
- A reconciliação nunca altera uma decisão de avaliação existente.
- **Contadores** (processo, rótulos fechados, nenhum valor do aparelho, escopo, instalação nem permit como rótulo; cada série sai com zero na primeira leitura de `/metrics`):
  - `sentomaru_offline_permits_total{result}`, `result` em `issued`, `disabled` (`403 offline-disabled`), `permit-open` (`409`) e `refused` (qualquer outra falha: prova, sessão, limite de taxa, loja).
  - `sentomaru_offline_reconcile_total{status}`, `status` em `accepted` e `rejected` (só o veredito **gravado nesta chamada**), `repeated` (a repetição que devolve o veredito gravado), `unknown-permit` (`404`), `expired` (`410`) e `refused`.
  - `sentomaru_offline_signal_total{signal}`, os três códigos de `signals`, uma vez por veredito novo rejeitado; a repetição **não** conta de novo.
  - `sentomaru_offline_advisory_total{advisory}`, hoje só `offline_boot_unavailable`, uma vez por veredito novo que o carrega (acréscimo a esta seção: é a taxa que a decisão sobre o Índice de Risco espera; não é um `signal`).
  - Conta-se **uma vez por requisição, depois do resultado da loja** (a loja pode repetir o corpo da transação, então nada é contado dentro dele). Um rótulo fora das listas fechadas é erro de programação, nunca uma série nova.
  - Estado: os contadores existem no serviço e saem em `/metrics` (as quatro famílias, todas as séries desde zero, `# TYPE … counter`).
## 8. Vetores (laboratório)

| Id | Cenário | Esperado |
|---|---|---|
| OFF-01 | Três itens, no meio o relógio de parede avança 2 h sem `elapsed` correspondente | `offline_clock_tampered` |
| OFF-02 | Três itens, o item de `seq` 1 é removido do lote | `offline_chain_gap_detected` e `offline_chain_broken` |
| OFF-03 | Reboot (`bootCount` +1) entre os itens: (a) relógio correto, (b) relógio de parede recuado 6 h | (a) `accepted`; (b) `offline_clock_tampered` |
| OFF-04 | `bootCount` `0xFFFFFFFF` (vetores `offline-proof-chain-v1-unavailable-vectors.json`): em todos os selos, com recuo de parede ou mistura com selos legíveis | `rejected` com `offline_chain_broken` nos quatro casos (D-26, v1.19); o recuo de parede traz também `offline_clock_tampered` |

Os vetores de bytes dourados (`contracts/sdk/offline-proof-chain-v1-vectors.json`) são conferidos pelo servidor (`OfflineChain`) e pelo SDK Android (`OfflineProofChainTest`, D-26c). O registro tem 110 bytes. A execução com relógio alterado e reboot **num aparelho** é a prova do SDK (fatia seguinte) e exige autorização para instalar.

## 9. Leitura do operador (Console, migração 0100)

`GET /v1/{org}/{app}/{env}/admin/offline/reconciliations?limit=&advisory=`: as reconciliações **do escopo** da rota, da mais nova para a mais antiga, para o operador ver o que o veredito não pôde conferir (`advisories`, §5) sem depender do aparelho. Operador do escopo com `DevicesRead` (Auditor, SecurityOperator e SuperAdmin; PolicyAuthor e Approver recebem 403), módulo `trust`, `Cache-Control: no-store`. É um sinal por instalação da frota, o mesmo conjunto de papéis que lê o registro do aparelho; não foi criada permissão nova.

Resposta: `{"items": [{"permitId", "installationCode", "status", "issuedAt", "reconciledAt", "itemCount", "signals", "bootCount", "advisories"}], "truncated": bool, "windowDays": 90}`. Instantes em UTC (`yyyy-MM-ddTHH:mm:ssZ`).

- **Só o que a reconciliação já gravou sobre o veredito.** Não saem a semente da cadeia, resumos de operação, hashes, assinaturas, valores de relógio nem o id bruto da instalação; a instalação aparece pelo código pseudônimo `INS-…` que o Console já mostra. Nenhum dado pessoal.
- **O aviso é derivado, não guardado.** `advisories` sai de `bootCount` ("available" ou "unavailable"), a mesma função que monta a resposta da reconciliação; uma reconciliação anterior ao aviso aparece igual. Continua não sendo um `signal`: `signals` e `status` não mudam.
- **Janela e retenção.** Só reconciliações (`accepted` ou `rejected`) dos últimos 90 dias, a mesma idade em que a purga apaga os itens da cadeia. A linha do permit (status, contagem, sinais, estado do `bootCount`) **não é apagada** pela purga; a migração 0100 não mudou isso, só criou o índice parcial que a leitura usa.
- `limit` 1..100 (padrão 50); `truncated` é verdadeiro quando havia mais linhas do que o limite. `advisory=offline_boot_unavailable` (único valor) mantém só as reconciliações com aviso. Erros fechados: `offline-list-limit` 400, `offline-list-filter` 400, `store-unavailable` 503.
- Não prova que o aparelho não omitiu o fim da cadeia nem que as operações são verdadeiras (§1); mostra o veredito e o aviso que o servidor gravou.
