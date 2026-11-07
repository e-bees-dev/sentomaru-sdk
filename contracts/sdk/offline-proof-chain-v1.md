# Cadeia de prova offline (`OfflineProofChain`, `v1`)

**Módulo:** Sentomaru Shield, SDK e servidor (`D-26`, HU-03 / SH-41 da avaliação do especialista; migração `0078`)
**Estado deste contrato:** escrito antes do código, junto com a ficha de dado. Decisão do dono: D-ESP1 (aprovada). Itens da D-26 sem prova em aparelho até a fatia do SDK ser medida; iOS é fatia própria.
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
- `bootCount` indisponível (`0xFFFFFFFF`) em **todos** os itens: o servidor só aplica a regra de parede (§5, regra 5) e devolve `bootCount: "unavailable"` no veredito. Mistura de disponível e indisponível no mesmo lote é `offline_chain_broken`.

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
 "items": [{"seq": 0, "operationDigest": "base64url"}]}
```

`status` é `accepted` só com `signals` vazio; caso contrário `rejected`. **`rejected` não apaga nada**: o veredito e os `signals` ficam registrados; o consumidor decide. O servidor nunca devolve valores do aparelho em `signals` (só os três códigos). Reconciliar de novo um permit já reconciliado devolve `200` com o **veredito gravado** e nunca regrava nem reavalia (o consumidor que perdeu a resposta a recupera repetindo a chamada); o lote repetido não é comparado com o gravado.

Uma repetição depois que os itens foram apagados pela retenção (90 dias) responde `410` `permit-expired`, não uma contagem sem itens (revisão B, RB-09).

## 6. Veredito para o consumidor

A resposta de `reconciliations` volta ao backend do consumidor, que a repassa ao app como quiser; o app nunca é a fonte do veredito. A resposta traz, por item, só `seq` e `operationDigest` (para o consumidor casar com o que o app lhe entregou). O consumidor, não o Sentomaru, decide se aceita operações de uma cadeia `rejected`. Sem dado pessoal. Não há rota de leitura separada nesta versão.

## 7. Falha segura e métricas

- Sem a opção habilitada, tabela indisponível ou erro de gravação: a rota recusa (`403` ou `503`) e **não** deixa o app selar operações sem permit. O app offline simplesmente não tem permit e segue sem a cadeia.
- A reconciliação nunca altera uma decisão de avaliação existente.
- Contadores de baixa cardinalidade previstos (`sentomaru_offline_permits_total{result}`, `sentomaru_offline_reconcile_total{status}`, `sentomaru_offline_signal_total{signal}`, nenhum rótulo com valor do aparelho): **não entram na fatia do servidor (D-26b)**; ficam para a telemetria.

## 8. Vetores (laboratório)

| Id | Cenário | Esperado |
|---|---|---|
| OFF-01 | Três itens, no meio o relógio de parede avança 2 h sem `elapsed` correspondente | `offline_clock_tampered` |
| OFF-02 | Três itens, o item de `seq` 1 é removido do lote | `offline_chain_gap_detected` e `offline_chain_broken` |
| OFF-03 | Reboot (`bootCount` +1) entre os itens: (a) relógio correto, (b) relógio de parede recuado 6 h | (a) `accepted`; (b) `offline_clock_tampered` |

Os vetores de bytes dourados (`contracts/sdk/offline-proof-chain-v1-vectors.json`) são conferidos pelo servidor (`OfflineChain`) e pelo SDK Android (`OfflineProofChainTest`, D-26c). O registro tem 110 bytes. A execução com relógio alterado e reboot **num aparelho** é a prova do SDK (fatia seguinte) e exige autorização para instalar.
