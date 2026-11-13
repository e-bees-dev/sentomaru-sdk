# Mensagem padrão ao usuário final, v1 (`sdk-user-message-v1`)

Os SDKs de app e web não traziam texto apresentável: devolviam códigos e tipos de erro. Esta versão acrescenta **um texto padrão curto, em três idiomas, com chave estável**, para o app mostrar ao usuário final quando uma operação não passa. **Os códigos de erro e a semântica de cada SDK não mudam**; só se acrescenta a mensagem.

## O que o usuário lê

Chave estável: `critical_operations_blocked`. Texto fixo, sem interpolação, sem prometer prazo:

| Idioma | Texto |
|---|---|
| `pt-BR` | Algumas operações críticas estão bloqueadas até a aprovação. Tente novamente mais tarde ou fale com o suporte. |
| `en` | Some critical operations are blocked until approval. Please try again later or contact support. |
| `es` | Algunas operaciones críticas están bloqueadas hasta su aprobación. Inténtelo de nuevo más tarde o póngase en contacto con el soporte. |

Os textos valem para todas as situações fechadas abaixo. O texto **não carrega código, motivo interno nem detalhe de detecção**: o usuário não aprende o que foi detectado, e a mensagem é a mesma para todas as situações (não distingue falha de atestação de verificação negada).

## Situações (conjunto fechado)

`attestation_failed`, `verification_denied`, `challenge`, `defer`, `unavailable`, `enrollment_pending`. Cada SDK mapeia os próprios códigos para uma destas (função `forCode`/equivalente); um código que **não** é bloqueio (cancelado pelo usuário, SDK não inicializado, configuração inválida, requisição malformada) devolve nada e o app decide o que mostrar. O mapa de cada plataforma está em `docs/sdk/USER_MESSAGES_INVENTORY.md`.

## Idioma

A etiqueta (BCP 47, `_` lido como `-`, sem diferenciar maiúsculas) resolve pelo subcódigo primário: `pt*` vira `pt-BR`, `es*` vira `es`, qualquer outra, vazia ou ausente vira `en`.

## Sobrescrita pelo host

O host pode passar um mapa idioma resolvido → texto. Texto sobrescrito não vazio (depois de aparar) substitui o padrão daquele idioma; vazio ou de outro idioma é ignorado e vale o padrão. O padrão do SDK já traz a informação, então um app que não sobrescreve nada mostra a mensagem correta.

## Vetor compartilhado e gates

`contracts/sdk/user-message-vectors-v1.json` (textos, resolução de idioma, sobrescrita, palavras que o texto nunca pode conter). Cada SDK o lê no próprio teste; a matriz está em `verification/sdk/shared-vectors-matrix.json`.
