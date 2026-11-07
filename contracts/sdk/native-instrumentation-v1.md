# Contrato `native_instrumentation` v1 (D-19, Android, sinal do cliente)

**Estado (5/11/2026): contrato e detector com testes JVM. O sinal NÃO está no catálogo publicado** (`signals-catalog-v1.json`,
`SignalsCatalog.kt`): registrar um id novo mexe no catálogo, na lista fechada de motivos de eventos, no vocabulário do iOS e do
Flutter e nas fichas, e fica como fatia própria. Enquanto isso, o `NativeInstrumentationDetector` existe e é testado, mas nenhum
coletor o chama e nenhuma resposta do SDK o carrega. Nada foi medido em aparelho.

## O que o sinal observa

O Java do próprio processo lê quatro fontes (cinco verificações; o mapa de arquivos serve a duas), sem NDK. As leituras de `/proc` não pedem permissão; a sondagem da porta do Frida usa um socket e precisa de `android.permission.INTERNET` (o SDK já a exige para falar com o servidor; sem ela a verificação falha e vira `partial`):

| Verificação (`indicators`) | Fonte | Conta como indicador quando |
|---|---|---|
| `tracer_attached` | `/proc/self/status`, campo `TracerPid` | o valor é um inteiro maior que zero (um processo faz `ptrace` neste) |
| `frida_map` | `/proc/self/maps` | algum arquivo mapeado tem `frida-agent` ou `frida-gadget` no nome (sem diferenciar maiúscula) |
| `hook_map` | `/proc/self/maps` (a mesma leitura) | algum arquivo mapeado tem `xposedbridge`, `liblspd`, `lsposed`, `edxposed` ou `libsubstrate` no nome (minúsculas): Xposed, LSPosed, EdXposed, Cydia Substrate |
| `frida_thread` | `comm` de cada tarefa em `/proc/self/task/*` | uma tarefa se chama `gum-js-loop` ou `pool-frida` |
| `frida_port` | conexão TCP a `127.0.0.1:27042` | a conexão é aceita (recusada é "nada escuta", resposta completa) |

`gmain` e `gdbus` (threads do glib) **não** são indicador: bibliotecas legítimas as usam. `frida` sozinho no nome também não
(`libfridayplanner.so` não casa).

## Estados e `detail`

Uma leitura cortada no teto (mais de 20 000 linhas em `status`/`maps`, mais de 1 024 tarefas) **não vale como completa**: falha e a verificação entra em `partial` (UNKNOWN se nada foi achado). **`maps` é a exceção do bloco 15:** o corte guarda as primeiras 20 000 linhas (`PartialRead`); um agente Frida ou um framework de hook **dentro** desse prefixo é um indicador real (`DETECTED`), e a verificação que não achou nada no prefixo continua `partial` (nunca `NOT_DETECTED`), porque o resto do arquivo não foi visto. `status` e as tarefas seguem sem prefixo. Mesma regra dos detectores D-05 (`Evidence`): `DETECTED` quando algum indicador aparece; `UNKNOWN` quando nenhum apareceu e alguma
verificação não rodou (arquivo negado ou ausente, `TracerPid` ausente ou malformado, conexão com tempo esgotado); `NOT_DETECTED`
só quando as cinco verificações rodaram e nada apareceu; `ERROR` para falha do próprio detector. `detail.indicators` é `none` ou os códigos
acima em ordem fixa (`tracer_attached,frida_map,hook_map,frida_thread,frida_port`); `detail.partial` lista as verificações que não
rodaram, com os códigos `tracer_pid`, `frida_map`, `hook_map`, `frida_thread`, `frida_port` (leitura de `maps` que falha marca `frida_map` e `hook_map`). **O `detail` nunca traz caminho, nome de thread,
pid nem endereço.** Orçamento: 25 ms (a conexão local tem teto de 15 ms).

## O que o sinal NÃO prova

- É **declarado pelo app**, não verificado pelo servidor: quem instrumenta o processo controla o que o processo lê. O Frida pode
  renomear o agente e as threads, mapear com outro nome, ouvir em outra porta ou apagar a própria entrada; um hook em
  `File.read` ou em `Socket.connect` devolve a resposta limpa.
- `NOT_DETECTED` não quer dizer "sem instrumentação"; quer dizer "estas cinco verificações não acharam nada".
- `tracer_attached` também é verdadeiro sob um depurador legítimo (ptrace de um IDE, `strace`): não distingue intenção.
- Não vê hooks nativos sem arquivo novo (trampolins em memória já mapeada), nem `LD_PRELOAD` com nome neutro, nem emulação.
- Não substitui a Play Integrity nem a atestação de chave; é uma pista a mais para a política.

## Prova que existe

`NativeInstrumentationDetectorTest` (12 testes JVM no registro original; hoje 15, `sdk/android/signals`): processo limpo; `TracerPid` positivo, zero, ausente e
malformado; agente e gadget no mapa (cinco nomes), biblioteca com `frida` no nome que não casa; `gum-js-loop` e `pool-frida`,
threads do glib que não casam; porta aberta; ordem dos indicadores; cada leitura falhando (UNKNOWN com o código certo) e o
indicador que vence a leitura que falhou; o `detail` sem vazar caminho, nome ou pid; falha inesperada de uma leitura sem
`ERROR`; o orçamento.

`NativeInstrumentationAndroidSourceTest` (10 testes) exercita o leitor real sobre uma árvore `/proc` falsa em disco (arquivos, teto exato, teto excedido, tarefas, `maps` ausente e, no bloco 15, o prefixo de um `maps` cortado: acerto no prefixo vale, erro no prefixo é parcial, o teto real de 20 000 linhas). `NativeInstrumentationDetectorTest` passou a 15 testes.

**Não provado:** uma leitura real de `/proc` num aparelho (a árvore usada é falsa); o Frida real (nenhum `frida-server` foi iniciado); permissão de leitura de `/proc/self/maps` e `/proc/self/task` em
Android recente sob SELinux (esperada, não medida); o custo real dos 25 ms; qualquer taxa de falso positivo; o registro no
catálogo, nos eventos e nos SDKs de iOS e Flutter.

## Fora do escopo desta versão (plano D-19, não feito)

Detectores em NDK, trampolins nas primeiras instruções de funções sensíveis (libc, ART, a própria biblioteca do SDK), hash do
próprio detector em memória, pipes com nome do agente e o sinal assinado `instrumentation` (H3) no catálogo. O desenho atual é
só Java sobre `/proc`, consultivo e fora do catálogo. A matriz adversarial (Frida, Objection, LSPosed) em aparelho de laboratório
tem o protocolo na documentação interna do Shield e **nenhuma linha medida**.
