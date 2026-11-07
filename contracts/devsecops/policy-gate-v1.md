# Portão de política do CI — contrato v1 (G-02)

Fatia G-02 do Sentomaru DevSecOps: o CI do cliente **falha a build** que não tiver **perfil de proteção válido**, que não
tiver **SBOM válido** ou que trouxer **dependência vulnerável conhecida** acima da severidade escolhida. Roda ao lado da
G-01 (`actions/protect`), como passo próprio: `tools/devsecops/policy_gate.py` (com `tools/devsecops/osv_versions.py`),
embrulhado pela Action `actions/policy-gate` (casca, sem lógica). Guia: [`docs/devsecops/CLI_PIPELINE.md`](../../docs/devsecops/CLI_PIPELINE.md) §3c.

**O que sai do runner:** nunca o app, o perfil, o SBOM nem segredo. Com a consulta online (`--osv-api`), as **package
URLs de todos os componentes**, inclusive as de bibliotecas internas (que revelam nomes e versões), vão para a API do
OSV, e o relatório traz o aviso `osv-api-purls-sent` a cada execução nesse modo. Para que nada saia, use a base
offline (`--osv-db`, preparada no job). O `stderr` leva só códigos, contagens e ids de vulnerabilidade; os nomes dos
componentes ficam no relatório, no runner.

**Princípio:** o que o portão não entende **reprova** (falha fechada): versão ou faixa que não sabe comparar conta como
afetada; componente sem package URL de ecossistema conhecido reprova; severidade que não sabe ler conta acima de
qualquer limite; base de vulnerabilidades ilegível reprova.

**Limite declarado:** o portão confere o que a build **declara** (SBOM e perfil). Não inspeciona o binário e é tão
completo quanto o SBOM e os dados do OSV.

## Invocação

```text
policy_gate.py --profile <protect-profile.json> --sbom <sbom.json> --out <dir>
               (--osv-api [--osv-api-url https://api.osv.dev] | --osv-db <dir> --osv-db-sha256 <hex>)
               [--min-severity low|medium|high|critical]    padrão high
               [--exceptions <exceptions.json>]
               [--profile-sha256 <hex>]                      pino do registro (Shield)
               [--allow-unavailable-db]                      degrada se a base não puder ser LIDA (nunca por integridade)
               [--allow-components-without-purl]             deixa passar componentes sem package URL (com aviso)
policy_gate.py --hash-db <dir>                               imprime o digest a fixar em --osv-db-sha256
```

Dependências: só `tools/devsecops/policy-gate.requirements.lock` (jsonschema, travado por hash; a Action instala num
venv privado). Sem ele a ferramenta sai com `internal-error` e a instrução de instalação. Esquemas do CycloneDX 1.5/1.6
**vendorizados** em `contracts/devsecops/schemas/cyclonedx/` (tag 1.6.1 da especificação), conferidos por SHA-256 antes
de usar: nenhum esquema é buscado na rede. A API do OSV só por https, **sem seguir redirecionamento**, com até 2 novas
tentativas (429/5xx/rede) e espera crescente; `http://127.0.0.1` só nos testes, com `SENTOMARU_POLICY_GATE_TEST_HTTP=1`.

## Verificações

| Verificação | Regra | Código |
|---|---|---|
| Perfil | existe; JSON estrito (sem chave duplicada); válido contra `protect-profile-v1.schema.json` | `profile-missing`, `profile-invalid` |
| Pino do registro | com `--profile-sha256`, o SHA-256 do arquivo é o fixado. **Sem ele, o pino não é conferido** (aviso `profile-not-pinned` no relatório) | `profile-digest-mismatch` |
| SBOM | existe; CycloneDX `specVersion` 1.5 ou 1.6; válido contra o esquema oficial, com os formatos que o jsonschema confere sem pacotes extras (`idn-email`, `email`, `date`, `ipv4`, `ipv6`, `regex`); **`date-time` e `iri-reference` não são conferidos** | `sbom-missing`, `sbom-invalid`, `sbom-version-unsupported` |
| Componentes | ao menos um; todo componente com package URL de ecossistema conhecido (Maven, Pub, npm, PyPI, NuGet, Go, crates.io, RubyGems, Packagist, Hex; tipo sem diferenciar maiúsculas). Sem componentes reprova sempre; sem package URL reprova, salvo `--allow-components-without-purl` (aviso) | `sbom-no-components`, `sbom-components-unmatched` |
| Dependências | cada componente cruzado com o OSV; achado com severidade ≥ `--min-severity` reprova. Registro `withdrawn` é ignorado | `vulnerable-dependency` |
| Exceções | `{"exceptions": [{"id", "reason", "expires": "AAAA-MM-DD", "component"?}]}`; casa pelo id ou por um alias (ex.: CVE), e pelo componente (package URL, nomes normalizados) se informado; **vale até o fim do dia `expires` em UTC**; validade máxima de 180 dias a partir de hoje; vencida volta a reprovar; uma exceção nunca silencia outra vulnerabilidade | `exception-format`, `exception-expired` |
| Base de vulnerabilidades | offline: diretório com o digest fixado (`--hash-db`), registros em UTF-8 de até 4 MiB; online: API do OSV com paginação (`next_page_token`) seguida até o fim e o detalhe de cada id conferido. **Integridade** (nunca degrada): digest diferente, link simbólico, registro grande ou ilegível; resposta da API malformada (JSON inválido ou truncado, número de resultados errado, id ou token de página fora do formato, detalhe com id diferente do pedido). **Indisponível** (degrada só com `--allow-unavailable-db`, marcado): diretório ausente, API inacessível depois das novas tentativas (rede, timeout, 429/5xx, redirecionamento recusado) | `vuln-db-integrity`, `vuln-db-unavailable` |

**Severidade:** a maior entre `database_specific.severity` (GHSA: LOW, MODERATE, HIGH, CRITICAL; rótulo confiável) e
a nota base de cada vetor CVSS v3.x legível (≥ 9 crítica, ≥ 7 alta, ≥ 4 média). Vetores CVSS v4 (que este portão não
calcula) e v3 ilegíveis não somam. **Sem rótulo e sem v3 legível (só v4, só vetor ilegível ou nada), a severidade é
desconhecida e conta acima de qualquer limite.**

### Ordem de versões (base offline)

O casamento offline usa a lista `versions` do registro e as faixas, avaliadas como no esquema OSV (eventos ordenados;
`introduced`, `fixed`, `last_affected`):

| Faixa / ecossistema | Ordem |
|---|---|
| `SEMVER`; npm, crates.io, Hex, Pub (`ECOSYSTEM`) | semver 2.0.0: `+build` ignorado; pré-release abaixo da release, comparada por identificador; NuGet e Pub aceitam a quarta parte numérica |
| Go | semver, sem o `v` inicial e sem `+incompatible` |
| Maven | a do Maven: número > qualificador; alpha < beta < milestone < rc (= cr) < snapshot < release (= ga, final) < sp < qualificador desconhecido (lexical); `31.0-jre` > `31.0`. Hífen seguido de dígito (`1-1`, snapshot com timestamp) abre uma sublista no Maven: aqui é ilegível e **conta como afetado** |
| NuGet | semver com a pré-release comparada sem diferenciar maiúsculas (`1.0.0-RC1` = `1.0.0-rc1`) |
| PyPI | PEP 440: epoch, release, pre (a/b/rc), post, dev; o segmento local é ignorado |
| RubyGems, Packagist, outros | sem comparação: só a lista `versions`; **uma faixa conta como afetada** |
| `GIT` | ignorada (commits não se aplicam a uma versão de pacote) |
| tipo de faixa desconhecido ou versão ilegível | **afetado** |

Limitações: a ordem do Maven não reproduz as sublistas do `ComparableVersion` (por isso o hífen numérico conta como
afetado); faixas `GIT` não são avaliadas; o modo online delega o casamento ao OSV e é o recomendado.

## Saídas e relatório

`<out>/policy-report.json` sempre é escrito (também na recusa):

```json
{
  "reportVersion": "1",
  "tool": { "name": "sentomaru-policy-gate", "version": "1" },
  "minSeverity": "high",
  "checks": {
    "profile": { "status": "pass", "profileId": "…", "sha256": "…", "pinned": false },
    "sbom": { "status": "pass", "specVersion": "1.6", "sha256": "…", "components": 3, "withPurl": 3 },
    "vulnerabilities": { "status": "fail", "components": 3, "withoutKnownPurl": 0,
      "source": { "mode": "offline", "databaseSha256": "…", "records": 2, "withdrawn": 0 },
      "findings": [ { "id": "…", "aliases": [], "component": "pkg:maven/…@1.1.0", "severity": "high" } ],
      "excepted": [] }
  },
  "warnings": [ { "code": "profile-not-pinned", "detail": "…" } ],
  "errors": [ { "code": "vulnerable-dependency", "detail": "1 finding(s): …" } ],
  "result": "fail",
  "code": "vulnerable-dependency"
}
```

`vulnerabilities.status`: `pass`, `fail` ou `skipped-unavailable` (só com `--allow-unavailable-db`, com aviso
`vuln-db-unavailable`). Avisos: `profile-not-pinned`, `sbom-components-unmatched` (com a opção), `vuln-db-unavailable`
(com a opção), `osv-api-purls-sent` (modo online). Achado coberto por exceção ativa vai para `excepted` com o motivo e a validade.

## Códigos de saída (estáveis)

| Saída | Códigos | Quando |
|---|---|---|
| 0 | — | todas as verificações passaram |
| 1 | `internal-error` | falha inesperada (inclui esquema vendorizado alterado e dependências não instaladas) |
| 2 | `usage`, `exception-format` | argumentos inválidos; arquivo de exceções malformado |
| 3 | `profile-missing`, `profile-invalid`, `profile-digest-mismatch` | perfil ausente, inválido ou fora do pino |
| 4 | `sbom-missing`, `sbom-invalid`, `sbom-version-unsupported`, `sbom-no-components`, `sbom-components-unmatched` | SBOM ausente, inválido, vazio ou com componentes que não podem ser conferidos |
| 5 | `vulnerable-dependency`, `exception-expired` | dependência vulnerável conhecida (ou coberta por exceção vencida) |
| 6 | `vuln-db-integrity`, `vuln-db-unavailable` | a base de vulnerabilidades não é a fixada, ou não pôde ser lida (falha fechada) |

**Precedência:** a saída é a do primeiro código na ordem `internal-error` → `usage` → `exception-format` → perfil → SBOM → componentes →
`vuln-db-integrity` → `vuln-db-unavailable` → `vulnerable-dependency` → `exception-expired`; os demais detectados vão
em `errors[]`. Mensagem em `stderr`: `{"code": "<código>", "detail": "<texto sem nome de componente>"}`.

**Compatibilidade:** campo ou aviso novo no relatório é acréscimo da v1; mudar o sentido de um código ou de uma saída
é v2.
