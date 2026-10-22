# Registro de validação

Dados 100% sintéticos. Os resultados exercitam o pipeline e **não** demonstram eficácia contra ransomware real. O sistema só **detecta**, sem conter: após o alerta, o simulador continua até 200/200 arquivos.

Ambiente: Linux Mint 22.3, kernel 7.0.0-38, x86_64, 4 CPUs, Python 3.12.3, sem privilégio. Windows e macOS não foram testados.

## Rodada 1 — incremento 1 (commit a235db7)
- Testes unitários: 20/20.
- Bateria: 11 cenários × 3 sementes = 33/33 conforme o esperado (`evidence/scenarios-20261022-050038.*`).
- Revisão independente (Sonnet, agente `reviewer`): **reprovado**, 12 achados.
  - Altos: (1) o simulador alterava arquivo por hardlink/symlink/marcador forjado; (2) evasão do R1 por tmp+rename.
  - Médios:
    - FIFO derruba o watch;
    - tipos não validados derrubam o replay;
    - o replay lia o disco;
    - `created` era ilimitado/sem expiração;
    - symlink de diretório era vigiado;
    - entropia `None` entrava no denominador;
    - watches de diretório movido.
  - Baixos: triggers incompletos; status com PID morto ou relógio adiantado; docs inexistentes.

## Rodada 2 — correções
| Achado | Estado | Verificação |
|---|---|---|
| 1 simulador (hardlink, symlink, marcador, `.locked`) | corrigido | `test_hardlink_swap_refused`, `test_symlink_swap_refused`, `test_locked_name_symlink_not_followed`, `test_refuses_forged_marker_dir` |
| 2 evasão tmp+rename | corrigido | `test_atomic_replace_evasion_detected` + cenário `sim_tmp_rename_replace` |
| 3 FIFO | corrigido | `test_entropy` (mkfifo → None) |
| 4 `created` ilimitado | corrigido (TTL 60 s + teto 100k) | `test_created_files_expire_to_preexisting` |
| 5 tipos do schema | corrigido | `test_rejects_malformed` (+6 casos) |
| 6 replay lê disco | corrigido (entropia vai no evento) | `test_default_sampler_never_reads_disk` |
| 7 None no denominador | corrigido; amostragem tardia documentada | `test_unsampled_writes_excluded_from_ratio` |
| 8 symlink de diretório | corrigido (`IN_DONT_FOLLOW|IN_ONLYDIR`, skip islink) | `test_dir_symlink_not_watched` |
| 9 overflow / wd repetido | parcial: gap na incerteza, wd repetido = update; dir movido para fora → pendente/documentado | `test_overflow_is_reported_as_coverage_gap` |
| 10 triggers / 0600 | corrigido | `test_permissions_and_append_only`, `test_existing_db_permissions_tightened` |
| 11 status | corrigido (pid, relógio) | `test_status_future_heartbeat_is_degraded`, `test_status_dead_pid_is_degraded` |
| 12 docs / R2 / dedupe | R2 cobre rename_to, com rate limit; docs criados; dedupe só tem efeito em replay (documentado) | `test_canary_atomic_replace` |

Achado novo do coordenador ao rodar a bateria: `IN_CLOSE_WRITE` disparava em abertura `O_RDWR` sem escrita e inflava o contador de sobrescritas. Corrigido com coalescência de `IN_MODIFY` no sensor (`test_open_for_write_without_writing_is_ignored`).

Resultado: 35/35 testes; bateria com 13 cenários × 3 sementes = 39/39 conforme o esperado (`evidence/scenarios-20261022-050736.*`).

| Cenário | Esperado | Ops antes do alerta (sementes 1, 2, 3) | s até o alerta |
|---|---|---|---|
| sim_overwrite | alert | 20, 20, 20 | ~0.10 |
| sim_write_new_delete | alert | 20, 20, 20 | ~0.12 |
| sim_rename_overwrite | alert | 20, 20, 20 | ~0.10 |
| sim_tmp_rename_replace | alert | 24, 20, 20 | 0.11–0.14 |
| sim_slow_below_threshold | known_miss | — | — |
| 7 cargas benignas | no_alert | — | — |
| benign_gzip_inplace | known_fp | 20, 20, 20 | ~0.01 |

A variação 24 vs 20 vem da latência entre o simulador e o pump do sensor (o simulador roda a 200 ops/s). Uma amostra de 3 sementes não sustenta nenhuma taxa estatística.

Revisão da rodada 2 (Sonnet): **reprovado**. Os dois altos da rodada 1 foram confirmados como fechados. Achados novos:
- (1) ALTO: o conjunto de IN_MODIFY podia ser enchido, cegando o R1 sem degradar a saúde;
- (2) ALTO: escrita por mmap e rename-antes-do-close tinham o `close_write` descartado (regressão);
- (3) MÉDIO: "novo" por caminho era contornável por hardlink e pelas fases rename→espera→overwrite;
- (4)/(5) BAIXOS: FP de `rename_to` mais amplo que o documentado; overflow não limpava o rastreamento.

## Rodada 3: correções do coordenador (limite de 2 rodadas de revisão atingido)
| Achado | Estado | Verificação |
|---|---|---|
| 1 enchente do rastreamento | corrigido: limpa em delete/rename/overflow; ao encher, limpa + degraded, nunca descarta | `test_modify_tracking_cleared_on_unlink`, `test_modify_flood_degrades_not_blinds` |
| 2 mmap / rename antes do close | corrigido: `close_write` sempre emitido, com `no_modify_seen`; conta se a entropia for alta | `test_mmap_write_is_not_dropped`, `test_open_for_write_without_writing_is_flagged_and_ignored_if_low_entropy` |
| 3 hardlink / fases | corrigido: novidade por (dev,inode); `rename_to` não concede; `multi_link` nunca é novo | `test_hardlink_alias_is_not_new`, `test_phased_rename_then_overwrite_detected`, `test_new_file_renamed_stays_new` |
| 4 FP de rename_to | documentado | — |
| 5 overflow | corrigido | — |
| simulador: janela residual por caminho | risco aceito temporariamente (mesmo uid, lab 0700) — **decisão pendente do responsável (usuário)** | — |

Resultado: 41/41 testes; bateria com 13 cenários × 3 sementes = 39/39 conforme o esperado (`evidence/scenarios-20261022-051252.*`).

As correções da rodada 3 ainda **não têm revisão independente**. Elas entram na revisão de arquitetura/sistema integrado do próximo marco.

## Rodada 4 — revisão das correções da rodada 3 + arquitetura
- Revisão (Sonnet): o escopo A foi reprovado por 1 evasão reproduzida (estado obsoleto por caminho após overflow, fallback para path_key).
- Corrigido:
  - inode conhecido ⇒ path_key não é consultado;
  - overflow limpa o estado de novidade;
  - limpeza por prefixo de diretório;
  - unsampled `no_modify_seen` conta;
  - `quality` em conjunto fechado.
- Re-revisão: **aprovado**.
- O escopo B virou `docs/threat-model.md`.
- Benchmark (`scripts/bench_sensor.py`): achou um O(n²) na janela (corrigido, CPU −60%) e perda acima de ~3–4 mil ops/s com saúde degraded (ADR 0002).
- 68 → 87 testes (com mail). Bateria: 39/39.

## ML baseline v1 (Marco C)
- Divisão pré-registrada, teste avaliado uma vez (`evidence/ml-eval-20261022-055045.json`).
- R1 F1 0,69 vs LR 0,56 vs IsolationForest 0,43.
- A LR falha na família reservada.
- **Modelo não promovido.** Ver `docs/model-card-ransomware-lr-v1.md`.

## Analisador .eml (Marco E, parte 1) — 2 revisões + correção do coordenador
- Autor: implementer (Sonnet). Revisor: reviewer (Sonnet, outro agente). Revisão direta do coordenador: fuzz por mutação (3000 casos, 0 exceções) + entradas patológicas. **Não** pegou os DoS abaixo: só a revisão independente encontrou.
- **R1: reprovado.** Altos:
  - RecursionError virava mensagem benigna;
  - limite de partes aplicado depois do parse (82 s / 215 MB);
  - cabeçalho de endereço cúbico (80 KB → 58 s);
  - veredito ignorava limites.
  - Médios: evasões de extensão (`a.exe .`, NUL, `:`, bidi) e AR "primeiro resultado vence".
- **R2: reprovado.** Os altos 1, 3 e 4 foram fechados. Ficou o bypass da pré-checagem por CR puro (73 s) e o crash de `start()`. A CLI usava a versão não isolada; o resultado do filho era pickle.
- **Correção do coordenador** (limite de 2 rodadas atingido):
  - fins de linha normalizados antes de contar;
  - bloco de cabeçalho por linhas;
  - `started` flag;
  - resultado do filho em JSON com tamanho máximo;
  - a CLI usa `analyze_eml_isolated`.
  - Repro do revisor: 73 s → 0,05 s.
- 91/91 testes; bateria 39/39 no candidato.
- **Sem revisão independente** desta última correção. Entra na revisão do sistema integrado.
- Limites aceitos:
  - `analyze_eml` direto não tem teto de tempo (só a versão isolada tem);
  - RLIMIT_AS não é sandbox (mesmo uid, sem seccomp);
  - no Windows só existe o timeout;
  - `(` não fechado no AR descarta o resto (neutro);
  - homógrafos fora de punycode/não-ASCII, `[dot]` e espaçamento escapam;
  - **não é proteção da caixa de entrada**: só análise offline de arquivo.
