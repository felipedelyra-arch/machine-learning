# Model card — ransomware LR v2 + ensemble R1 OU LR (**NÃO promovido**)

- **Modelo**: regressão logística sobre 16 features (janelas de 10 s e 60 s, log1p), C=0,1 fixado a priori, calibrada (Platt) na validação. Limiar 0,593 (FPR ≤ 10% na validação).
- **Pré-registro**: `docs/data-card-ransomware-traces.md` §v2, em commit anterior ao teste.
- **Evidência**: `evidence/ml-eval-v2-20261022-062220.json`.

## Teste v2 (204 traços inéditos, 84 maliciosos, avaliado uma vez)
| Modelo | Precisão | Recall | FP / 120 | PR-AUC | Brier |
|---|---|---|---|---|---|
| R1 | 0,59 | 0,62 | 36 | — | — |
| LR v2 | 1,00 | 0,71 | 0 | 0,90 | 0,11 |
| R1 OU LR v2 | 0,70 | 0,99 | 36 | — | — |

- Ganho de recall do ensemble sobre a R1: IC95 [0,27; 0,48] (bootstrap pareado).
- **O critério de promoção pré-registrado foi atendido.**
- Família inédita `sim_burst_pause`: LR 12/12 (R1 0/12), com ~2 operações antes da detecção.
- A LR perde `tmp_rename_replace` e `write_new_delete`; a R1 os cobre.
- Os FPs do ensemble são todos da R1: `media_resync`, `gzip_inplace` e `backup_rotate` (inédita), 12/12 cada.
- Calibração: no bin 0,4–0,6 a fração de positivos é 0,19 (abaixo do previsto); nos extremos ela é boa.

## Sonda exploratória (fora do pré-registro) — `ml/probe_inplace_resave.py`
- Carga benigna nova: reescrever no lugar k arquivos JPEG já existentes, como faz um editor de foto, um banco de dados ou um app de escritório.
- **A LR v2 alerta com k ≥ 2, em 3/3 execuções.**
- O conjunto de dados não tem nenhuma família benigna desse tipo, então o FP = 0 do teste não representa uso real. É o artefato de simulador previsto no data card.

## Decisão
**Não promover.** O critério pré-registrado é necessário, não suficiente. A sonda revelou uma lacuna de dados que o tornaria ruidoso em uso normal. A produção continua só com a R1.

**v3** precisa de novo pré-registro:
- famílias benignas de sobrescrita in-place de alta entropia (foto/vídeo, SQLite, docx/xlsx, VM disk) no treino E no teste;
- pelo menos uma família benigna inédita no teste;
- talvez uma feature de "fração de arquivos tocados no diretório", para separar 2 arquivos editados de 200 cifrados.
