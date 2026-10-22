# Model card — ransomware-lr-v1 (**NÃO promovido**)

- **Tipo**: regressão logística sobre 8 features da janela de 10 s do detector (`endguard/ml_model.py`).
- **Treino**: scikit-learn 1.7.2.
- **Artefato**: `models/ransomware-lr-v1.json`, sha256 `4d96dc59…1d21`. JSON, sem pickle.
- **Dados**: `docs/data-card-ransomware-traces.md`, 300 traços sintéticos.
- **Divisão pré-registrada**: treino 144 / val 48 / teste 108 (40 positivos), com 3 famílias reservadas.
- **Evidência**: `evidence/ml-eval-20261022-055045.json`.

## Resultado no teste (avaliado uma vez, limiar congelado na validação)
| Modelo | Precisão | Recall (IC95) | F1 (IC95) | PR-AUC (IC95) | FP / 68 benignos |
|---|---|---|---|---|---|
| Regra R1 (em produção) | 0,59 | 0,83 (0,69–0,93) | 0,69 (0,58–0,78) | — (binária) | 23 |
| LR | 0,81 | 0,43 (0,28–0,58) | 0,56 (0,41–0,70) | 0,73 (0,61–0,84) | 4 |
| IsolationForest (só benignos) | 0,36 | 0,53 | 0,43 | 0,37 | 37 |

**Por família**:
- **R1**:
  - Detecta `overwrite`, `rename_overwrite` e `write_new_delete` em 4/4, e `tmp_rename_replace` (reservada) em 20/20.
  - Perde `slow` (1/4) e `mixed` (0/4).
  - FP em `media_resync` (19/20) e `gzip_inplace` (4/4).
- **LR**:
  - Detecta `slow` e `mixed` em 4/4.
  - **Falha na família reservada** `tmp_rename_replace` (1/20) e em `write_new_delete` (0/4).
  - FP em `media_resync` 4/20.

## Interpretação
- A LR **não supera** a R1 no geral (F1 0,56 vs 0,69, com ICs sobrepostos). Ela é complementar: pega ataques lentos e diluídos, que a R1 perde.
- **Não generaliza para a família não vista.** A feature `replace` nunca aparece no treino, então o coeficiente fica em 0. É o risco de deriva e de família nova, materializado.
- O limiar escolhido na validação (≈1 − 4e-10) mostra probabilidades saturadas e **não calibradas** (Brier por traço 0,28). O escore não deve ser exibido como probabilidade.
- `media_resync` é o caso indistinguível sem atribuição de processo. Nenhum modelo resolve isso com essas features.
- Com 40 positivos e dados sintéticos de autor único, **a eficácia não está demonstrada**.

## Decisão
**Não promover.** O caminho de produção continua só com a R1.

Próxima iteração, com **novo pré-registro e novo conjunto de teste** (este teste já foi consumido):
- features de taxa e duração;
- treino com mais famílias de padrão (incluir replace);
- calibração (Platt/isotônica na validação);
- avaliar R1 OR LR como ensemble.
