# Data card — traços sintéticos de comportamento de arquivo (v1)

**Origem**: `scripts/record_traces.py`. Sensor inotify real sobre labs em tmp. Malicioso = simulador seguro (bytes aleatórios sobre arquivos próprios). Benigno = cargas sintéticas.

**Licença**: própria do projeto. Não há dados de terceiros nem pessoais.

**Período/coleta**: 22/10/2026. Uma máquina (Mint 22.3, kernel 7.0, x86_64).

**Rótulo**: por traço (1 = o simulador rodou). Janelas iniciais de traços maliciosos parecem benignas, então o rótulo por janela é ruidoso. A avaliação é por traço (escore máximo).

**Classes**:
- Maliciosas (6 famílias × 20 sementes): `overwrite`, `write_new_delete`, `rename_overwrite`, `tmp_rename_replace`, `slow`, `mixed` (lento + edição benigna concorrente).
- Benignas (9 × 20): `copy_compressed`, `bulk_text_edit`, `rm_tree`, `zip_archive`, `tar_backup`, `unzip_media`, `editor_atomic_save`, `gzip_inplace`, `media_resync`.
- Parâmetros (taxa, nº de arquivos, parada parcial) derivados de `random.Random(f"{family}:{seed}")`.

**Divisão (pré-registrada antes de qualquer treino)**:
- Famílias reservadas, só no teste: `sim_tmp_rename_replace`, `benign_media_resync`, `benign_editor_atomic_save`.
- Demais famílias: sementes 0–11 treino, 12–15 validação (limiar), 16–19 teste.
- Limiar escolhido só na validação e congelado antes de abrir o teste. O teste é avaliado uma vez.
- Duplicatas: o sha256 do traço é checado; transformações (escala) ajustadas só no treino.

**Limitações**:
- Sintético e de uma única máquina: **não** representa ransomware real (criptografia parcial, intermitente, multi-thread, via rede) nem cargas reais de usuário.
- `media_resync` é indistinguível de ransomware sem atribuição de processo.
- A temporização depende de carga/CPU, então os traços não são bit-a-bit reproduzíveis. Os hashes no manifesto identificam os dados exatos usados.

**Riscos de contaminação**: o simulador e as features vêm do mesmo autor. Um modelo pode aprender artefatos do simulador (tamanho fixo, bytes uniformes).

**Armazenamento**: `data/traces/` (gitignored, ~MB), com `manifest.json` (hashes). Os traços são regeneráveis pelo script.

## v2 — pré-registro (22/10/2026, antes de gravar o teste v2)
- **Treino/validação**: todos os 300 traços v1. Sementes 0–13 → treino, 14–19 → validação (limiar + calibração Platt). O teste v1 já foi consumido, por isso entra no treino.
- **Teste v2**: gravado depois deste registro, em `data/traces-v2-test/`.
  - Sementes 100–111 das 15 famílias v1.
  - Famílias inéditas, nunca treinadas: `sim_burst_pause` (rajadas de 15 ops + pausa de 11 s) e `benign_backup_rotate` (cria arquivos novos e apaga os antigos de alta entropia).
- **Modelos**:
  - R1;
  - LR v2 (features de 10 s + 60 s, log1p) calibrada;
  - ensemble R1 OU LR v2.
- **Limiar**: o menor com FPR ≤ 10% nos traços benignos da validação, congelado antes do teste.
- **Critério de promoção (fixado agora)**: o ensemble só é promovido se, no teste v2, o recall for maior que o da R1 com IC95 do ganho excluindo 0 (bootstrap pareado) E FP ≤ FP da R1 + 5% dos benignos.
- Hiperparâmetro fixado a priori, sem busca: LR com C=0,1, class_weight=balanced.
