# ADR 0002 — Throughput do sensor Python e coletor nativo

**Status**: proposto (22/10/2026). Evidência: `evidence/bench-20261022-052420.json`.

**Medição**: Mint 22.3, 4 CPUs. Gerador de escrita benigna em processo separado; 4 KiB por arquivo.

| Ops | Taxa do gerador | p50 / p95 da latência | Perda |
|---|---|---|---|
| 2000 | ~20k/s | 0,45 / 0,58 s | 0 |
| 10000 | ~12k/s | — | 35% (overflow, saúde degraded) |
| 30000 | ~14k/s | — | 70% (overflow, saúde degraded) |

- RSS: ~30 MB.
- Capacidade sustentada: ~3–4 mil ops/s. O custo dominante, depois de remover um O(n²) da janela, é a amostragem de entropia (`Counter` em 4 KiB, ~0,28 ms por amostra).
- A fila do kernel é `max_queued_events=16384`.

**Decisão**: o sensor Python fica como referência e para baixa taxa. Para o Marco D, um coletor nativo em Rust:
- leitura do inotify/fanotify e amostragem de entropia em thread dedicada;
- fila limitada com contagem de descarte;
- envio de eventos já normalizados ao processo Python por IPC autenticado.

Até lá, a perda sob rajada continua sinalizada como `degraded` e entra na incerteza das decisões. Nunca é silenciosa.

**Consequência**: dependência de toolchain Rust (não instalada) e do contrato IPC (`docs/architecture.md`). Alternativa barata, a medir antes: amostrar só os primeiros 1 KiB, o que reduz o custo ~4x com mais ruído na entropia.
