# ADR 0001 — Primeiro incremento: Python stdlib + sensor Linux observacional

**Status**: aceito (22/10/2026)

**Contexto**: única máquina disponível é Linux Mint 22.3 x86_64 sem sudo; sem Windows/macOS, sem pip deps instaladas.

**Decisão**: núcleo em Python 3.12 só com stdlib (dataclasses validadas, sqlite3, ctypes/inotify, unittest). Regras explicáveis antes de ML. Sem IPC/executor até existir resposta privilegiada.

**Consequência**: zero dependências a auditar agora; cobertura Linux é *limitada* (sem bloqueio, sem processo). fanotify (permissão), ETW e Endpoint Security ficam para o Marco D com autorização/equipamento. scikit-learn entra no Marco C via ADR própria.
