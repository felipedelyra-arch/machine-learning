# Checkpoint (22/10/2026)

**Concluído** (até 4b89604+):
- Marcos B, C (v1 e v2 avaliados; nada promovido), E parte 1 (mail offline isolado), TUI.
- Revisão integrada aprovada.

**Concluído antes**:
- Marco A parcial: arquitetura, matriz de capacidades e resumo de ameaças.
- Marco B parcial: schema, sensor inotify, regras R1/R2, auditoria, CLI, replay, simulador seguro e bateria.
- 3 rodadas de correção e teste, com 2 revisões independentes; ver `docs/validation.md`.

**Pendente (próxima ação primeiro)**:
1. ML v3: novo pré-registro com famílias benignas de sobrescrita in-place de alta entropia (a lacuna revelada pela sonda v2).
2. Revisão independente das últimas correções da TUI (ainda sem 3ª revisão).
3. Coletor nativo (ADR 0002) para throughput, se for desejado. Sem privilégio, ele só melhora a observação.
4. Windows/macOS: sem teste nativo por decisão do usuário (sem VM). Ficam como não suportados.

**Decisão do usuário (22/10/2026), permanente**: NUNCA usar sudo/privilégio, VMs, amostras reais de malware, acesso à caixa de e-mail real, nem nada que reduza a segurança do PC.
- Consequência: escopo = Linux sem privilégio (só observação/detecção, sem atribuição de processo nem bloqueio).
- fanotify, ETW, Endpoint Security, contenção e integrações reais ficam fora até nova decisão explícita.

**Bloqueios**: sem sudo; sem Windows/macOS; agentes do projeto em `.claude/agents/` só carregam após reiniciar a sessão (por ora os globais são usados com override `model: sonnet`).
