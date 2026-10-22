# Checkpoint (22/10/2026)

**Concluído**:
- Marco A parcial: arquitetura, matriz de capacidades e resumo de ameaças.
- Marco B parcial: schema, sensor inotify, regras R1/R2, auditoria, CLI, replay, simulador seguro e bateria.
- 2 rodadas de teste.

**Pendente (próxima ação primeiro)**:
1. Fechar a revisão da rodada 2.
2. Modelo de ameaças completo + revisão de arquitetura antes de existir executor/IPC.
3. fanotify (exige root ou CAP_SYS_ADMIN: **autorização do usuário**) para atribuir processo e mediar aberturas.
4. Marco C: dataset de traços sintéticos + baseline (ADR para scikit-learn).
5. Marco E: parser `.eml` local.
6. Windows/macOS: sem máquina ou VM; precisa de equipamento/VMs.

**Bloqueios**: sem sudo; sem Windows/macOS; agentes do projeto em `.claude/agents/` só carregam após reiniciar a sessão (por ora os globais são usados com override `model: sonnet`).
