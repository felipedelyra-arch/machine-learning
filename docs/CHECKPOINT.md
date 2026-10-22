# Checkpoint (22/10/2026)

**Concluído**:
- Marco A parcial: arquitetura, matriz de capacidades e resumo de ameaças.
- Marco B parcial: schema, sensor inotify, regras R1/R2, auditoria, CLI, replay, simulador seguro e bateria.
- 3 rodadas de correção e teste, com 2 revisões independentes; ver `docs/validation.md`.

**Pendente (próxima ação primeiro)**:
1. Revisão do sistema integrado (inclui a última correção do mail.py, ainda sem revisão independente).
   - Feito até aqui: Marco B (núcleo Linux); Marco C v1 (LR não promovida); Marco E parte 1 (`endguard mail`, offline e isolado).
2. Modelo de ameaças completo + revisão de arquitetura antes de existir executor/IPC.
3. fanotify (exige root ou CAP_SYS_ADMIN: **autorização do usuário**) para atribuir processo e mediar aberturas.
4. Marco C v2: novo pré-registro, features de taxa, calibração, ensemble R1+LR (o teste v1 já foi consumido).
5. Marco E parte 2: primeira integração real de e-mail (IMAP/Gmail/M365) — **precisa de autorização e escolha do provedor**.
6. Windows/macOS: sem máquina ou VM; precisa de equipamento/VMs.

**Bloqueios**: sem sudo; sem Windows/macOS; agentes do projeto em `.claude/agents/` só carregam após reiniciar a sessão (por ora os globais são usados com override `model: sonnet`).
