# endguard — proteção de endpoint (defensivo)

- Spec completa sob demanda: `docs/SPEC.md`. Arquitetura/capacidades/ameaças: `docs/architecture.md`. Estado: `docs/CHECKPOINT.md`. Evidências: `docs/validation.md`, `evidence/`.
- Python stdlib primeiro; dependência nova só com justificativa em ADR (`docs/adr/`).
- Nunca: executar/baixar malware real; simulador fora de lab marcado em tmp; LLM no caminho crítico; pickle/joblib de fonte não confiável; desativar proteções do SO.
- Diferenciar sempre observação / detecção / bloqueio / contenção / recuperação. Sensor sem permissão ou com perda = "degraded", nunca "protegido".
- Testes: `python3 -m unittest discover -s tests -t .` (afetados por incremento); bateria: `python3 scripts/run_scenarios.py --seeds 1 2 3`.
- Agentes: researcher (Haiku), implementer/validator/reviewer (Sonnet). Máx. 2 em paralelo, 1 nível. Autor não aprova o próprio diff.
- **Decisão do usuário, permanente**: nunca sudo/privilégio, VMs, malware real, caixa de e-mail real nem redução de segurança do PC. Não pedir de novo.
