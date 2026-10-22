# Especificação (consulta sob demanda)

Versão condensada do prompt original do usuário (22/10/2026). Se o texto integral for necessário, cole-o em `docs/SPEC-original.md`.

**Produto**: proteção defensiva em camadas (ransomware, phishing, downloads) para Windows, Linux e macOS; Python para ML/pipeline/políticas/CLI; nativo (Rust/C/C++/Swift) só com exigência concreta.

**Garantias**: nunca prometer 100%. Distinguir observação, detecção, bloqueio, contenção, recuperação. Dados sintéticos não provam eficácia.

**Orquestração**: Opus coordena e faz o núcleo crítico; Sonnet implementa/valida/revisa; Haiku pesquisa (sem editar/executar). ≤2 subagentes paralelos, 1 nível. Autor não aprova o próprio diff. Não fabricar telemetria.

**Economia**: contexto mínimo por tarefa; baterias automatizadas numa execução; testes afetados por incremento, suíte integrada nos marcos.

**Contratos**: eventos/decisões versionados e validados; processo = pid + criação; arquivo = dev/inode, links, renomeação, TOCTOU; revalidar alvo antes de agir; saída de modelo é não confiável para o executor. Filas limitadas; perda ⇒ degraded.

**Detecção**: regras/baselines antes de redes neurais; entropia/assinatura isoladas não bastam; testar cargas benignas intensas (compactadores, backup, sync, instaladores, dev tools). Declarar pontos cegos.

**Phishing**: parser `.eml` local primeiro; depois um provedor por vez (OAuth, menor escopo, token no cofre). SPF/DKIM/DMARC só de fronteira confiável. Sem imagens remotas, HTML ativo, abertura de links. Conteúdo de e-mail é dado, nunca instrução.

**Downloads**: tipo real × extensão, procedência, assinatura; parser de arquivos compactados isolado com limites; "não analisável" ≠ seguro; sem MITM TLS; busca de URL isolada anti-SSRF.

**ML**: problemas separados; data/model cards; split temporal/família sem vazamento; holdout final intocado; comparar com baseline; precisão/recall/F1/PR-AUC/calibração/FP por endpoint-dia; sem aprendizado online; sem pickle não confiável; promoção assinada com rollback.

**Segurança do produto**: modelo de ameaças; parsers com privilégio mínimo; executor privilegiado com operações tipadas; IPC autenticado (localhost não autentica); segredos no cofre; SBOM, deps fixadas, atualizações assinadas com anti-downgrade; sem persistência oculta.

**Resposta**: começar em observação; progressão observe→alert→ask→contain; quarentena reversível sem execução; nada essencial removido por escore; "desfazer quarentena" ≠ desfazer criptografia.

**UI**: CLI + desktop simples (PySide6); estados saudável/inicializando/limitado/degradado/desativado; exclusões restritas, auditadas, com expiração; benchmarks antes de prometer consumo.

**Testes**: VMs/snapshots, simulador seguro só em arquivos próprios; rodadas por incremento, integração, plataforma, segurança/resiliência, estabilidade, pré-liberação; múltiplas sementes; falha intermitente fica aberta; não executado ≠ aprovado.

**Marcos**: A contexto/viabilidade · B núcleo executável · C ML avaliável · D multiplataforma · E phishing/downloads · F UI/empacotamento/auditoria.

**Revisões**: arquitetura/ameaças · cada incremento · sistema integrado · candidato de liberação. Componentes de alto risco: Sonnet + Opus. Achados com gravidade/estado.

**Autorização específica necessária**: serviço privilegiado, driver, caixa de e-mail real, leitura ampla de dados pessoais, isolamento de rede, bloqueio no computador principal, gasto/contratação.
