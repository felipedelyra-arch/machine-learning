# Modelo de ameaças (v1, 22/10/2026)

Escopo: o endguard como software instalado. O desenvolvimento assistido por LLM fica fora do runtime.

## Ativos
1. **Arquivos do usuário**: o que o produto protege.
2. **Decisões e auditoria**: base para responder e reconstruir incidentes.
3. **Políticas, exclusões e limiares**: quem as altera desliga a proteção.
4. **Modelos e regras**: envenenados ou trocados, cegam a detecção.
5. **Executor privilegiado**: futuro. Se abusado, vira arma: mata processos, move arquivos.
6. **Tokens de e-mail**: futuro (OAuth).
7. **Conteúdo pessoal**: nomes de arquivo, e-mails, URLs.

## Atores
- **A1, malware sem privilégio, mesmo uid do usuário**: o caso principal do ransomware.
- **A2, malware no uid do próprio endguard** (hoje é o mesmo uid do usuário): pode matar o processo, editar o DB e a config, inundar eventos.
- **A3, admin/root hostil, ou kernel/firmware comprometido**: fora de alcance.
- **A4, remetente de e-mail ou site hostil**: só envia dados (mensagens, anexos, URLs).
- **A5, canal de atualização ou distribuição comprometido**.
- **A6, envenenamento de dados de treino**.

## Fronteiras de confiança
| # | Fronteira | Hoje | Exigido |
|---|---|---|---|
| F1 | kernel → sensor | inotify; overflow, caminho rejeitado e raiz removida → degraded com causa | fanotify/ETW/ES (fora do escopo por decisão do usuário) |
| F2 | sensor → detector | mesmo processo, schema estrito; `quality` em conjunto fechado | com processos separados: IPC autenticado (F4) |
| F3 | arquivo de replay → detector | não confiável: tipos e flags validados; linha inválida (JSON profundo, UTF-8 inválido) rejeitada e contada; não lê disco | resultados de replay refletem só as alegações do arquivo |
| F4 | processos sem privilégio → executor | **não existe** | ver contrato abaixo |
| F5 | config/política → motor | **sem integridade** (A2 edita) | arquivo root-owned 0644, ou assinado; mudança auditada |
| F6 | modelo → inferência | JSON validado + sha256 fixado | assinatura + anti-downgrade (pendente) |
| F7 | e-mail/anexo → parser | dado não confiável; limites; nunca executa nem busca rede | parser em processo isolado sem rede (seccomp/sandbox) |
| F8 | strings de evento → CLI/UI/logs | CLI: JSON `ensure_ascii` (escapa surrogates, bidi, C1); TUI: Cc/Cf/Cs → "?" | — |
| F9 | atualização → instalação | **não existe** | assinatura, anti-downgrade, instalação transacional |
| F10 | dados de treino → modelo | sintético, autor único | procedência, revisão de rótulos, sem aprendizado online |

## Contrato mínimo do executor privilegiado e do IPC (antes de escrever código)
- **Transporte**: socket Unix em diretório root-owned, 0600. Par identificado por `SO_PEERCRED` (uid/pid), com pidfd para fixar a identidade. **Nunca TCP/localhost.** No Windows: named pipe com ACL e SID do cliente. No macOS: XPC com verificação de code signing.
- **Operações fechadas e tipadas**: `quarantine_file`, `restore_file`, `suspend_process`, `resume_process`, `kill_process`. Não existe "executar comando", caminho livre nem shell.
- **Validação da mensagem**: schema versionado, tamanho máximo, campos desconhecidos rejeitados, nonce (idempotência) e limite de taxa.
- **Alvos**:
  - Arquivo = `(dev, inode)`, aberto por fd (`openat2` com `RESOLVE_NO_SYMLINKS`, ou `O_PATH`) e revalidado (`fstat`, `nlink`) imediatamente antes de agir, agindo pelo fd.
  - Processo = `(pid, start_time)` via pidfd, revalidado antes de sinalizar.
- **Lista de proteção**: pid 1, o próprio endguard, processos de sessão/sistema e o shell do admin. Nada de suspensão indefinida: duração máxima e retomada automática.
- **Política reaplicada no executor**: ele confere modo `contain` habilitado, escopo e exclusões. A saída do modelo e o solicitante são **não confiáveis**.
- **Auditoria**: antes e depois de cada ação. Falha do executor ou da auditoria → a ação não acontece e o status fica degraded.
- **Quarentena**: move preservando metadados para um diretório root-owned sem permissão de execução, com manifesto de restauração. **Restaurar a quarentena não desfaz criptografia.**

## Riscos aceitos hoje (dono: usuário, pendente de decisão explícita)
- A2 consegue desligar o endguard e editar a auditoria. Mitigação planejada: serviço em uid próprio e exportação de auditoria.
- Janela por caminho no simulador (mesmo uid, lab 0700).
- Throughput: rajadas acima de ~3–4 mil ops/s perdem eventos (sinalizado). Ver ADR 0002.
