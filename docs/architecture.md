# Arquitetura, capacidades e ameaças (v0.1)

## Camadas e estado

| # | Camada | Implementação atual | Estado |
|---|---|---|---|
| 1 | Coletores nativos | `endguard/sensors/linux_inotify.py` (ctypes, sem privilégio) | implementado, testado localmente (Linux x86_64) |
| 2 | Canal autenticado + normalização | normalização em `schema.py`; **sem IPC** (processo único) | parcial — IPC entra junto com o executor privilegiado |
| 3 | Características/correlação | janela deslizante em `rules.py` | implementado |
| 4 | Regras + modelos locais | R1 (dano em massa), R2 (canário); ML no Marco C | regras implementadas; ML pendente |
| 5 | Políticas | modos observe/alert | parcial |
| 6 | Executor privilegiado | — | **não existe**; nenhuma resposta além de registrar/alertar |
| 7 | Auditoria local | SQLite 0600, trigger append-only | implementado (não resiste a admin/dono) |
| 8 | UI/admin | CLI (`python3 -m endguard.cli`) | CLI; PySide6 no Marco F |

```mermaid
flowchart LR
  S[Sensor inotify] -->|FileEvent validado| D[Detector R1/R2]
  D -->|Decision| P[Política observe/alert]
  P --> A[(Auditoria SQLite)]
  S -->|health| A
  CLI --> A
```

LLMs (Opus/Sonnet/Haiku) só no desenvolvimento. Produção: regras e modelos locais, sem rede.

## Matriz de capacidades

| Plataforma | Fonte | Privilégio | Bloqueia antes? | Atribui processo? | Estado no projeto |
|---|---|---|---|---|---|
| Linux ≥5.x | inotify | nenhum | **não** (observacional) | **não** | implementado, testado nativo (Mint 22.3, kernel 7.0, x86_64) |
| Linux | fanotify `FAN_OPEN_PERM`/`FAN_ACCESS_PERM` (+`FAN_REPORT_FID`) | CAP_SYS_ADMIN | só na **abertura/acesso**; não medeia gravações em fd já aberto nem mmap | sim (pid; pidfd ≥5.15) | planejado; kernel local tem `CONFIG_FANOTIFY_ACCESS_PERMISSIONS=y`; **sem sudo nesta sessão** |
| Windows 10/11 | ETW (Kernel-File, Kernel-Process) | admin | não | sim | planejado; sem máquina Windows |
| Windows | minifilter (pre-write) | driver assinado (EV + atestação MS) | sim | sim | alto risco, componente separado; adiado |
| macOS 13+ | Endpoint Security (AUTH_OPEN/RENAME/UNLINK + NOTIFY_WRITE) | entitlement `com.apple.developer.endpoint-security.client`, assinatura, TCC FDA | AUTH sim, com prazo; escrita só NOTIFY | sim (audit token) | planejado; sem Mac nem entitlement |
| macOS | FSEvents | nenhum | não | não | modo limitado de fallback |

Fontes: man7.org fanotify(7)/inotify(7); learn.microsoft.com “About file system filter drivers”; developer.apple.com Endpoint Security.

## Limites de garantia (atuais)
- **Só detecção**, nunca prevenção: o alerta chega depois de ~20 arquivos alterados (ver `docs/validation.md`). Sem contenção, o dano continua.
- Sem atribuição de processo: atividade benigna concorrente soma na janela; não há como apontar/parar o culpado.
- Evasões conhecidas do R1 (abertas):
  - taxa abaixo de 20 ops destrutivas/10 s;
  - cifrar só parte do arquivo, mantendo baixa entropia nos primeiros 4 KiB;
  - arquivos < ~150 B (a entropia não chega a 7.2);
  - diluição da razão com escritas de baixa entropia;
  - wipers que só apagam (sem escrita de alta entropia o R1 não dispara; o R1 é voltado à criptografia);
  - arquivos fora da árvore vigiada e diretórios movidos para dentro dela (seus arquivos não geram eventos);
  - corrida entre `mkdir` e `add_watch`;
  - backlog: a entropia é amostrada na leitura do evento, e um arquivo já renomeado/apagado fica "unsampled" (fora da razão, mas ainda conta como destrutivo).
- Evasão corrigida: "grava temporário + rename por cima" (`replace`), coberta desde a v2 da regra.
- Falsos positivos conhecidos: `gzip -r`/recompressão in-place; `rename_to` de arquivo criado na sessão para um nome novo (ex.: `.part`→final) conta como `replace`, porque o inotify não informa se o destino existia.
- Limites do sensor: `close_write` só conta se houve `IN_MODIFY` (abrir para escrita sem escrever é ignorado); diretório movido para fora da árvore mantém o watch com caminho antigo; um overflow deixa a saúde em degraded até reiniciar e entra na incerteza das decisões.
- Fora de alcance: kernel/firmware, rootkits, malware dormente, invasor com privilégio igual ou superior.

## Modelo de ameaças (resumo; detalhar no Marco A2)
| Ativo | Ameaça | Mitigação atual | Pendente |
|---|---|---|---|
| Leitura de conteúdo | symlink trocado (TOCTOU), FIFO para travar/derrubar o sensor | `O_NOFOLLOW|O_NONBLOCK`, `S_ISREG`, erros → None, só 4 KiB; o detector nunca lê disco (replay determinístico) | componentes intermediários do caminho ainda seguem symlink → usar o fd do evento (fanotify) |
| Auditoria | adulteração | 0600 (inclusive em DB pré-existente), `O_NOFOLLOW`, triggers impedem UPDATE/DELETE nas duas tabelas — barreira contra bugs, **não** contra o dono do arquivo | cadeia de hash; export remoto opcional |
| Simulador | uso contra dados reais | só (dev,inode) criados pelo próprio processo (registro em memória, não no disco), `O_NOFOLLOW`/`O_EXCL`, `st_nlink==1`, dono, lab 0700 direto em tmp, limites, bytes aleatórios | — |
| Status | “protegido” falso | heartbeat; >30 s, relógio adiantado ou PID morto ⇒ degraded | ids por sensor quando houver vários watchers |
| Replay | evento hostil derruba/sonda | tipos estritos no schema; linha inválida é rejeitada e contada | assinatura de replays |
| Executor/IPC/atualização/ML | — | não existem ainda | revisar antes de existirem |
