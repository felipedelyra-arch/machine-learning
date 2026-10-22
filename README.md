# endguard

Protótipo de proteção de endpoint para Linux contra comportamento de ransomware, com regras explicáveis, um pipeline de ML avaliado com rigor e um analisador offline de e-mails `.eml`.

> **Estado: protótipo de observação e detecção.** Não bloqueia, não contém e não substitui antivírus nem backup. Todos os resultados vêm de dados sintéticos e **não demonstram eficácia contra ransomware real**.

## O que faz

- **Observa** uma pasta no Linux via inotify, sem privilégio. Detecta dano em massa a arquivos já existentes, combinado com conteúdo de alta entropia (regra R1), e alterações em arquivos canário (R2).
- **Registra** cada decisão com evidências, versão da regra, incerteza e a ação permitida pela política, numa auditoria SQLite local (0600, append-only).
- **Mostra o estado real do sensor**: `limited`, `degraded` ou `disabled`, sempre com a causa. Nunca aparece "protegido".
- **Analisa e-mails `.eml` offline**: remetente forjado, Reply-To divergente, links que mentem, anexos perigosos e Authentication-Results confiáveis. O parser roda num subprocesso com tempo e memória limitados.

## O que não faz

- Não bloqueia nem contém. O alerta chega depois de ~20 arquivos alterados, e o ataque continua.
- Não identifica qual processo agiu (o inotify não informa isso). Um sincronizador de fotos e um ransomware parecem iguais.
- Não protege a caixa de entrada; só lê arquivos `.eml`.
- Não suporta Windows nem macOS. Não cobre kernel, firmware nem rootkits.
- Ataques mais lentos que o limiar da R1 passam sem alerta. Rajadas acima de ~3–4 mil escritas/s perdem eventos (sinalizado como `degraded`).

A lista completa está em [`docs/architecture.md`](docs/architecture.md) e [`docs/threat-model.md`](docs/threat-model.md).

## Uso

Requer Python 3.12. O núcleo usa só a biblioteca padrão.

```bash
python3 -m endguard.cli watch ~/Documentos --mode alert       # observa uma pasta (Ctrl+C para parar)
python3 -m endguard.cli status                                 # saúde efetiva do sensor
python3 -m endguard.cli tui                                    # painel de terminal (somente leitura)
python3 -m endguard.cli decisions --limit 20                   # últimas decisões em JSON
python3 -m endguard.cli mail mensagem.eml --trusted-authserv mx.seu-provedor.com
python3 -m endguard.cli replay eventos.jsonl                   # reprocessa eventos gravados
```

### Simulador seguro

```bash
python3 -m endguard.cli simulate --variant overwrite --files 200
```

O simulador cria a própria pasta em `/tmp` e só altera arquivos que ele mesmo criou, conferidos por inode. Grava bytes aleatórios, sem criptografia real nem chaves, e recusa qualquer outro alvo. Não há malware real neste repositório.

## Testes e evidências

```bash
python3 -m unittest discover -s tests -t .      # 106 testes
python3 scripts/run_scenarios.py --seeds 1 2 3  # 13 cenários com o sensor real
python3 scripts/bench_sensor.py                 # throughput e perda de eventos
```

Resultados e rodadas de revisão independente: [`docs/validation.md`](docs/validation.md).

### ML

Pipeline em `ml/`. As dependências ficam à parte e são fixadas com hash:

```bash
python3 -m venv .venv && .venv/bin/pip install --require-hashes -r requirements-ml.txt
python3 scripts/record_traces.py               # grava traços sintéticos em data/traces
.venv/bin/python ml/train_eval.py
```

Nenhum modelo está em uso. A v2 atendeu ao critério pré-registrado (R1 OU LR: detecção de 99% contra 62%), mas não foi promovida: uma sonda mostrou falso alarme ao salvar duas fotos JPEG no lugar. Detalhes em [`docs/model-card-ransomware-lr-v2.md`](docs/model-card-ransomware-lr-v2.md). Os modelos são JSON validado, nunca pickle.

## Estrutura

| Caminho | Conteúdo |
|---|---|
| `endguard/` | schema, sensor inotify, regras, auditoria, status, CLI, TUI, analisador de e-mail, carregador de modelo |
| `tests/` | testes unitários e de regressão |
| `scripts/` | cenários, benchmark, gravação de traços |
| `ml/` | treino e avaliação (fora do caminho de produção) |
| `docs/` | arquitetura, ameaças, ADRs, data/model cards, validação, checkpoint |
| `evidence/` | saídas brutas das execuções |

## Licença

[Apache-2.0](LICENSE). Fornecido "como está", sem garantia. Veja [`NOTICE`](NOTICE).
