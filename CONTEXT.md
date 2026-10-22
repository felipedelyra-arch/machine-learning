# Vocabulário
- **Evento (FileEvent)**: observação normalizada de um sensor; não confiável até validada pelo schema.
- **Pré-existente**: arquivo não criado durante a sessão do detector. Só operações sobre ele contam como destrutivas.
- **Destrutiva**: sobrescrita, renomeação ou exclusão de arquivo pré-existente.
- **Decisão**: saída de regra/modelo com evidências, versão, incerteza e ação permitida pela política.
- **Modo**: observe (só registra) → alert → ask → contain. Só observe/alert existem hoje.
- **Saúde do sensor**: initializing, limited (funciona com cobertura parcial conhecida), degraded (perda/limite/falha), disabled.
- **Lab**: diretório em tmp com `.endguard-lab`, criado pelo simulador; único alvo permitido do simulador.
- **Canário**: arquivo plantado em diretório controlado; qualquer escrita gera decisão R2.
