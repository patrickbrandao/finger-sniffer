# 0028 — Projeto independente de consumidores específicos

Status: aceita
Data: 2026-11-09
Substitui: 0022 (a parte do consumidor: caminhos com proxy pelo script de um consumidor, receitas para ele e a
pendência externa no PR de release). O restante da 0022 (matriz direta e medição das RNF) continua valendo.

## Contexto
Desde a ADR 0001 as specs tratam um consumidor específico como "consumidor principal": a matriz e2e da spec 017
listava caminhos por proxies de um ambiente que o projeto não controla, a spec 000 citava o script de teste dele
como usuário principal, o `docs/probes.md` trazia receitas com os nomes dos proxies e a ADR 0022 registrava a
matriz com proxy como pendência externa no PR de release. Fato novo: decisão do humano, literal: "Esqueça
completamente qualquer detalhe do go-xproxy, esse projeto é independente, o go-xproxy deverá se adaptar a ele."

## Decisão
- O espelho é **genérico**: serve a qualquer cliente que repete a sondagem por caminhos diferentes (direto,
  proxies, túneis) e compara o que o espelho viu. Nenhum consumidor específico é citado nas specs, nos docs, nos
  critérios de aceite nem nos testes.
- A **matriz e2e** da spec 017 é só pelo **caminho direto**, mais a verificação de que o espelho expõe tudo o que
  um cliente precisa para comparar caminhos (campos estáveis entre execuções, sinais de proxy, bytes crus e
  diferenças esperadas descritas de forma genérica em `docs/probes.md`).
- A **comparação entre caminhos** e qualquer script que passe por um proxy são do cliente. As receitas de
  `docs/probes.md` usam um proxy genérico (`PROXY:PORTA`): proxy HTTP, túnel `CONNECT` e HTTPS-proxy.
- **Não há pendência externa** para release: o MVP fecha com os itens da spec 000 provados no espelho.
- Sinais de proxy (spec 009 RF-07) só listam cabeçalhos conhecidos do mercado: sai `X-xproxy-*`; `X-Squid*` fica
  (cabeçalho padrão do squid, genérico), assim como `X-Proxy-*`.

## Alternativas consideradas
- Manter o consumidor citado como exemplo: contraria a decisão do humano e amarra o contrato a um projeto externo.
- Manter `X-xproxy-*` na lista de sinais: é cabeçalho de um único projeto, sem uso de mercado; um cliente que
  precise dele configura a lista (RF-07 é configurável).

## Consequências
- AGENTS.md, README.md, specs 000, 004, 009, 010, 017, PLAN e a nota de licença da ADR 0010 ficam genéricos.
- `docs/probes.md` e `docs/README.md` sem nomes de consumidor nem de host de proxy; sem a seção do script externo
  e sem os sufixos de sessão de um proxy específico.
- `pkg/h1` deixa de marcar `X-xproxy-*` como sinal de proxy (muda comportamento em runtime do web; implantado junto
  com a próxima entrega do web).
- O texto histórico das ADRs 0001, 0021, 0022 e 0023 não é reescrito; o HISTORY.md marca a 0022 como substituída
  na parte do consumidor.
