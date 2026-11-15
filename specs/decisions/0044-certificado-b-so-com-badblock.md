# 0044 — Certificado B e rota do traefik só com `finger-01.badblock.net.br`

Status: aceita
Data: 2026-11-15

## Contexto
A ADR 0038 (itens 4 e 6) dava ao certificado B os nomes `finger-01.badblock.net.br` e `finger-01.tmsoft.com.br`,
e a rota de passthrough do traefik para os dois, condicionando `finger-01.tmsoft.com.br` ao aval do humano (o
container `traefik-certs` já tem um roteador nesse nome). Na task 232 o humano decidiu que
`finger-01.tmsoft.com.br` fica com o traefik dele; a task 238 tirou o nome do padrão de `FS_CERT_NAMES_HTTP01`
(`pkg/certs`) e o `.env.example` acompanhou. Specs e docs ficaram com o texto antigo (auditoria da task 236).

## Decisão
1. Certificado B: só `finger-01.badblock.net.br` (TLS-ALPN-01 pelo passthrough do traefik, como na ADR 0038).
2. Rota do traefik para a página do espelho: só `finger-01.badblock.net.br`. `finger-01.tmsoft.com.br` segue como
   nome do host para ssh e fica com o traefik do humano (fora do espelho).
3. Altera a ADR 0038 itens 4 e 6 nesse ponto; o resto dela fica.

## Alternativas consideradas
- Manter os dois nomes no B — tiraria a rota do container do humano; recusado por ele na task 232.

## Consequências
- Specs 001, 014, 015 e 016 atualizadas; `docs/api.md` e `docs/README.md` pelo docs (task 249).
- Código sem mudança (já conforme desde a task 238).
