- infra: unit `finger-sniffer-bot` no target e na fatia (depois do store; 1G/768MiB/200%, sem swap nem capabilities,
  `var/bot` em disco preservado pelo deploy); `make build`/`deploy`/release com 6 binários e `SVC=bot`; 9002/9003 fora
  da captura (o deploy troca o padrão antigo instalado) e 9003 na bridge do traefik (10.249.255.254/16); smoke do bot
  (9002 com TLS, 9003 loopback/bridge/403) e banco-modelo do bot no verify (task 269).
