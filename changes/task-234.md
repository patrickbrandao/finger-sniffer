- test: e2e, golden e carga apontam para o finger-01 (ADRs 0038 e 0039): zona `finger-west-01.badblock.net.br`, web
  em 8080/8443 e h3 na UDP 8443 (clientes h3 por IPv6), HTTPS RR em `_8443._https`, página pelo traefik e direta;
  `loadmon` lê `finger.slice/finger-sniffer.slice` e grava `nr_throttled`, `loadgen` com 400/100 e `conntrack -S`
  antes/depois; resultados da vps602 ficam como registro (task 234).
