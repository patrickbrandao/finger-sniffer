- test: e2e, golden e carga apontam para o finger-01 (ADRs 0038 e 0039): zona `finger-west-01.badblock.net.br`, web
  em 8080/8443 e h3 na UDP 8443 (clientes h3 por IPv6), HTTPS RR em `_8443._https`, página pelo traefik e direta;
  `loadmon` lê `finger.slice/finger-sniffer.slice` e grava `nr_throttled`, `loadgen` com 400/100 e `conntrack -S`
  antes/depois; resultados da vps602 ficam como registro (task 234).
- test: ferramentas de referência no finger-01 (tshark 4.4.19, p0f 3.09b, ja4 0.18.6 em `/root/ja4-rust`); matriz
  direta (13 casos) verde contra o finger-01 em `v0.2.1-75` (task 234).
