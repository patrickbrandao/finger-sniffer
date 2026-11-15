- docs: `docs/`, `htdocs/` e README apontam para o finger-01 (ADRs 0038 e 0039): API em `finger-01.badblock.net.br`,
  zona `finger-west-01.badblock.net.br`, web em TCP 8080/8443 e UDP 8443, Alt-Svc `h3=":8443"`, HTTPS RR em
  `_8443._https`, certificados A/B, limites novos, sysctls do host e conntrack informativo; "Run probe" com porta
  explícita e aviso de que o tráfego dos sites atrás do traefik também é público (task 233).
