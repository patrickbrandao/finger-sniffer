- dns: zona padrão `finger-west-01.badblock.net.br` com SOA/NS em `finger-01.badblock.net.br.`; HTTPS RR com prefixo
  de porta em `_<P>._https.<nome>` para cada porta de `FS_WEB_TCP_PORTS` (alvo `<nome>`, `alpn="h3,h2"` se a porta
  está em `FS_WEB_UDP_PORTS`), nome sem prefixo só com 443 na lista, demais rótulos `_` em NODATA e probe lido
  depois dos rótulos `_` à esquerda (task 227, ADR 0038).
