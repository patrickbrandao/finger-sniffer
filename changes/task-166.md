- pkg: captura do ClientHello em `tlsparse.Conn` incremental; cada Read examina só os registros novos e
  `Reassemble` roda uma vez, sem o custo quadrático do gotejamento byte a byte (task 166).
