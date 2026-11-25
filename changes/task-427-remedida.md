- test: remedida da h3 depois das tasks 424, 427 e 430 (`v0.5.2-135-gddd1620`), contando registros por probe: a
  divisão da h3 acabou (Mac 30 000 de 30 000 com 1 registro e 3 requisições, 0 `quic` órfão); restam 1 requisição na
  conexão anterior da porta (Mac, enlace ruim) e 5 de 24 000 com 2º registro na loopback (task 432). Bot com o teto
  de 320 MiB na carga oficial de 5 min: índice máx 199,8 MiB, 0 despejo, forwardAuth p99 23,57 ms (ADR 0079).
