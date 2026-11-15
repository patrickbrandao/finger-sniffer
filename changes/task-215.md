- web: orçamento de entrada reserva a memória alocada (capacidade de `RawHead`, cópias e fatias de campos do h1, buffer do HEADERS h3, pendente do `tap`), 2 MiB por sessão WebSocket, padrão 24 MiB na faixa 8–32 MiB; `bufio` do HTTP/1 de 16 KiB, `SO_RCVBUF`/`SO_SNDBUF` de 64 KiB no WebSocket sobre HTTP/1, janelas do quic-go em 2/4 MiB e `GOMEMLIMIT` do web em 64 MiB (task 215, ADR 0036).
- test: carga do orçamento do web no finger-01 (ADR 0039, `v0.2.1-75`): janelas A (220 h1/16 WS/14 h3) e A4 (900/32/56)
  com `memory.peak` 539/544 MB (meta ≤ 704 MiB), `anon` 493/488 MiB, `memory.events max` 0, sem reinício e
  `thp_fault_alloc` 0 com `GODEBUG=disablethp=1`; a parcela anônima não mapeada da vps602 sumiu (task 215).
