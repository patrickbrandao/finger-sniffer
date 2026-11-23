- bot: a 9002 limita 16 conexões simultâneas por origem (IPv4 ou /64 IPv6, fechadas no `accept` sem ocupar vaga),
  fecha as ociosas em 30 s e, com 180 ou mais, as ociosas mais antigas; `ReadHeaderTimeout` (e handshake TLS) de 5 s;
  `fs_bot_public_conns_closed_total{reason}` e health `public conns` (task 336, ADR 0073 item 1).
