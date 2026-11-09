- store: `ip.packets` com o cabeçalho IP do SYN, do ACK do handshake e do primeiro pacote com dados (UDP: só o
  primeiro datagrama); long-poll `?wait` aceita `settle` (0–10 s) e `min_conns` (1–1000) e responde `wait_met`;
  instantes por requisição de h1/h2/h3 conferidos até o registro e nos exemplos do openapi (task 114, ADR 0029).
