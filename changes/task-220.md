- test(load): `budgetload` separa por causa as conexões h1/WebSocket encerradas sem resposta (`close_causes`,
  `ws_session_ends`, `max_ws_sessions`; `closed_by_server` vira `closed_no_response`), `budget.sh` com `RESTART_WEB=1`
  e memória do web por janela de 30 s; janelas A e B da task 215 em `test/load/RESULTS.md` (task 220).
