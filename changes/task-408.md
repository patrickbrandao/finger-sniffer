- bot: na 9003 a chave só escolhe domínios e modo — sem balde nem cota em nenhuma rota, uso ainda gravado em
  `key_usage_daily` — e o forwardAuth em `block` não cai mais em fail-open por 429; health `block key limited` quando
  uma chave em `block` recebe 429 na 9002 (task 408, ADR 0073 item 4).
