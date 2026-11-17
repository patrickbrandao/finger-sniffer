- bot: `forget <ip|prefixo>` alcança a memória do serviço em execução (índice, vereditos, agregados, cache de
  comportamento e de verificação de robô) e `lists refresh [nome]` baixa pelo serviço, pela tabela
  `control_requests` (migration 0002 do bot, ciclo de 2 s, concluídos apagados em 24 h; ADR 0056 item 2).
- bot: health `store feed silent` (store `ok` pelo heartbeat e > 60 s sem `fs.v1.store.connection`) e conferência
  das métricas da spec 018 RF-12 no heartbeat, com os contadores zerados desde o início.
