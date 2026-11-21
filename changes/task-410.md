- test(store): os testes que sobem um `Store` real usam `newTestStore`, com espaço do banco folgado e fixo
  (`Config.SpaceReader`, nil = statfs), e deixam de depender do disco livre de quem roda (task 410).
