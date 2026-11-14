- store: `DELETE /api/v1/probes/{id}` roda numa transação e leva também as conexões abertas do probe, que somem na
  hora de todas as leituras; pacotes, eventos e o fechamento delas são descartados sem recriar a linha (task 150).
