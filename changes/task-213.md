- web: o `http2.stream` cancelado pelo cliente (RST_STREAM) logo depois do HEADERS da resposta não perde mais o
  `response_started_at`: o registro espera as escritas em andamento chegarem ao parser passivo (task 213).
