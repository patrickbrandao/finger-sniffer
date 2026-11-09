- docs: `docs/probes.md` corrige o fechamento após `Connection: close` (achado A6): o espelho não fecha (spec 005
  RF-08); quem fecha é o cliente (em TLS, `close_notify` respondido pelo espelho), um cliente que espera o EOF fica
  até os 120 s de ociosidade, e `close=after`/`idle=` pedem o fechamento pelo servidor (task 119).
