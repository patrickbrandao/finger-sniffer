- store: o `/metrics` republica chaves do heartbeat com rótulos (`nome{r="v"}`) como `fs_<nome>{service,<rótulos>}`,
  junta `_bucket`/`_sum`/`_count` num histograma e conta chaves malformadas, em conflito ou além de 512 em
  `fs_store_heartbeat_metrics_invalid_total{service}` (ADR 0056 item 4).
