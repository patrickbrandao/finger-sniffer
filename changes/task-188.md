- docs: `docs/metrics.md` completo com todos os contadores do heartbeat (dns, web, raw, store, produtor) e
  `fs_store_flows_dropped_total`, alertas `increase(...) > 0` para descarte de evento, lote inválido, ACME, RRL e
  tabelas cheias; teste em `docs/docs_test.go` falha se uma métrica do código faltar no guia (task 188).
