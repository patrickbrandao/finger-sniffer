- bot: agregados com teto por origem (IPv4 ou /64 IPv6: 32 pares IP + site por hora, 256 fingerprints novas por dia,
  `fs_bot_agg_limited_total{reason}`), requisição do ingest sem router e 404 fora dos agregados e, com o teto global
  cheio, despejo dos comportamentos já gravados (`fs_bot_agg_evicted_total`, health `agg full`) (task 363, ADR 0073 item 7).
