- store: tabela de fluxos com teto de 8192 entradas; cheia, despeja a não estabelecida mais antiga (sem registro nem
  avulso) ou recusa a 5-tupla nova, em `fs_store_flows_dropped_total{reason=evicted|table_full}`; TCP sem handshake
  completo sai em 10 s; contagem de vivas do modo degradado em O(1) (task 128).
