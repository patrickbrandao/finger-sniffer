- store: padrões `FS_MAX_CONNS` 1000 e `FS_MAX_NEW_CONNS_PER_S` 250, `FS_STORE_MAX_BYTES` 8 GiB e stream
  `FS_EVENTS` com 128 MiB (ajustado no start); no health, `conntrack_loaded` e `nft_ruleset_lines` ficam
  informativos e só `nat_on_mirror_ports` degrada (`nat on mirror ports`); exemplos com os nomes do finger-01
  (ADRs 0038 e 0039, task 228).
