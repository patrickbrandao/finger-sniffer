- infra: as 7 units entram em `finger-sniffer.slice` (`MemoryMax=6G`, `CPUQuota=800%`) com os limites da ADR 0039
  (store 2G, nats 1G, web 768M, capture 512M, raw e dns 256M; `GOMEMLIMIT`, `CPUQuota`, `MemorySwapMax=0`,
  `GODEBUG=disablethp=1`), web sem `CAP_NET_BIND_SERVICE`; sysctl com `somaxconn`/`tcp_max_syn_backlog` 65535 e
  `rmem_max`/`wmem_max` 128 MiB (iguais aos do host); rede na `ens192` com `nat_on_mirror_ports` no `net-status.json`
  (só ele reprova o deploy; nft e conntrack informativos); bootstrap instala só os pacotes ausentes; NATS com
  `max_memory_store` 256MB (task 225).
