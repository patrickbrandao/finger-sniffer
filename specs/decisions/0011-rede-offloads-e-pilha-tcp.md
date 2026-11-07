# 0011 — Offloads desligados e pilha TCP fixada

Status: aceita
Data: 2026-11-07

## Contexto
Em 2026-11-07 a `eth0` (virtio_net) tinha GRO, rx-gro-hw, TSO, GSO e tx-checksum ligados; o kernel juntaria
segmentos e o pcap não mostraria o que veio do fio. `tcp_syncookies=1`, `tcp_ecn=2`, `htcp`, `fq_codel`, sem
firewall nem conntrack.

## Decisão
- Desligar no boot (unit oneshot): `gro`, `rx-gro-hw` (no virtio faz o hypervisor parar de entregar pacotes
  agregados), `lro`, `tso`, `gso`, `tx-checksumming`, `rx-udp-gro-forwarding`.
- Verificação contínua: nenhum frame capturado > MTU + 14; health mostra os offloads efetivos.
- Sysctls TCP fixados em `deploy/sysctl/90-finger-sniffer.conf`: `syncookies=1` com `somaxconn` e
  `tcp_max_syn_backlog` altos (cookies nunca disparam em uso normal) e contador de disparos; publicados no health
  junto com a versão do kernel.
- Sem firewall com estado, sem conntrack/NAT.

## Alternativas consideradas
- Só offloads de RX; `syncookies=0`; deixar o padrão do kernel.

## Consequências
- Um pouco mais de CPU por pacote.
- O hypervisor ainda pode alterar pacotes antes da VM; o critério MTU + 14 detecta agregação residual.
