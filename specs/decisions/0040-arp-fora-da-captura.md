# 0040 — ARP fora da captura

Status: aceita
Data: 2026-11-15

## Contexto
No finger-01 (ADR 0038; `/27` em VMware), o gateway do segmento manda ARP *who-has* em broadcast para os vizinhos
o tempo todo. Leitura de `GET /api/v1/packets?limit=1000` em 2026-11-15: 1000 avulsos em 131 s, dos quais 896
(≈ 6,8/s) são quadros ARP (ethertype `0x0806`, 884 em broadcast, 889 do mesmo MAC do gateway), publicados como
`packet.stray` "non-IP frame" (`internal/store/record.go`). Os outros 104 são TCP, ICMP/ICMPv6 e UDP. O feed global
da página fica tomado por ARP e o tráfego dos clientes some. A spec 003 RF-02 dizia "todo o resto entra" e a
ADR 0038 decidiu capturar "toda a NIC" (em oposição a filtrar as portas do traefik), sem tratar quadros não IP.

## Decisão
1. O filtro BPF do capture descarta, no kernel, quadros com ethertype ARP (`0x0806`), com ou sem uma tag VLAN
   `0x8100`, sempre (inclusive com `FS_CAPTURE_EXCLUDE_PORTS` vazio). Sem variável de configuração.
2. Os demais quadros não IP (LLDP, STP, RARP etc.) continuam entrando e virando avulsos "non-IP frame", como hoje.
3. Store, API, feed, contratos e página não mudam.

## Alternativas consideradas
- **Gravar e não publicar no feed** (filtro `kind`/flag): mantém ~7 linhas/s de ruído no SQLite, no NATS e no
  `/api/v1/packets`, e exige mudar o contrato do tempo real; sem ganho, porque o ARP não informa nada do cliente.
- **Agregar (um evento por intervalo)**: muda o `StrayPacket` e o asyncapi, código novo no store para um dado inútil.
- **Filtrar só na página**: o JSON do feed e o `/api/v1/packets` continuam inundados para qualquer outro cliente.

## Consequências
- O ARP é da rede local do servidor: não atravessa roteador, logo nenhum cliente remoto do espelho o produz e nenhum
  caminho (direto, proxy, túnel, ADR 0028) muda o que ele mostra. Descartá-lo não esconde informação útil.
- Menos ~7 pacotes/s no capture, no NATS, no ingest e na tabela `stray_packets` no finger-01.
- Quem precisar ver ARP do host usa `tcpdump` na `ens192`; o espelho não o registra.
- Altera a spec 003 RF-02 e complementa a ADR 0038 (captura de toda a NIC, exceto ARP).
