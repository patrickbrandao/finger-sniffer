# 003 — Serviço capture

Status: aprovada
Depende de: 001, 016

## Contexto
Captura na íntegra todos os pacotes que passam pela `eth0` (exceto portas de gerência e da API) e os publica no
NATS para o store correlacionar e analisar. Não analisa nada além do necessário para o envelope.

## Requisitos
- RF-01: captura AF_PACKET TPACKET_V3 (gopacket/gopacket `afpacket`, Go puro), snaplen completo
  (`FS_CAPTURE_SNAPLEN`, padrão 65535), nos dois sentidos, na interface `FS_CAPTURE_IFACE` (eth0).
- RF-02: filtro BPF exclui as portas `FS_CAPTURE_EXCLUDE_PORTS` (padrão 48022, 48161, 9000, 9001) em TCP e UDP,
  origem ou destino. Todo o resto entra: TCP, UDP, ICMP/ICMPv6, fragmentos, inclusive fluxos iniciados pelo próprio
  servidor (ACME, NTP, apt).
- RF-03: cada pacote vira um registro do lote `fs.v1.capture.packet` em formato binário FSPB v1 (ADR 0015):
  timestamp do kernel (ns UTC), direção (`in`/`out`), flags, tamanho no fio e o frame Ethernet completo. A
  5-tupla é extraída do frame pelo store.
- RF-04: publicação em lote (agrupamento até 5 ms ou 256 pacotes) para respeitar RNF-02 com menos mensagens.
  `block timeout` do TPACKET_V3 em ~10 ms (o padrão de 64 ms levou a latência kernel → lote a p99 72 ms no spike da
  task 006).
- RF-05: se o NATS estiver fora, buffer até `FS_PRODUCER_BUFFER_MAX_AGE` (30 s) / `FS_PRODUCER_BUFFER_MAX_BYTES`
  (16 MiB); acima disso descarta e incrementa `dropped_events_total`.
- RF-06: no start, verifica os offloads (spec 016); se algum agregador estiver ligado, publica health `degraded`
  e marca os pacotes com `offload_suspect=true`.
- RF-07: conta pacotes perdidos pelo kernel (estatísticas do socket) e publica em métricas e heartbeat.
- RNF-01: sustentar a carga de RNF-01 (spec 000) com < 30% de 1 vCPU (provisório; medido no spike, task 006).
- RNF-02: nenhum frame capturado > MTU + 14 bytes (verificação de offload).

## Comportamento
- Start: lê config → abre socket → aplica BPF → conecta NATS → começa a publicar → heartbeat a cada 5 s.
- Falha ao abrir o socket ou aplicar BPF: sai com código ≠ 0 (systemd reinicia com backoff).
- Sem estado de conexão: a correlação é do store.

## Interfaces e contratos
- Publica: `fs.v1.capture.packet` (lote), `fs.v1.svc.heartbeat`. Ver [asyncapi.yaml](../eventbus/nats/asyncapi.yaml).
- Métricas: `fs_capture_packets_total{dir}`, `fs_capture_kernel_drops_total`, `fs_dropped_events_total`.

## Dados
Não persiste nada. Pacotes pertencem ao store após o ingest.

## Critérios de aceite
- [ ] Um `curl` à porta 80 gera eventos `in` e `out` com SYN, SYN-ACK, ACK, dados e FIN.
- [ ] Tráfego em 48022 e 9000/9001 não aparece em nenhum evento.
- [ ] Com offloads desligados, nenhum frame > MTU + 14 em 1 min de tráfego de download de 64 MiB.
- [ ] Com NATS parado por 10 s, os pacotes chegam depois que ele volta; parado por 60 s, `dropped_events_total` > 0.

## Fora de escopo
- Análise IP/TCP (spec 013), gravação de pcap (spec 004).

## Decisões relacionadas
- specs/decisions/0004-pacotes-pelo-nats.md
- specs/decisions/0015-lote-binario-de-pacotes.md
- specs/decisions/0011-rede-offloads-e-pilha-tcp.md
- specs/decisions/0006-portas-e-api-sem-captura.md
