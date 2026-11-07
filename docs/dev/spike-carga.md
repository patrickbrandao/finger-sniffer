# Spike de carga — pacotes pelo NATS + BLOBs no SQLite em 1 vCPU (task 006)

Data: 2026-11-07 · Máquina: vps602 (Linode, Debian 13, kernel 6.12, 1 vCPU, 967 MiB, disco 25 GB) ·
Protótipo: [`test/spike/`](../../test/spike/README.md) · Para: architect (confirmar ou substituir as ADRs 0004 e 0005).

## Resumo

| Pergunta | Resposta |
| --- | --- |
| A arquitetura das ADRs 0004/0005/0015 aguenta 200 conexões simultâneas e 50 novas/s? | **Sim**, com folga de CPU (média 17–22%, pico 36%) e memória (store ≤ 50 MiB de 384M). |
| A meta de evento ao vivo < 1 s (RNF-02) é atingida? | **Não com o JetStream em arquivo** (ingestão p95 1,0–1,8 s). **Sim com o stream em memória** (p95 178 ms, p99 203 ms). |
| Onde está o gargalo? | **Escrita em disco do JetStream (file store)**: iowait até 98% e travamentos de ~2 s entre o NATS e o consumidor. O SQLite não é o gargalo (commit p99 21–27 ms, máx. 36 ms). |
| E as consultas (RNF-03, p95 < 100 ms)? | p95 0,8–1,1 ms (registro + pcap/pacotes). |
| Perdas? | Nenhuma perda no kernel e nenhum erro de publicação em nenhuma rodada; maior frame 1484 bytes (≤ MTU + 14). |

**Recomendação ao architect** (detalhe no fim):
1. **ADR 0004** (todos os pacotes pelo NATS, análise IP/TCP no store): confirmar como **aceita**.
2. **ADR 0005** (SQLite com BLOBs): confirmar como **aceita**; o teto de 2 GiB comporta 10 min a 50 conexões/s
   (estimativa ~1,1–1,2 GB).
3. **Nova ADR**: stream `FS_EVENTS` em **memória** (`MemoryStorage`, 32 MiB, `max_age` 60 s) em vez de arquivo;
   ajustar `nats.conf` (`max_memory_store` 64 MB → manter; `max_file_store` só para uso futuro).
4. **Aumentar `MemoryMax` do NATS de 128M para 192M**: o RSS do nats-server chegou a 118–124 MiB em todas as
   rodadas a 50/s, colado no limite atual.
5. Ajuste fino da captura (spec 003): `OptBlockTimeout` do TPACKET_V3 de 64 ms (padrão) para ~10 ms, para cortar a
   latência kernel → lote (p99 hoje 72 ms).

## O que foi medido

Fluxo idêntico ao planejado para os serviços reais:

```
spikeload (Mac) ──HTTP──► spikeweb :8080 (vps602)
                               │ pacotes na eth0
spikecap (AF_PACKET TPACKET_V3, Go puro) ──lotes FSPB v1 (≤5 ms/256)──► nats-server (unit finger-sniffer-nats)
                                                                          │ JetStream FS_EVENTS
spikestore (consumidor durável) ──► SQLite (modernc, WAL, migration 00001): connections, packets (BLOB),
                                    pcaps (BLOB materializado no fechamento), stray_packets; expurgo + incremental_vacuum
```

- Carga: `rate` conexões novas/s; cada conexão faz 4 requisições keep-alive com 1 s de intervalo; 10% baixam 256 KiB.
  Concorrência observada 227–559 (depende do RTT do cliente).
- Cada programa na VPS rodou em unit transitória com o mesmo `MemoryMax`/`GOMEMLIMIT` das units reais (store 384M,
  capture/web 96M); o NATS foi o da unit real (`MemoryMax=128M`).
- Ingestão = commit no SQLite − timestamp do kernel, por pacote. "cap" = lote publicado − kernel; "bus" = commit −
  lote publicado. Consulta = `SELECT` do registro + pcap (ou pacotes) de uma conexão recente, a cada 200 ms.
- Retenção do spike: 2 min (para exercitar o expurgo dentro da rodada), salvo indicado.

## Resultados

| Rodada | Duração / taxa | Variação | Conexões | Pacotes | Ingestão p50 / p95 / p99 (ms) | Janelas de 5 s com p95 > 1 s | CPU média / máx. | RSS NATS / store (MiB) | Banco |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Teste | 1 min / 20/s | — | 1.243 | 58.187 | 96 / 161 / 182 | 0/18 | 9% / 12% | 74 / 38 | 51 MB |
| **Oficial** | **10 min / 50/s** | JetStream arquivo | **30.207** | **1.400.299** | **120 / 1039 / 2010** | **19/125** | **22% / 36%** | **124 / 50** | 239 MB |
| A | 4 min / 50/s | sem expurgo | 12.357 | 622.183 | 119 / 951 / 1990 | 7/54 | 21% / 36% | 121 / 45 | 485 MB |
| B | 4 min / 50/s | expurgo sem vacuum | 12.077 | 578.422 | 117 / 1138 / 2013 | 11/53 | 18% / 24% | 119 / 45 | 150 MB |
| C | 4 min / 50/s | latência por estágio | 12.299 | 586.907 | 124 / 1466 / 2087 | 14/53 | — | — | 252 MB |
| D | 4 min / 50/s | + duração do commit | ~12.000 | — | 126 / 1773 / 2149 | 20/53 | 17% / 23% | 118 / 49 | 230 MB |
| **E** | **4 min / 50/s** | **JetStream em memória** | ~12.000 | — | **107 / 178 / 203** | **0/53** | **18% / 27%** | **119 / 47** | 216 MB |

Latência por estágio e disco:

| Rodada | cap p99 (kernel → lote) | bus p95 / p99 (lote → commit) | Commit SQLite p50 / p99 / máx. | iowait médio / máx. | Segundos com iowait ≥ 20% |
| --- | --- | --- | --- | --- | --- |
| C (arquivo) | 72 ms | 1424 / 2052 ms | — | 11% / 97% | 41 de 272 |
| D (arquivo) | 72 ms | 1726 / 2102 ms | 1,0 / 27 / 36 ms | 17% / 98% | 63 |
| E (memória) | 72 ms | 128 / 152 ms | 1,1 / 21 / 32 ms | 0,8% / 3% | 0 |

Outros números da rodada oficial: consulta p50 0,30 ms, p95 1,09 ms, p99 2,43 ms; expurgo (DELETE em lotes + vacuum)
~200 ms a cada 10 s; materialização de pcaps ≤ 216 ms por lote; 24.976 conexões expurgadas; captura 1.401.633
pacotes no kernel, 0 perdidos, 0 congelamentos de fila; 1.337 pacotes filtrados (portas de gerência); steal ~0%.

## Análise

1. **CPU não é limite.** O store (correlação + inserts + pcap + expurgo) gastou 14% da vCPU em média a 50/s; o
   sistema todo, 22%. Há margem para a análise IP/TCP real e para o TLS/HTTP do web.
2. **O gargalo é o JetStream em arquivo.** As rodadas A (sem expurgo) e B (sem vacuum) mantiveram os picos, então
   expurgo e vacuum não são a causa. A rodada C isolou o atraso no trecho NATS → consumidor (captura sempre ≤ 72 ms).
   A rodada D mostrou commits do SQLite curtos (máx. 36 ms) enquanto o iowait chegava a 98%. A rodada E, com o
   stream em memória e o resto igual, eliminou os picos e o iowait.
3. **SQLite com BLOBs é viável.** Commits curtos, consultas em ~1 ms, expurgo estável e banco estável com retenção
   de 2 min (~240 MB). Extrapolando linearmente para 10 min a 50/s: ~1,1–1,2 GB, abaixo do teto de 2 GiB.
4. **Memória do NATS está no limite.** RSS de 118–124 MiB em todas as rodadas a 50/s, contra `MemoryMax=128M`
   (com stream em arquivo ou em memória de 32 MiB). Risco de OOM na carga nominal.
5. **Captura.** Sem perdas; o p99 de 72 ms vem do `block timeout` padrão do TPACKET_V3 (64 ms) somado ao lote de
   5 ms — ajustável.
6. **Erros no cliente.** 0,0–0,4% das requisições do gerador falharam (1 a 201 por rodada), concentrados quando a
   concorrência passou de ~400 (rodada A, 559 conexões abertas a partir de uma rede doméstica). Nenhum erro ou
   perda apareceu do lado do servidor; trato como limitação do cliente de teste, a confirmar na carga da F5 a
   partir de outra máquina.

## Consequências do stream em memória (para a nova ADR)

- O buffer de reinício do store continua: o stream sobrevive a reinícios do store enquanto o NATS estiver no ar.
- Se o próprio NATS reiniciar, perdem-se até 60 s de eventos ainda não consumidos — aceitável com retenção de
  10 min e servidor de testes; o buffer de 30 s dos produtores (ADR 0003) cobre a queda do NATS.
- 32 MiB de stream a ~1,8 MB/s de pacotes (50/s) dão ~17 s de folga se o store parar; acima disso o NATS descarta
  os mais antigos (`DiscardOld`). Se precisar de mais folga, subir para 48–64 MiB junto com o `MemoryMax` do NATS.

## Reproduzir

```bash
test/spike/run.sh 10m 50
```

```bash
FS_SPIKE_LABEL=E-stream-memoria STORE_ARGS="-retention 2m -mem-stream" test/spike/run.sh 4m 50
```

Outras variações: `STORE_ARGS="-retention 30m"` (sem expurgo), `"-retention 1m -no-vacuum"`. Resultados em
`tmp/spike-results/<data>-<duração>-<taxa>[-rótulo]/` (`load.jsonl`, `spike-store.jsonl`, `spike-cap.jsonl`,
`spike-mon.jsonl`, `vmstat.txt`). O `run.sh` envia os binários para `/root/spike` na vps602, roda cada um em unit
transitória e apaga tudo (inclusive o stream `FS_EVENTS`) no fim.
