# Carga de 10 min — metas RNF (task 068, spec 017 RF-13, ADR 0022/0024)

Resultado: **as metas da ADR 0022 não passam todas**. A task 068 fica `bloqueada` nas tarefas 103 (store, modo
degradado no próprio perfil), 104 (architect, `ts` do `connection.updated` do raw) e 105 (store, expurgo trava o
ingest), com escalonamento da spec 002 item 5.

## Como reproduzir

```sh
OUT=test/load/results/<nome> QUIC_TARGET=500ms test/load/run.sh -commit <commit implantado>
# outras taxas: ... test/load/run.sh -rate 45
```

`run.sh` (no Mac) compila o `loadgen` (local) e o `loadmon` (linux/amd64, build tag `load`), cria
`/tmp/fs-load-running` na vps602 (convenção: ninguém implanta nem roda e2e enquanto existir), sobe o `loadmon`
(CPU/RAM por unit pelo cgroup v2 a cada 1 s), roda a carga, traz o `cgroup.csv`, gera `summary.md`/`summary.json`
e apaga tudo na vps602 (trap, inclusive em falha). Dados brutos grandes (`conns.csv`, `cgroup.csv`, `gen.json`,
coletas do `/metrics`) ficam em `tmp/load/raw/` e não entram no Git.

## Perfil e método

- Gerador: Mac pela internet (~20 ms de ida e volta; a vps602 em loopback não serve: o capture só vê a `eth0`).
  O Mac não satura: 0 erros de cliente na janela sem saturação do servidor.
- 50 conexões novas/s em intervalos iguais de 20 ms, cada uma com probe ID próprio (`ld…`), vida 3,8 s com 3
  trocas (requisições HTTP ou linhas no raw) → 191–200 simultâneas no cliente; teto de 200 no gerador.
- Mix por ciclo de 100: h1 em claro 15 (80/8080), h1 TLS 15 (443/8443), h2 20 (443/8443), h3 20 (UDP 443),
  raw echo 10 (7), banner 12 (21/25), sink 8 (143, `PROBE … mode=sink`); raw com meio-fechamento. Dial direto no IP
  com Host/SNI `<id>.dns-monitor.tmsoft.com.br` (sem consulta DNS por conexão).
- Durante toda a carga: um cliente `/api/v1/ws` e um `/api/v1/stream` na 9000 (HTTPS) lendo o feed global;
  amostragem de `GET /connections/{id}` e `GET /probes/{id}` (5/s cada, IDs recém-fechados do feed); health a cada
  5 s; `/metrics` no início, no fim do aquecimento e no fim.
- Relógio: deslocamento vps602 − Mac medido por ssh (`loadmon clock`, menor ida e volta ~17 ms → erro ≤ ~9 ms),
  no início e no fim (deriva < 4 ms).
- Medições (primeiro minuto descartado): RNF-02 = chegada no cliente − `ts` do evento; RNF-04 = `Close` no cliente
  → chegada do `connection.closed` daquele probe no feed (limite superior: inclui a ida pela internet e a entrega do
  feed; o evento sai depois do commit); RNF-03 no cliente (inclui ~20 ms de rede) e no servidor (histograma);
  RNF-01 = todo probe fechado tem `connection.closed` no feed ou registro na API, `degraded`, `dropped_events_total`,
  `kernel_drops`; RNF-05 = depois da carga, os 20 primeiros probes somem (404) após retenção + 75 s e os fechados há
  ~9 min continuam (200); RNF-07 = `capture_max_frame_bytes`, `offload_suspect`.

## Execuções

| Pasta | Início (UTC) | Commit | Taxa | Observação |
| --- | --- | --- | --- | --- |
| `results/official-50` | 2026-11-09 11:46:47 | `6facb2c` | 50/s | **interferência**: a task 100 rodou os casos 6 e 11 do e2e por ~2 min logo após o início (~17 conexões a mais, ociosas de 30–180 s); banco quase vazio (o expurgo só apagava pouco) |
| `results/full-45` | 2026-11-09 11:58:32 | `6facb2c` | 45/s | complementar, quase sem `degraded` (análise completa de todas as conexões) |
| `results/official-50b` | 2026-11-09 12:10:59 | `6facb2c` | 50/s | **janela oficial**: repetição limpa (sem e2e nem deploy; `versions_match: true` e versão `6facb2c` antes e depois), banco em regime (expurgo dos ~27 mil registros da janela anterior durante a carga) |

Antes de `official-50` só o store estava em `6facb2c` (deploy por serviço, `versions_match: false`); o tester
rodou `make deploy` de `origin/main` e esperou 2 min sem deploy antes de começar.

## Resultado por meta (janela oficial `official-50b`)

| Meta | Métrica | Alvo | Medido | Resultado |
| --- | --- | --- | --- | --- |
| RNF-02 | feed /ws e /stream, chegada − `ts`, p99 (ADR 0022 literal) | < 1 s | p50 116 / p95 810 / **p99 3 952** / máx 150 167 ms (203 406 eventos) | **falhou** (task 104) |
| RNF-02 | idem sem o `connection.updated` do `raw.session` | < 1 s | p50 113 / p95 469 / p99 818 ms | passou (folga de 0,18 s) |
| RNF-02 | `stream.dropped` (ws e sse) | 0 | 0 | passou |
| RNF-03 | `GET /connections/{id}`, p95 no cliente / no servidor | < 100 ms | 48,5 ms / 1,6 ms | passou |
| RNF-03 | `GET /probes/{id}`, p95 no cliente / no servidor | < 100 ms | 50,5 ms / 1,8 ms | passou |
| RNF-04 | TCP: fim no cliente → registro, p95 | ≤ 500 ms | p50 156 / **p95 489** / p99 814 / máx 1 360 ms | passou (no limite) |
| RNF-04 | QUIC: CONNECTION_CLOSE → registro, p95 | ≤ 500 ms (task 090; ADR 0024: 3 s) | p50 212 / **p95 566** / p99 848 / máx 1 285 ms | **falhou** na meta de 500 ms (task 105); passa nos 3 s da ADR 0024 |
| RNF-01 | probes sem registro | 0 | 0 de 29 994 | passou |
| RNF-01 | registros `degraded` | 0 | **3 843 (13%)** | **falhou** (task 103) |
| RNF-01 | erros no cliente / puladas pelo teto | 0 | 3 timeouts de 15 s (h1tls/h2) / 3 | **falhou** (picos de CPU, task 105) |
| RNF-01 | `dropped_events_total` (5 serviços), `kernel_drops` | 0 | 0 / 0 | passou |
| RNF-01 | RAM: anon máx (memory.current) / MemoryMax, MiB | anon < MemoryMax | capture 8 (11)/96, web 28 (43)/96, raw 13 (21)/96, dns 4 (7)/96, store 74 (384)/384, nats 90 (161)/192 | passou (store com cache de página encostado no teto) |
| RNF-05 | expurgo: 20 primeiros 404; ~9 min ainda 200 | — | 20/20 sumiram; 20/20 presentes | passou |
| RNF-07 | maior frame / `offload_suspect` | ≤ 1514 / 0 | 1514 / 0 (0 de 2 697 registros amostrados) | passou |

CPU por unit (% de 1 vCPU, média / p95 / máx): capture 1,7/2,0/2,4; web 13,7/14,6/16,8; raw 2,1/2,3/3,2;
dns 0/0,1/0,4; **store 27,6/57,5/64,6**; nats 4,4/5,1/5,7; host 50/83/100. Série por segundo em
`results/*/cpu_mem_by_second.csv`.

## Decomposição do atraso (ms, p50 / p95 / p99)

| Etapa | official-50b (regime) | official-50 (banco vazio) | full-45 |
| --- | --- | --- | --- |
| `ingest_lag` (`ts` → commit) | 94 / 479 / 1 204 | 84 / 153 / 285 | 98 / 413 / 1 147 |
| `live_delay` (`ts` → envio ao cliente) | 110 / 1 028 / 4 390 ² | 99 / 558 / 4 393 ² | 113 / 840 / 4 389 ² |
| cliente /ws (`ts` → chegada) | 116 / 810 / 3 952 ² | 107 / 383 / 3 941 ² | 120 / 709 / 3 950 ² |
| `record_ready{close}` (fim → gravado) | 108 / 426 / 990 | 98 / 156 / 262 | 109 / 376 / 770 |
| `record_ready{quic_close}` | 200 / 537 / 1 101 | 189 / 304 / 314 | 201 / 394 / 849 |
| API `GET /connections/{id}` no servidor | 0,5 / 1,6 / 3,8 | 0,5 / 1,2 / 3,2 | 0,5 / 1,2 / 2,8 |

² inclui o `connection.updated` do raw (`ts` = accept, ~3,9 s).
Histogramas do store por diferença aquecimento → fim, interpolados em buckets largos (0,01–10 s, 11 buckets).
Referência da F4: evento isolado 430–570 ms; 150 req/s p95 ~0,6 s.

Leitura: rede + entrega (cliente − `live_delay`) fica em ~5–10 ms no p50. O que cresce em regime é o ingest: o
`retentionLoop` expurga a cada 10 s e cada expurgo leva o store a 55–65% de CPU por ~1 s (s 25, 35, 45, … em
`cpu_mem_by_second.csv`), segurando o escritor do SQLite; o p99 por segundo do feed sobe de ~0,4 s para 1,2–1,6 s
nesses segundos. Com o banco vazio (`official-50`) o mesmo perfil deu TCP p95 227 ms e QUIC p95 262 ms.

## Por que as metas falharam

1. **RNF-02 literal** (task 104, architect): o raw publica `fs.v1.raw.session` no fim da sessão com `ts` = accept,
   e o store usa esse `ts` no `connection.updated`; 4% dos eventos chegam ~3,9 s (a vida da conexão) "depois" do
   `ts`. Não é latência do pipeline; é preciso decidir a definição ou o `ts`. Sem esses eventos o p99 passa
   (818 ms em regime, 384 ms com o banco vazio).
2. **`degraded` no perfil** (task 103, store): `overloaded` conta conexões em folga de fechamento e fluxos alheios
   (avulsos, DNS UDP, scanners) e usa janela fixa de 1 s para novas/s; com 50/s exatos e ~193 vivas, 13% das
   conexões saem `degraded` (a 45/s: 15 de 27 001).
3. **QUIC p95 > 500 ms, timeouts e CPU em regime** (task 105, store): o expurgo a cada 10 s trava o ingest.

## Interferência registrada

A janela `official-50` começou junto com o e2e da task 100 (casos 6 e 11): ~17 conexões a mais, inclusive sessões
ociosas de 30–180 s. Efeito medido: `store_connections_open` 199–208 (contra 192–196 na janela limpa) e
`degraded` 72–97% nos primeiros 4,5 min contra 2–12% no resto; o `connection.updated` do raw com máx 120 s e o
registro mais antigo com 632 s (pelo início) vêm dessas sessões. As latências (RNF-02/03/04) não mudaram de forma
relevante, mas como a meta de `degraded` mudou, a janela foi repetida (`official-50b`), que é a oficial. Na
repetição, um vigia consultou `/connections` a cada 15 s durante toda a janela: nenhuma conexão com probe
alheio à carga.

## Arquivos

- `results/<run>/summary.md` e `summary.json`: tabela completa (todas as metas, por tipo de conexão e de evento).
- `timeline.csv`: por segundo, conexões abertas, puladas, erros e (a cada 5 s) `store_connections_open`,
  `web_connections_active`, `raw_active_sessions`.
- `feed_delay_by_second.csv`: atraso do /ws por segundo do `ts` (n, p50, p95, p99, máx).
- `cpu_mem_by_second.csv`: CPU % por unit e do host por segundo.
- `run.log`: log do gerador.
