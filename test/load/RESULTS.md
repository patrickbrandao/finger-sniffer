# Carga de 10 min — metas RNF (tasks 068 e 120, spec 017 RF-13, ADR 0022/0024/0025/0026)

Resultado da rodada atual (`90c86d8`, `v0.1.0-12-g90c86d8`, candidata à v0.2.0; task 120): **a meta
`degraded` = 0 (RNF-01) falhou nas quatro janelas**, sempre por tráfego alheio da internet que soma às ~191–196
conexões vivas da carga e passa do limite de 200 do modo degradado (spec 004 RF-11); todas as outras metas passaram
nas quatro, inclusive o RNF-04 (TCP p95 186–202 ms, QUIC p95 253–264 ms). A rodada de `899ade1` (v0.1.0), que
passou em tudo, segue abaixo como histórico. Não é resultado aprovado: a decisão fica com o coordenador.

## Como reproduzir

```sh
OUT=tmp/load/raw/<nome> QUIC_TARGET=500ms test/load/run.sh -commit <commit implantado>
# outras taxas: ... test/load/run.sh -rate 45
```

Antes da janela oficial, o banco é posto em regime com uma carga de 9 min sem medição (o expurgo dos registros
dela cai dentro da janela oficial), segurando `/tmp/fs-load-running` na vps602 à mão até o `run.sh` assumir:

```sh
ssh -p 48022 root@vps602.tmsoft.com.br 'mkdir -p /tmp/fs-load; date -u +%FT%TZ > /tmp/fs-load-running'
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -tags load -o tmp/load/loadmon ./test/load/cmd/loadmon
scp -P 48022 tmp/load/loadmon root@vps602.tmsoft.com.br:/tmp/fs-load/loadmon
go build -tags load -o tmp/load/loadgen ./test/load/cmd/loadgen
tmp/load/loadgen run -out tmp/load/raw/prefill -duration 9m -retention-check=false -commit <commit> \
  -clock-cmd "ssh -p 48022 -o BatchMode=yes root@vps602.tmsoft.com.br /tmp/fs-load/loadmon clock"
```

O vigia de tráfego alheio (`foreign_watch.txt`) é um laço no Mac, do início do pré-aquecimento ao fim da janela:
a cada 15 s, `GET /api/v1/connections?since=<agora − 15 s>&limit=1000` na 9001 e a lista das conexões cuja
`src.ip` não é o IP público do Mac. Uma janela em que o tráfego alheio mexe em alguma meta é repetida.

`run.sh` (no Mac) compila o `loadgen` (local) e o `loadmon` (linux/amd64, build tag `load`), cria
`/tmp/fs-load-running` na vps602 (convenção: ninguém implanta nem roda e2e enquanto existir), sobe o `loadmon`
(CPU/RAM por unit pelo cgroup v2 a cada 1 s), roda a carga, traz o `cgroup.csv`, gera `summary.md`/`summary.json`
e apaga tudo na vps602 (trap, inclusive em falha). Os brutos ficam em `tmp/load/raw/`; da janela oficial, os que
cabem (< 5 MB no total) são copiados para `test/load/results/<janela>/` (`conns.csv`, `cgroup.csv` e `gen.json`
em gzip; `run.log` vira `run.txt` porque o `.gitignore` ignora `*.log`).

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
- Relógio: deslocamento vps602 − Mac medido por ssh (`loadmon clock`, menor ida e volta ~12–17 ms → erro ≤ ~9 ms)
  no início, **a cada 15 s durante a carga** e no fim. O atraso do feed usa o deslocamento vigente na chegada; o
  RNF-04 é medido só no relógio do Mac (fim no cliente → chegada do `connection.closed`). Motivo: na carga de
  pré-aquecimento desta rodada o timesyncd da vps602 corrigiu o relógio em rampa (500 ppm, −265 ms em 9 min); com
  o deslocamento fixo do início o atraso do feed sairia errado nessa medida. Nas janelas oficiais a faixa ficou em
  poucos ms (`summary.md`, linha "Deslocamento acompanhado").
- Medições (primeiro minuto descartado): RNF-02 = chegada no cliente − `ts` do evento; RNF-04 = `Close` no cliente
  → chegada do `connection.closed` daquele probe no feed (limite superior: inclui a ida pela internet e a entrega do
  feed; o evento sai depois do commit); RNF-03 no cliente (inclui ~20 ms de rede) e no servidor (histograma);
  RNF-01 = todo probe fechado tem `connection.closed` no feed ou registro na API, `degraded`, `dropped_events_total`,
  `kernel_drops`; RNF-05 = depois da carga, os 20 primeiros probes somem (404) após retenção + 75 s e os fechados há
  ~9 min continuam (200); RNF-07 = `capture_max_frame_bytes`, `offload_suspect`.

## Execuções (rodada atual, `90c86d8`)

Deploy completo de `origin/main` (`90c86d8`, detached, sem `-dirty`) às 22:04 UTC, smoke ok, `versions_match: true`;
`make verify-full ARGS="--e2e"` verde antes da carga (e2e 233 s) e `TestCase12HTTP3` 10/10 (task 125). Nenhum
deploy nem e2e durante as janelas; `/tmp/fs-load-running` na vps602 do início do pré-aquecimento ao fim de cada
janela; `FS_RETENTION=10m` conferido. O vigia de conexões alheias (`foreign_watch.txt`) rodou do início do
pré-aquecimento ao fim da última janela.

| Pasta | Início (UTC) | Commit | Taxa | Observação |
| --- | --- | --- | --- | --- |
| (`tmp/load/raw/prefill`, fora do Git) | 2026-11-09 22:18:10 | `90c86d8` | 50/s, 9 min | pré-aquecimento do banco, sem medição |
| `results/official-50f` | 2026-11-09 22:27:43 | `90c86d8` | 50/s | **interferência**: força bruta ssh na porta 22 (raw `banner`) de 193.141.127.102 e 154.18.197.29, uma conexão nova a cada ~30 s de cada IP com ~105 s de vida (máx 133 s): ~10 vivas alheias o tempo todo, `store_connections_open` 201–207 na janela inteira e **29 430** conexões da carga `degraded`. Repetida |
| `results/official-50g` | 2026-11-09 22:46:28 | `90c86d8` | 50/s | os dois IPs da força bruta recebem RST na porta 22 (`nft`, tabela `inet fsloadblock`, só durante as janelas 50g–50i; removida às 23:24). **2** `degraded`, cada um aberto 3–6 ms depois de um par de conexões de um scanner TLS na 993 (87.236.176.x, a cada ~33 s; `foreign_993.txt`). 1 erro h3 no cliente no minuto de aquecimento (t=46,8 s; `timeout: no recent network activity`, registro `quic` sem h3; já expirado quando analisado). Repetida |
| `results/official-50h` | 2026-11-09 22:59:51 | `90c86d8` | 50/s | **27** `degraded`, 26 entre t=233 e 309 s (23:03:44–23:05:00), junto com um rastreador em `45.79.168.172:80` (4–5 conexões por fatia de 15 s), `3.131.220.121:443` e uma rajada de 10+ conexões de 66.132.172.x na 993 às 23:04:39–54 |
| `results/official-50i` | 2026-11-09 23:12:05 | `90c86d8` | 50/s | última repetição (limite combinado com o coordenador). **1** `degraded` (h1 às 23:21:22,7), junto com 2 conexões de 195.182.16.23 na 8080 abertas às 23:21:22,76–22,98 |

## Resultado por meta (rodada `90c86d8`, janelas `official-50f` a `official-50i`)

| Meta | Métrica | Alvo | 50f | 50g | 50h | 50i | Resultado |
| --- | --- | --- | --- | --- | --- | --- | --- |
| RNF-02 | feed /ws, chegada − `LiveEvent.ts`, p99 (máx) | < 1 s | 389 (477) | 391 (486) | 394 (631) | 395 (527) ms | passou |
| RNF-02 | feed /stream (SSE), p99 (máx) | < 1 s | 388 (725) | 390 (486) | 397 (635) | 395 (527) ms | passou |
| RNF-02 | `stream.dropped` (ws e sse) | 0 | 0 | 0 | 0 | 0 | passou |
| RNF-03 | `GET /connections/{id}`, p95 no cliente | < 100 ms | 36,1 | 33,0 | 32,6 | 37,9 ms | passou |
| RNF-03 | `GET /probes/{id}`, p95 no cliente | < 100 ms | 29,2 | 33,5 | 32,3 | 38,2 ms | passou |
| RNF-04 | TCP: fim no cliente → registro, p95 (máx) | ≤ 500 ms | 186 (295) | 195 (315) | 198 (500) | 202 (426) ms | passou |
| RNF-04 | QUIC: CONNECTION_CLOSE → registro, p95 (máx) | ≤ 500 ms | 254 (338) | 253 (343) | 264 (546) | 261 (384) ms | passou |
| RNF-01 | probes sem registro | 0 | 0/30 000 | 0/29 999 | 0/30 000 | 0/30 000 | passou |
| RNF-01 | registros `degraded` da carga | 0 | **29 430** | **2** | **27** | **1** | **falhou** (tráfego alheio) |
| RNF-01 | erros no cliente / puladas pelo teto | 0 | 0 / 0 | **1** (aquecimento) / 0 | 0 / 0 | 0 / 0 | passou, menos 50g |
| RNF-01 | `dropped_events_total`, `kernel_drops`, health fora de `ok` | 0 | 0 | 0 | 0 | 0 | passou |
| RNF-01 | RAM: anon máx / MemoryMax (store; nats), MiB | anon < MemoryMax | 72/384; 88/192 | 73/384; 88/192 | 76/384; 88/192 | 82/384; 88/192 | passou |
| RNF-05 | expurgo: 20 primeiros 404; ~9 min ainda 200 | — | 20/20; 20/20 | 20/20; 20/20 | 20/20; 20/20 | 20/20; 20/20 | passou |
| RNF-07 | maior frame / `offload_suspect` | ≤ 1514 / 0 | 1514 / 0 | 1514 / 0 | 1514 / 0 | 1514 / 0 | passou |

CPU (% de 1 vCPU, média / p95 / máx): store 23,1/27,5/32,0 (50f), 27,0/31,9/40,3 (50g), 29,5/33,8/38,9 (50h),
31,0/37,8/59,3 (50i); web ~16/17/19; host 49/54/61 → 58/66/87. Na v0.1.0 (`official-50e`): store 28,1/32,9/41,5,
host 52/58/83. As janelas rodaram em sequência sobre o mesmo banco, por isso a 50f teve menos expurgo que as
seguintes.

### Causa provável do `degraded`

O limite do modo degradado conta toda conexão TCP/QUIC aberta, de qualquer origem (`liveLimited()` em
`internal/store/flows.go`, spec 004 RF-11). O perfil oficial ocupa 190–196 das 200 no store (`timeline.csv`,
igual à v0.1.0: 191–195), então sobram 4–10 vagas para o ruído da internet. Nas quatro janelas, cada lote de
conexões da carga que saiu `degraded` coincide, em milissegundos, com conexões alheias abertas no mesmo instante
(ver as observações da tabela de execuções). Na v0.1.0 (`official-50e`) também havia tráfego alheio, mas nenhuma
coincidência levou a carga a `degraded`; nesta noite o ruído foi mais denso (scanner da 993 a cada ~33 s,
rastreadores na 80, força bruta ssh na 22).

Hipótese conferida (do coordenador): a task 122 desligou o keepalive TCP dos listeners do web; o ruído com par
morto poderia ficar vivo até a ociosidade de 120 s e ocupar vagas. Os dados não a sustentam:
- 50i (`foreign_api.jsonl.gz`, todas as conexões alheias de 23:14 a 23:23, consultadas antes do expurgo):
  38 conexões TCP/QUIC alheias, 56 conexões·s no total, duração máxima 11 s, **nenhuma com mais de 30 s** e
  nenhuma aberta no fim;
- v0.1.0/pré-122 (`official-50d/connections_api.json.gz`, 8 min): 16 conexões, 21 conexões·s, máximo 8 s;
- as de vida longa da 50f são do raw na porta 22 (~105 s, perto do `FS_IDLE_DEFAULT=120s`), e o raw tem o
  keepalive desligado desde a v0.1.0 (task 029); a 122 não mudou o raw;
- nas 50g e 50h, as conexões alheias que coincidiram com os `degraded` duraram 0,4–0,8 s (scanner da 993).

Não é defeito de código das tasks 122–125: as latências e o restante das metas ficaram iguais aos da v0.1.0. A
falha é a margem do perfil contra o limite de 200 sob o ruído da internet, uma questão de spec/ADR (perfil da
ADR 0022 contra o limite da spec 004 RF-11) que fica para o architect decidir.

### Conferência de fingerprints

`git diff v0.1.0..90c86d8 -- pkg/fingerprint pkg/tlsparse pkg/h2passive`: `pkg/fingerprint` sem mudança;
`pkg/tlsparse` só ganhou `alerts.go` (alertas TLS pelos bytes, task 115/116); `pkg/h2passive` só ganhou os
instantes por stream (`FeedAt`, `HeadersAt`/`EndAt`/`ResetAt`, ADR 0029). O cálculo de JA3/JA4/Akamai não muda e
`test/e2e/testdata/fingerprints-f5.md` continua válido.

## Histórico: rodada de `899ade1` (v0.1.0, depois da task 108)

Resultado: todas as metas passavam na janela `official-50e`.

### Execuções

| Pasta | Início (UTC) | Commit | Taxa | Observação |
| --- | --- | --- | --- | --- |
| (`tmp/load/raw/prefill`, fora do Git) | 2026-11-09 14:51:56 | `899ade1` | 50/s, 9 min | pré-aquecimento do banco, sem medição; a vps602 já estava em `899ade1` com `versions_match: true` (último deploy às 14:38 UTC, nenhum deploy desta rodada), `FS_RETENTION=10m` conferido no env; `/tmp/fs-load-running` criado antes do pré-aquecimento |
| `results/official-50e` | 2026-11-09 15:01:24 | `899ade1` | 50/s | **janela oficial**: banco em regime (expurgo do pré-aquecimento durante a carga), sem deploy nem e2e; `versions_match: true` e `899ade1` antes e depois; vigia de conexões alheias a cada 15 s (`foreign_watch.txt`, ver abaixo) |

### Resultado por meta (janela oficial `official-50e`, `899ade1`)

| Meta | Métrica | Alvo | Medido | Resultado |
| --- | --- | --- | --- | --- |
| RNF-02 | feed /ws, chegada − `LiveEvent.ts` (ADR 0025), p99 | < 1 s | p50 108 / p95 324 / **p99 389** / máx 576 ms (202 105 eventos) | passou |
| RNF-02 | feed /stream (SSE), idem | < 1 s | p50 109 / p95 324 / **p99 388** / máx 576 ms | passou |
| RNF-02 | `stream.dropped` (ws e sse) | 0 | 0 | passou |
| RNF-03 | `GET /connections/{id}`, p95 no cliente / no servidor | < 100 ms | 28,5 ms / 1,3 ms | passou |
| RNF-03 | `GET /probes/{id}`, p95 no cliente / no servidor | < 100 ms | 30,6 ms / 1,8 ms | passou |
| RNF-04 | TCP: fim no cliente → registro, p95 | ≤ 500 ms | p50 129 / **p95 193** / p99 225 / máx 515 ms | passou |
| RNF-04 | QUIC: CONNECTION_CLOSE → registro, p95 | ≤ 500 ms (task 090, ADR 0026) | p50 191 / **p95 250** / p99 282 / máx 472 ms | passou |
| RNF-01 | probes sem registro | 0 | 0 de 30 000 | passou |
| RNF-01 | registros `degraded` da carga | 0 | **0** | passou |
| RNF-01 | erros no cliente / puladas pelo teto | 0 | 0 / 0 | passou |
| RNF-01 | `dropped_events_total` (5 serviços), `kernel_drops`, health fora de `ok` | 0 | 0 / 0 / 0 | passou |
| RNF-01 | RAM: anon máx (memory.current) / MemoryMax, MiB | anon < MemoryMax | capture 9 (10)/96, web 30 (43)/96, raw 10 (12)/96, dns 4 (5)/96, store 75 (384)/384, nats 90 (99)/192 | passou |
| RNF-05 | expurgo: 20 primeiros 404; ~9 min ainda 200 | — | 20/20 sumiram; 20/20 presentes | passou |
| RNF-07 | maior frame / `offload_suspect` | ≤ 1514 / 0 | 1514 / 0 (0 de 2 700 registros amostrados) | passou |

CPU por unit (% de 1 vCPU, média / p95 / máx): capture 1,7/2,0/2,3; web 14,6/15,6/16,6; raw 1,9/2,1/2,4;
dns 0/0,1/0,1; store 28,1/32,9/41,5; nats 4,6/5,2/5,7; host 52/58/83 (steal 0,1).

#### Decomposição do atraso (ms, p50 / p95 / p99)

| Etapa | official-50e (`899ade1`) | official-50d (`efcb465`) |
| --- | --- | --- |
| `ingest_lag` (`ts` do envelope → commit) | 92 / 155 / 298 | 91 / 155 / 295 |
| `live_delay` (`LiveEvent.ts` → envio ao cliente) | 104 / 326 / 570 ¹ | 104 / 318 / 569 ¹ |
| cliente /ws (`LiveEvent.ts` → chegada) | 108 / 324 / 389 | 107 / 323 / 389 |
| `record_ready{close}` (fim → gravado) | 106 / 212 / 296 | 106 / 203 / 294 |
| `record_ready{quic_close}` | 189 / 304 / 314 | 194 / 304 / 314 |
| API `GET /connections/{id}` no servidor | 0,5 / 1,3 / 2,6 | 0,5 / 1,6 / 3,6 |

¹ Histograma do store interpolado em buckets largos (0,25–0,5–1 s), por isso acima do medido no cliente.
O pipeline não mudou com a 108 (mesmos números da `official-50d`). Por tipo, o maior p99 continua no
`connection.updated` do h3 (421 ms) e do TLS (h2 399, h1 414 ms); `packet.stray` (642 eventos) p99 174 / máx
207 ms, sem o avulso de 30 s da rodada anterior.

#### Tráfego alheio e `fs_store_connections_degraded_total`

O vigia (`foreign_watch.txt`, conexões com origem diferente do Mac a cada 15 s) viu, durante a janela, varreduras
avulsas (ssh e portas variadas, 1–4 por janela de 15 s), um rastreador em `45.79.207.71:80` a partir de 15:07 e,
**no minuto de aquecimento** (descartado), uma rajada de 14 conexões de `128.14.236.41` na 8443 às 15:01:35–49.
Nesse instante o `store_connections_open` chegou a 197–199 (t=20–30 s em `timeline.csv`); no período medido o
máximo foi 196.

O contador `fs_store_connections_degraded_total` subiu 15 entre o fim do aquecimento e o fim (é somado quando o
registro é gravado, no fechamento), e **nenhuma** das 15 é da carga (`conns.csv`: 0 `degraded` em 30 000). Uma foi
conferida na API antes do expurgo: varredura ssh de `91.230.168.140` às 15:10:24. As outras 14 já tinham saído da
retenção quando a análise começou; o número bate com a rajada de 14 conexões da 8443 no aquecimento (inferência:
abertas com a conta no limite, gravadas só depois). É o modo degradado da spec 004 RF-11 agindo sobre tráfego
acima do perfil, não sobre a carga; a janela não foi repetida porque a interferência não tocou nenhuma meta
(diferente da `official-50c`, em que 3 309 conexões da carga saíram `degraded`).

## Arquivos

- `results/<run>/summary.md` e `summary.json`: tabela completa (todas as metas, por tipo de conexão e de evento).
- `timeline.csv`: por segundo, conexões abertas, puladas, erros e (a cada 5 s) `store_connections_open`,
  `web_connections_active`, `raw_active_sessions`.
- `feed_delay_by_second.csv`: atraso do /ws por segundo do `ts` (n, p50, p95, p99, máx).
- `cpu_mem_by_second.csv`: CPU % por unit e do host por segundo.
- `run.txt`: log do gerador.
- Em `official-50e` (~1,3 MB) e `official-50d` (~2,4 MB), brutos: `conns.csv.gz` (uma linha por conexão: tipo, probe, `conn_id`, proto,
  `degraded`, registro no cliente e a partir de `data.ended`), `cgroup.csv.gz` (amostras do cgroup por unit a cada
  1 s), `gen.json.gz` (configuração, health a cada 5 s, medições do relógio e resultados agregados),
  `metrics_{start,warm,end}.prom` (coletas do `/metrics`) e `foreign_watch.txt` (vigia de conexões alheias à
  carga a cada 15 s, desde o início do pré-aquecimento na `official-50e`); só na `official-50d`,
  `connections_api.json.gz` (`GET /connections` de 13:50:33 a 13:58:27, antes do expurgo, usado na análise da
  rajada).

- Em `official-50f` a `official-50i` (~1,4 MB cada), os mesmos brutos em gzip e `foreign_watch.txt` do trecho de
  cada janela; em `official-50g`, `foreign_993.txt` (conexões do scanner da 993) e os dois registros `degraded`
  em JSON; em `official-50h`, `foreign_api.txt` (o que restava das alheias de 23:03–23:05 na hora da análise);
  em `official-50i`, `foreign_api.jsonl.gz` (todas as conexões alheias de 23:14 a 23:23, antes do expurgo).

## Histórico: rodada de `efcb465` (depois das tasks 103, 105 e 106; antes da 108)

Resultado: todas as metas passavam, menos `degraded` = 0: 6 de 30 000 conexões (0,02%) saíram `degraded` numa
rajada de pacotes depois de uma pausa de ~360 ms da rede (o store viu 210 vivas por um instante). A 068 ficou
`bloqueada` na task 108 (store).
### Execuções

| Pasta | Início (UTC) | Commit | Taxa | Observação |
| --- | --- | --- | --- | --- |
| (`tmp/load/raw/prefill`, fora do Git) | 2026-11-09 13:24:08 | `efcb465` | 50/s, 9 min | pré-aquecimento do banco, sem medição; deploy completo às 13:21:53 (`versions_match: true`), `FS_RETENTION=10m` conferido no env da vps602 |
| `results/official-50c` | 2026-11-09 13:35:38 | `efcb465` | 50/s | **interferência externa**: às 13:43:13 um serviço de checagem de sites abriu ~30 conexões de várias regiões (h2 com keep-alive, além de consultas DNS dos resolvedores públicos); `store_connections_open` 214–235 por 66 s e 3 309 conexões da carga `degraded` (todas entre t=464 e 531 s). O resto passou; repetida |
| `results/official-50d` | 2026-11-09 13:48:22 | `efcb465` | 50/s | **janela oficial**: banco em regime (expurgo da `official-50c` durante a carga), sem deploy nem e2e; vigia de conexões alheias a cada 15 s (`foreign_watch.txt`): só varreduras avulsas (ssh, 1–3 por janela de 15 s) |

### Resultado por meta (janela oficial `official-50d`, `efcb465`)

| Meta | Métrica | Alvo | Medido | Resultado |
| --- | --- | --- | --- | --- |
| RNF-02 | feed /ws, chegada − `LiveEvent.ts` (ADR 0025), p99 | < 1 s | p50 107 / p95 323 / **p99 389** / máx 30 117 ms (201 867 eventos) | passou |
| RNF-02 | feed /stream (SSE), idem | < 1 s | p50 112 / p95 326 / **p99 392** / máx 30 123 ms | passou |
| RNF-02 | `stream.dropped` (ws e sse) | 0 | 0 | passou |
| RNF-03 | `GET /connections/{id}`, p95 no cliente / no servidor | < 100 ms | 31,0 ms / 1,6 ms | passou |
| RNF-03 | `GET /probes/{id}`, p95 no cliente / no servidor | < 100 ms | 30,6 ms / 1,9 ms | passou |
| RNF-04 | TCP: fim no cliente → registro, p95 | ≤ 500 ms | p50 128 / **p95 191** / p99 224 / máx 491 ms | passou |
| RNF-04 | QUIC: CONNECTION_CLOSE → registro, p95 | ≤ 500 ms (task 090; ADR 0024: 3 s) | p50 195 / **p95 252** / p99 284 / máx 408 ms | passou |
| RNF-01 | probes sem registro | 0 | 0 de 30 000 | passou |
| RNF-01 | registros `degraded` | 0 | **6** (rajada às 13:57:37.76, ver abaixo) | **falhou** (task 108) |
| RNF-01 | erros no cliente / puladas pelo teto | 0 | 0 / 0 | passou |
| RNF-01 | `dropped_events_total` (5 serviços), `kernel_drops`, health fora de `ok` | 0 | 0 / 0 / 0 | passou |
| RNF-01 | RAM: anon máx (memory.current) / MemoryMax, MiB | anon < MemoryMax | capture 10 (12)/96, web 30 (44)/96, raw 11 (14)/96, dns 6 (7)/96, store 76 (384)/384, nats 90 (153)/192 | passou |
| RNF-05 | expurgo: 20 primeiros 404; ~9 min ainda 200 | — | 20/20 sumiram; 20/20 presentes | passou |
| RNF-07 | maior frame / `offload_suspect` | ≤ 1514 / 0 | 1514 / 0 (0 de 2 700 registros amostrados) | passou |

CPU por unit (% de 1 vCPU, média / p95 / máx): capture 1,7/2,0/2,4; web 14,4/15,5/17,4; raw 1,9/2,2/2,5;
dns 0/0,1/0,1; **store 27,8/32,4/40,9** (antes da 105: 27,6/57,5/64,6); nats 4,7/5,3/6,3; host 52/58/79.
O pico de CPU do expurgo sumiu: nenhuma conexão com erro no cliente (antes: 3 timeouts de 15 s).

O máximo de 30,1 s do feed é um único `packet.stray` (518 no total, p99 218 ms); não muda o p99, mas sugere um
avulso decidido só depois da ociosidade de 30 s (anotado na task 108 para conferir contra a ADR 0025).

### Decomposição do atraso (ms, p50 / p95 / p99)

| Etapa | official-50d (regime) | official-50b (`6facb2c`, antes) |
| --- | --- | --- |
| `ingest_lag` (`ts` do envelope → commit) | 91 / 155 / 295 | 94 / 479 / 1 204 |
| `live_delay` (`LiveEvent.ts` → envio ao cliente) | 104 / 318 / 569 ¹ | 110 / 1 028 / 4 390 |
| cliente /ws (`LiveEvent.ts` → chegada) | 107 / 323 / 389 | 116 / 810 / 3 952 |
| `record_ready{close}` (fim → gravado) | 106 / 203 / 294 | 108 / 426 / 990 |
| `record_ready{quic_close}` | 194 / 304 / 314 | 200 / 537 / 1 101 |
| API `GET /connections/{id}` no servidor | 0,5 / 1,6 / 3,6 | 0,5 / 1,6 / 3,8 |

¹ Histograma do store interpolado em buckets largos (0,25–0,5–1 s), por isso acima do medido no cliente
(389 ms). Por tipo, o maior p99 é o `connection.updated` do h3 (418 ms) e do TLS (h2 398, h1 404 ms); com o
`ts` = publicação no `FS_EVENTS` (ADR 0025), esse atraso é fila do ingest até o commit e do commit ao envio. Rede +
entrega ao cliente ficam em ~5 ms no p50.

### A rajada que degradou 6 conexões

Às 13:57:37.40 UTC a vps602 deixou de ver pacotes da carga por ~360 ms (pausa no caminho pela internet). Às
.760–.765 chegaram juntos 18 SYNs/Initials novos e os fins de ~20 conexões que terminaram durante a pausa; o store
processou as aberturas antes dos fechamentos e contou **210 vivas** por um instante (100 ms antes e depois:
190–193). Com `liveLimited() >= 200`, as 6 últimas aberturas da rajada (2 h2, 4 h3) saíram `degraded`. O cliente
nunca passou de 197 simultâneas e o balde de novas/s, simulado com os `started` de todas as conexões TCP/QUIC da
janela (`connections_api.json.gz`, inclusive as 16 alheias), nunca ficou abaixo de 25 fichas. Sem a rajada, a
janela teria 0 `degraded`: a 103 resolveu o modo degradado no perfil, falta tolerar a reordenação da rajada
(task 108).

## Histórico: rodada de `6facb2c` (antes das tasks 103–106)

Resultado: as metas não passavam todas; a 068 ficou `bloqueada` nas tasks 103, 104 e 105 (a 104 gerou a ADR 0025
e a task 106). Naquela rodada o relógio só era medido no início e no fim.

### Execuções

| Pasta | Início (UTC) | Commit | Taxa | Observação |
| --- | --- | --- | --- | --- |
| `results/official-50` | 2026-11-09 11:46:47 | `6facb2c` | 50/s | **interferência**: a task 100 rodou os casos 6 e 11 do e2e por ~2 min logo após o início (~17 conexões a mais, ociosas de 30–180 s); banco quase vazio (o expurgo só apagava pouco) |
| `results/full-45` | 2026-11-09 11:58:32 | `6facb2c` | 45/s | complementar, quase sem `degraded` (análise completa de todas as conexões) |
| `results/official-50b` | 2026-11-09 12:10:59 | `6facb2c` | 50/s | **janela oficial**: repetição limpa (sem e2e nem deploy; `versions_match: true` e versão `6facb2c` antes e depois), banco em regime (expurgo dos ~27 mil registros da janela anterior durante a carga) |

Antes de `official-50` só o store estava em `6facb2c` (deploy por serviço, `versions_match: false`); o tester
rodou `make deploy` de `origin/main` e esperou 2 min sem deploy antes de começar.

### Resultado por meta (janela oficial `official-50b`)

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

### Decomposição do atraso (ms, p50 / p95 / p99)

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

### Por que as metas falharam

1. **RNF-02 literal** (task 104, architect): o raw publica `fs.v1.raw.session` no fim da sessão com `ts` = accept,
   e o store usa esse `ts` no `connection.updated`; 4% dos eventos chegam ~3,9 s (a vida da conexão) "depois" do
   `ts`. Não é latência do pipeline; é preciso decidir a definição ou o `ts`. Sem esses eventos o p99 passa
   (818 ms em regime, 384 ms com o banco vazio).
2. **`degraded` no perfil** (task 103, store): `overloaded` conta conexões em folga de fechamento e fluxos alheios
   (avulsos, DNS UDP, scanners) e usa janela fixa de 1 s para novas/s; com 50/s exatos e ~193 vivas, 13% das
   conexões saem `degraded` (a 45/s: 15 de 27 001).
3. **QUIC p95 > 500 ms, timeouts e CPU em regime** (task 105, store): o expurgo a cada 10 s trava o ingest.

### Interferência registrada

A janela `official-50` começou junto com o e2e da task 100 (casos 6 e 11): ~17 conexões a mais, inclusive sessões
ociosas de 30–180 s. Efeito medido: `store_connections_open` 199–208 (contra 192–196 na janela limpa) e
`degraded` 72–97% nos primeiros 4,5 min contra 2–12% no resto; o `connection.updated` do raw com máx 120 s e o
registro mais antigo com 632 s (pelo início) vêm dessas sessões. As latências (RNF-02/03/04) não mudaram de forma
relevante, mas como a meta de `degraded` mudou, a janela foi repetida (`official-50b`), que é a oficial. Na
repetição, um vigia consultou `/connections` a cada 15 s durante toda a janela: nenhuma conexão com probe
alheio à carga.
