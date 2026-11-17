# Carga de 10 min — metas RNF (tasks 068, 120 e 285, spec 017 RF-13 e RF-17, ADR 0022/0024/0025/0026/0030/0046)

> **Servidor anterior (vps602).** Todas as rodadas abaixo foram medidas na vps602 (1 vCPU, 967 MiB, `eth0`,
> cgroups em `system.slice`) e ficam como registro. Desde a ADR 0038/0039 os scripts (`run.sh`, `budget.sh`,
> `loadgen`, `budgetload`, `loadmon`) apontam para o finger-01: alvo `finger-01.badblock.net.br`, zona
> `finger-west-01.badblock.net.br`, web em 8080/8443 (TCP) e 8443 (UDP), cgroups em
> `/sys/fs/cgroup/finger.slice/finger-sniffer.slice/<unit>`, perfil padrão de 200 simultâneas e 50 novas/s (o
> oficial da ADR 0042; o de 400/100, meta da fase F7, é `-rate 100 -max-active 400`), h3 por IPv6 (`-h3-family`),
> `nr_throttled` por unit e `conntrack -S` antes e depois. As rodadas no finger-01 entram numa seção própria.

Resultado da rodada atual (`c1aefd8`, `v0.1.0-13-gc1aefd8`, candidata à v0.2.0; task 120), com os limites do modo
degradado da [ADR 0030](../../specs/decisions/0030-margem-do-modo-degradado.md) (`FS_MAX_CONNS=250`,
`FS_MAX_NEW_CONNS_PER_S=60`; garantia do RNF-01 continua 200 simultâneas e 50 novas/s): **todas as metas passaram
na janela oficial `official-50k`**, com o tráfego da internet presente e sem bloquear nenhuma origem. A janela
anterior (`official-50j`) também teve `degraded` = 0 e passou em todas as metas medidas; só registrou 1 erro h3 no
cliente no minuto de aquecimento (descartado). As janelas `official-50f` a `official-50i` (`90c86d8`, limites
200/50), que falharam só no `degraded` = 0 por tráfego alheio e motivaram a ADR 0030, seguem abaixo como histórico,
junto com a rodada de `899ade1` (v0.1.0).

## finger-01, F8 (task 285; spec 018 RNF-01/RNF-02, spec 017 RF-17, ADRs 0055 item 2, 0057 item 2 e 0058)

**Resultado.** Bot (`v0.4.0-26-g8a4ca69`, regras `v1.2`, `versions_match`) com o forwardAuth a 200 requisições/s
junto da carga oficial 400/100: **todas as metas do bot passaram** (forwardAuth p95 0,62 ms / p99 1,62 ms no
cliente, consulta p95 0,31 ms, veredito no feed em no máximo 86 ms, `bot_auth_ja4h_total{source="header"}` igual às
318 217 requisições, sem espera da RF-04, sem OOM), e **todas as metas da ADR 0046 do lado do espelho passaram com
o bot assinando** (backlog máx 0,07 s, `stream_lost` Δ 0, `db_full` Δ 0, `memory.events` do store 0/0, feed global
p99 327 ms e 0 `stream.dropped` lido de dentro do finger-01). O custo de CPU do store com o bot assinando ficou
abaixo da resolução da medida (45,3 → 44,0% de um núcleo). No trecho hostil o teto do índice segurou
(`bot_index_bytes` máx 384,00 MiB, 29 243 despejos por bytes, bot em 733 MiB de `anon` sem OOM) e o forwardAuth
manteve as metas na janela (p99 44,8 ms), mas **uma meta falhou: o health não voltou a `ok` 60 s depois do trecho
hostil** (ficou `degraded` com `index bytes` por 7 min 23 s; ver abaixo). Reportado ao architect (escalonamento 5 da
spec 002), sem mudar limites nem regras.

**Gerador limitado (Mac).** O enlace do Mac estava em ~9 Mbit/s nos dois sentidos durante toda a tarefa (30 MB do
finger-01 em 26,7 s; 10 MB do speed.cloudflare.com em 8,8 s; o finger-01 baixa 50 MB em 0,33 s). As conexões da
carga passaram (100 novas/s entregues, 0 erros no cliente na janela oficial), mas os dois feeds do `loadgen`
(`/ws` e `/sse`) e a amostragem da API não cabem no enlace: o store descarta para o cliente lento (`stream.dropped`)
e o atraso medido no Mac sobe a 5–9 s. Como na ADR 0046, essas metas estão separadas abaixo como **falhas do
cliente**, com a medida do espelho ao lado: um container no finger-01 (`botload feed`) lê o mesmo feed global do
store pela 9001 sem passar pelo enlace do Mac.

### Preparo e método

- Servidor só para a carga (`/tmp/fs-load-running` segurado pelo vigia lateral `f8-side.sh` de 05:15 a 06:28 UTC);
  bot em `MemoryMax=1G`, `GOMEMLIMIT=768MiB`, `CPUQuota=200%`, `FS_BOT_INDEX_MAX_BYTES=402653184`, `FS_BOT_VIEW_WAIT=100ms`.
- Gerador do bot: `test/load/cmd/botload` (build tag `load`), binário estático importado como imagem
  `fs-load-f8:285` (`docker import`, sem download) e rodado em containers temporários `fs-load-f8-<nome>` na rede
  `network_public` (bridge `br-net-public`, origem 10.249.0.0/16 como o traefik), `--cpus 1`, `--memory 1g`, pelo
  `test/load/f8-remote.sh`. O `traefik-app` não foi tocado; os containers e a imagem foram removidos no fim.
- Chaves de teste (`load-f8-<nome>`, domínios `fs-load.example,*.hostile.fs-load.example`, `--rate 5000 --burst
  10000 --daily 100000000`) criadas pela CLI do bot no servidor; o segredo fica só numa variável do shell remoto e
  entra no container pela entrada padrão (nunca em argumento, arquivo ou log). As três chaves (smoke, auth, hostil)
  foram revogadas no fim (`key list` mostra `revoked_at` 06:28:39).
- `botload auth` (traefix simulado): lê `connection.opened` das portas 8080 e 8443 do feed do store (as conexões
  reais da carga oficial), manda o `TraefikIngestBatch` da conexão (ClientHello e prefixo h2 de Chrome e curl dos
  goldens do bot, origem e destino da conexão real) em lotes de 50 ms e só depois do 202 passa a mandar
  `GET /bot/v1/auth` na 9003 com os `X-Fs-*`, `X-Fs-Ja4h`, `Authorization: Bearer` da chave e os cabeçalhos do
  visitante (sem `Cookie`), a 200/s em passo uniforme, revezando as conexões ativas (até 16 requisições e 30 s por
  conexão); depois de cada 200 manda o `type=request` no ingest; 20 consultas/s `GET /bot/v1/verdict` pela origem;
  lê o feed SSE do bot (`site=fs-load.example`) e mede o atraso envio do forwardAuth → veredito no feed.
- `botload hostile`: lotes de 40 conexões × 17 registros (~3,4 MB, abaixo de 1 024 registros e 4 MiB) com SNI,
  entry point, ALPN, cifra, caminho de 256 bytes, UA de 512 bytes, seis campos de 512 bytes, nomes de campo e de
  cookie, JA4H, router e service únicos, origem em 198.18.0.0/15.
- `botload feed`: feed global do store (`/api/v1/stream`, sem filtros) lido no finger-01; atraso `ts` → chegada.
- `loadmon` ganhou a linha do bot (CPU, memória, `nr_throttled`, `memory.events`); o `summary.md` mostra o bot na
  tabela de CPU/RAM e a linha "RNF-02 (018)".

| Rodada (UTC) | Perfil | Bot | Papel |
| --- | --- | --- | --- |
| smoke 05:09:07–05:10:37 | 200/50, 1m30s | auth 50/s, 45 s | conferência do gerador (não entra nas metas) |
| [`cpu-f8-off`](results/cpu-f8-off/) 05:16:11–05:19:41 | 400/100, 3m30s | parado | item 3 |
| [`cpu-f8-on`](results/cpu-f8-on/) 05:27:16–05:30:46 | 400/100, 3m30s | no ar, sem forwardAuth | item 3 |
| prefill-f8 05:39:10–05:48:18 | 400/100, 9 min | auth 200/s | pré-aquecimento (relatório do loadgen interrompido na conferência, que pelo enlace do Mac levaria ~20 min) |
| [`official-f8`](results/official-f8/) 05:51:59–06:01:59 (medida 05:52:59–06:01:59) | 400/100, 10 min | auth 200/s | **janela oficial da F8** |
| [`hostile-f8`](results/hostile-f8/) 06:12:22–06:18:22 | 400/100, 6 min | auth 200/s + hostil 06:13:47–06:15:49 | item 4 |

Os brutos do bot estão em [`results/f8-bot`](results/f8-bot/): `report-<janela>.md` (saída do `botload report`
por janela, com as contas do heartbeat entre as duas coletas do health mais próximas), `bot_index.csv`
(`bot_index_bytes` e despejos a cada 5 s), `bot_health.jsonl.gz`, `cgroup_side.txt.gz`, `store_metrics_side.txt.gz`
e os logs dos containers. As amostras cruas (`samples.csv`, 30 MB; `feed_samples.csv`, 49 MB) ficaram fora do Git.

```sh
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -tags load -o tmp/load/botload ./test/load/cmd/botload
scp -P 48022 tmp/load/botload test/load/f8-remote.sh test/load/f8-side.sh root@finger-01.tmsoft.com.br:/tmp/fs-load-f8/
ssh -p 48022 root@finger-01.tmsoft.com.br 'cd /tmp/fs-load-f8 && ./f8-remote.sh image && (setsid ./f8-side.sh &)'
ssh -p 48022 root@finger-01.tmsoft.com.br 'cd /tmp/fs-load-f8 && ./f8-remote.sh start-nokey feed-main feed -duration 60m && ./f8-remote.sh start auth auth -duration 60m -rate 200 -query-rate 20'
OUT=tmp/load/raw/official-f8 test/load/run.sh -commit v0.4.0-26-g8a4ca69 -rate 100 -max-active 400   # depois do prefill de 9 min
ssh -p 48022 root@finger-01.tmsoft.com.br 'cd /tmp/fs-load-f8 && ./f8-remote.sh start hostile hostile -duration 2m -rate 80'
ssh -p 48022 root@finger-01.tmsoft.com.br 'cd /tmp/fs-load-f8 && ./f8-remote.sh cleanup'   # containers, chaves e imagem
go run -tags load ./test/load/cmd/botload report -dir <out-auth> -from <início> -to <fim> -health-before hb.json -health-after ha.json
```

### Metas do bot (itens 1, 2 e 4)

forwardAuth no cliente = tempo do `GET /bot/v1/auth` medido no container (inclui a ida e volta na bridge); no
servidor, fração de `bot_auth_seconds` abaixo do limite (buckets do heartbeat por diferença). A espera da RF-04
não entrou em nenhuma requisição: `bot_view_wait_total` Δ 0 (`fork` e `tcp`), `bot_auth_wait_seconds` todo no
primeiro bucket (≤ 1 ms; soma 5,7 s para 318 217 requisições, 18 µs em média) e `view.tcp=true` em 318 217 de
318 217 respostas, então `bot_auth_seconds` − `bot_auth_wait_seconds` ≈ `bot_auth_seconds`.

| Meta | Oficial (05:52:59–06:01:59) | Trecho hostil (06:13:47–06:15:49) | Resultado |
| --- | --- | --- | --- |
| forwardAuth p95 ≤ 10 ms | cliente 0,62 ms (n = 108 000, 0 erro); servidor 99,995% ≤ 10 ms | cliente 1,84 ms (n = 24 400, 0 erro); servidor 99,59% ≤ 10 ms | ok |
| forwardAuth p99 ≤ 50 ms | cliente 1,62 ms (máx 84 ms); servidor 99,998% ≤ 50 ms | cliente 44,84 ms (máx 86 ms); servidor 99,90% ≤ 50 ms | ok |
| `bot_auth_ja4h_total{source="header"}` = requisições | 318 217 = 318 217 forwardAuth 200 de 05:39:09 a 06:21:40 (`ingest` 0, `none` 0) | (incluído) | ok |
| consulta `GET /bot/v1/verdict` p95 ≤ 50 ms | 0,31 ms (n = 10 873, 0 erro; máx 43 ms) | 0,38 ms (n = 2 461; máx 78 ms) | ok |
| veredito no feed ≤ 1 s depois da primeira requisição | primeira requisição p99 1,27 ms, máx 80 ms (26 439); todas máx 86 ms; 0 sem veredito, 0 `stream.dropped` | primeira p99 39,9 ms, máx 74 ms | ok |
| bot sem OOM, dentro de `MemoryMax=1G`/`GOMEMLIMIT=768MiB` | `anon` máx 537 MiB, `memory.current` 542 MiB; `memory.events` max/oom_kill Δ 0/0 | `anon` máx 733 MiB, `memory.current` 786 MiB (1 s, `hostile-f8`); Δ 0/0 | ok |
| bot dentro de `CPUQuota=200%` | média 42,3%, p95 61,2%, máx 73,6% de um núcleo (`nr_throttled` +146, informativo) | média 60,2%, p95 103%, máx 145% (`nr_throttled` +240) | ok |
| `bot_index_bytes` ≤ `FS_BOT_INDEX_MAX_BYTES` | máx 237,1 MiB (06:02:11) | máx 402 652 485 bytes (384,00 MiB) contra 402 653 184 | ok |
| `bot_conns_evicted_total{reason="bytes"}` | Δ 0 no prefill e na janela oficial (`count` 0) | Δ 27 173 na janela, 29 243 no total | ok |
| health `degraded` com `index bytes` durante | `ok` | `degraded` `["index bytes"]` desde 06:14:42 | ok |
| health `ok` 60 s depois | — | **`ok` só às 06:23:12, 7 min 23 s depois do fim do trecho** | **falhou** |

**Por que o health não voltou em 60 s.** O índice fica no teto enquanto as conexões hostis vivem (TTL 10 min). Com
ele cheio, cada conexão nova do store (a carga oficial até 06:18:22, depois o fim dela e o tráfego da internet) entra
despejando a mais antiga por bytes e renova os 60 s do `index bytes` (RF-11): despejos por bytes Δ ~1 970 de
06:15:53 a 06:18:21, mais 87 depois disso; o último perto de 06:22:13, e o `ok` veio 60 s depois. O bot
segue a regra da RF-11 como escrita; quem não fecha é a meta da tarefa ("`ok` 60 s depois") com o TTL de 10 min:
depois de tráfego hostil, o health só volta quando o índice cai abaixo do teto (o despejo é pelas mais antigas, que
são as legítimas de antes do trecho; as hostis vão saindo depois), o que leva até o TTL. Decisão do architect
(manter a meta e mudar o critério do health, ou ajustar a meta). Com o índice no teto depois do trecho, o
forwardAuth seguiu dentro das metas (06:15:49–06:18:22: p95 0,74 ms, p99 39,2 ms, máx 191 ms no cliente;
servidor 99,39% ≤ 10 ms e 99,81% ≤ 50 ms), mas com cauda maior que antes do trecho (06:12:30–06:13:47: p99 0,77 ms,
máx 3,9 ms): o bot passa a trabalhar perto do `GOMEMLIMIT` (`anon` 733 MiB) e o GC pesa.

Detalhe do trecho hostil: 9 560 conexões únicas a 80/s (162 520 registros aceitos, 0 recusados, 239 lotes, ingest
p50 93 ms / p99 241 ms, 0 erro). A taxa planejada era 50/s; como o índice tinha caído a 25 MiB no intervalo entre
a janela oficial e esta rodada (a conferência do `loadgen` levou 10 min pelo enlace do Mac e o TTL esvaziou o
índice), a taxa subiu para 80/s para passar do teto dentro dos 2 min (passou aos ~55 s, às 06:14:42). Por 10 s,
o forwardAuth chegou a p95 28,9 ms / p99 63,5 ms (06:15:19–06:15:39, no log do container); na janela de 2 min as
metas valem.

### CPU do store com e sem o bot (item 3, ADR 0055 item 2)

Duas rodadas iguais de 3m30s a 400/100 (3 min medidos), com o feed global lido no finger-01 nas duas:

| Unit (% de um núcleo, média / p95 / máx) | bot parado (`cpu-f8-off`) | bot no ar (`cpu-f8-on`) | Δ média |
| --- | --- | --- | --- |
| store | 45,3 / 52,1 / 57,3 | 44,0 / 48,5 / 54,9 | −1,3 |
| nats | 15,3 / 18,0 / 21,8 | 15,2 / 17,9 / 19,8 | −0,1 |
| bot | — | 27,8 / 30,3 / 31,9 | +27,8 |
| fatia | 111,7 / 124,1 / 139,5 | 134,4 / 142,7 / 146,6 | +22,7 |

A 100 conexões/s, a diferença do store por conexão é −0,13 ms de CPU, dentro do ruído entre rodadas (o store
publica `fs.v1.store.connection` com ou sem assinante; o NATS core descarta sem assinante quase de graça e a
entrega a um assinante local não aparece na CPU do nats). Referência do benchmark da ADR 0055: 0,75 ms/conexão para
publicar, já incluído nas duas rodadas. O bot sozinho custa ~2,8 ms de CPU por conexão do store (27,8% a 100/s),
sem forwardAuth. Nas duas rodadas o lado do espelho ficou igual: `ingest_lag` p95 142 ms, `record_ready{close}` p95
156 / 155 ms, feed global no finger-01 p99 327 / 327 ms e 0 `stream.dropped`.

### Metas da ADR 0046 com o bot assinando (janela `official-f8`)

| Meta | Medido no Mac (`summary.md`) | Medido no espelho | Resultado |
| --- | --- | --- | --- |
| feed p99 ws / sse < 1 s | 7 934 / 8 193 ms | feed global no finger-01 p99 327 ms, máx 587 ms (421 289 eventos); `live_delay` p50 220 ms | ok no espelho; **falhou (cliente)** |
| `stream.dropped` 0 | 907 / 1 693 avisos | 0 no feed lido no finger-01 | ok no espelho; **falhou (cliente)** |
| API p95 < 100 ms | 511 / 510 ms no cliente, 0 erro | servidor p95 1,0 / 1,0 ms | ok no espelho; **falhou (cliente)** |
| registro p95 ≤ 500 ms | TCP 7 166, QUIC 7 291 ms (pelo feed do Mac) | `record_ready{close}` p95 156 ms, `{quic_close}` 166 ms; `ingest_lag` p95 142 ms | ok no espelho; **falhou (cliente)** |
| probes sem registro 0 | 30 798 de 59 991 (sem `connection.closed` nos feeds do Mac; a consulta pela API correu atrás do expurgo de 10 min) | `fs_store_connections_total` Δ igual ao gerado por tipo: h1 9 000 → `http1.1` 9 001, h1tls 9 000 → 9 000, h2 11 996 → 11 996, h3 11 995 → 11 995, raw 18 000 → 18 073 (excedente = alheio) | ok no espelho; **falhou (cliente)** |
| `degraded` 0 | 0 | — | ok |
| conexões com erro no cliente 0 | 0 de 59 991 | — | ok |
| conexões puladas pelo teto do gerador 0 | 9 | — | **falhou (cliente)** |
| `dropped_events_total` 0, `kernel_drops` 0 | 0, 0 | — | ok |
| `flows_dropped` sem crescer | Δ 0 (`evicted` e `table_full`) | — | ok |
| `nr_throttled` sem crescer (units do espelho) | 0 em todas | — | ok |
| `anon` < `MemoryMax` (MiB) | capture 11/512, web 41/768, raw 21/256, dns 5/256, store 179/6 144, nats 307/1 024, bot 537/1 024, fatia 1 099/10 240 | — | ok |
| `memory.events` do store max / oom_kill Δ 0 | 0 / 0 | — | ok |
| `fs_store_db_full_total` Δ 0 | 0 (prefill → fim da rodada hostil) | — | ok |
| maior frame ≤ 1514 | 1514, `offload_suspect` 0 | — | ok |
| expurgo depois de 10 min | 20 primeiros 404; a conferência "~9 min presentes" não achou probes nessa idade (rodou 10 min depois do fim, pela demora da conferência no enlace do Mac) | `purged_total{age}` +33 401 na janela, `size`/`space` 0; banco máx 2 366 MiB | ok no espelho; conferência de ~9 min não executável |
| `stream_lost` Δ 0 | — | 0 de 05:39 a 06:28 | ok |
| health do store sem `ingest backlog`/`stream lost` | 0 amostras fora de `ok` na janela | backlog máx 0,07 s na janela (0,18 s de 05:39 a 06:28), pendentes máx 23 | ok |

Sem meta: CPU do store 45,0 / 48,9 / 56,1% (F7 sem bot: 50,6 / 58,2 / 64,2%), web 39,0%, nats 15,6%, bot 42,3%,
fatia 151,2 / 172,0 / 187,2%; host 183% de um núcleo (11,4% dos 16 vCPU). O expurgo na janela (62/s) ficou abaixo
das ~100/s criadas porque o prefill acabou 3,5 min antes da janela (a conferência do `loadgen` dele foi
interrompida para emendar), e o banco ainda estava subindo para o regime.

**Observação.** Na rodada `cpu-f8-on`, 1 probe h3 de 21 000 (`ldbbld9yvemwr7cr`, sem erro no cliente) não tinha
registro na API no fim da rodada, e `fs_store_connections_total{proto="quic/h3"}` subiu 4 199 para 4 200 geradas
(na `cpu-f8-off`, 4 198 para 4 200, com o probe achado; na janela oficial, 11 995 = 11 995). Fica anotado como
possível perda de um QUIC pelo caminho IPv6 do Mac; não foi investigado nesta tarefa.

## finger-01, ADRs 0039, 0042 e 0043

### Carga oficial de 10 min (task 235)

**Resultado da v0.3.0: não passou** na janela oficial `official-f01c` (200 simultâneas / 50 novas/s, RNF-01 da
[ADR 0042](../../specs/decisions/0042-rnf-01-200-50-na-v0-3-0.md)): feed p99 1 908 ms, registro p95 TCP 1 465 /
QUIC 1 490 ms. Todas as outras metas passaram, sem perda no stream. **Aceito pelo humano (2026-11-15) como limite
conhecido da v0.3.0 (ADR 0043)**; causa provável no IO/fsync do disco da VM, correção na fase F7 (task 248).

**F7, 400/100 com o banco em tmpfs (`official-f7`, 2026-11-16, `v0.3.0-10-g8a6ba1b`, task 247): todas as metas
do espelho passaram** (feed p99 352 ms, registro p95 TCP 193 / QUIC 188 ms, backlog máx 0,11 s, sem perda); falharam
só as duas metas do gerador no Mac (135 erros no cliente, 2 720 puladas pelo teto); seção própria abaixo.

**Depois da task 248 (`official-f01d`, 2026-11-16, `v0.3.0-3-g38e4415`): todas as metas passaram** (feed p99
441 ms, registro p95 TCP 234 / QUIC 236 ms); seção própria abaixo.

Preparo comum a todas as rodadas abaixo: `versions_match` na versão implantada, finger-01 só para a carga
(`/tmp/fs-load-running` do início ao fim; traefik e qdisc intocados), clientes no Mac (h1/WebSocket por IPv4, h3 por
IPv6), `QUIC_TARGET=500ms`, vida e mix do `official-50k` (vida 3,8 s, 3 trocas; h1 15, h1 TLS 15, h2 20, h3 20, raw
echo 10, banner 12, sink 8), vigia de tráfego alheio. Desde os degraus, vigia lateral a cada 5 s (health e
`/metrics` do store) em `health_watch.jsonl.gz` e `/jsz` antes e depois.

| Pasta | Início (UTC) | Versão | Perfil | Papel |
| --- | --- | --- | --- | --- |
| [`results/official-f01a`](results/official-f01a/) | 2026-11-15 18:38:47 | `v0.2.1-75-g1f83ec0` | 400/100, 10 min | histórico: falhou, causa da ADR 0041 |
| [`results/step-f01-50`](results/step-f01-50/) | 2026-11-15 20:38:46 | `v0.2.1-83-gaf14a7c` | 200/50, 3m30s | degrau, medida da ADR 0042 |
| [`results/step-f01-75`](results/step-f01-75/) | 2026-11-15 20:45:19 | `v0.2.1-83-gaf14a7c` | 300/75, 3m30s | degrau, medida da ADR 0042 |
| [`results/step-f01-100`](results/step-f01-100/) | 2026-11-15 20:52:04 | `v0.2.1-83-gaf14a7c` | 400/100, 3m30s | degrau, medida da ADR 0042 |
| [`results/prefill-f01b`](results/prefill-f01b/) | 2026-11-15 20:58:51 | `v0.2.1-83-gaf14a7c` | 400/100, 9 min | pré-aquecimento, medida da ADR 0042 |
| [`results/official-f01b`](results/official-f01b/) | 2026-11-15 21:08:40 | `v0.2.1-83-gaf14a7c` | 400/100 | abortada no aquecimento (stream perdido) |
| [`results/prefill-f01c`](results/prefill-f01c/) | 2026-11-15 21:44:01 | `v0.2.1-83-gaf14a7c` | 200/50, 9 min | pré-aquecimento emendado na janela |
| [`results/official-f01c`](results/official-f01c/) | 2026-11-15 21:53:37 | `v0.2.1-83-gaf14a7c` | 200/50, 10 min + 1 min | **janela oficial da v0.3.0** |
| [`results/official-f01c-side`](results/official-f01c-side/) | 21:44:01–22:05:22 | — | — | vigia lateral da `prefill-f01c` e da `official-f01c` |
| [`results/prefill-f01d`](results/prefill-f01d/) | 2026-11-16 03:02:10 | `v0.3.0-3-g38e4415` | 200/50, 9 min | pré-aquecimento emendado na janela (depois da task 248) |
| [`results/official-f01d`](results/official-f01d/) | 2026-11-16 03:11:37 | `v0.3.0-3-g38e4415` | 200/50, 10 min + 1 min | **janela oficial depois da task 248: passou** |
| [`results/official-f01d-side`](results/official-f01d-side/) | 03:02:02–03:22:59 | — | — | vigia lateral da `prefill-f01d` e da `official-f01d` |

```sh
test/load/run.sh -commit v0.2.1-75-g1f83ec0                            # official-f01a (padrão de então, 400/100)
test/load/run.sh -commit v0.2.1-83-gaf14a7c -rate 50 -max-active 200   # prefill-f01c (9 min) e official-f01c
```

#### Histórico: `official-f01a` (400/100, causa da ADR 0041)

Janela 18:38:47–18:48:47 UTC (cobertura e retenção até 19:00:11), depois de um pré-aquecimento `prefill-f01` de
9 min sem relatório (a cobertura dele foi interrompida; brutos fora do Git).

| Meta | Medido | Resultado |
| --- | --- | --- |
| feed p99 ws / sse < 1 s | p50 29 / p95 59 477 / p99 60 127 / máx 69 626 ms (os dois) | **falhou** |
| `stream.dropped` 0 | 0 / 0 | ok |
| API p95 < 100 ms | `/connections/{id}` 20,3 ms, `/probes/{id}` 20,4 ms; 1 erro na amostragem | p95 ok, **1 erro** |
| registro p95 ≤ 500 ms | TCP 58 541 ms; QUIC 151 933 ms | **falhou** |
| probes sem registro 0 | **38 657 de 60 000** (feed 21 343, só API 0) | **falhou** |
| `degraded` 0 | 0 | ok |
| `dropped_events_total`, `kernel_drops` 0 | 0, 0 | ok |
| `fs_store_flows_dropped_total` sem crescer | 0 | ok |
| `nr_throttled` sem crescer | 0 em todas as units | ok |
| `anon` < `MemoryMax` (MiB) | capture 8/512, web 48/768, raw 18/256, dns 7/256, store 138/2048, nats 312/1024 | ok |
| maior frame ≤ 1514 | 1514, `offload_suspect` 0 | ok |
| expurgo depois de 10 min | 20 primeiros 404; dos fechados há ~9 min **0 presentes** (nunca gravados) | **falhou** |

Sem meta: CPU média (% de um núcleo) store 78,0 (p95 122,2, máx 143,6), web 38,2, nats 10,1, raw 6,6, capture 3,6,
dns 0,1; host 155% de um núcleo (p95 211%); `conntrack -S` Δ 0, sem "table full"; alheio 0,05/s (máx 1,8/s em 5 s);
`store_stray_total` Δ 269 060. O atraso fica em ~55–60 s desde o 1º minuto (`lag.txt`: a conexão mais nova na API
~55 s atrás do relógio) e para aí porque o JetStream descarta pelo `max_age` de 60 s do `FS_EVENTS` (~1,14 M
mensagens expiradas sem entrega no `/jsz`), o que explica os probes sem registro e o expurgo "0 presentes"; a perda
não aparecia em nenhum contador nem no health. Causa
([ADR 0041](../../specs/decisions/0041-ingest-atrasado-relogio-e-lacunas.md)): `flows.due` comparava o relógio de
parede do store com o instante de captura, os fluxos se partiam em avulsos (~450/s) e a realimentação derrubava o
ingest. Corrigido nas tasks 242–245 (relógio de captura, perda e atraso do stream visíveis, fluxos depois de
lacuna, avulsos de meio de fluxo).

#### Degraus e pré-aquecimento a 100/s em `v0.2.1-83-gaf14a7c` (medida da ADR 0042)

3m30s por degrau, com 30 s de aquecimento descartado e 2 min de pausa entre eles.

| Degrau (UTC, medido) | CPU store % núcleo méd/p95/máx | backlog máx | Δ stream_lost | ingest_lag p95 | record_ready close / quic_close p95 | feed p99 | stray/s | midflow/s |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 50/s, 200 (20:39:16–20:42:16) | 27,0 / 32,5 / 37,9 | 0,11 s | 0 | 251 ms | 265 / 316 ms | 534 ms | 0,8 | 0,00 |
| 75/s, 300 (20:45:49–20:48:49) | 39,4 / 60,6 / 78,8 | 0,61 s | 0 | 1 042 ms | 1 040 / 1 102 ms | 1 273 ms | 0,7 | 0,00 |
| 100/s, 400 (20:52:34–20:55:34) | 49,0 / 114,0 / 142,4 | 2,94 s | 0 | 2 365 ms | 2 340 / 2 359 ms | 2 705 ms | 2,4 | 0,15 |

Nos três degraus: probes sem registro 0, health do store sempre `ok`, `flows_dropped` 0, `nr_throttled` 0, alheio
≤ 0,23/s. No de 100/s o gerador pulou 705 conexões (teto de 400) em t=176–210 s, com ~186 conexões no web (provável
lado do cliente); o `summary.json` desse degrau saiu vazio (vale o `summary.md`). Atraso em 75 e 100/s estável, sem
crescer, nos 3 min.

**`prefill-f01b`** (9 min a 100/400, 20:58:51–21:07:51 UTC): o atraso cresce sem parar (feed p99 por fatia de 30 s
~10–16 s no 1º minuto e meio, ~2 s em 150 s e, de 180 s em diante, até ~55–63 s, o teto do `max_age`).
`fs_store_stream_lost_total` 0 → **32 678**; health do store fora de `ok` em 92 amostras; feed p99 55,0 s, registro
p95 TCP 55,2 s / QUIC 61,5 s; 1 060 de 53 997 probes sem registro; stray 8,2/s e midflow 7,6/s (a realimentação da
ADR 0041 sumiu). CPU do store por fatia de 30 s: 32–67% de um núcleo de média, máx 119–143%; o store não satura um
núcleo e mesmo assim não acompanha. `memory.current` do store estável em ~1 745 MiB (`file` ~1 585) de 210 s a
480 s, abaixo do `MemoryMax`, enquanto o atraso crescia (a hipótese do cache de página não se confirmou, ADR 0042
item 4). A janela **`official-f01b`** (21:08:40) foi abortada no minuto de aquecimento: health já em
`stream lost 32678 messages in 5m`, backlog 0 → 27,7 s em 75 s; `stream_lost` 35 348 depois do aborto.

Conclusão (ADR 0042): 100/s não se sustenta além de ~3 min; o RNF-01 da v0.3.0 recua para 200/50 e 400/100 vai para
a fase F7 (tasks 246 e 247).

#### Janela oficial `official-f01c` (200/50, ADR 0042)

Pré-aquecimento `prefill-f01c` de 9 min a 200/50 (21:44:01–21:53:30 UTC, 30 s de aquecimento, sem medição oficial)
emendado na janela, para o expurgo dele rodar dentro dela. Gate do pré-aquecimento ok: `stream_lost` Δ 0, health
sem `ingest backlog`/`stream lost`, backlog máx 0,44 s. Janela: geração 21:53:37–22:03:37 UTC (medida
21:54:37–22:03:37), expurgo conferido até ~22:05:03.

| Meta | Medido | Resultado |
| --- | --- | --- |
| feed p99 ws / sse < 1 s | p50 108 / p95 1 340 / p99 1 908 / máx 2 613 ms (os dois) | **falhou** |
| `stream.dropped` 0 | 0 / 0 | ok |
| API p95 < 100 ms | `/connections/{id}` 21,3 ms, `/probes/{id}` 21,0 ms; 0 erro | ok |
| registro p95 ≤ 500 ms | TCP 1 465 ms (p99 2 017); QUIC 1 490 ms (p99 2 065) | **falhou** |
| probes sem registro 0 | 0 de 29 999; 0 erro no cliente; **1 pulada pelo teto do gerador** (200) | ok / **1 pulada** |
| `degraded` 0 | 0 (Δ `connections_degraded_total` 0) | ok |
| `dropped_events_total` 0, `kernel_drops` 0 | 0, 0 | ok |
| `flows_dropped` sem crescer | Δ 0 | ok |
| `nr_throttled` sem crescer | 0 em todas as units | ok |
| `anon` < `MemoryMax` (MiB) | capture 10/512, web 28/768, raw 14/256, dns 4/256, store 81/2048, nats 180/1024 | ok |
| maior frame ≤ 1514 | 1514, `offload_suspect` 0 | ok |
| expurgo depois de 10 min | 20 primeiros 404; ~9 min 20 presentes | ok |
| `stream_lost` Δ 0 (pré-aquecimento → fim) | 35 348 → 35 348 (Δ 0) | ok |
| health do store sem `ingest backlog`/`stream lost` | 0 amostras com motivo em 257 (21:44:01–22:05:22) | ok |

**Resultado: não passou** (feed p99 1 908 ms, registro p95 TCP 1 465 / QUIC 1 490 ms); **aceito pelo humano como
limite conhecido da v0.3.0 (ADR 0043), correção na F7 (task 248)**. A conexão pulada pelo teto do gerador é do
cliente (o servidor não recusou nada).

**Sem meta.**
- CPU (% de um núcleo, média/p95/máx): store 27,6/50,5/67,3 (pré-aquecimento 26,7/32,7/43,6); web 20,5, nats 7,9,
  raw 3,7, capture 3,4, dns 0,1 de média; host 69/96/125% de um núcleo (4,3% dos 16 vCPU, steal 0,0).
- Ingest: backlog máx 1,81 s na janela (0,44 s no pré-aquecimento), pendentes máx 933; avulsos 0,8/s, meio de fluxo
  0,00/s. Decomposição na janela (p50/p95/p99 ms): `ingest_lag` 108/1 653/2 469, `record_ready{close}`
  115/1 594/2 334, `record_ready{quic_close}` 224/1 688/2 354.
- Rede e alheio: `conntrack -S` Δ 0, sem "table full" no `dmesg`; alheio média 0,07/s (máx 1,4/s em 5 s,
  37 conexões), longe dos limites de descarte (1000 vivas, 250/s).
- Memória do store (cgroup, a cada 5 s, `store_mem.txt.gz`): `memory.current` 108 → 1 183 MiB no fim do
  pré-aquecimento e ~1 280 MiB estável na janela (máx 1 300; `file` ~1 160–1 205, `anon` 48–80) contra o
  `MemoryMax` de 2 048; `memory.events` high 0, max 792 → 792 (Δ 0); `pgscan` 70 464, `pgsteal` 70 139,
  `workingset_refault_file` 51 474 **sem crescer**; `memory.pressure` some avg10 0,00 o tempo todo.
- `io.pressure` do store (full avg10): 8–17% no pré-aquecimento, **18–32% na janela**.
- Banco (`db-antes.txt`, `db-depois.txt`): `finger-sniffer.sqlite` 7,75 MB → 1 203,8 MB; WAL 64 MiB nos dois
  instantes (shm 256 KiB). Disco: VMware Virtual NVMe.

**Paradas periódicas do escritor** (provável; a confirmar na task 248):
- Não é memória: o store fica a ~750 MiB do `MemoryMax`, sem `pgscan`, `refault` nem pressão de memória crescendo
  (o item 4 da ADR 0042 não se aplica).
- O atraso vem em rajadas: o feed por segundo (`feed_delay_by_second.csv`) fica em p50 ~85–115 ms e, a cada ~6–7 s,
  um segundo salta para p50 0,6–1,7 s / máx 1,2–2,2 s (96 dos 679 segundos do arquivo com p50 > 500 ms). As paradas
  começam ~30 s depois do início da janela (~21:54, quando os registros do pré-aquecimento, de 21:44, passam dos
  10 min de retenção) e somem ~22:03, quando o expurgo do pré-aquecimento termina; coincidem com o `io.pressure full`
  subindo de ~10% para 20–30%. Hipótese: o expurgo (DELETE de linhas e BLOBs) mais o checkpoint do WAL na mesma
  rodada travam o escritor único em IO/fsync no disco da VM.
- Já no pré-aquecimento (banco crescendo, sem expurgo) as metas ficaram no limite: feed p99 881 ms, registro p95 TCP
  494 ms / QUIC 548 ms (máx 29 s), 7 puladas pelo teto; o degrau `step-f01-50` (3 min, banco pequeno) tinha feed p99
  534 ms. A 200/50 em regime (banco de ~1,2 GB com expurgo contínuo) o finger-01 não cumpre RNF-02/RNF-04, mas sem
  perda no stream.

**Brutos** (todos guardados, nenhuma rodada passa de ~2,2 MB): por rodada, `summary.md` e `summary.json`,
`timeline.csv`, `feed_delay_by_second.csv`, `cpu_mem_by_second.csv`, `metrics_{start,warm,end}.prom`,
`conntrack-{antes,depois}.txt`, `run.txt` (log do gerador, horários locais UTC−3) e, em gzip, `conns.csv.gz`,
`cgroup.csv.gz` e `gen.json.gz`; nos degraus e na `official-f01b`, `health_watch.jsonl.gz` e
`jsz-{antes,depois}.json`; na `official-f01a`, `foreign_watch.txt`, `foreign_api.jsonl.gz` e `lag.txt` (conexão mais
nova na API a cada 30 s); em `official-f01c-side`, `health_watch.jsonl.gz` (health e `/metrics` do store a cada 5 s
da `prefill-f01c` ao fim da `official-f01c`), `store_mem.txt.gz` (memória, `memory.events`, `memory.stat` e pressões
do store a cada 5 s), `jsz-{antes,depois}.json` e `db-{antes,depois}.txt`. Os `conntrack-dmesg.txt` saíram vazios
(sem "table full") e não foram copiados. Fora do Git ficou só o `prefill-f01` (pré-aquecimento da `official-f01a`,
sem relatório).

### Carga oficial 200/50 depois da task 248 (`official-f01d`, critério de saída da F7 para a 248)

**Resultado: todas as metas passaram** na janela oficial `official-f01d` (`v0.3.0-3-g38e4415`, PR #222 implantado,
`versions_match`): feed p99 441 ms (era 1 908 ms na `official-f01c`), registro p95 TCP 234 / QUIC 236 ms (eram
1 465 / 1 490 ms), sem perda no stream. O limite conhecido da ADR 0043 não se repete com o escritor da task 248.

Mesmo procedimento da `official-f01c` (preparo comum acima; perfil padrão do `loadgen`, 200/50): pré-aquecimento
`prefill-f01d` de 9 min (03:02:10–03:11:10 UTC de 2026-11-16, 30 s de aquecimento) emendado na janela, para o
expurgo dele rodar dentro dela; banco recém-criado pelo deploy da 248 (8,4 MB no início). Janela: geração
03:11:37–03:21:37 UTC (medida 03:12:37–03:21:37), expurgo conferido até 03:22:57. Vigia lateral de
03:02:02 a 03:22:59 UTC, a cada 5 s, rodando no próprio finger-01 (health, `/metrics` do store com as métricas
novas da 248, memória e pressões do cgroup do store).

```sh
OUT=test/load/results/prefill-f01d  test/load/run.sh -commit v0.3.0-3-g38e4415 -duration 9m -warmup 30s -retention-check=false
OUT=test/load/results/official-f01d test/load/run.sh -commit v0.3.0-3-g38e4415
```

| Meta | Medido (`official-f01d`) | `official-f01c` | Resultado |
| --- | --- | --- | --- |
| feed p99 ws / sse < 1 s | p50 88 / p95 263 / p99 441 (sse 442) / máx 1 400 ms | p99 1 908 ms | ok |
| `stream.dropped` 0 | 0 / 0 | 0 / 0 | ok |
| API p95 < 100 ms | `/connections/{id}` 24,0 ms, `/probes/{id}` 23,2 ms; 0 erro | 21,3 / 21,0 ms | ok |
| registro p95 ≤ 500 ms | TCP 234 ms (p99 478, máx 1 011); QUIC 236 ms (p99 525, máx 29 116) | 1 465 / 1 490 ms | ok |
| probes sem registro 0 | 0 de 30 000; 0 erro no cliente; 0 pulada pelo teto | 0 de 29 999, 1 pulada | ok |
| `degraded` 0 | 0 | 0 | ok |
| `dropped_events_total` 0, `kernel_drops` 0 | 0, 0 | 0, 0 | ok |
| `flows_dropped` sem crescer | Δ 0 (`evicted` e `table_full`) | Δ 0 | ok |
| `nr_throttled` sem crescer | 0 em todas as units | 0 | ok |
| `anon` < `MemoryMax` (MiB) | capture 11/512, web 28/768, raw 13/256, dns 3/256, store 78/2048, nats 180/1024 | store 81/2048 | ok |
| maior frame ≤ 1514 | 1514, `offload_suspect` 0 | 1514, 0 | ok |
| expurgo depois de 10 min | 20 primeiros 404; ~9 min 20 presentes | igual | ok |
| `stream_lost` Δ 0 (pré-aquecimento → fim) | 0 → 0 (Δ 0) | Δ 0 | ok |
| health do store sem `ingest backlog`/`stream lost` | 0 amostras fora de `ok` em 250 (03:02:02–03:22:59) | 0 em 257 | ok |

Pré-aquecimento (`prefill-f01d`, sem meta oficial; gate ok: `stream_lost` Δ 0, health sempre `ok`, backlog máx
0,056 s): feed p99 379 ms, registro p95 TCP 231 / QUIC 232 ms, API p95 20,8 / 22,3 ms; **1 probe h3 sem registro**
de 27 000 (`ldajgdbd0x6o3y9z`, t=221 s ≈ 03:05:51 UTC, 3 trocas sem erro no cliente; já expurgado quando foi
notado, causa não investigada). O máx QUIC de ~29 s (um registro por rodada, também na `prefill-f01d`) é o caso
de sempre do `CONNECTION_CLOSE` que não chega e o fluxo fecha por ociosidade.

**Sem meta.**
- CPU (% de um núcleo, média/p95/máx): store 24,3/28,3/39,5 (pré-aquecimento 22,8/25,5/31,3); web 20,1, nats 8,0,
  raw 3,6, capture 3,2, dns 0,1 de média; host 64/77/95% de um núcleo (4,0% dos 16 vCPU, steal 0,0).
- Ingest: backlog máx 0,224 s na janela (0,056 s no pré-aquecimento), pendentes máx 110 (933 na `f01c`); avulsos
  ~0,6/s, meio de fluxo 0. Decomposição na janela (p50/p95/p99 ms): `ingest_lag` 81/156/776, `live_delay`
  77/282/564, `record_ready{close}` 90/158/472, `record_ready{quic_close}` 177/308/526.
- Feed por segundo (`feed_delay_by_second.csv`): 1 dos 680 segundos com p50 > 500 ms (96 de 679 na `f01c`); as
  paradas periódicas de ~6 s da ADR 0043 não aparecem.
- Memória do store (cgroup, a cada 5 s, `store_mem.txt.gz`): `memory.current` 13 → 1 245 MiB no pré-aquecimento,
  1 270–1 354 MiB na janela (`file` 1 158–1 241, `anon` 75–78) contra o `MemoryMax` de 2 048; `memory.events`
  high/max/oom 0 → 0; `pgscan`, `pgsteal` e `workingset_refault_file` 0 do início ao fim; `memory.pressure` some
  e full avg10 0,00 o tempo todo.
- `io.pressure` do store: full avg10 3,6–13,0% (média 8,4) no pré-aquecimento e **11,9–28,5% (média 20,2) na
  janela**; pelo `total`, 9,1% e 20,8% do tempo com todas as tarefas paradas em IO. O disco continua lento (igual à
  `f01c`, 18–32%), mas a espera deixou de travar o caminho do feed.
- Banco (`db-antes.txt`, `db-depois.txt`, horários do servidor em UTC−5): `finger-sniffer.sqlite` 8,4 MB →
  1 205,0 MB; WAL 0,5 MB → 64 MiB; `fs_store_db_bytes` 1 223–1 309 MB na janela. Expurgo: `purged_total{age}`
  Δ 25 882 na janela (31 000 no total), `size` 0.
- `fs_store_packet_spills_total`: nunca apareceu no `/metrics` (0 transbordos para a tabela `packets`).
- `fs_store_wal_frames`: 693–36 458 na janela (179–32 690 no pré-aquecimento).

Durações do escritor (`fs_store_writer_seconds{op}`, Δ do histograma; p* = limite superior do bucket, máx = faixa do
maior bucket com contagem):

| op | pré-aquecimento n / média / p95 / p99 / máx (ms) | janela n / média / p95 / p99 / máx (ms) |
| --- | --- | --- |
| `ingest_tx` | 4 479 / 11,3 / ≤ 13,6 / ≤ 50,8 / 368–713 | 4 727 / 13,0 / ≤ 26,3 / ≤ 98,4 / 713–1 380 |
| `ingest_commit` | 4 479 / 1,5 / ≤ 1,9 / ≤ 50,8 / 98–190 | 4 727 / 2,0 / ≤ 1,9 / ≤ 50,8 / 368–713 |
| `finalize_tx` | 4 434 / 2,1 / ≤ 3,6 / ≤ 7,0 / 190–368 | 4 669 / 2,8 / ≤ 7,0 / ≤ 13,6 / 368–713 |
| `purge_delete` | 2 005 / 0,8 / ≤ 1,0 / ≤ 13,6 / 98–190 | 2 071 / 2,9 / ≤ 13,6 / ≤ 98,4 / 98–190 |
| `purge_vacuum` | 0 | 0 |
| `wal_checkpoint` | 545 / 240 / ≤ 713 / ≤ 1 380 / 713–1 380 | 563 / 425 / ≤ 2 670 / ≤ 2 670 / 1 380–2 670 |
| `wal_restart` | 19 / 298 / ≤ 713 / ≤ 713 / 368–713 | 24 / 450 / ≤ 1 380 / ≤ 1 380 / 713–1 380 |

Leitura: o checkpoint continua lento no disco desta VM (até 1,4–2,7 s na janela, com o expurgo), mas agora roda
fora do `COMMIT`; o `ingest_commit` fica em p95 ≤ 1,9 ms e só raras transações de ingest passam de 0,7 s, o que
explica o máx de 1,4 s do feed sem levar o p99 acima de 0,5 s.

**Brutos** (como nas rodadas anteriores): em `prefill-f01d` e `official-f01d`, `summary.md`, `summary.json`,
`timeline.csv`, `feed_delay_by_second.csv`, `cpu_mem_by_second.csv`, `metrics_{start,warm,end}.prom`,
`conntrack-{antes,depois}.txt`, `run.txt` (log do gerador, horários locais UTC−3) e, em gzip, `conns.csv.gz`,
`cgroup.csv.gz` e `gen.json.gz`; em `official-f01d-side`, `health_watch.jsonl.gz` (health do store a cada 5 s),
`metrics.txt.gz` (`/metrics` do store a cada 5 s: `fs_store_writer_seconds`, `fs_store_wal_frames`,
`fs_store_packet_spills_total`, `stream_lost`, backlog, pendentes, avulsos, `flows_dropped`, `db_bytes`, `purged`,
somas de `record_ready`/`ingest_lag`/`live_delay`), `store_mem.txt.gz` (memória, `memory.events`, `memory.stat`,
pressões e `cpu.stat` do store a cada 5 s), `jsz-{antes,depois}.json` e `db-{antes,depois}.txt`. Os
`conntrack-dmesg.txt` saíram vazios e não foram copiados.

### finger-01, F7: degraus e carga oficial 400/100 (task 247, ADR 0042 item 5, ADR 0045)

**Resultado: todas as metas do espelho passaram** na janela oficial `official-f7` a 400 simultâneas / 100 novas/s,
com o banco do store num tmpfs (ADR 0045; `v0.3.0-10-g8a6ba1b`, `versions_match`): feed p99 352 ms, registro p95
TCP 193 / QUIC 188 ms, backlog máx 0,11 s, `stream_lost` Δ 0, `db_full` Δ 0, `memory.events` do store max/oom_kill
Δ 0, expurgo acompanhando a criação (96/s contra 95/s criadas). **Duas metas do relatório falharam do lado do
gerador no Mac**, não do espelho: 135 conexões com erro no cliente (0,24%) e 2 720 puladas pelo teto de 400 do
gerador (ver "Falhas do lado do cliente" abaixo). A decisão de devolver o RNF-01 a 400/100 é do architect (passo 5
da tarefa).

Preparo: o mesmo da `official-f01d` (preparo comum acima): finger-01 só para a carga (`/tmp/fs-load-running` do
início dos degraus ao fim da janela, segurado entre as rodadas pelo vigia), clientes no Mac (h1/WebSocket por IPv4,
h3 por IPv6), `QUIC_TARGET=500ms`, vida e mix do `official-50k`. Vigia lateral no próprio finger-01 a cada 5 s,
de 07:27:46 a 08:02:30 UTC ([`official-f7-side/side247.sh`](results/official-f7-side/side247.sh)): health,
`/metrics` do store, memória/`memory.events`/pressões/`cpu.stat` do store e da fatia, tamanho do banco e do
tmpfs, e as conexões por origem a cada 5 s (vigia de tráfego alheio); `/jsz` antes e depois. Banco no início dos
degraus: 8 MB de páginas (o expurgo já tinha esvaziado o da task 255). O `loadmon` passou a gravar também a linha da
fatia, o `shmem`, o `memory.max` real e os contadores max/oom_kill do `memory.events` de cada cgroup; o relatório
usa o `memory.max` lido (store 6 144 MiB, fatia 10 240 MiB) em vez da tabela fixa, que ainda mostrava 2 048 MiB.

```sh
OUT=tmp/load/raw/step-f7-50  test/load/run.sh -commit v0.3.0-10-g8a6ba1b -rate 50  -max-active 200 -duration 3m30s -warmup 30s -retention-check=false
OUT=tmp/load/raw/step-f7-75  test/load/run.sh -commit v0.3.0-10-g8a6ba1b -rate 75  -max-active 300 -duration 3m30s -warmup 30s -retention-check=false
OUT=tmp/load/raw/step-f7-100 test/load/run.sh -commit v0.3.0-10-g8a6ba1b -rate 100 -max-active 400 -duration 3m30s -warmup 30s -retention-check=false
OUT=tmp/load/raw/prefill-f7  test/load/run.sh -commit v0.3.0-10-g8a6ba1b -rate 100 -max-active 400 -duration 9m -warmup 30s -retention-check=false
OUT=tmp/load/raw/official-f7 test/load/run.sh -commit v0.3.0-10-g8a6ba1b -rate 100 -max-active 400   # emendada no pré-aquecimento
```

| Pasta | Início (UTC) | Perfil | Papel |
| --- | --- | --- | --- |
| [`results/step-f7-50`](results/step-f7-50/) | 2026-11-16 07:28:07 | 200/50, 3m30s | degrau |
| [`results/step-f7-75`](results/step-f7-75/) | 2026-11-16 07:32:31 | 300/75, 3m30s | degrau |
| [`results/step-f7-100`](results/step-f7-100/) | 2026-11-16 07:36:45 | 400/100, 3m30s | degrau |
| [`results/prefill-f7`](results/prefill-f7/) | 2026-11-16 07:41:05 | 400/100, 9 min | pré-aquecimento emendado na janela |
| [`results/official-f7`](results/official-f7/) | 2026-11-16 07:50:33 | 400/100, 10 min + 1 min | **janela oficial da F7** |
| [`results/official-f7-side`](results/official-f7-side/) | 07:27:46–08:02:30 | — | vigia lateral de todas as rodadas acima |

#### Degraus (3 min medidos, sem meta)

Colunas da tabela dos degraus da ADR 0042 (`step-f01-*`, `v0.2.1-83-gaf14a7c`, banco em disco) e das rodadas da
task 246 (`docs/dev/ingest-vazao.md`). Backlog máximo e pendentes do vigia lateral (5 s); CPU em % de um núcleo
(cgroup, 1 s); stray/midflow/expurgo por diferença do `/metrics` aquecimento → fim.

| Degrau (UTC, medido) | CPU store méd/p95/máx | CPU fatia méd/p95/máx | backlog máx | Δ stream_lost | ingest_lag p95 | record_ready close / quic_close p95 | feed p95 / p99 | registro p95 TCP / QUIC | stray/s | midflow/s | expurgo/s | banco máx | shmem store |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 50/s, 200 (07:28:37–07:31:37) | 24,9 / 30,4 / 35,7 | 61 / 74 / 82 | 0,08 s | 0 | 152 ms | 219 / 302 ms | 237 / 379 ms | 229 / 234 ms | 1,3 | 0,36 | 0,0 | 434 MiB | 467 MiB |
| 75/s, 300 (07:33:01–07:36:01) | 38,1 / 44,2 / 49,6 | 91 / 103 / 111 | 0,11 s | 0 | 150 ms | 179 / 302 ms | 245 / 369 ms | 221 / 226 ms | 1,9 | 0,76 | 0,2 | 1 023 MiB | 1 068 MiB |
| 100/s, 400 (07:37:15–07:40:15) | 50,2 / 58,9 / 64,3 | 110 / 122 / 127 | 0,06 s | 0 | 145 ms | 158 / 249 ms | 233 / 349 ms | 193 / 186 ms | 2,0 | 0,95 | 40,0 | 1 588 MiB | 1 622 MiB |

Comparação a 100/400: degrau da ADR 0042 (`step-f01-100`, disco) backlog 2,94 s, `ingest_lag` p95 2 365 ms,
`record_ready` 2 340 / 2 359 ms, feed p99 2 705 ms; rodadas A–D da task 246 (disco, 14 min) backlog 2,2–4,5 s, feed
p99 2,0–2,7 s, registro p95 0,9–1,3 s, expurgo 20–30/s. Com o banco em tmpfs o atraso fica igual nos três degraus
(feed p99 ~350–380 ms, `ingest_lag` p95 ~150 ms): a taxa deixou de pesar no caminho do ingest. Nos três: probes sem
registro 0, health sempre `ok`, `db_full` Δ 0, `memory.events` max/oom_kill do store Δ 0, `nr_throttled` 0. O
expurgo de 40/s no degrau de 100 é o dos registros dos degraus anteriores vencendo; não há registro de antes da
task 247 no banco.

#### Janela oficial `official-f7` (400/100)

Pré-aquecimento `prefill-f7` de 9 min (07:41:05–07:50:05 UTC, 30 s de aquecimento) emendado na janela, para o
expurgo dele rodar dentro dela. Gate do pré-aquecimento ok: `stream_lost` Δ 0, health sem `ingest backlog`/`stream
lost`, backlog máx 0,07 s, `db_full` Δ 0, `memory.events` do store Δ 0. Janela: geração 07:50:33–08:00:33 UTC
(medida 07:51:33–08:00:33), expurgo conferido até 08:01:51.

| Meta | Medido (`official-f7`) | `official-f01d` (200/50, disco) | Resultado |
| --- | --- | --- | --- |
| feed p99 ws / sse < 1 s | p50 67 / p95 232 / p99 352 (sse 351) / máx 2 112 ms | p99 441 ms | ok |
| `stream.dropped` 0 | 0 / 0 | 0 / 0 | ok |
| API p95 < 100 ms | `/connections/{id}` 19,3 ms, `/probes/{id}` 19,5 ms; 0 erro | 24,0 / 23,2 ms | ok |
| registro p95 ≤ 500 ms | TCP 193 ms (p99 208, máx 3 280); QUIC 188 ms (p99 212, máx 28 989) | 234 / 236 ms | ok |
| probes sem registro 0 | 0 de 57 145 (feed ws e sse 57 145) | 0 de 30 000 | ok |
| `degraded` 0 | 0 | 0 | ok |
| conexões com erro no cliente 0 | **135 de 57 280** (só TCP por IPv4; 120 delas têm registro no espelho) | 0 | **falhou (cliente)** |
| conexões puladas pelo teto do gerador 0 | **2 720** | 0 | **falhou (cliente)** |
| `dropped_events_total` 0, `kernel_drops` 0 | 0, 0 | 0, 0 | ok |
| `flows_dropped` sem crescer | Δ 0 (`evicted` e `table_full`) | Δ 0 | ok |
| `nr_throttled` sem crescer | 0 em todas as units | 0 | ok |
| `anon` < `MemoryMax` (MiB, `memory.max` lido) | capture 10/512, web 41/768, raw 18/256, dns 4/256, store 132/6 144, nats 312/1 024, fatia 516/10 240 | store 78/2 048 | ok |
| `memory.events` do store max / oom_kill Δ 0 (ADR 0045) | 0 / 0 (pré-aquecimento → fim) | — | ok |
| `fs_store_db_full_total` Δ 0 (ADR 0045) | 0 (pré-aquecimento → fim; `db_full_dropped` 0) | — | ok |
| maior frame ≤ 1514 | 1514, `offload_suspect` 0 | 1514, 0 | ok |
| expurgo depois de 10 min | 20 primeiros 404; ~9 min 20 presentes | igual | ok |
| `stream_lost` Δ 0 (pré-aquecimento → fim) | 0 → 0 | Δ 0 | ok |
| health do store sem `ingest backlog`/`stream lost` | 0 serviços fora de `ok` em 249 amostras (07:41:05–08:02:30) | 0 em 250 | ok |

**Falhas do lado do cliente** (Mac, não o espelho):
- Puladas pelo teto: o gerador abre uma conexão por slot e pula quando tem 400 abertas. As conexões que demoram no
  Mac (TLS/HTTP no cliente com load average 4–5, outros processos pesados no Mac) seguram slots; o espelho não
  recusou nada (`degraded` 0, modo degradado nunca ligou, na janela o web teve em média ~170 conexões ativas e o store ~385
  abertas, incluindo as em folga de fechamento, contra 400 abertas no gerador). As puladas também aparecem nos degraus menores (246 a 50/200, 324 a 75/300,
  546 a 100/400) e na task 255 (1 502; 621), e não na `official-f01d` de madrugada; nenhum contador do servidor
  acompanha.
- Erros no cliente: 135 (0,24%), todos em conexões TCP por IPv4 (h1 34, h1 TLS 37, h2 38, raw 26), **nenhum em h3
  (IPv6)**; quase todos `context deadline exceeded`/`i/o timeout` no cliente, em rajadas (41 no último minuto).
  120 das 135 têm registro no espelho (o espelho recebeu e gravou a conexão). No servidor, no mesmo tempo:
  backlog ≤ 0,11 s, `kernel_drops` 0, `conntrack -S` Δ só 1 `error`, sem "table full", CPU do web 35% de um núcleo,
  `nr_throttled` 0. Provável: caminho IPv4 do Mac (NAT doméstico) ou o próprio Mac, como as perdas de UDP IPv4 já
  conhecidas nesse caminho.
- Para medir essas duas metas sem o Mac, o gerador pode rodar noutro cliente (ou no próprio finger-01, contando a
  CPU dele); não foi feito nesta tarefa (sem cenário novo).

**Sem meta.**
- CPU (% de um núcleo, média/p95/máx): store 50,6/58,2/64,2 (pré-aquecimento 49,0/57,5/61,7); fatia
  109,3/120,7/130,2 (107,8/119,7/127,4); web 35,1, nats 13,2, raw 6,9, capture 3,4, dns 0,1 de média; host
  123/145/178% de um núcleo (7,7% dos 16 vCPU, steal 0,0).
- Ingest: backlog máx 0,11 s na janela (0,07 s no pré-aquecimento), pendentes máx 25; avulsos 2,5/s, meio de fluxo
  1,4/s. Decomposição na janela (p50/p95/p99 ms): `ingest_lag` 62/145/158, `live_delay` 59/249/498,
  `record_ready{close}` 107/172/288, `record_ready{quic_close}` 125/253/304. Feed por segundo: 0 dos 679 segundos
  com p50 > 500 ms. O máx QUIC de ~29 s é o caso de sempre do `CONNECTION_CLOSE` que não chega e o fluxo fecha por
  ociosidade.
- Memória do store (cgroup): `memory.current` até 2 399 MiB de 6 144 (`shmem` 2 268, `anon` ≤ 132); fatia até
  2 802 MiB de 10 240 (`shmem` 2 269, `anon` 516); `pgscan`, `pgsteal` e `workingset_refault_file` do store 0 do
  início ao fim; `memory.pressure` some avg10 0,00 o tempo todo; `io.pressure` full avg10 do store ≤ 0,24% (era
  11,9–28,5% na `official-f01d` com o banco em disco). O `memory.events max` da fatia está em 40 194 desde antes da
  carga (histórico, sem crescer).
- Banco e tmpfs: `fs_store_db_bytes` 1 672 → 2 356 MB do início do pré-aquecimento ao fim (máx 2 230 MiB na janela);
  `fs_store_db_fs_bytes` livre mínimo 1 834 MiB de 4 096 na janela (45%); arquivo do banco 2 306 MB e WAL 49,6 MB no
  fim (`fs_store_wal_frames` máx 11 474); expurgo `purged_total{age}` 96,4/s na janela contra ~95,5/s criadas
  (`size` e `space` 0). O banco em regime a 100/s fica abaixo do teto de 3 GiB.
- Rede e alheio: `conntrack -S` Δ drop 0, insert_failed 0, early_drop 0, error 1; alheio 0,50/s na janela (máx 12 em
  5 s), 0,44/s do pré-aquecimento ao fim (máx 33 em 5 s), longe dos limites de descarte.
- `/jsz`: `FS_EVENTS` com 96 mensagens e o consumidor `store` com 0 pendentes e 0 reentregas no fim (93 e 0 antes).

**Brutos** (como nas rodadas anteriores): por rodada, `summary.md` e `summary.json`, `timeline.csv`,
`feed_delay_by_second.csv`, `cpu_mem_by_second.csv` (agora com a coluna da fatia), `metrics_{start,warm,end}.prom`,
`conntrack-{antes,depois}.txt`, `run.txt` (log do gerador, horários locais UTC−3) e, em gzip, `conns.csv.gz`,
`cgroup.csv.gz` (15 colunas, com `shmem`, `memory_max`, `events_max`, `oom_kill` e a linha `slice`) e
`gen.json.gz`; em `official-f7-side`, `side247.sh` (o vigia), `health_watch.jsonl.gz` (objetos JSON do health,
indentados, um por amostra), `metrics.txt.gz`, `store_mem.txt.gz`, `foreign_watch.txt.gz` (conexões por origem a
cada 5 s; as origens do Mac aparecem como `mac-ipv4`, `mac-ipv6` e `mac-ipv6b`), `jsz-{antes,depois}.json` e
`db-{antes,depois}.txt`. Os `conntrack-dmesg.txt` saíram vazios e não foram copiados.

### Orçamento de entrada do web (task 215, quarta rodada)

Rodada de 2026-11-15 contra a `main` implantada `v0.2.1-75-g1f83ec0` (`versions_match`; web com `MemoryMax=768M`,
`GOMEMLIMIT=512MiB`, `GODEBUG=disablethp=1`, `FS_WEB_INPUT_BUDGET=201326592`, `FS_MAX_CONNS=1000`; THP do host
`always`, kernel 6.12.117), finger-01 só para esta carga (`/tmp/fs-load-running`), web reiniciado antes de cada
janela (`RESTART_WEB=1`), clientes no Mac (h1/WebSocket por IPv4, h3 por IPv6). Brutos em
[`results/budget-215f01a/`](results/budget-215f01a/) e [`results/budget-215f01a4/`](results/budget-215f01a4/);
`memstat-5s.txt` é o `memory.stat` (chaves `anon`, `active_anon`, `inactive_anon`, `anon_thp`, `thp_*`, `sock`,
`kernel`, `slab`) e o `nr_throttled` do web a cada 5 s, lidos por um laço de `grep` no servidor.

```sh
RESTART_WEB=1 OUT=tmp/load/raw/budget-215f01a  test/load/budget.sh -duration 4m -h1 220 -ws 16 -h3 14   # janela A
RESTART_WEB=1 OUT=tmp/load/raw/budget-215f01a4 test/load/budget.sh -duration 4m -h1 900 -ws 32 -h3 56   # janela A4
```

| Meta (ADR 0039 item 4) | A (17:58:20–18:02:41 UTC) | A4 (18:04:28–18:08:38 UTC) |
| --- | --- | --- |
| `memory.peak` ≤ 738 197 504 | 539 148 288 — ok | 544 223 232 — ok |
| `memory.events max` delta 0 | 0 → 0 — ok | 0 → 0 — ok |
| `anon` máx ≤ 603 979 776 | 517 189 632 — ok | 512 098 304 — ok |
| `NRestarts` 0, `oom_kill` 0, mesmo `MainPID` | ok (24278) | ok (25066) |
| `web_input_budget_used_bytes` ≤ 201 326 592 | 201 321 672 — ok | 201 324 054 — ok |
| `web_input_budget_denied_total` crescendo | 29 → 19 582 — ok | 1899 → 38 929 — ok |
| `cpu.stat nr_throttled` do web (registro) | 0 → 2 | 0 → 0 |
| health do web | 237 `ok`, 0 `down` | 225 `ok`, 0 `down` |

**Todas as metas atingidas nas duas janelas.** Margem do `memory.peak` até o `MemoryMax` (805 306 368): 254 MiB (A)
e 249 MiB (A4). O `anon` fica perto do `GOMEMLIMIT` (493 e 488 MiB de 512 MiB): com o orçamento cheio (192 MiB) o
runtime trabalha no limite macio, como previsto na conta; o `memory.current` máximo nas amostras de 1 s foi
496,5 MiB (A) e 500,6 MiB (A4).

Memória do web por janela de 30 s (máx., MiB; "estimado" = `memory.current − anon − file`):

| janela (s) | A: current | A: anon | A: estimado | A: sock | A4: current | A4: anon | A4: estimado | A4: sock | A4: kernel | A4: slab |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 0–30 | 414,5 | 409,1 | 5,4 | 1,9 | 496,7 | 485,0 | 15,8 | 9,6 | 5,6 | 4,0 |
| 30–60 | 428,3 | 424,0 | 6,0 | 2,0 | 495,3 | 484,0 | 12,6 | 5,9 | 5,6 | 4,1 |
| 60–90 | 438,3 | 434,0 | 5,9 | 1,7 | 498,3 | 487,1 | 12,7 | 5,8 | 5,6 | 4,0 |
| 90–120 | 435,4 | 430,5 | 5,4 | 1,8 | 493,5 | 481,3 | 12,6 | 5,7 | 5,6 | 4,0 |
| 120–150 | 437,4 | 432,4 | 5,0 | 1,4 | 500,6 | 488,4 | 12,7 | 6,0 | 5,6 | 4,0 |
| 150–180 | 432,0 | 427,1 | 5,5 | 1,8 | 495,7 | 482,6 | 13,5 | 6,6 | 5,6 | 4,0 |
| 180–210 | 432,5 | 426,8 | 5,7 | 1,5 | 499,4 | 486,0 | 13,5 | 6,4 | 5,8 | 4,2 |
| 210–240 | 435,8 | 430,8 | 4,9 | 1,4 | 500,2 | 487,9 | 13,3 | 6,2 | 5,8 | 4,2 |
| 240–270 | 496,5 | 493,2 | 4,1 | 1,1 | 491,7 | 480,8 | 12,2 | 6,0 | 5,9 | 4,3 |

Na A, `kernel` do `memory.stat` 2,5–2,6 MiB e `slab` 1,1–1,2 MiB por janela.

**Sem meta.**
- THP com `GODEBUG=disablethp=1`: `thp_fault_alloc` **0** nas duas janelas; `thp_collapse_alloc` 3 e `anon_thp`
  6 MiB constantes desde o início do processo (khugepaged em áreas fora do heap). O cgroup deste kernel não expõe
  `thp_split_page`. `active_anon + inactive_anon − anon` entre −0,56 e 0 MiB em todas as amostras com carga: a
  parcela de 22,6–27,9 MiB de páginas anônimas não mapeadas da 215c (vps602) **sumiu**.
- Memória de kernel: estimado 4,1–6,0 MiB (A) e 12,2–15,8 MiB (A4, ~950 conexões), dentro dos 62,5 + 16 MiB da conta.
- h1: A 16 767 aberturas, 16 468 × 431, 165 sem resposta (todas `client_hold_expired`: cabeçalho parcial aceito no
  orçamento e segurado 60 s pelo cliente, o esperado), 7 erros de conexão; A4 27 332 aberturas (no máximo 825 de
  900 ativas no cliente), 26 800 × 431, 114 sem resposta (46 `client_hold_expired`, 68 `client_write_timeout`),
  21 erros de conexão.
- h3: `H3_EXCESSIVE_LOAD` 2894 (A) e 12 383 (A4).
- WebSocket: A 1001 aberturas, 73 × 101, 918 × 503, 10 outras, até 16 sessões ao mesmo tempo, 65 encerradas por RST
  do servidor (eco travado); A4 1191 aberturas, 13 × 101, 1167 × 503 (orçamento cheio pelos cabeçalhos h1: no
  máximo 9 sessões, abaixo do teto de 32), 4 sem resposta (`client_read_timeout`), 7 outras.
- `nstat` do host, deltas A / A4: `TcpExtTCPRcvQDrop` 744 / 875, `TcpExtTCPMemoryPressures` 0 / 0,
  `TcpExtPruneCalled` 56 190 / 808 091, `TcpExtRcvPruned` 48 898 / 13 313, `TcpExtTCPOFODrop` 48 135 / 12 438,
  `TcpExtTCPZeroWindowDrop` 364 / 53, `UdpRcvbufErrors` 0 / 0.
- CPU média (% de um núcleo), A / A4: web 68,5 / 132,4, store 36,7 / 27,8, nats 18,8 / 31,4, capture 10,0 / 18,2,
  raw e dns ~0,1; `nr_throttled` 0 em todas as outras units.

## E2e pendentes do store (task 217, itens das tasks 151 e 201)

Rodada de 2026-11-15 contra `v0.2.1-54-g91c7f25` (`FS_IDLE_DEFAULT=120s`, `FS_IDLE_MAX=600s`), do Mac.

- **Ociosidade do TCP estabelecido (151, ADR 0034 item 2)**: `TestStoreIdleKeepsOneConnection`
  (`test/e2e/f5_idle_store_test.go`), 00:48:51–00:52:10 UTC: h1 na porta 80 com `idle=300`, parada 200 s (além de
  `FS_IDLE_DEFAULT` + 30 s = 150 s), segunda requisição na mesma conexão e FIN do cliente. O web não fechou e o
  store registrou **uma conexão só** (`01M7EAV9RY2Q42CV3ACV8YN3T5`, probe `f3qpo9aa1up7ot4c`, 2 requisições,
  `close` client/fin). Passou.
- **`ts_clock_hz` (201), caso 11 em 5 execuções seguidas** (`go test -run '^TestCase11TCPConsistency$'`, curl e Go,
  3 conexões cada por execução = 30 conexões por rodada):
  - 00:48:51–00:49:18 UTC: 29 valores entre 997,45 e 1001,79 Hz (nominal 1000 Hz, todos a < 0,3%) e **1 `null`**
    (curl, execução 3 da 4ª rodada, `01M7EAVYCP71TJ0Q854CGEAR7M`). O `null` é o comportamento da task 201 (erro
    acima de 5%), mas o teste ainda exigia o campo não nulo (`requireConnFields` "11" e `checkCase11`): 4 de 5
    rodadas passaram. Corrigido o teste: `null` numa execução é aceito, exige-se ao menos uma estimativa por
    cliente e o mesmo nominal nas publicadas.
  - 00:50:06–00:50:34 UTC, com o teste corrigido: **5 de 5 passaram**, 30 valores entre 998,09 e 1001,18 Hz, nenhum
    `null`. Estável: mesmo nominal (1000 Hz) ou `null`.

## Orçamento de entrada depois da ADR 0037 (task 215, terceira rodada)

Rodada de 2026-11-15 contra a `main` implantada `v0.2.1-58-gea48c88` (ADR 0037: `SO_RCVBUF`/`SO_SNDBUF` de 16 KiB
em toda conexão TCP do web, UDP do QUIC com 1 MiB pedido; `FS_WEB_INPUT_BUDGET=25165824`, `GOMEMLIMIT=64MiB`,
`MemoryMax=96M`), vps602 só para esta carga, web reiniciado antes (`RESTART_WEB=1`), clientes na máquina de
desenvolvimento (caminho real pela eth0, não o loopback da vps602). Brutos em
[`results/budget-215c/`](results/budget-215c/). O `budget.sh` agora grava também `sock`, `kernel`, `slab` e
`percpu` do `memory.stat` (máximo por janela de 30 s) e o `nstat -asz` antes e depois (deltas no `web.txt`).

```sh
RESTART_WEB=1 OUT=tmp/load/raw/budget-215c test/load/budget.sh -duration 4m -h1 220 -ws 16 -h3 14   # janela A
```

| Meta (ADR 0036 item 6, ADR 0037 item 5) | 215a (ADR 0036) | 215c (02:30:11–02:34:39 UTC) |
| --- | --- | --- |
| `memory.peak` ≤ 92 274 688 | 104 792 064 — falhou | **100 941 824 — falhou** |
| `memory.events max` delta 0 | 0 → 304 563 — falhou | **0 → 1663 — falhou** (183× menos) |
| `anon` máx ≤ 75 497 472 | 64 552 960 — ok | 63 787 008 — ok |
| `NRestarts` 0, `oom_kill` 0, mesmo `MainPID` | ok | ok (69207) |
| `web_input_budget_used_bytes` ≤ 25 165 824 | 25 165 793 — ok | 25 165 379 — ok |
| `web_input_budget_denied_total` crescendo | 0 → 15 476 — ok | 356 → 27 077 — ok |
| health do web | 235 `ok`, 2 `down` | 237 `ok`, 0 `down` |

Memória do web por janela de 30 s (máx., MiB; "estimado" = `memory.current − anon − file`; `sock`, `kernel`,
`slab` do `memory.stat`; `percpu` < 0,1 em todas):

| janela (s) | memory.current | anon | estimado | sock | kernel | slab |
| --- | --- | --- | --- | --- | --- | --- |
| 0–30 | 94,8 | 60,8 | 37,4 | 9,7 | 1,7 | 1,2 |
| 30–60 | 94,9 | 58,7 | 38,3 | 9,4 | 1,7 | 1,2 |
| 60–90 | 93,9 | 58,3 | 34,8 | 9,1 | 1,7 | 1,2 |
| 90–120 | 94,8 | 58,3 | 32,7 | 7,8 | 1,7 | 1,2 |
| 120–150 | 95,8 | 59,7 | 39,9 | 12,1 | 1,8 | 1,3 |
| 150–180 | 94,4 | 59,4 | 32,3 | 7,8 | 2,0 | 1,5 |
| 180–210 | 94,7 | 59,2 | 33,1 | 8,3 | 1,8 | 1,3 |
| 210–240 | 93,5 | 57,6 | 33,2 | 8,1 | 1,7 | 1,2 |
| 240–270 | 94,0 | 59,1 | 32,8 | 7,7 | 1,7 | 1,2 |

**Meta não atingida, mas não pela memória de kernel.** A ADR 0037 funcionou onde mirava: `sock` ficou em 7,7–12,1
MiB (esperado ≤ ~10) e o `kernel` do `memory.stat` em 1,7–2,0 MiB; somados, ≤ 14 MiB, dentro da conta de ~24 MiB. O
`memory.current` saiu de colado em 96 MiB para 93,5–95,8 MiB e os eventos `max` caíram de 304 563 para 1663. O
que falta para os 88 MiB é uma terceira parcela: **`memory.current − anon − file − sock − kernel` = 22,6–27,9 MiB
(média 23,9) em todas as amostras depois dos primeiros 15 s**, que não é socket nem slab. No `memory.stat` depois
da carga, `active_anon + inactive_anon` = 74,3 MiB contra `anon` 48,1 MiB (e `swapcached` 1,5 MiB): são páginas
anônimas no LRU do cgroup que não estão mapeadas. Causa provável (não confirmada): THP em `always` na vps602
(`/sys/kernel/mm/transparent_hugepage/enabled`; `thp_fault_alloc` 22 no cgroup, `thp_deferred_split_page` 1870 no
host) — o scavenger do Go devolve pedaços de 4 KiB de páginas de 2 MiB com `MADV_DONTNEED`, a página grande vai
para a fila de divisão adiada e as sub-páginas livres seguem cobradas do cgroup até a divisão; o `anon`
(mapeado) não as conta. A vps602 também tem 512 MiB de swap (28,8 MiB em uso). Por esta tarefa (papel tester) não
se corrige: volta ao architect.

**Sem meta (ADR 0037 item 3).** h1: 21 393 aberturas, 21 370 × 431, **0 fechadas sem resposta** (1805
`client_write_timeout` na 215a), 2 erros de conexão. h3: 4257 `H3_EXCESSIVE_LOAD`. WebSocket: 1713 aberturas,
15 × 101 (no máximo 5 sessões ao mesmo tempo; as 12 encerradas com RST do servidor, eco travado), 1628 × 503 antes
do 101 e 70 outras respostas; 0 sem resposta (183 `client_read_timeout` na 215a). `nstat` do host, deltas:
`TcpExtTCPRcvQDrop` 3510, `TcpExtTCPMemoryPressures` 0, `TcpExtPruneCalled` 4764, `TcpExtRcvPruned` 3548,
`TcpExtTCPOFODrop` 11, `TcpExtTCPZeroWindowDrop` 549, `UdpRcvbufErrors` 3401 (filas de 32 KiB/2 MiB cheias com o
web sem ler: o descarte acontece no socket, não no cgroup). CPU média na janela (1 vCPU): web 36%, store 34%,
nats 13%, capture 5%.

## Orçamento de entrada depois da ADR 0036 (tasks 215 e 220)

Rodada de 2026-11-15 contra a `main` implantada `v0.2.1-54-g91c7f25` (`FS_WEB_INPUT_BUDGET=25165824`,
`GOMEMLIMIT=64MiB`, `MemoryMax=96M`), vps602 só para esta carga (`/tmp/fs-load-running`), web reiniciado antes de
cada janela (`RESTART_WEB=1`: o `memory.peak` é só da janela). Brutos em
[`results/budget-215a/`](results/budget-215a/) e [`results/budget-215b/`](results/budget-215b/).

```sh
RESTART_WEB=1 OUT=tmp/load/raw/budget-215a test/load/budget.sh -duration 4m        # A: mesmo cenário da 214
RESTART_WEB=1 OUT=tmp/load/raw/budget-215b test/load/budget.sh -duration 4m \
	-h1 0 -ws 24 -h3 0 -ws-ramp 100ms                                               # B: só WebSocket, 10 aberturas/s
```

| Meta (ADR 0036 item 6) | A (00:35:47–00:39:56 UTC) | B (00:40:45–00:44:51 UTC) |
| --- | --- | --- |
| `memory.peak` ≤ 92 274 688 | **104 792 064 — falhou** | 49 700 864 — ok |
| `memory.events max` delta 0 | **0 → 304 563 — falhou** | 0 → 0 — ok |
| `anon` máx ≤ 75 497 472 | 64 552 960 — ok | 32 944 128 — ok |
| `NRestarts` 0, `oom_kill` 0, mesmo `MainPID` | ok (65060) | ok (65375) |
| `web_input_budget_used_bytes` ≤ 25 165 824 | 25 165 793 (≥ 24 MB em 229 de 237 amostras) — ok | 23 466 510 — ok |
| `web_input_budget_denied_total` crescendo | 0 → 15 476 — ok | 0 → 2843 — ok |
| health do web | 235 `ok`, 2 `down` | 240 `ok` |

Memória do web por janela de 30 s (máx. de `memory.current` / `anon` / kernel = `memory.current − anon − file`,
MiB):

| janela (s) | A | B |
| --- | --- | --- |
| 0–30 | 96,5 / 61,6 / 53,1 | 36,1 / 28,3 / 4,2 |
| 30–60 | 96,3 / 54,9 / 64,7 | 44,4 / 28,3 / 12,6 |
| 60–90 | 96,0 / 46,9 / 60,3 | 44,4 / 29,5 / 12,5 |
| 90–120 | 96,1 / 48,0 / 54,5 | 42,6 / 29,8 / 10,3 |
| 120–150 | 96,3 / 48,7 / 55,4 | 44,9 / 30,9 / 10,4 |
| 150–180 | 96,1 / 48,1 / 55,1 | 45,4 / 30,9 / 10,8 |
| 180–210 | 96,2 / 47,5 / 55,8 | 47,1 / 31,4 / 11,9 |
| 210–240 | 96,6 / 47,3 / 53,3 | 46,4 / 30,6 / 12,1 |
| 240–270 | 96,0 / 53,7 / 52,3 | 45,1 / 29,1 / 12,1 |

**Janela A (meta não atingida).** O `anon` caiu de 88,6 MiB (214) para no máximo 61,6 MiB, abaixo do `GOMEMLIMIT`
de 64 MiB: a parte da ADR 0036 sobre o heap funcionou. Mas o `memory.current` ficou colado em 96 MiB a janela
inteira (não só 150 s, como na 214) e os eventos `max` subiram 6× (304 563 contra 47 403). O que enche o cgroup é a
**memória de kernel**: 52–65 MiB em todas as janelas de 30 s, quase toda buffer de recepção dos sockets — 220
conexões h1 que mandam 64 KiB a cada 250 ms (1,3 GB enviados) e 14 conexões h3 (3,8 GB). O `SetReadBuffer` da
ADR 0036 vale só para o WebSocket; os sockets h1 seguem com o `tcp_rmem` autoajustado. CPU média na janela: web
52%, store 23%, nats 8%, capture 5% (1 vCPU). Por esta tarefa (papel tester) não se corrige: o próximo passo
previsto pelo architect na task 215 é o padrão de 16 MiB, mas com o `anon` já dentro da meta, baixar o orçamento
não deve tirar os ~55 MiB de kernel.

**Janela B (todas as metas).** 2939 aberturas, **88 × 101 e 2850 × 503** antes do 101; no health, 11 sessões
WebSocket de pé em 224 de 240 amostras e no máximo 12 (`max_ws_sessions` 12 no cliente, conforme a previsão do
implementer-web: 11, ≤ 12). As 77 sessões encerradas durante a carga terminaram com RST do servidor (eco travado);
nenhuma tentativa sem resposta. O 503 está na API: conexão `01M7EACXR0NHXSYM3G57AF1YJE` (probe
`bgu80u3rfmwuz0ku`, 00:40:59 UTC), `GET /p/bgu80u3rfmwuz0ku/ws`, `status` 503. Janela C (opcional) não rodada.

**Fechamentos sem resposta (task 220).** O `budgetload` agora separa a causa de cada conexão h1/WebSocket que
termina sem linha de resposta (`close_causes` no `summary.json`: `server_fin`, `server_rst`,
`client_write_timeout`, `client_read_timeout`, `client_hold_expired`, `other_error`; `ws_session_ends` para as
sessões com 101; `closed_no_response`, antes `closed_by_server`). Na janela A: h1 **1805, todas
`client_write_timeout`** (o web parou de ler o cabeçalho por 10 s; 0 FIN, 0 RST); WebSocket **183, todas
`client_read_timeout`** (a resposta do Upgrade não chegou em 10 s), mais 217 × 503 e 0 × 101 (o orçamento já estava
cheio dos cabeçalhos h1 quando os WS abriram). `web_connections_active` = 236 em 229 de 237 amostras (< 250).
Causa medida: não é recusa do servidor nem limite de conexões, é o web sem ler a tempo, com o cgroup em
`memory.max` a janela inteira (reclaim contínuo) e a CPU perto do teto. Como a memória não ficou dentro da meta,
não se abriu tarefa nova para o implementer-web (task 220, item 2): fica com a revisão da 215.

## Orçamento de memória de entrada do web (task 214; critério da task 155, spec 005 RF-12, ADR 0033)

Rodada de 2026-11-14, 23:01:55–23:06:05 UTC (250 s), contra a `main` implantada `v0.2.1-42-gb76caec`
(`FS_WEB_INPUT_BUDGET=41943040`, `MemoryMax=96M`, `GOMEMLIMIT=80MiB`), com a vps602 só para esta carga
(`/tmp/fs-load-running`). Brutos em [`results/budget-214/`](results/budget-214/).

```sh
OUT=tmp/load/raw/budget-official test/load/budget.sh -duration 4m   # padrão: -h1 220 -ws 16 -h3 14
```

Perfil (`test/load/cmd/budgetload`, do Mac pela internet), 250 trabalhadores ao mesmo tempo:
- **h1**: 220 conexões nas portas 80/8080, cada uma com cabeçalho parcial de 999 424 bytes (linhas de 1,1 KiB,
  abaixo do teto de 1 MiB e de 1024 campos) mandado em pedaços de 64 KiB a cada 250 ms e depois 1 byte a cada 5 s,
  sem nunca fechar o cabeçalho; reabre 1 s depois da resposta ou do fechamento;
- **WebSocket**: 16 sessões `/p/<id>/ws` mandando mensagens de 1 MiB − 64 sem ler o eco (janela zerada);
- **h3**: 14 conexões QUIC com 2 streams cada, HEADERS declarado de 1 MiB − 1024 e só 1 MiB − 2048 enviados.

| Medida | Valor |
| --- | --- |
| `web_input_budget_used_bytes` (health a cada 1 s) | máx. 41 943 037 (o orçamento inteiro), em 168 de 236 amostras ≥ 41 MB |
| `web_input_budget_denied_total` | 0 → **2540** |
| h1 | 4633 conexões; 40 seguraram o cabeçalho inteiro; **220 × 431**; 4220 fechadas sem resposta |
| WebSocket | 305 tentativas; 16 × 101 (as sessões iniciais); 289 fechadas sem resposta; 0 × 503 |
| h3 | 14 conexões, **2613 streams recusados com `H3_EXCESSIVE_LOAD`** (orçamento ou prazo de 10 s) |
| web `NRestarts` / PID | 0 → 0; `MainPID` 58179 antes e depois (**não reiniciou**) |
| web `memory.events` | `oom` 0, `oom_kill` 0; **`max` 0 → 47 403** |
| web `memory.peak` | 78 999 552 antes (desde o deploy) → **104 382 464** depois |
| web `memory.current` (amostras de 1 s) | máx. **100 773 888** (= 96,1 MiB); > 90 MiB em 131 de 251 amostras |
| web `anon` (amostras de 1 s) | máx. **92 909 568** (88,6 MiB, acima do `GOMEMLIMIT` de 80 MiB) |

Memória do web por janela de 30 s (máximo de `memory.current` / `anon`, MiB): 0–30 s 96,1/77,4; 30–60 s
96,0/71,1; 60–90 s 96,0/81,3; 90–120 s 96,0/87,5; 120–150 s 96,0/88,6; 150–180 s 81,1/74,5; 180–210 s 82,5/75,1;
210–240 s 89,7/81,5; 240–270 s 90,5/82,2.

**Leitura.** O orçamento faz o que a ADR 0033 pede: o contador encosta nos 40 MiB e para ali, as recusas sobem
(431 no h1, `H3_EXCESSIVE_LOAD` no h3) e o processo **não morreu nem reiniciou** (sem `oom_kill`, mesmo PID).
Mas **o web não ficou abaixo do `MemoryMax=96M`**: nos primeiros 150 s o `memory.current` ficou colado no teto
(96,0 MiB) e o cgroup registrou 47 403 eventos `max` (o kernel recuperando memória do cgroup no limite); o
`memory.peak` passou o `MemoryMax` (104 MB contra 100,7 MB) e o `anon` chegou a 88,6 MiB, acima do `GOMEMLIMIT`.
A conta da ADR 0033 (40 MiB de orçamento + 8 MiB do tracker QUIC, ~32 MiB para o resto) não deixou margem com
este perfil: o que não é reservado do orçamento (buffers de leitura das 250 conexões, quic-go com 28 streams de
~1 MiB em voo, eco WebSocket travado, eventos e fluxos `stream.bytes` de 800 MB de entrada h1) consumiu o resto.
Não corrigido aqui (papel tester): registrado para o architect decidir (rever o padrão de `FS_WEB_INPUT_BUDGET`
ou o que fica fora dele).

Observações do cliente: os 4220 fechamentos h1 sem resposta e os 289 do WebSocket não eram `FS_MAX_CONNS` nem
`FS_MAX_NEW_CONNS_PER_S` (conferido na task 215: `web_connections_active` 236 < 250, e o web não aplica o limite de
novas/s); a causa foi medida na janela A da task 220, acima; o 503 do WebSocket por orçamento não apareceu porque as 16 sessões iniciais ficaram de pé e as
seguintes nem chegaram ao Upgrade. O cenário mede o orçamento sob saturação, não a capacidade do RNF-01.

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
`src.ip` não é o IP público do Mac. Desde a ADR 0030, a janela só é descartada e repetida quando o tráfego
alheio, somado à carga, passa do limite do modo degradado: vivas TCP/QUIC acima de 250 por mais de 200 ms ou novas/s
acima de 60 sustentadas. O ruído abaixo disso faz parte do ambiente; bloquear origens (`nft`) não faz parte do
método. O vigia usado na rodada `c1aefd8` também grava as conexões alheias em `foreign_api.jsonl`.

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

## Execuções (rodada atual, `c1aefd8`, limites 250/60 da ADR 0030)

A vps602 já estava em `c1aefd8` (`v0.1.0-13-gc1aefd8`, `versions_match: true`), com `FS_MAX_CONNS=250` e
`FS_MAX_NEW_CONNS_PER_S=60` no env e conferidos no `/proc/<pid>/environ` do store, do web e do raw;
`FS_RETENTION=10m`; nenhuma regra `nft` de bloqueio (a `inet fsloadblock` das 50g–50i foi removida às 23:24).
Antes da carga: branch rebaseada em `c1aefd8`, `make verify-quick` verde e `go test -tags e2e ./test/e2e/...`
verde contra a vps602 (240 s; o `verify-full --e2e` completo já tinha passado em `90c86d8` + caso 7, e o `c1aefd8`
só muda os padrões dos limites, docs e specs). Nenhum deploy nem e2e durante as janelas; `/tmp/fs-load-running`
na vps602 do pré-aquecimento ao fim de cada janela; vigia de conexões alheias rodando o tempo todo.

| Pasta | Início (UTC) | Commit | Taxa | Observação |
| --- | --- | --- | --- | --- |
| (`tmp/load/raw/prefill`, fora do Git) | 2026-11-09 23:54:47 | `c1aefd8` | 50/s, 9 min | pré-aquecimento do banco, sem medição |
| `results/official-50j` | 2026-11-10 00:04:06 | `c1aefd8` | 50/s | `degraded` = 0 com a força bruta ssh na 22 presente (os mesmos 154.18.197.29 e 193.141.127.102 da 50f, sem bloqueio); `store_connections_open` medido p5 200 / mediana 202 / máx **212** (acima do antigo limite de 200). 1 erro h3 no cliente em t=17,9 s, **no aquecimento** (`timeout: no recent network activity`, registro `quic` sem h3 gravado, `degraded` falso); o `summary.md` conta o erro na janela inteira e marca a linha como falha. Por isso a segunda janela |
| `results/official-50k` | 2026-11-10 00:16:01 | `c1aefd8` | 50/s | **janela oficial**: todas as metas passaram (`summary.md`: "Todas as metas passaram"); força bruta ssh ainda presente; `store_connections_open` p5 201 / mediana 204 / máx 210 |

## Resultado por meta (rodada `c1aefd8`, janelas `official-50j` e `official-50k`)

| Meta | Métrica | Alvo | 50j | 50k (oficial) | Resultado |
| --- | --- | --- | --- | --- | --- |
| RNF-02 | feed /ws, chegada − `LiveEvent.ts`, p99 (máx) | < 1 s | 398 (535) ms | 396 (588) ms | passou |
| RNF-02 | feed /stream (SSE), p99 (máx) | < 1 s | 397 (539) ms | 396 (649) ms | passou |
| RNF-02 | `stream.dropped` (ws e sse) | 0 | 0 | 0 | passou |
| RNF-03 | `GET /connections/{id}`, p95 no cliente | < 100 ms | 35,5 ms | 33,1 ms | passou |
| RNF-03 | `GET /probes/{id}`, p95 no cliente | < 100 ms | 38,1 ms | 33,7 ms | passou |
| RNF-04 | TCP: fim no cliente → registro, p95 (máx) | ≤ 500 ms | 204 (426) ms | 203 (504) ms | passou |
| RNF-04 | QUIC: CONNECTION_CLOSE → registro, p95 (máx) | ≤ 500 ms | 261 (568) ms | 269 (569) ms | passou |
| RNF-01 | probes sem registro | 0 | 0/29 999 | 0/30 000 | passou |
| RNF-01 | registros `degraded` da carga | 0 | **0** | **0** | passou |
| RNF-01 | erros no cliente / puladas pelo teto | 0 | 1 (aquecimento) / 0 | 0 / 0 | passou (50k) |
| RNF-01 | `dropped_events_total`, `kernel_drops`, health fora de `ok` | 0 | 0 | 0 | passou |
| RNF-01 | `fs_store_connections_degraded_total` (Δ, qualquer origem) | — | 0 | 0 | — |
| RNF-01 | RAM: anon máx / MemoryMax (store; nats), MiB | anon < MemoryMax | 73/384; 89/192 | 76/384; 88/192 | passou |
| RNF-05 | expurgo: 20 primeiros 404; ~9 min ainda 200 | — | 20/20; 20/20 | 20/20; 20/20 | passou |
| RNF-07 | maior frame / `offload_suspect` | ≤ 1514 / 0 | 1514 / 0 | 1514 / 0 | passou |

CPU (% de 1 vCPU, média / p95 / máx): store 30,9/36,0/49,7 (50j), 30,3/34,7/43,2 (50k); web 16,1/15,9 de média;
capture ~1,9; raw ~2,1; nats 5,0; host 58/65/77 (50j) e 56/64/71 (50k), steal 0,1. Iguais aos da 50i (store 31,0
de média) e abaixo do gatilho de revisão da ADR 0030 (host > 75% de média). Decomposição na 50k (ms, p50/p95/p99):
`ingest_lag` 97/162/308, `record_ready{close}` 112/257/305, `record_ready{quic_close}` 195/304/314.

### Tráfego alheio e a regra da ADR 0030

- Vivas: com o perfil em 190–197 no cliente, o `store_connections_open` (health a cada 5 s, `timeline.csv`, sem o
  aquecimento) ficou acima de 200 em quase todas as amostras da 50j (104 de 112; máx 212) e na 50k (máx 210),
  pela força bruta ssh na 22 (raw `banner`, ~105 s de vida por conexão) e por varreduras avulsas. Com 200/50 isso
  degradou 29 430 conexões da carga na 50f; com 250 sobram ~40 vagas e nenhuma foi degradada. Nunca passou de 250.
- Novas/s: o vigia viu 64 (50j) e 63 (50k) conexões TCP/QUIC alheias em ~10 min (~0,1/s; no máximo 8 numa fatia
  de 15 s), contra 10 fichas/s de sobra no balde de 60/s. Nenhuma rajada perto de esvaziar o balde.
- Portanto nenhuma das condições de descarte da ADR 0030 ocorreu e as duas janelas valem. Origens mais vistas
  (pré-aquecimento + 50j): 154.18.197.29 e 193.141.127.102 na 22 (82 conexões), 45.79.207.111 na 80 (11).

### Conferência de fingerprints (rodada `c1aefd8`)

`git diff v0.1.0..c1aefd8 -- pkg/fingerprint pkg/tlsparse pkg/h2passive`: igual ao de `90c86d8` (o `c1aefd8` não
toca esses pacotes): `pkg/fingerprint` sem mudança, `pkg/tlsparse` só ganhou `alerts.go` e `pkg/h2passive` só os
instantes por stream. `test/e2e/testdata/fingerprints-f5.md` continua válido.

## Histórico: rodada de `90c86d8` (limites 200/50, antes da ADR 0030)

Falhou só na meta `degraded` = 0, nas quatro janelas (50f–50i): com o limite do modo degradado igual à garantia
(200/50), o perfil ocupava 190–196 vagas e o tráfego alheio da internet completava o resto. A causa e a decisão
estão na [ADR 0030](../../specs/decisions/0030-margem-do-modo-degradado.md), que separou a garantia do RNF-01 do
limite (padrão 250/60) e tirou o bloqueio por `nft` do método.

### Execuções (`90c86d8`)

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

### Resultado por meta (rodada `90c86d8`, janelas `official-50f` a `official-50i`)

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

#### Causa provável do `degraded`

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
ADR 0022 contra o limite da spec 004 RF-11), decidida pela ADR 0030.

#### Conferência de fingerprints (`90c86d8`)

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
- Em `official-50j` e `official-50k` (~1,4 MB cada, rodada `c1aefd8`), os mesmos brutos em gzip, `foreign_watch.txt`
  e `foreign_api.jsonl.gz` (as conexões alheias de cada fatia de 15 s, gravadas pelo vigia durante a janela;
  a da 50j inclui o pré-aquecimento).

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
