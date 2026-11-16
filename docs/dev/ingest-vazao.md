# Vazão do ingest do store a 400/100 no finger-01 (task 246)

Diagnóstico de 2026-11-16, depois da task 248 (PR #222), no finger-01, perfil 100 novas/s e até 400 simultâneas
(`test/load/run.sh -rate 100 -max-active 400 -duration 14m -warmup 30s -retention-check=false`, vida e mix do
`official-50k`), com um vigia lateral a cada 1 s no servidor (`/metrics` do store, `memory.*`, `io.pressure` e
`cpu.stat` do cgroup, `/proc/<pid>/io`, tamanho do banco e do WAL), perfis `pprof` de CPU, bloqueio e mutex e
`runtime/trace` de 10 s pela 9001 (rota nova, só de loopback) e `strace` dos `fsync`/`pwrite64` do store. Brutos
fora do Git, em `tmp/load/raw/s246-100{a,b,d}` e `tmp/t246/` do worktree da tarefa.

## Resumo

- **O ingest não é limitado por CPU nem pelo caminho por mensagem.** A 100/s o store usa 45–53% de um núcleo
  (média); o laço do ingest passa ~66% do tempo esperando o `Fetch` (canal vazio), ~8% esperando a conexão do
  escritor e o resto em transações. O `BenchmarkIngestOfficialMix` (~2 500 conexões/s num núcleo) mede bem a CPU;
  o que ele não mede é o **disco**.
- **Gargalo medido: escrita aleatória no arquivo do banco acima do que o disco da VM entrega.** A 100/s o
  checkpoint copia ~1 250 páginas/s para o banco (690 páginas distintas/s, espalhadas por um arquivo de 3–6 GB) e
  o store escreve 16–17 MB/s no disco (`write_bytes`; ~160 KiB por conexão, 4× os ~40 KiB de dado que ficam no
  banco). O `fsync` do banco depois de ~1 s de cópias leva 1–2,7 s (`strace`); `io.pressure` full fica em 20–31%.
  O escritor é um só, e toda espera do disco que cai no caminho dele vira atraso do feed e do registro.
- **Onde a espera aparece** (sem perda: `stream_lost` Δ 0 e 0 probes sem registro em todas as rodadas):
  1. recomeço do WAL (`wal_restart`, passada final do checkpoint com o escritor parado): 0,25–0,7 s com o banco
     novo, 1,0–2,8 s depois de 7 min e 1,5–4,6 s com o banco já em regime (reuso de páginas livres);
  2. checkpoint automático dentro do COMMIT (2,3–4,7 s), quando o WAL chega a 65 536 quadros antes de o laço do
     store conseguir recomeçá-lo;
  3. **expurgo atrás da criação**: 20–30 conexões/s expurgadas contra 100 criadas. Os registros que vencem são os
     mais antigos e estão fora do cache (banco > `MemoryMax` 2G do store): o DELETE em cascata lê páginas de
     estouro e de índice do disco com o escritor preso (~5 ms por conexão no finger-01 contra 0,025 ms com o banco
     no cache), e o orçamento de 100 ms/s dá ~20/s. O banco cresce sem parar (8 MB → 5,6 GB em 3 rodadas de 14
     min) até o teto de tamanho, que usa o mesmo orçamento.
- A 50/s (carga oficial `official-f01d`) os três cabem: metade das páginas, o expurgo acompanha (43/s) e o banco
  em regime (~1,2 GB) cabe no cache.

## Rodadas a 100/400 (14 min, 30 s de aquecimento)

| Rodada | Banco no início | Mudança | feed p95 / p99 / máx (ms) | registro p95 TCP / QUIC (ms) | backlog máx | `wal_restart` Σ (n) | expurgo |
| --- | --- | --- | --- | --- | --- | --- | --- |
| A (`s246-100a`) | 8 MB (novo) | `main` + pprof | 918 / 2 000 / 3 531 | 1 009 / 1 048 | 2,24 s | 60 s (52) | 3 400 em 13 min |
| B (`s246-100b`) | 3,2 GB (regime) | + WAL sem corte | 1 224 / 2 032 / 2 973 | 1 296 / 1 340 | 2,42 s | 75 s (52) | 20/s |
| D (`s246-100d`) | 5,6 GB (atrasado) | + fsync por passada e leitura antecipada do expurgo | 785 / 2 681 / 5 333 | 886 / 940 | 4,51 s | 23 s (44) | 30/s |

Em todas: probes sem registro 0 (de ~83 000), `stream_lost` Δ 0, health `ok`, `nr_throttled` 0, `anon` do store
≤ 129 MiB, `memory.current` no `MemoryMax` (2 048 MiB, `pgscan` crescendo) a partir de ~7 min. A rodada C foi
abortada (condição do fsync errada, ver abaixo).

## Hipóteses da tarefa

| Hipótese | Resultado | Medida que decide |
| --- | --- | --- |
| Expurgo disputa com o ingest | **confirmada, por vazão** (não por paradas: cada passo fica em 25–50 ms) | 20–30/s expurgadas contra 100/s criadas; ~5 ms por conexão com o banco fora do cache, 0,025 ms dentro |
| Checkpoint do WAL com o escritor parado | **confirmada** | `wal_restart` 1–4,6 s; `strace`: o `fsync` do banco na passada final leva 0,9–3,6 s |
| Cache de página no cgroup | **confirmada como agravante** | banco em regime a 100/s (2,4 GB em 10 min, mais o atraso do expurgo) > `MemoryMax` 2G; leituras frias no expurgo (0,4 MB/s, ~100 páginas/s); `memory.current` no teto com `pgscan` a partir de ~7 min |
| Custo por mensagem (Fetch, ack, decodificação, hub, API) | **descartada** | ingest 66% ocioso no `Fetch`; CPU do store 45–53% de um núcleo; `GET` da API p95 < 20 ms |

O que o perfil de CPU mostra (60 s, 44% de um núcleo): ingest 27% (eventos de aplicação 12%, finalização 4%,
preparo de SQL repetido 4% — `Exec` com texto em vez de comando preparado), GC 15%, API/feed 9%. Nada disso está
no caminho crítico.

## Benchmark que prevê o finger-01

`TestWriterNoStallDuringPurge` (task 248) ganhou `FS_STALL_RATE` (e `FS_STALL_JSL`, o `journal_size_limit`).
No disco do finger-01, com o binário de teste e o banco cheio de 10 min a 100/s:

```sh
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c -o store.test ./internal/store
FS_STALL_DIR=/var/tmp/st FS_STALL_RATE=100 FS_STALL_CONNS=60000 FS_STALL_SECS=300 FS_STALL_MAX_MS=100000 \
  ./store.test -test.run '^TestWriterNoStallDuringPurge$' -test.v
```

Ele escreve 175 KiB por conexão (o store no finger-01, 160 KiB) e reproduz as paradas do recomeço do WAL
(`wal_restart` p50 0,41 s, máx 1,28 s; pior atraso de mensagem 1,35 s). Ele não reproduz o banco maior que o
cache (o processo de teste não está no cgroup do store): ali o expurgo custa 0,025 ms por conexão. Para prever o
regime do finger-01, rodar o teste dentro de um cgroup com o mesmo `MemoryMax` (`systemd-run --scope -p
MemoryMax=2G`) e com um banco de 2,4 GB ou mais.

## O que foi mudado (PR desta tarefa)

- `journal_size_limit` 64 MiB → 512 MiB (`WALJournalLimit`, acima do `wal_autocheckpoint` de 256 MiB): o WAL não é
  mais cortado a cada recomeço e não volta a alocar blocos (cada bloco novo entra no commit do journal do ext4,
  que todo `fsync` espera). No benchmark acima, 300 s a 100/s: pior atraso 1,35 → 0,73 s, mensagens > 1 s
  230 → 0, `wal_restart` máx 1,28 → 0,57 s. Sem mudança de durabilidade; ~200 MiB a mais de disco no WAL.
- `/debug/pprof/` na 9001, só para clientes de loopback (`/debug/pprof/rates?block=N&mutex=N` liga os perfis de
  bloqueio e mutex), para a task 247 e diagnósticos futuros.

Testadas e **não incluídas** (medida não conclusiva ou efeito colateral):
- `fsync` do banco depois de cada passada do checkpoint (o SQLite só o faz quando o WAL não cresceu durante a
  cópia; o retorno do `PRAGMA wal_checkpoint` não diz isso — `log` e `checkpointed` são da foto do início): a soma
  de `wal_restart` caiu de 75 para 23 s na rodada D, mas cada passada passou a levar 2–3 s, o laço do store
  ficou lento, o WAL chegou a 65 536 quadros e o checkpoint automático caiu dentro do COMMIT (paradas de 2,3–4,7
  s). Só vale com o checkpoint num laço próprio, separado do expurgo.
- Leitura antecipada do lote do expurgo pelo banco de leitura (aquece o cache antes do DELETE): expurgo 20 → 30/s
  na rodada D, longe dos 100/s, porque o disco já está saturado.

## Para o architect (não aplicado)

Nenhuma mudança dentro do store, mantendo disco, durabilidade, schema e limites, leva 100/s a backlog < 1 s neste
disco: o volume de escrita aleatória (página de 4 KiB por toque, índices e BLOBs em estouro, expurgo) passa do que
a VM entrega. Opções, da que mais resolve à que menos:

1. **Banco em RAM** (plano B do humano, ADR antes): elimina `fsync` e leituras frias. Conta: a 100/s, 10 min de
   retenção são ~2,4 GB de banco mais WAL (até 256 MiB) e o `anon` do store (~130 MiB) — não cabe no
   `MemoryMax=2G` do store nem com folga na fatia de 6G (ADR 0039); exige rever esses limites (ou
   `FS_STORE_MAX_BYTES`/retenção menores).
2. **Disco melhor** para `/finger-sniffer/var/store` (fora do repositório).
3. **`MemoryMax` do store ≥ 3,5–4 GB** (com a fatia): o banco em regime cabe no cache, o expurgo volta a ~0,03
   ms por conexão e as leituras frias somem; não resolve a escrita (recomeço do WAL e `fsync` continuam).
4. **Schema que escreve menos** (migration): `pcaps`/`record_json` grandes em estouro e índices em `probe_id`
   aleatório são a maior parte das páginas por conexão; por exemplo, apagar o expurgo por faixa de rowid em vez de
   cascata por `conn_id`, ou guardar o pcap fora do SQLite (arquivo por janela de tempo, apagado inteiro).
5. `synchronous=OFF` (ADR 0043, alternativa já recusada até aqui): tira o `fsync` do recomeço do WAL, mas não a
   saturação do disco nem o expurgo atrasado.

Independentemente da escolha, a 100/s o expurgo precisa de vazão ≥ criação; hoje o orçamento de 100 ms/s só
basta com o banco no cache. Isso vale para qualquer RNF acima de ~50/s neste disco.

## Probe h3 sem registro (`prefill-f01d`)

Não reproduzido: 0 probes sem registro em ~250 000 das rodadas A, B e D (~48 000 h3). O caso
(`ldajgdbd0x6o3y9z`, h3 na 8443, 03:05:51 UTC) já tinha saído do banco e o journal não tem aviso do store nem do
web na janela; sem dado para diagnosticar.

## Depois do banco em RAM (task 255, ADR 0045)

Medida de 2026-11-16 no finger-01, com a task 254 implantada (tmpfs de 4G em `/finger-sniffer/var/store`, store
com `MemoryMax=6G`, fatia 10G) e a task 255 (`synchronous=OFF`, WAL de 64 MiB, teto de 3 GiB, expurgo pelo livre
do tmpfs, reserva de 32 MiB), versão `v0.3.0-10-g8a6ba1b`, carga do Mac (`test/load/run.sh -rate 100 -max-active
400 -warmup 30s -retention-check=false`). Vigia lateral a cada 1 s (`/metrics` do store, `memory.stat` e
`memory.events` do cgroup do store e da fatia, tamanho do banco e do WAL). Brutos fora do Git, em
`tmp/load/raw/s255-100` e `s255-100b` do worktree da tarefa.

| Rodada | Banco no início | Duração | feed p95 / p99 / máx (ms) | registro p95 TCP / QUIC (ms) | backlog máx | expurgo | CPU do store média / máx |
| --- | --- | --- | --- | --- | --- | --- | --- |
| E (`s255-100`) | vazio (tmpfs novo) | 9 min + 30 s | 232 / 350 / 867 | 192 / 186 | **0,10 s** | — (nada venceu: banco mais novo que 10 min) | 50% / 63% de um núcleo |
| F (`s255-100b`) | 2,0 GB (9,5 min, em regime) | 4 min + 30 s | 233 / 349 / 834 | 193 / 187 | **0,10 s** | 96–99/s por idade, banco estável em 2 070 MiB | 46–53% |

Nas duas: `stream_lost` Δ 0, probes sem registro 0, health `ok`, `fs_store_db_full_total` Δ 0,
`fs_store_purged_total{reason="space"|"size"}` 0, `memory.events` do store com `max` 0 e `oom_kill` 0,
`nr_throttled` 0. Banco em regime a 100/s com 10 min: **2 070 MiB** de páginas usadas (abaixo do teto de 3 GiB);
`fs_store_db_fs_bytes` livre mínimo 1 994 MiB de 4 096 (49%); `shmem` do store até 2 101 MiB (fatia 2 102 MiB),
`anon` ≤ 126 MiB, `memory.current` ≤ 2 234 MiB (de 6 GiB); WAL ≤ 46 MiB (9 362 quadros); `wal_restart` 25 em
4 min, soma 1,5 ms (antes 1–4,6 s cada); `purge_delete` médio 2,1 ms por lote; `purge_vacuum` 0 (regime sem
encolher).

Contra as rodadas A–D da task 246: backlog máximo 2,2–4,5 s → 0,10 s; feed p99 2,0–2,7 s → 0,35 s; registro p95
0,9–1,3 s → 0,19 s; expurgo 20–30/s → igual à criação. O disco saiu do caminho do ingest, como previsto na ADR 0045.

Metas do relatório que falharam nas duas rodadas, do lado do gerador no Mac (não do espelho): conexões com erro no
cliente (61 de 52 498 em E; 20 de 23 379 em F) e conexões puladas pelo teto de 400 do gerador (1 502; 621). A linha
"expurgo depois da retenção" sai como falha porque a checagem foi desligada (`-retention-check=false`), como na 246;
a coluna `MemoryMax` do store no relatório ainda mostra 2 048 MiB (tabela fixa em
`test/load/cmd/loadgen/report.go`; o real agora é 6 GiB).
