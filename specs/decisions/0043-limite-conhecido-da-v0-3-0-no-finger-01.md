# 0043 — Limite conhecido da v0.3.0: latência da carga 200/50 no finger-01 acima das metas

Status: aceita (correção escolhida pelo humano: banco em RAM, ver 0045)
Data: 2026-11-15

## Contexto
A carga oficial 200/50 da task 235 (`official-f01c`, 2026-11-15 21:44–22:05 UTC, `v0.2.1-83-gaf14a7c`, ADR 0042
item 3; números em `test/load/RESULTS.md`, seção "finger-01, ADRs 0039, 0042 e 0043") cumpriu a vazão e a
integridade, mas não a latência:
- ok: `fs_store_stream_lost_total` Δ 0 do pré-aquecimento ao fim, health do store sem `ingest backlog`/`stream
  lost`, 0 probes sem registro (de 29 999), API p95 21 ms, `degraded` 0, `dropped_events`/`kernel_drops`/
  `flows_dropped`/`nr_throttled` 0, memória do store ~1 280 de 2 048 MiB sem pressão, CPU do store 28% de um núcleo,
  expurgo depois de 10 min;
- **falhou**: feed p99 1 908 ms (RNF-02, meta < 1 s) e registro p95 TCP 1 465 / QUIC 1 490 ms (RNF-04, meta
  ≤ 500 ms).

Causa medida na task 248 (diagnóstico local, branch `task/248-purge-writer-io`, commit `ef6c2a9`, sem push):
- o disco da VM do finger-01 faz **37 IOPS** de escrita aleatória 4 KiB com fsync (p99 do fsync 138 ms);
- com `synchronous=NORMAL` em WAL, o checkpoint automático (`wal_autocheckpoint`) roda dentro do `COMMIT` do
  escritor único e espera os fsync do banco: a cada ~6 s o escritor para por até ~1 s, o que dá as paradas
  periódicas vistas no feed (p50 ~90 ms fora delas, 0,6–1,7 s nelas) enquanto o expurgo do pré-aquecimento roda;
- a única correção medida que resolve é `synchronous=OFF` (pior commit 960 → 154 ms), que muda a durabilidade do
  banco numa queda de energia/kernel;
- achado: cada pacote é gravado na tabela `packets` antes de virar pcap (~240 KB de WAL por conexão), o que
  multiplica a escrita.

Na vps602 a mesma carga passou (ADR 0022): o limite é do disco desta VM somado ao volume de escrita do store, não
da arquitetura (ADRs 0004 e 0005 ficam).

## Decisão
1. **Decisão do humano (2026-11-15): "Lançar assim".** A `v0.3.0` sai com RNF-02 e RNF-04 não atingidos na carga
   oficial 200/50 do finger-01, registrados como **limite conhecido** desta versão (CHANGELOG, PR de release e
   release do GitHub). RNF-01 (200/50, ADR 0042), RNF-03 e a integridade (perda 0, probes sem registro 0) valem.
2. As metas RNF-02 e RNF-04 da spec 000 **não mudam**: a exceção é só desta versão neste servidor. O item 3 dos
   objetivos da spec 000 fica pendente para a próxima release.
3. A correção vai para a **fase F7**, antes da vazão 400/100: task 248 (implementer-store, `aberta`) parte do
   rascunho `ef6c2a9` (instrumentação do escritor e teste de reprodução; não mergear como está) e escolhe entre as
   alternativas abaixo com medida; mudança de durabilidade, unit, disco ou limite volta ao architect (ADR nova).
   As tasks 246 e 247 vêm depois dela.

## Alternativas consideradas
- **`synchronous=OFF` já, e recriar o banco do zero se ele vier corrompido depois de uma queda** — resolve a medida
  (154 ms), e a retenção é de 10 min (perder o banco numa queda custa pouco), mas troca a garantia de durabilidade
  sem spec nem teste de recuperação; fica como candidata principal da 248 (com detecção de corrupção na partida e
  recriação automática).
- **Disco da VM melhor** (outro datastore, cache de escrita no hipervisor) — fora do espelho e do repositório,
  depende do humano; registrar como opção.
- **Banco em RAM** (`tmpfs` ou `:memory:`) — elimina o fsync, mas o banco a 200/50 chega a ~1,2 GB e conta no
  `MemoryMax` do store (2G) e da fatia (6G, ADR 0039); muda limites e a ADR 0039.
- **Escrever menos** — pcap direto sem passar cada pacote pela tabela `packets`, checkpoint `PASSIVE` fora do
  `COMMIT`, expurgo em lotes menores; reduz o WAL por conexão (~240 KB) e o número de fsync, sem mudar
  durabilidade; mais trabalho, a medir na 248.
- **Segurar a release até a 248** — recusado pelo humano.

## Consequências
- CHANGELOG `[0.3.0]`, PR de release e release do GitHub com a seção "Limite conhecido".
- PLAN: F6 sai com este limite registrado; F7 começa pela 248, depois 246 → 247.
- Task 235 encerrada ("não passou, aceito pelo humano"); task 248 vai para a F7, `aberta`.
