# 0046 — RNF-01 volta a 400/100 com o banco do store em RAM

Status: aceita
Data: 2026-11-16

## Contexto
A ADR 0042 recuou o RNF-01 para 200 simultâneas e 50 novas/s na `v0.3.0` e pôs 400/100 como meta da fase F7, a ser
devolvida só por uma ADR nova com a carga da task 247 aprovada (item 5). A ADR 0043 registrou o limite conhecido da
`v0.3.0` (RNF-02 e RNF-04 falhando a 200/50 por IO do disco da VM) e a ADR 0045 levou o banco do store para um tmpfs
de 4G, com os limites de memória para 400/100.

Fato novo: a carga oficial `official-f7` da task 247 (PR #231; 2026-11-16 07:50–08:01 UTC, `v0.3.0-10-g8a6ba1b`,
`versions_match`, banco em tmpfs, sozinha no finger-01, clientes no Mac com h1/WebSocket por IPv4 e h3 por IPv6,
vida e mix do `official-50k`, 10 min mais 1 min de aquecimento descartado, emendada num pré-aquecimento de 9 min no
mesmo perfil; números em `test/load/RESULTS.md`, seção "finger-01, F7"):

| Meta (ADRs 0022, 0039, 0041, 0042 item 3, 0045 item 6) | Medido | Resultado |
| --- | --- | --- |
| feed p99 < 1 s (RNF-02) | p95 232 / p99 352 ms (sse 351 ms) | ok |
| API p95 < 100 ms (RNF-03) | 19,3 / 19,5 ms, 0 erro | ok |
| registro p95 ≤ 500 ms (RNF-04) | TCP 193 / QUIC 188 ms | ok |
| probes sem registro 0 | 0 de 57 145 | ok |
| `degraded` 0, `stream.dropped` 0 | 0, 0 | ok |
| `fs_store_stream_lost_total` Δ 0 e health sem `ingest backlog`/`stream lost`, do pré-aquecimento ao fim | 0; 249 amostras `ok`; backlog máx 0,11 s | ok |
| `dropped_events_total`, `kernel_drops`, `flows_dropped`, `nr_throttled` | 0 | ok |
| `memory.events` max/oom_kill do store Δ 0, `fs_store_db_full_total` Δ 0 | 0 / 0, 0 | ok |
| expurgo depois de 10 min | ok (96,4/s expurgadas contra ~95,5/s criadas) | ok |
| conexões com erro no cliente 0 | **135 de 57 280** (0,24%) | falhou (gerador) |
| conexões puladas pelo teto do gerador 0 | **2 720** | falhou (gerador) |

As duas falhas são do lado do gerador no Mac:
- os 135 erros são todos em TCP por IPv4 (nenhum em h3 por IPv6), quase todos `context deadline exceeded`/`i/o
  timeout` no cliente, em rajadas; 120 deles têm registro no espelho (a conexão chegou e foi gravada); no servidor,
  no mesmo tempo, backlog ≤ 0,11 s, `kernel_drops` 0, `conntrack -S` com drop/insert_failed/early_drop 0, CPU do web
  35% de um núcleo — provável caminho IPv4 do Mac (NAT doméstico) ou o próprio Mac (load average 4–5), como as
  perdas de UDP IPv4 já conhecidas nesse caminho;
- os 2 720 pulados são o teto de 400 conexões abertas do próprio gerador, segurado por conexões que demoram no Mac;
  o espelho não recusou nada (modo degradado nunca ligou; ~170 conexões ativas no web e ~385 abertas no store,
  incluindo as em folga de fechamento). Pulados aparecem também nos degraus de 50/200 (246) e 75/300 (324) e na
  task 255, e não na `official-f01d` de madrugada; nenhum contador do servidor acompanha.

Folga medida: CPU do store 50,6% de um núcleo de média (máx 64%), fatia 109% (máx 130%, 7,7% dos 16 vCPU);
`memory.current` do store até 2 399 de 6 144 MiB (`shmem` 2 268, `anon` ≤ 132), fatia até 2 802 de 10 240 MiB;
tmpfs com no mínimo 45% livre; `pgscan`/`pgsteal` 0; `io.pressure` full ≤ 0,24%. Nos degraus de 3 min (50/75/100)
o atraso não muda com a taxa (feed p99 ~350–380 ms, `ingest_lag` p95 ~150 ms).

Decisão do orquestrador (2026-11-16): aceitar as duas falhas como do cliente e devolver o RNF-01 a 400/100.

## Decisão
1. **RNF-01: 400 conexões simultâneas e 100 conexões novas/s com análise completa** (spec 000). Substitui a ADR 0042 (item 1, o recuo para 200/50, e item 5, a meta da F7, cumprida). A ADR
   0039 item 5 (400/100) volta a valer no número; os limites de memória são os da ADR 0045.
2. **Falhas do gerador não reprovam a carga quando o espelho não as acompanha.** As metas "conexões com erro no
   cliente 0" e "puladas pelo teto do gerador 0" ficam no relatório (spec 017 RF-13), mas uma falha nelas é aceita
   como do cliente quando, na mesma janela: o modo degradado não ligou, `kernel_drops`, `flows_dropped`,
   `conntrack -S` (drop, insert_failed, early_drop) e `nr_throttled` não cresceram, o backlog do ingest ficou
   < 1 s, e os erros se concentram num caminho do cliente (família, protocolo) e não num serviço. O relatório diz
   qual condição sustenta a aceitação. Fora dessas condições a falha é do espelho e a carga reprova.
3. **Ressalva registrada**: medir erro e pulo do cliente de forma limpa exige um gerador fora do Mac (outro host
   com caminho de rede sem NAT doméstico, ou o próprio finger-01 contando a CPU do gerador à parte). Fica como
   tarefa de baixa prioridade do tester (task 256); até ela, o Mac continua o gerador oficial e o item 2 vale.
4. **Carga oficial** (spec 017 RF-13): o perfil passa a 400 simultâneas e 100 novas/s, com o pré-aquecimento de 9 min
   e todas as metas e registros das ADRs 0022, 0039, 0041, 0042 item 3 e 0045 item 6, sem mudança. Os degraus de
   3 min (50, 75, 100 novas/s) continuam sem meta, para quando o ingest mudar.
5. **Modo degradado sem mudança**: `FS_MAX_CONNS` 1000 e `FS_MAX_NEW_CONNS_PER_S` 250 (ADRs 0030 e 0039), acima da
   garantia, com margem para o tráfego alheio e os sites do host.
6. **ADR 0043 resolvida**: RNF-02 e RNF-04 são atingidos a 400/100 (e a 200/50, degrau de 50/s: feed p99 379 ms,
   registro p95 229/234 ms); o limite conhecido fica só na `v0.3.0`. ADRs 0004 e 0005 ficam (com o banco em RAM da
   ADR 0045).

## Alternativas consideradas
- **Repetir a carga com um gerador fora do Mac antes de decidir** — os números do espelho já passam com folga e
  nenhum contador do servidor acompanha as falhas do cliente; segurar a decisão por um gerador que ainda não existe
  não muda o que o espelho mostrou. Fica como tarefa (item 3).
- **Rodar o gerador no finger-01** — mede o caminho sem NAT, mas o gerador disputa CPU com o espelho e com os sites
  do humano e não passa pelo caminho real de um cliente; serve como medida complementar, não como a oficial.
- **Ficar em 200/50 e só registrar 400/100 como medido** — contradiz a ADR 0042 item 5, que previu exatamente esta
  volta com a carga 247 aprovada nas metas do espelho.
- **Relaxar as metas do gerador (aceitar até N% de erro)** — um número fixo esconderia uma falha real do espelho com
  poucos erros; o critério do item 2 amarra a aceitação aos contadores do servidor.

## Consequências
- Spec 000 RNF-01 (e o limite conhecido da `v0.3.0` marcado como resolvido na F7), spec 004 RF-11 e critério de
  aceite do modo degradado, spec 017 RF-13 e PLAN (F7 concluída) atualizados; contratos sem mudança.
- ADR 0042: substituída por esta. ADR 0043: limite resolvido (status atualizado). ADR 0039 item 5: volta a valer.
- Task 256 (tester, baixa prioridade): gerador fora do Mac e padrão 400/100 no `run.sh`/`loadgen`. Task 257 (docs):
  `docs/README.md` com o limite conhecido da `v0.3.0` resolvido e o RNF-01 400/100.
- A release seguinte (PLAN F7) leva o RNF-01 400/100 e o banco em RAM; ela não foi feita nesta ADR.
