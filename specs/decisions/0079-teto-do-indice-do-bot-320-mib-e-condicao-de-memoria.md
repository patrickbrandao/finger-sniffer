# 0079 — Teto do índice do bot em 320 MiB e condição de memória pelo cgroup

Status: aceita
Data: 2026-11-25

## Contexto
**Fato novo**: task 309, passo 2 (`test/load/RESULTS.md`, "finger-01, teto do índice do bot no trecho hostil",
PR #412; `v0.5.2-126-g5830de3`, `versions_match`, bot com a visão TCP enxuta e regras `v1.6`). Trecho hostil da
carga da F8 (forwardAuth a 200/s, 400/100 do Mac, `botload hostile` a 80 conexões/s por 2 min), repetido com o teto
`FS_BOT_INDEX_MAX_BYTES` atual e com tetos menores, demais limites iguais (`MemoryMax=1G`, `GOMEMLIMIT=768MiB`,
`CPUQuota=200%`, `FS_BOT_VIEW_WAIT=100ms`):

| Teto | forwardAuth p99 no cliente (pior minuto) | espera da visão TCP (de ~24 000) | `anon` máx (% do `GOMEMLIMIT`) | `memory.current` máx | `max`/`oom_kill` |
| --- | --- | --- | --- | --- | --- |
| 384 MiB | 43,16 ms (62,2) | 0 | 95,7% | ≤ 800 MiB | 0/0 |
| 320 MiB | 37,00 ms (46,8) | 0 | 95,2% | ≤ 800 MiB | 0/0 |
| 256 MiB | 26,97 ms (41,2) | 4 | 98,5% | 800,3 MiB na janela | 0/0 |
| 192 MiB | 100,50 ms (100,6) | 292 | 86,5% | ≤ 800 MiB | 0/0 |
| 320 MiB, `GOGC=50` | 53,99 ms (65,4) | 4 | 93,2% | ≤ 800 MiB | 0/0 |

Em todas: ingest hostil 163 200 aceitos e 0 recusado, `mismatch` Δ 0, 0 sem veredito no feed, `memory.current`
máx entre 694 e 800 MiB. Na `hostile-051` (v0.5.1, ADR 0064), 384 MiB deu p99 52,47 ms.

Leitura: nenhum teto atende às duas condições da ADR 0064 item 3 (p99 ≤ 50 ms no cliente e `anon` ≤ 90% do
`GOMEMLIMIT`). A condição de memória está errada, não o teto: o `GOMEMLIMIT` é o alvo suave do GC, e com o heap vivo
acima de metade dele (índice no teto, `GOGC=100`) o runtime do Go usa até perto do limite por desenho; o `anon`
nesse ponto não indica risco (sem `max` nem OOM, `memory.current` com 200 MiB de folga até o `MemoryMax`). Forçar o
`anon` para baixo custa GC: `GOGC=50` levou a CPU a 93% e o p99 a 54 ms. Abaixo de ~256 MiB o teto despeja as
conexões legítimas do forwardAuth (abertas há até 30 s) e o p99 vai aos 100 ms do `FS_BOT_VIEW_WAIT`.

A decisão não toca meta da spec 000 (ela não fixa memória do bot) nem os limites da RNF-02 da spec 018; muda só o
padrão do teto e o critério de aceite de memória da carga hostil.

## Decisão
1. **Teto padrão `FS_BOT_INDEX_MAX_BYTES` = 320 MiB** (`335544320`; antes 384 MiB, ADR 0057 item 2), pela regra
   da ADR 0064 item 3 (o maior teto com o forwardAuth p99 ≤ 50 ms no cliente): 37,00 ms, pior minuto 46,8 ms, sem
   espera da visão TCP. 384 MiB fica de fora porque já falhou (52,47 ms na `hostile-051`). **256 MiB, proposto pelo
   tester, não**: a janela oficial (400/100 com forwardAuth a 200/s, sem hostil) leva o índice a 233,9–237,1 MiB
   (`RESULTS.md`, v0.5.1 e F8), 92% de 256 MiB; o tráfego normal encostaria no teto (despejo e health `index bytes`)
   com pouco crescimento. 320 MiB deixa ~83 MiB de folga sobre o normal. 256 MiB é o piso medido: **nunca abaixo de
   256 MiB sem nova medida**, porque 192 MiB despeja conexões legítimas. `FS_BOT_MAX_CONNS`, TTL, `GOMEMLIMIT`,
   `MemoryMax`, `CPUQuota` e `GOGC` (padrão) sem mudança.
2. **Condição de memória do bot com o índice no teto** (substitui a condição de `anon` da ADR 0064 item 3 e o
   gatilho de `anon` da ADR 0061 item 3), medida pelo cgroup do bot em toda a rodada hostil:
   - `memory.events` `max` e `oom_kill` com Δ 0; e
   - `memory.current` máximo ≤ 90% do `MemoryMax` (≤ 921,6 MiB com `MemoryMax=1G`).
   O `anon` e a razão `anon`/`GOMEMLIMIT` continuam registrados na carga, sem meta. O custo do GC perto do limite
   aparece no p99 do forwardAuth, que já é meta (RNF-01).
3. **Gatilhos de revisão do teto** (substituem a ADR 0061 item 3): uma carga com o índice no teto que meça
   forwardAuth p99 > 50 ms no cliente, `max`/`oom_kill` > 0, `memory.current` > 90% do `MemoryMax`, ou espera da
   visão TCP em mais de 1% das requisições do forwardAuth (o teto despejando legítimos), ou, sem hostil, o
   `bot_index_bytes` máximo da janela oficial acima de 90% do teto (288 MiB) abre nova ADR. A meta de
   recuperação da ADR 0061 item 2 não muda.
4. **Fim do limite conhecido da v0.5.1** (substitui a ADR 0064): com 320 MiB, o forwardAuth fica nas metas da RNF-01
   também com o índice no teto (medido na 309). A confirmação vem da próxima carga da F8 ou da release, com o padrão
   novo implantado e as condições do item 2.
5. **Aplicação (task 428, infra, com delegação da ADR 0023)**: padrão no código (`internal/bot/config.go` e o teste),
   `.env.example`, `docs/metrics.md` e o env do finger-01, que o `env-merge.sh` não sobrescreve (chave existente fica
   com o valor do servidor): trocar a linha no `/finger-sniffer/etc/finger-sniffer.env` e reiniciar o bot no deploy.

## Alternativas consideradas
- **Manter `anon` ≤ 90% do `GOMEMLIMIT` e subir o `GOMEMLIMIT`** (ex.: 896 MiB dentro do `MemoryMax=1G`): não medido;
  o runtime subiria o heap até o novo alvo, a razão ficaria parecida, e a folga do cgroup para memória do kernel e
  pilhas cairia de ~250 para ~130 MiB. Ganharia só o número, não segurança.
- **Teto de 192 MiB** (único com `anon` ≤ 90%): falha o p99 (100,5 ms) e despeja conexões legítimas.
- **`GOGC` menor**: medido com 50; piora o p99 (54 ms) e a CPU sem trazer o `anon` a 90%.
- **Heap vivo depois do GC** como condição: honesto, mas o bot não exporta essa medida e a carga não a registra;
  `memory.events` e `memory.current` já são o que decide se o kernel mata ou estrangula o processo.
- **256 MiB** (proposta do tester): mais folga no p99 hostil (26,97 ms, pior minuto 41,2), mas o índice da janela
  oficial (até 237,1 MiB) ficaria a 92% do teto; trocaria a cauda do hostil por despejo no tráfego normal.
- **Manter 384 MiB**: passou nesta rodada (43,16 ms, pior minuto 62,2), mas falhou na v0.5.1 (52,47 ms).

## Consequências
- Spec 018 RF-02 (padrão 320 MiB), RNF-02 (condição de memória do item 2) e critério da carga hostil atualizados.
- Com o teto menor, sob tráfego hostil o índice despeja mais cedo (31 927 despejos por bytes contra 28 691 em
  384 MiB) e o health `index bytes` aparece antes; no tráfego normal o índice fica abaixo do teto (máx medido
  237,1 MiB). A próxima carga da F8 registra o `bot_index_bytes` máximo da janela oficial (gatilho do item 3).
- O pior minuto do hostil em 320 MiB (46,8 ms) tem pouca margem: a carga da próxima release confere o p99 com o
  padrão novo implantado; passar de 50 ms aciona o item 3 (o próximo passo medido é 256 MiB com a folga da janela
  oficial reavaliada).
- ADR 0064 substituída; ADR 0061 item 3 substituído (itens 1 e 2 mantidos).
