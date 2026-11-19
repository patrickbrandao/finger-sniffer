# 0064 — Limite conhecido da v0.5.1: forwardAuth acima da meta com o índice do bot no teto

Status: provisória (revisar na task 309, com o teto do índice remedido)
Data: 2026-11-18

## Contexto
**Fato novo**: carga da F8 para a v0.5.1 (`test/load/RESULTS.md`, "finger-01, v0.5.1", PR #280; bot
`v0.5.0-7-g20e513b`, gerador com `traefix.fingerprint/v1`):
- janela oficial (400/100 + forwardAuth a 200/s): todas as metas passaram (forwardAuth p95 0,66 / p99 4,01 ms no
  cliente; `mismatch` Δ 0 em 857 901 registros; metas da ADR 0046 no espelho);
- trecho hostil (índice cheio de propósito): forwardAuth **p95 11,41 ms / p99 52,47 ms no cliente** (metas 10/50;
  na v0.5.0, p99 44,8 ms); no servidor 99,46% ≤ 10 ms e 99,80% ≤ 50 ms, isto é, o tempo a mais fica fora do
  handler; `anon` do bot em **96,1% do `GOMEMLIMIT`** (738 MiB de 768 MiB), sem OOM, `nr_throttled` +194 em 2 min;
  teto do índice segurou (29 810 despejos por bytes); health `ok` em 7 min 59 s (meta da ADR 0061 item 2 atendida);
- causa provável, não isolada: o custo por conexão da visão TCP do traefix no índice (task 302).

As duas condições de revisão da ADR 0061 item 3 foram atingidas (p99 > 50 ms no teto e `anon` > 95% do
`GOMEMLIMIT`).

**Decisão do humano** (2026-11-18), diante de "lançar com o hostil como limite conhecido ou ajustar o teto antes":
"Lançar assim".

## Decisão
1. **Limite conhecido da v0.5.1**: com o índice do bot no teto (tráfego hostil deliberado), o forwardAuth pode
   passar da RNF-01 da spec 018 no cliente (medido: p95 11,4 / p99 52,5 ms) e o bot fica perto do `GOMEMLIMIT`. Fora
   do teto, as metas valem e foram medidas. Registrado no PR e no CHANGELOG da v0.5.1.
2. **Teto e limites sem mudança na v0.5.1**: `FS_BOT_INDEX_MAX_BYTES` 384 MiB, `GOMEMLIMIT` 768 MiB e `MemoryMax` 1G
   do bot ficam como estão até a medida da task 309.
3. **Revisão (task 309)**: medir o custo por conexão da visão TCP do traefix no índice e repetir o trecho hostil com
   um teto menor (ponto de partida 320 MiB, ADR 0061 item 3), escolhendo o maior teto com forwardAuth p99 ≤ 50 ms no
   cliente e `anon` ≤ 90% do `GOMEMLIMIT` no teto; o resultado vira ADR que substitui esta e muda o padrão.

## Alternativas consideradas
- Ajustar o teto antes da release — mais uma rodada de carga de ~1 h no servidor; decisão do humano de lançar já.
- Subir `GOMEMLIMIT`/`MemoryMax` do bot — mexe no orçamento da fatia (ADR 0045/0039) sem atacar o custo por conexão.
- Tirar a visão TCP do traefix do índice — perde `known_client`/`ua_os_tcp_mismatch` dos sites externos.

## Consequências
- v0.5.1 lançada com o limite conhecido; task 309 aberta (implementer-bot + tester; infra se mudar o padrão no
  deploy).
- Complementa a ADR 0061 (meta de recuperação mantida, atendida).
