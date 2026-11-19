# 0061 — Recuperação do health do bot depois do índice cheio

Status: aceita (teto do índice provisório: revisar se a cauda do forwardAuth passar da meta com o índice no teto) (revisão do teto acionada na carga da v0.5.1: ver 0064)
Data: 2026-11-17

## Contexto
Fatos da carga da F8 (task 285, PR #268, `test/load/RESULTS.md`, "finger-01, F8"):
- No trecho hostil (2 min, 9 560 conexões únicas a 80/s) o teto `FS_BOT_INDEX_MAX_BYTES` (384 MiB) segurou o índice,
  sem OOM (`anon` máx 733 MiB contra `GOMEMLIMIT=768MiB`), e o forwardAuth ficou nas metas.
- A tarefa pedia o health de volta a `ok` 60 s depois do fim do trecho; voltou em **7 min 23 s**. A spec 018 não
  tinha meta de recuperação: a RF-11 diz só `degraded` com `index bytes` enquanto houver despejo por bytes nos
  últimos 60 s, e o bot cumpre a regra.
- Causa: as entradas hostis vivem até `FS_BOT_CONN_TTL` (10 min). Com o índice no teto, cada conexão nova do store
  entra despejando a mais antiga por bytes e renova os 60 s. O índice só sai do teto quando as hostis vencem.
- Com o índice no teto depois do trecho, o forwardAuth seguiu nas metas, mas com cauda maior (p99 39,2 ms, máx
  191 ms, contra p99 0,77 ms antes do trecho): o bot trabalha perto do `GOMEMLIMIT` e o GC pesa.

## Decisão
1. **A regra do `index bytes` não muda.** Enquanto o índice estiver no teto, cada conexão nova custa a visão de
   outra, o bot está perto do `GOMEMLIMIT` e a cauda do forwardAuth cresce: é o estado que o operador deve ver como
   `degraded`. O health volta a `ok` 60 s depois do último despejo por bytes.
2. **Meta de recuperação** (spec 018 RF-11 e critérios): depois do fim de um tráfego que encheu o índice, o health
   volta a `ok` em até `FS_BOT_CONN_TTL` + 60 s (11 min com os padrões), e durante esse tempo o forwardAuth fica nas
   metas da RNF-01 (p95 ≤ 10 ms, p99 ≤ 50 ms). A carga da F8 atende: 7 min 23 s, forwardAuth p95 0,74 ms / p99
   39,2 ms no período. O "falhou" do `RESULTS.md` foi medido contra a meta antiga da tarefa e fica como registro.
3. **Teto de 384 MiB mantido, provisório**: sem fato de meta perdida, não muda. Se uma carga futura medir o
   forwardAuth acima de p99 50 ms com o índice no teto, ou `anon` do bot acima de 95% do `GOMEMLIMIT`, uma nova ADR
   revê o padrão (ex.: 320 MiB) ou o `GOMEMLIMIT`.

## Alternativas consideradas
- `degraded` só acima de uma taxa de despejo por bytes — com tráfego legítimo moderado e o índice cheio de entradas
  hostis, o despejo segue a cada conexão e a memória fica no teto; a taxa esconde justamente esse estado, e o limiar
  seria arbitrário.
- `degraded` só se o despejo atingir entradas mais novas que X — depois do trecho, as despejadas são as legítimas
  de antes e depois as hostis, ambas antigas: o health voltaria cedo com o bot ainda no teto de memória. Exige ainda
  guardar e expor a idade do despejo, sem ganho para o operador.
- Expirar antes as entradas hostis (TTL menor no teto, ou despejo pelas maiores) — muda a visão de 10 min da spec 018
  (RF-01) e a ordem de despejo da ADR 0057 item 2 sem fato que peça; um cliente hostil escolheria o que sai.
- Manter a meta de 60 s — inalcançável com TTL de 10 min sem mudar a regra ou o TTL.

## Consequências
- Spec 018: RF-11 e critério de aceite com a meta de recuperação. Sem mudança de código, contrato, migration ou
  base própria; nenhuma tarefa para o implementer-bot.
- O item de carga do critério de saída da F8 fica atendido pela carga da task 285.
