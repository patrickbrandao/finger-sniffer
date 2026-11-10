# 0030 — Garantia do RNF-01 separada do limite do modo degradado (margem para o tráfego alheio)

Status: aceita (era provisória até a carga oficial; confirmada na release v0.2.0, task 127)
Data: 2026-11-09
Altera: 0022 (regra de `degraded` = 0 na medição), 0026 (item 4, descarte da janela com tráfego alheio). Não muda
a spec 000 RNF-01.

## Contexto
A spec 000 RNF-01 garante 200 conexões simultâneas e 50 novas/s com análise completa. A spec 004 RF-11 usava os
mesmos números como limite do modo degradado (`FS_MAX_CONNS=200`, `FS_MAX_NEW_CONNS_PER_S=50`), e a ADR 0026
(item 4) mandou contar as conexões alheias (o espelho é público) e descartar e repetir a janela de carga em que
o tráfego alheio passasse do perfil.

Fato novo: carga oficial da task 120 em `90c86d8` (candidata à v0.2.0; `test/load/RESULTS.md` da branch
`task/120-carga-v0.2.0`), quatro janelas seguidas (`official-50f` a `official-50i`):
- todas as metas passaram nas quatro, exceto `degraded` = 0: **29 430 / 2 / 27 / 1** conexões da carga
  `degraded`;
- o perfil sozinho ocupa **190–196** das 200 vagas no store (igual à v0.1.0: 191–195); sobram 4–10 para o ruído
  da internet. Na 50f, força bruta ssh na 22 (~10 vivas alheias o tempo todo, ~105 s cada) levou
  `store_connections_open` a 201–207 na janela inteira; nas 50g–50i (com os dois IPs da força bruta bloqueados
  por `nft` só durante as janelas), cada `degraded` coincide em milissegundos com conexões alheias (scanner TLS na
  993 a cada ~33 s, rajada de 10+ na 993, rastreadores na 80/443/8080);
- o balde de novas/s também não tem margem: a carga abre exatamente 50/s, a recarga é 50/s e cada conexão alheia
  que completa o handshake gasta uma ficha que não volta enquanto a carga roda (só os avulsos devolvem). Na 50i
  houve 38 conexões TCP/QUIC alheias em 9 min; o balde desce de 50 para ~12 fichas e, numa noite mais densa, se
  esvazia, degradando conexões da carga uma a uma. Nas 50g–50h a amostragem de 5 s mostrou `connections_open`
  ≤ 196, o que aponta o balde como causa provável de parte desses `degraded`; o store não diz qual limite
  marcou cada registro, então os dados não separam os dois;
- a hipótese do keepalive (task 122) foi descartada pelos dados (nenhuma conexão alheia acima de 30 s na 50i);
- recursos medidos no perfil: store CPU média 23–31%, p95 28–38%, máx 59% de 1 vCPU; web ~16%; host médio
  49–58%, p95 54–66%, máx 87%; RAM anon do store 72–82 MiB de 384 MiB (`MemoryMax`), NATS 88 de 192 MiB; VPS de
  1 vCPU e 967 MiB.

Com o limite igual à garantia, `degraded` = 0 só é alcançável sem tráfego alheio, e a regra "descartar e repetir"
da ADR 0026 não converge num servidor público com o ruído atual.

## Decisão
1. **Garantia ≠ limite.** A spec 000 RNF-01 (200 simultâneas e 50 novas/s com análise completa) continua sendo a
   garantia. O limite do modo degradado (spec 004 RF-11) é configurável e o padrão fica **acima** da garantia,
   com margem para o tráfego alheio de um servidor público:
   - `FS_MAX_CONNS` padrão **250** (garantia + 25%; ~10× o pico de vivas alheias visto na 50f);
   - `FS_MAX_NEW_CONNS_PER_S` padrão **60** (garantia + 20%): com a carga em 50/s, a recarga sobra 10 fichas/s
     para o ruído (observado ~0,1/s, rajadas de ~10) e o balde volta a encher em ~1 s depois de uma rajada.
   A contagem (TCP/QUIC vivas de qualquer cliente, UDP não-QUIC fora dos limites, balde pelo instante de
   captura com devolução dos avulsos) e a janela de 200 ms da ADR 0027 não mudam.
2. O mesmo `FS_MAX_CONNS` continua limitando as conexões simultâneas do web (o accept espera por uma vaga, sem
   recusar; spec 001, ameaças); o padrão do web também passa a 250.
3. **Medição (altera ADR 0022 e ADR 0026 item 4):** na carga oficial, com os padrões novos, a meta é `degraded` = 0
   para as conexões da carga, com o tráfego da internet presente. A janela só é descartada e repetida quando o
   tráfego alheio, somado à carga, passa do limite novo: vivas TCP/QUIC acima de 250 por mais de 200 ms, ou novas/s
   acima de 60 sustentadas (balde esvaziado), comprovado pelo vigia de conexões alheias e registrado no RESULTS.
   O ruído abaixo disso faz parte do ambiente: bloquear origens alheias na vps602 durante a janela oficial não faz
   parte do método.
4. **Por que cabe na VPS:** o custo do store cresce com as novas/s e com os bytes analisados, não com conexões
   paradas. Mesmo extrapolando linearmente o pior caso sustentado (250 vivas, 60 novas/s), o store ficaria em
   ~37% de média e o host em ~70% (p95 ~80%), e a RAM do store em ~100 MiB de 384 MiB; o disco segue limitado pela
   retenção (10 min) e pelo teto de 2 GiB (ADR 0012). A margem é para o ruído transitório, não uma garantia nova:
   acima da garantia o espelho pode atrasar, e acima do limite degrada como antes.
5. **Servidor existente:** o `deploy/env-merge.sh` não muda chaves que já existem no env do servidor; a vps602 tem
   os valores 200/50 gravados e é atualizada à mão na task 126.

## Alternativas consideradas
- Baixar o perfil da carga (ex.: 180 vivas): mediria menos do que a spec 000 garante.
- Excluir o tráfego alheio da contagem: o espelho não tem como saber quem é "a carga" (ADR 0026).
- Manter 200/50 e seguir repetindo janelas, ou bloquear origens por `nft`: não converge (4 janelas seguidas) e
  mede um ambiente que não é o de produção.
- Margem maior (300 / 75): sem ganho medido sobre o ruído observado e mais excesso sustentado antes de proteger o
  armazenamento; com 1 vCPU, o host passaria de ~85% de média no pior caso.
- Manter o balde em 50 e só subir o `FS_MAX_CONNS`: o balde a exatos 50/s gasta uma ficha por conexão alheia sem
  repor; o `degraded` volta assim que o ruído acumula.
- Rótulo do limite que marcou (`fs_store_connections_degraded_total{limit}`): útil para separar as causas, mas é
  mudança de contrato de métricas sem necessidade para esta decisão; entra se a revisão desta ADR for acionada.

## Consequências
- Spec 004 RF-11 e critério de aceite com o limite padrão 250/60 e a garantia de 200/50; spec 000 RNF-01 só
  aponta para esta ADR na frase do modo degradado; ADR 0022 e ADR 0026 apontam para esta.
- Código e config (task 126, delegação da ADR 0023): `.env.example`, padrão do store (`internal/store/store.go`)
  e do web (`internal/web/config.go`), testes dos padrões, `docs/api.md` e o env da vps602.
- A carga da task 120 é refeita pelo tester com os padrões novos; o resultado decide a revisão desta ADR.

## Revisão (task 127, release v0.2.0)
Carga oficial `official-50k` em `c1aefd8` com os padrões 250/60 (`test/load/RESULTS.md`, task 120): todas as
metas da ADR 0022 passaram, `degraded` = 0 com o ruído da internet presente e sem bloqueio de origens
(`store_connections_open` máx 210, nunca acima de 250; ~0,1 conexão alheia nova/s); CPU do host 56% de média
(p95 64%, máx 71%), abaixo de 75%. A janela `official-50j` deu o mesmo resultado (`degraded` = 0, host 58%).
Nenhum gatilho de revisão disparou: a decisão passa de provisória a **aceita**. A revisão volta a ser
acionada pelos mesmos fatos (tráfego alheio que esgote a margem, ou CPU do host acima de 75% de média).
