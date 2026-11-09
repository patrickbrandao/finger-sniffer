# 0026 — Fechamento rápido do registro (TCP e QUIC) e ajustes da carga para a v0.1.0 (agrupados)

Status: aceita
Data: 2026-11-09
Substitui: 0024. Altera: 0019 (folga de 2 s do fim do QUIC), 0022 (QUIC à parte), 0025 (`ts` do `packet.stray`).

## Contexto
Fatos novos desde a ADR 0024 (exceção provisória de p95 ≤ 3 s para o registro do QUIC):
- task 077 (#84, #89): o registro TCP deixou de esperar 1 s fixo depois do fim. RST fecha na hora; FIN dos dois
  lados fecha no ACK final ou depois de `FS_TCP_CLOSE_GRACE` (padrão 100 ms, 0–500 ms); pacotes tardios até 2 s
  depois (pelo instante de captura) são anexados ao pcap e ao registro já gravados. A métrica
  `fs_store_record_ready_seconds` ganhou o rótulo `reason`.
- task 090 (#95): o QUIC passou ao mesmo mecanismo: fecha `FS_TCP_CLOSE_GRACE` depois do `http3.connection` com
  `close`, em vez dos 2 s da ADR 0019, com os datagramas tardios da mesma 5-tupla/DCID anexados ao registro.
- carga oficial da task 068 (`test/load/RESULTS.md`, janela `official-50d`, `efcb465`): registro TCP p95 191 ms
  (máx. 491 ms) e **QUIC p95 252 ms** (máx. 408 ms); `record_ready{quic_close}` p95 304 ms. A exceção não é mais
  necessária.
- task 103 (#102): o modo degradado (spec 004 RF-11) disparava no próprio perfil do RNF-01. O implementer decidiu,
  sem o architect, o que conta nos limites e pediu a revisão.
- carga `official-50c`: ~30 conexões h2 alheias à carga (serviço de checagem de sites) levaram as vivas a
  214–235 por 66 s e 3 309 conexões da carga saíram `degraded`; a janela foi repetida.
- `official-50d`: um único `packet.stray` chegou ao feed 30,1 s depois do `ts` (fluxo UDP sem resposta que só
  vira avulso depois da ociosidade). A ADR 0025 listou o `packet.stray` como "publicado na hora do fato", premissa
  que não vale para o avulso decidido por ociosidade.

## Decisão
1. **Meta de registro igual para TCP e QUIC** (substitui a ADR 0024): p95 ≤ 500 ms do fim da conexão (spec 000
   RNF-04, spec 004 RNF-01); para o QUIC, o fim é o `http3.connection` com `close` (CONNECTION_CLOSE visto pelo
   web). A carga continua reportando TCP e QUIC em linhas separadas, ambos com meta de 500 ms.
2. **Fechamento rápido** (spec 004, "Comportamento"):
   - TCP: RST fecha na hora; FIN dos dois lados fecha no ACK final (os dois FIN confirmados) ou, sem ele, depois de
     `FS_TCP_CLOSE_GRACE` (padrão 100 ms, aceita 0–500 ms; valor fora disso não sobe o store).
   - QUIC: `http3.connection` com `close` → fim depois de `FS_TCP_CLOSE_GRACE` (substitui os 2 s da ADR 0019);
     `close.how = quic_close` como antes.
   - Pacotes tardios: até 2 s depois do fim (instante de captura), pacotes da mesma 5-tupla (TCP: ACK, RST depois
     do FIN; QUIC: datagramas da mesma 5-tupla/DCID) entram no pcap e nos totais do registro gravado, contados em
     `fs_store_late_packets_total`; não viram conexão nova nem avulso. SYN novo (TCP) ou Initial com DCID novo
     (QUIC) na mesma 5-tupla abre conexão nova (ADR 0019). Fluxo que virou avulso não recebe tardios.
3. **`fs_store_record_ready_seconds{reason}`**: histograma fim → registro gravado com `reason` ∈ `close` (FIN/RST),
   `quic_close` (close do web) e `idle` (ociosidade), os três pré-criados. A meta RNF-04 é lida em `close` e
   `quic_close`; `idle` mede por definição `idle` + 30 s e fica fora da meta.
4. **Contagem do modo degradado** (spec 004 RF-11; revisão da decisão da task 103, confirmada):
   - "conexões simultâneas" = conexões **TCP e QUIC vivas** na tabela do store, de qualquer cliente: as já
     fechadas (FIN dos dois lados ou RST) que só esperam a folga não contam; fluxos UDP que não são QUIC (consultas
     DNS e outros) **não entram nos limites**, mas saem `degraded` se chegarem com o limite já passado.
     `fs_store_connections_open` continua contando a tabela inteira.
   - "novas/s" = balde de `FS_MAX_NEW_CONNS_PER_S` fichas (capacidade de 1 s do limite) recarregado pelo instante
     de captura; pacotes fora de ordem não recarregam; tentativas que viram avulso (SYN recusado ou sem resposta,
     varreduras) devolvem a ficha.
   - Conexões TCP/QUIC alheias à carga **contam** (o espelho é público e não distingue quem gera carga). Na
     medição da ADR 0022, `degraded` = 0 vale "abaixo do perfil" visto pelo servidor: uma janela em que tráfego
     alheio leva as vivas acima de 200 (como a `official-50c`) é descartada e repetida, com o motivo no RESULTS.
   - A tolerância à reordenação de uma rajada que a task 108 vai implementar (aplicar os fechamentos do mesmo lote
     ou de uma janela ≤ 100 ms antes de decidir, ou exigir que o excesso persista por ≤ 100 ms) é compatível com
     o RF-11 e não precisa de nova ADR; uma janela maior que 100 ms precisa.
5. **`ts` do `packet.stray`** (complementa a ADR 0025): avulso emitido na hora em que o pacote chega (RST avulso,
   ICMP) mantém o `ts` do pacote; avulso que só é decidido depois (fluxo UDP sem resposta ou SYN sem resposta,
   decididos pelo fim por ociosidade) leva `ts` = instante em que o store decidiu, como o `connection.closed` por
   ociosidade. Os instantes dos pacotes ficam no `data` e em `/api/v1/packets`. Implementação na task 108.

## Alternativas consideradas
- Manter a ADR 0024 até a release: a meta provisória de 3 s ficaria no contrato do produto sem necessidade, com o
  QUIC já medido em p95 252 ms.
- Folga de fechamento separada para QUIC (`FS_QUIC_CLOSE_GRACE`): sem ganho medido; a mesma folga cobre os dois e
  os tardios são anexados de qualquer forma. O nome `FS_TCP_CLOSE_GRACE` fica (já está no `.env.example` e na
  vps602), documentado como válido também para o QUIC.
- Contar fluxos UDP não-QUIC nos limites: consultas DNS ficam 30 s na tabela por ociosidade e ocupariam vagas sem
  pesar no armazenamento (não têm pcap grande nem bytes crus de aplicação); degradaria o perfil.
- Excluir das contas os clientes que não são da carga: o espelho não tem como saber quem é "a carga"; o modo
  degradado protege o servidor, não a medição.

## Consequências
- ADR 0024 passa a "substituída por 0026"; ADR 0019 aponta para esta na parte do fim do QUIC; ADR 0022 e ADR 0025
  apontam para esta; ADR 0001 (metas) idem.
- Spec 000 RNF-04, spec 004 (RNF-01, RF-11, Comportamento, Métricas, CA), spec 011 (CA) e ADR 0022 sem a exceção.
- `docs/http3.md` e `docs/probes.md` ainda citam a ADR 0024 e o atraso de ~2 s (com `docs/docs_test.go` exigindo
  esses trechos): tarefa do papel docs.
- O long-poll `wait` de um probe h3 responde ~100–300 ms depois do fim, como no TCP.
