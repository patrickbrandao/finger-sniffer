# 0024 — Meta de registro do QUIC: exceção provisória de 3 s

Status: provisória (revisar quando a task 090 aplicar ao QUIC o fechamento rápido da task 077)
Data: 2026-11-09

## Contexto
A meta "registro completo ≤ 500 ms após o fim da conexão" (spec 000 RNF-04, spec 004 RNF-01, ADR 0001, medida
como p95 na carga pela ADR 0022) foi escrita pensando no TCP. A ADR 0019 fez o store fechar o fluxo QUIC **2 s
depois** do `http3.connection` final (folga para os últimos pacotes do capture), e a spec 011 aceitou "≤ 3 s"
no seu CA. A auditoria F5 (task 071) mediu o fecho do QUIC em ~2,1 s: incompatível com a meta.

A task 077 (store, bloqueia a release) troca a espera fixa do TCP (`CloseGrace` de 1 s) por um fechamento
rápido em que pacotes tardios são anexados ao registro já gravado, sem virar conexão nova. O mesmo mecanismo
serve ao QUIC, mas aplicá-lo agora disputaria o mesmo código com a 077 às vésperas da `v0.1.0`.

## Decisão
- Para a `v0.1.0`, a meta de registro do **QUIC** é **p95 ≤ 3 s** contados do `http3.connection` com `close`
  (o CONNECTION_CLOSE visto pelo web), como no CA da spec 011; TCP mantém p95 ≤ 500 ms.
- A carga (task 068) reporta a meta de registro **separada** por L4: TCP (meta 500 ms) e QUIC (meta 3 s).
- A task 090 (store, depois da 077) leva o QUIC ao mesmo mecanismo da 077 e à meta de 500 ms; quando ela for
  mergeada e medida, esta ADR é substituída e a exceção sai das specs.

## Alternativas consideradas
- Reduzir já a folga de 2 s da ADR 0019: arrisca perder os últimos pacotes do capture (vira avulso ou conexão
  nova) sem o anexo tardio que a 077 está construindo.
- Medir o QUIC junto com o TCP na meta de 500 ms: a carga reprovaria por um valor decidido de propósito.

## Consequências
- Spec 000 RNF-04, spec 004 RNF-01 e ADR 0022 citam a exceção; a ADR 0019 aponta para esta.
- O long-poll `wait` de um probe h3 responde ~2 s depois do fim da conexão até a 090.
