# 0022 — Prova do MVP no espelho: matriz direta e medição das metas RNF

Status: aceita, parte de consumidor substituída pela 0028 (semântica do `ts` do feed: ver 0025; QUIC com a mesma meta de 500 ms e `degraded` com tráfego alheio: ver 0026)
Data: 2026-11-09

## Contexto
A spec 000 fecha o MVP com três itens: a matriz de testes da spec 017 de ponta a ponta, as impressões JA3/JA4/JA4T/
Akamai conferidas com FoxIO e tshark, e as metas de RNF atingidas no teste de carga. Na F5 há dois fatos novos:
1. O projeto do espelho não tem acesso ao `xproxy03` nem ao repositório do go-xproxy. Os caminhos squid 1080,
   go-xproxy 4128 e go-xproxy HTTPS-proxy 4443 da matriz só podem ser exercidos pelo script do xProxy
   (`go-xproxy/tests/nao-interferencia.sh`), e a spec 017 já diz que a comparação entre caminhos é dele. A matriz
   tem hoje 13 casos (12 e 13 entraram na F4), não 11.
2. O e2e da F4 mediu o atraso do feed: um evento isolado leva 430–570 ms do `ts` do pacote até o cliente da 9000;
   a 150 req/s, p95 ~0,6 s e máximo ~1,1 s. A meta "evento ao vivo em < 1 s" (RNF-02) não dizia como medir, e um
   máximo absoluto em 10 min num 1 vCPU (pausas de GC, `fsync`, agendador) não é verificável de forma estável.

## Decisão
- **Item 1 da spec 000, no espelho**: os 13 casos da matriz passam de ponta a ponta contra a vps602 pelo **caminho
  direto** (casos 1–13; sufixos `-random`/`-session-X` não se aplicam ao espelho), numa única execução de
  `make verify-full ARGS="--e2e"`, e cada registro traz os campos das specs 008–013. O espelho entrega ao xProxy o
  que ele precisa para os caminhos com proxy: receitas por caso em `docs/probes.md` e a lista de campos estáveis
  (iguais entre execuções do mesmo cliente) e de diferenças esperadas por proxy. A execução da matriz com proxy fica
  registrada como pendência externa no PR de release, sem bloquear a `v0.1.0`.
- **Medição das metas RNF** (`test/load/`, spec 017 RF-13), no perfil do RNF-01 (200 conexões simultâneas, 50
  novas/s, 10 min, mix h1/h2/h3/raw), descartando o primeiro minuto (aquecimento):
  - RNF-02 (feed): atraso = chegada no cliente da 9000 − `ts` do evento (`LiveEvent.ts`, semântica da ADR 0025); meta **p99 < 1 s**; p50/p95/máximo
    reportados; `stream.dropped` = 0 para um cliente que lê em dia.
  - RNF-03 (API): `GET /connections/{id}` e `GET /probes/{id}` com **p95 < 100 ms**.
  - RNF-04 (registro completo): fim da conexão no cliente → registro fechado na API, **p95 ≤ 500 ms**; máximo
    reportado. QUIC é reportado à parte, com a mesma meta (fim = `http3.connection` com `close`; ADR 0026).
  - RNF-01: nenhuma conexão perdida (todo probe da carga tem registro), `degraded` = 0 abaixo do perfil,
    `dropped_events_total` = 0 e `kernel_drops` = 0; CPU e RAM por serviço dentro dos `MemoryMax` das units.
  - RNF-05 e RNF-07: retenção e frame ≤ MTU+14 conferidos durante a carga.
- **Se uma meta falhar**: o tester abre a tarefa de otimização do serviço responsável (store, para o feed e o
  registro) com os números; se a otimização não bastar, o architect registra uma ADR provisória de revisão das ADRs
  0004/0005 (spec 002, escalonamento 5) e o trabalho segue.

## Alternativas consideradas
- Esperar o xProxy rodar a matriz com proxy antes da `v0.1.0`: bloquearia a release por algo fora do alcance do
  projeto, sem mudar nada no espelho.
- Meta do feed como máximo absoluto: reprovaria por um único evento atrasado por GC; p99 em 10 min (~30 mil
  eventos) ainda pega atraso sistemático.

## Consequências
- Spec 000 (itens de sucesso), 017 (RF-13 e matriz) e PLAN (F5) ajustados.
- O atraso fixo de ~0,5 s de um evento isolado deixa ~0,5 s de folga sob carga; o relatório da carga decompõe o
  atraso (capture → NATS → ingest → commit → hub) com as métricas `fs_store_ingest_lag_seconds` e
  `fs_store_live_delay_seconds` para orientar uma eventual otimização.
