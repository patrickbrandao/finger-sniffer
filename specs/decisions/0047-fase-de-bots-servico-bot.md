# 0047 — Fase de bots: serviço `bot`, fontes de dados e portas

Status: aceita (traefik modificado: projeto externo traefix, ver 0054)
Data: 2026-11-16

## Contexto
Decisão do humano (entrevista de 2026-11-15, `tmp/entrevista-finger-01.md`, seção 3; aprovação "Yes, release and
F8" de 2026-11-16): a análise do espelho passa a identificar bots e é oferecida por API aos sites que querem se
proteger, em três formas de consumo (forwardAuth do traefik, consulta pelo site, feed/webhook), a sites próprios
atrás do traefik do finger-01 e a clientes externos com chave emitida por nós. Um traefik modificado (fork em
`./traefik/`, ADR 0048) entrega os dados de aplicação que o espelho não vê.

Fatos que moldam a decisão:
- O tráfego dos sites chega à `ens192` nas portas 80/443 do traefik e já é capturado (ADR 0038 item 6): o store tem
  a visão IP/TCP dessas conexões (SYN, JA4T, p0f, TTL, MSS, `src_kind`), mas não a de aplicação: o TLS é
  terminado pelo traefik, não pelo web.
- O banco do store está num tmpfs sem durabilidade e com retenção de 10 min (ADRs 0012 e 0045); agregados de 7
  dias e chaves de API precisam sobreviver ao reinício.
- A API do store é aberta e sem autenticação (ADR 0007); a de vereditos exige chave (decisão do humano).
- O store está dimensionado para 400/100 (ADR 0046); o PLAN pede que a análise de bots não some trabalho ao
  ingest dele.

## Decisão
1. **Serviço novo `finger-sniffer-bot`** (sexto serviço, `cmd/finger-sniffer-bot`, `internal/bot`; spec 018),
   dono de: vereditos, sinais, listas de referência, agregados por IP/fingerprint de 7 dias, chaves de API e
   webhooks. Roda como os outros (systemd, fatia `finger-sniffer.slice`, heartbeat `fs.v1.svc.heartbeat`, health
   pelo store). O store continua dono das conexões; o bot não lê o banco do store.
2. **Banco próprio em disco**: SQLite (`modernc.org/sqlite`, goose) em `/finger-sniffer/var/bot/bot.db`, no NVMe,
   fora do tmpfs, WAL com `synchronous=NORMAL`; escrita em lotes (agregados acumulados em memória e gravados a cada
   `FS_BOT_FLUSH_INTERVAL`, padrão 5 s), para não depender do IO do disco no caminho do veredito (ADR 0043).
   Migrations em `database/sqlite/bot/` (implementer-bot escreve; o architect aprova). Queda do host perde no
   máximo o último intervalo de agregados; chaves e webhooks são gravados na hora.
3. **Fontes de dados do veredito**:
   - **Visão IP/TCP e de aplicação do espelho**: o store publica, depois do commit, cada estado da conexão em
     `fs.v1.store.connection` (NATS core, fora do `FS_EVENTS`; asyncapi 0.6.0): estágios `opened` (SYN analisado),
     `updated` (evento de aplicação incorporado) e `closed` (registro final), com o mesmo `Connection` da API,
     sem BLOBs, até 900 KiB (ADR 0018). Sem assinante, o custo é só a serialização; o store mede o tempo
     (`fs_store_conn_publish_seconds`) e descarta com contador se o NATS recusar. O bot mantém um índice em memória
     das conexões dos últimos `FS_BOT_CONN_TTL` (10 min) pela 5-tupla.
   - **Visão de aplicação do traefik**: o fork envia ao bot, em lote, o ClientHello cru, SNI, ALPN, prefixo do h2,
     origem/destino, id da conexão e um resumo de cada requisição (`POST /bot/v1/ingest/traefik`; ADR 0048, spec
     019). O bot calcula as fingerprints com `pkg/tlsparse`, `pkg/h2passive` e `pkg/fingerprint` (as mesmas do
     espelho) e casa com a visão IP/TCP pela origem `src_ip:src_port` e a porta de destino.
   - **Probes** (clientes externos sem traefik): a página do cliente faz o navegador do visitante abrir uma conexão
     com `<id>.finger-west-01.badblock.net.br:8443` (o probe de sempre); o veredito daquele probe sai da visão
     completa do espelho (web + store).
4. **Portas** (fora da captura, como 9000/9001; `FS_CAPTURE_EXCLUDE_PORTS` passa a `48022,48161,9000,9001,9002,
   9003`):
   - **9002 HTTPS** em `FS_LISTEN_IPV4`/`FS_LISTEN_IPV6`: API pública de vereditos com chave (ADR 0051), mesmo
     certificado da 9000 (`pkg/certs`, escolha por SNI).
   - **9003 HTTP** só em `127.0.0.1` e no IP do host na bridge do traefik (`FS_BOT_INTERNAL_LISTEN`, no finger-01
     o gateway de `br-net-public`; o infra confirma o endereço): forwardAuth e ingest do traefik local, sem chave
     (confiança pela rede de origem; qualquer outra origem → 403). Nunca em `*` (ADR 0023).
5. **Limites no finger-01** (dentro da fatia de 10 GiB da ADR 0045): `MemoryMax=1G`, `GOMEMLIMIT=768MiB`,
   `CPUQuota=200%`, `MemorySwapMax=0`, `GODEBUG=disablethp=1` (ADR 0039). Banco do bot com teto
   `FS_BOT_MAX_BYTES` (padrão 2 GiB; acima, expurgo antecipado dos agregados mais antigos).
6. **Metas do bot** (spec 018 RNF, medidas na carga da F8): forwardAuth p95 ≤ 10 ms e p99 ≤ 50 ms a 200
   requisições/s, sem contar a espera pela visão (item 7); consulta p95 ≤ 50 ms; veredito disponível ≤ 1 s depois
   da primeira requisição; o store mantém as metas da ADR 0046 com o bot assinando `fs.v1.store.connection`.
7. **Espera pela visão**: no forwardAuth e na consulta, se a visão do traefik ou a IP/TCP da conexão ainda não
   chegou, o bot espera até `FS_BOT_VIEW_WAIT` (padrão 100 ms) e responde com o que tiver (`view` diz o que
   faltou); nunca bloqueia além disso.
8. **Falha do bot não derruba os sites**: o forwardAuth do fork é *fail-open* (ADR 0048): bot fora do ar ou lento
   além do prazo → a requisição segue com `X-Fs-Verdict: unavailable`.

## Alternativas consideradas
- Veredito dentro do store — banco em tmpfs e retenção de 10 min não servem para 7 dias e chaves; somaria
  trabalho ao ingest dimensionado para 400/100 e misturaria a API aberta com a autenticada.
- Bot como consumidor próprio do `FS_EVENTS` — refaria a correlação e a análise IP/TCP do store.
- Bot lendo o SSE `/api/v1/stream` do store — o `ConnectionSummary` do feed não traz TLS/TCP, e cliente lento perde
  eventos sem retomada.
- Bot consultando `GET /api/v1/connections/{id}` a cada evento — dobra a carga da API do store e acopla a latência
  do veredito à dela.
- Fork do traefik publicando no NATS — o container do traefik não alcança o NATS de loopback, e o NATS passaria a
  aceitar conexões de fora do host.
- Rotas do bot dentro da 9000/9001 por proxy no store — mistura API aberta e autenticada no mesmo processo e
  faz a 9000 depender do bot.

## Consequências
- Seis serviços + NATS (8 units com a de rede); spec 001, 002, 003 (padrão das portas excluídas), 004
  (publicação `fs.v1.store.connection`), 016 e 017 mudam; spec 018 (bot), 019 (fork do traefik) e 020 (API de
  vereditos) são novas.
- Contratos novos: `cmd/finger-sniffer-bot/openapi.yaml` (0.1.0); asyncapi 0.6.0 com `fs.v1.store.connection`.
- O espelho continua sem Docker (ADR 0009); só o fork do traefik vira imagem (ADR 0048).
- Altera a spec 000 ("Fora de escopo": banco permanente, autorização) nos termos das ADRs 0051 e 0052.
