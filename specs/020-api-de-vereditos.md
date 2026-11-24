# 020 — API de vereditos, chaves, feed e webhook

Status: aprovada
Depende de: 018, 019

## Contexto
O serviço bot (spec 018) oferece os vereditos por HTTP em portas próprias, fora da captura (ADRs 0047 e 0051):
9002 HTTPS pública com chave e 9003 HTTP interna para o traefik do finger-01. Contrato:
[cmd/finger-sniffer-bot/openapi.yaml](../cmd/finger-sniffer-bot/openapi.yaml) (OpenAPI 3.1, versão 0.7.0).

## Requisitos
- RF-01: 9002 em `FS_LISTEN_IPV4`/`FS_LISTEN_IPV6` com TLS de `FS_CERT_DIR` (`pkg/certs`, A e B por SNI, recarga a
  quente); 9003 em `127.0.0.1` e `FS_BOT_INTERNAL_LISTEN`, HTTP, aceitando só origens de loopback e da rede de
  `FS_BOT_INTERNAL_ALLOW` (padrão a sub-rede de `FS_BOT_INTERNAL_LISTEN`, no finger-01 `10.249.0.0/16`); outra
  origem → 403. Nunca em `*`.
- RF-02: autenticação `Authorization: Bearer fsk_<52 caracteres base32>`; chave desconhecida ou revogada → 401
  (`error: invalid_key`); na 9002 toda rota exige chave exceto `health` e `openapi.yaml`; na 9003 a chave é opcional
  (sem chave, o `site` vale para qualquer domínio) e um `Authorization` que não seja `Bearer fsk_...` é ignorado,
  porque o forwardAuth repassa os cabeçalhos do visitante (ADR 0055 item 5). Na 9003, com ou sem chave, os limites
  são só os globais: a chave escolhe domínios e modo, e balde, cota, cobrança por registro e partes por chave não se
  aplicam em nenhuma rota (o uso continua gravado em `key_usage_daily`; ADR 0073 item 4).
- RF-03: domínios da chave (ADR 0051 item 3): o `site` do recurso pedido tem de casar com um domínio da chave; senão
  404 `not_found`, igual a recurso inexistente.
- RF-04: limites (ADR 0051 item 4 e ADR 0073; constantes do código):
  - por chave, só na 9002: balde (padrão 20/s, rajada 40) e cota diária (100 000) por requisição → 429
    `rate_limited` com `Retry-After` em segundos; no ingest, também balde de registros (padrão 500/s, rajada 2 048;
    `key create --ingest-rate --ingest-burst`): o lote tira `len(records)` fichas de uma vez, sem fichas para o lote
    inteiro → 429 sem aplicar nenhum registro; até 2 lotes do ingest ao mesmo tempo → 429 `Retry-After: 1`; até 4
    clientes do feed → 429 `Retry-After: 15`; até 10% de cada teto do índice (conexões e bytes) e dos agregados, e
    todas as chaves da 9002 juntas até 50% (acima, despejo das conexões da própria chave, ou observação descartada
    nos agregados; spec 018 RF-02 e RF-08). Com o forwardAuth na 9002 cada requisição do visitante gasta uma ficha:
    a chave de um `block` é criada com `--rate`/`--burst` acima do pico e `--daily` acima do volume do dia;
  - conexões da 9002: 200 simultâneas; até 16 por origem (IPv4 ou /64 IPv6; a excedente é fechada no `accept` sem
    ocupar vaga; ADR 0073 item 1.1); `IdleTimeout` 30 s (9003: 120 s); `ReadHeaderTimeout` 5 s nas duas
    portas, que é também o prazo do handshake TLS; com 180 ou mais conexões, as ociosas mais antigas são fechadas
    até ficarem menos de 180;
  - ingest: corpo até 4 MiB por lote → 413 `payload_too_large`; até 8 lotes em leitura e aplicação no processo, dos
    quais no máximo 6 da 9002 → acima, 503 `busy` com `Retry-After: 1`, sem ler o corpo; prazo de 10 s para o corpo
    chegar → 400 `bad_request`; textos acima dos tetos da spec 018 RF-03 são cortados, não recusados;
  - feed: 64 clientes, no máximo 48 da 9002 (16 para a 9003) → 503 `internal`.
- RF-05: rotas (detalhe no openapi):
  - `GET /bot/v1/auth` (forwardAuth): sujeito = requisição descrita por `X-Forwarded-Method`, `X-Forwarded-Host`,
    `X-Forwarded-Uri` e `X-Traefix-*` (spec 019 RF-05 e RF-08; os `X-Fs-*` antigos só sem `X-Traefix-Conn-Id`,
    nunca misturados, ADR 0063 item 1), com o JA4H de `X-Traefix-Ja4h` quando bem formado e, sem ele, o da última
    requisição da conexão no ingest (ADR 0058 item 1); visão TLS e h2 do registro de conexão do ingest e, antes
    dele, de `X-Traefix-Ja4`, `-Ja3`, `-H2` e `-Alpn` bem formados (ADR 0062 item 4, ADR 0063 item 6); visão TCP do
    store, senão do registro do traefix, senão de `X-Traefix-Ja4t` e `X-Traefix-Ttl`, ignorados com origem privada (ADR 0063 item 5 e adendo,
    ADR 0065 item 4); tempos de `X-Traefix-Timing` e ALPN vazio pelo `00` do JA4 (ADR 0065 itens 2 e 5); espera a visão até
    `FS_BOT_VIEW_WAIT` só na 9003 (ADR 0063 item 7); 200 com `X-Traefix-Verdict`, `X-Traefix-Score`,
    `X-Traefix-Signals` (ids separados por vírgula, até 1 KiB), os `X-Fs-*` equivalentes (obsoletos) e corpo
    `Verdict`; 403 quando a chave está em modo `block` e `class=bot`, com corpo mínimo `{"error":"forbidden"}`, sem
    nenhum cabeçalho de veredito (`X-Traefix-Verdict`, `-Score`, `-Signals` nem os `X-Fs-*`) e só com o marcador
    `X-Traefix-Deny: 1`, que o traefix usa para devolver o 403 ao visitante (ADR 0074); nenhuma outra resposta traz
    `X-Traefix-Deny`, e nenhuma resposta de erro traz `X-Traefix-Verdict` nem `X-Fs-Verdict` (fail-open de 4xx,
    spec 019 RF-04; ADR 0058 item 3). Sem os cabeçalhos de origem do traefix → 400 `missing_fork_headers`;
    com chave cujos domínios não casam com `X-Forwarded-Host` → 400 `bad_request` (erro de configuração do
    operador, ADR 0055 item 6).
  - `GET /bot/v1/verdict?src_ip=&src_port=&site=` e `GET /bot/v1/verdict/conn/{fs_conn_id}`: o último veredito da
    conexão (com o da última requisição dela); `wait=<ms>` opcional até 1000 para esperar a visão; 404 se
    desconhecida ou expirada (10 min).
  - `GET /bot/v1/probes/{id}/verdict`: veredito do probe (conexões do probe no espelho); 404 sem conexões.
  - `GET /bot/v1/ip/{ip}`: agregados de 7 dias do IP nos domínios da chave, por dia, mais as listas em que o IP está
    e a verificação de robô.
  - `GET /bot/v1/fingerprints/{kind}/{value}` (`kind` = `ja4`|`akamai`|`ja4h`|`ja4t`): contagens dos 7 dias por
    família de UA e classe, e o rótulo na base própria e na ja4db.
  - `GET /bot/v1/stream`: SSE de `VerdictEvent` dos domínios da chave; filtros `class` e `site`; sem replay; fila de
    1024 por cliente com descarte e evento `stream.dropped`; ping a cada 15 s; tetos de clientes da RF-04. Só vereditos por requisição
    (forwardAuth e ingest); o do probe não é publicado no feed nem no webhook (ADR 0060 item 2).
  - `POST /bot/v1/ingest/traefik`: corpo `TraefixFingerprintBatch` (`schema: traefix.fingerprint/v1`, o formato do
    traefix) ou `TraefikIngestBatch` (sem `schema`); outro `schema` → 400 `bad_request` (ADR 0062 item 2); 202 com
    `accepted`/`rejected`; registro inválido conta e é ignorado sem rejeitar o lote; 429 e 503 dos limites da RF-04
    (o traefix trata como falha de envio e descarta o lote).
  - `GET /bot/v1/health`, `GET /bot/v1/openapi.yaml`.
- RF-06: webhook (ADR 0051 item 5): corpo `VerdictEvent`, cabeçalhos `X-Fs-Signature`, `X-Fs-Timestamp`,
  `X-Fs-Key-Prefix`; prazo de 5 s; novas tentativas 1 s, 5 s, 30 s; fila de 1000 por chave.
- RF-07: erros JSON `{"error": "<código>", "detail": "..."}` com os códigos `invalid_key`, `rate_limited`,
  `not_found`, `bad_request`, `missing_fork_headers`, `payload_too_large`, `forbidden_origin`, `internal`, `busy`
  (503 de capacidade do ingest, ADR 0073 item 2) e `forbidden` (403 do modo `block`, ADR 0074).
- RF-08: CORS: `Access-Control-Allow-Origin` só para os domínios da chave nas rotas `GET` (consulta pelo navegador
  não é o uso previsto; a chave fica no backend do site).

## Critérios de aceite
- [ ] Teste de contrato: respostas de cada rota validadas contra o openapi do bot (`redocly lint` limpo).
- [ ] 401/404/429 conforme RF-02–RF-04, inclusive domínio fora da chave indistinguível de recurso inexistente.
- [ ] Limites da ADR 0073: conexões ociosas de uma origem não impedem outra de responder `health`; upload lento no
      ingest não segura a vaga além de 10 s; uma chave não passa do seu balde de registros nem despeja conexões da
      9003; forwardAuth com chave na 9003 nunca dá 429.
- [ ] forwardAuth com o traefix (spec 019) dá 200 com os `X-Traefix-*` (e os `X-Fs-*` obsoletos) e, em `block`, 403 mínimo com `X-Traefix-Deny` e sem cabeçalhos de veredito (ADR 0074) para um
      cliente `bot`.
- [ ] Webhook assinado verificável pelo exemplo do `docs/`; nova tentativa em 5xx; fila cheia conta descarte.

## Fora de escopo
- Cadastro, painel de chaves na web, cobrança.

## Clientes externos
Os dois casos valem (resposta do humano à antiga pendência P3, ADR 0054 item 7): (a) veredito por probe, com o site
externo fazendo o navegador do visitante abrir uma conexão a `<id>.finger-west-01.badblock.net.br:8443`; e (b) o
site externo rodando a imagem pública do traefix (`tmsoftbrasil/traefix`) com `export.url` na 9002 (perfil da spec 019 RF-03) e a própria chave
(visão de aplicação sem a visão IP/TCP, que só existe para o tráfego que chega ao finger-01).

## Decisões relacionadas
- specs/decisions/0051-api-de-vereditos-e-chaves.md
- specs/decisions/0047-fase-de-bots-servico-bot.md
- specs/decisions/0052-dados-pessoais-e-retencao-de-7-dias.md
- specs/decisions/0054-traefix-projeto-externo.md
- specs/decisions/0055-ajustes-da-primeira-onda-da-f8.md
- specs/decisions/0056-segunda-onda-da-f8.md
- specs/decisions/0058-forwardauth-do-bot-ja4h-chave-e-ja4t-sem-mss.md
- specs/decisions/0060-ja4h-library-sem-campos-de-contexto-e-probe-fora-do-feed.md
- specs/decisions/0062-traefix-consumido-como-esta.md
- specs/decisions/0063-cabecalhos-x-traefix-e-visao-tcp-do-traefix.md
- specs/decisions/0064-limite-conhecido-da-v0-5-1-forwardauth-com-indice-no-teto.md
- specs/decisions/0065-tempos-do-traefix-relay-e-ttl-em-h3.md
- specs/decisions/0073-limites-de-entrada-da-api-de-vereditos.md
- specs/decisions/0074-resposta-minima-do-403-no-modo-block.md
