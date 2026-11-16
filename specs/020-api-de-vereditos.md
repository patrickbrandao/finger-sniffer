# 020 — API de vereditos, chaves, feed e webhook

Status: aprovada
Depende de: 018, 019

## Contexto
O serviço bot (spec 018) oferece os vereditos por HTTP em portas próprias, fora da captura (ADRs 0047 e 0051):
9002 HTTPS pública com chave e 9003 HTTP interna para o traefik do finger-01. Contrato:
[cmd/finger-sniffer-bot/openapi.yaml](../cmd/finger-sniffer-bot/openapi.yaml) (OpenAPI 3.1, versão 0.1.0).

## Requisitos
- RF-01: 9002 em `FS_LISTEN_IPV4`/`FS_LISTEN_IPV6` com TLS de `FS_CERT_DIR` (`pkg/certs`, A e B por SNI, recarga a
  quente); 9003 em `127.0.0.1` e `FS_BOT_INTERNAL_LISTEN`, HTTP, aceitando só origens de loopback e da rede de
  `FS_BOT_INTERNAL_ALLOW` (padrão a sub-rede de `FS_BOT_INTERNAL_LISTEN`, no finger-01 `10.249.0.0/16`); outra
  origem → 403. Nunca em `*`.
- RF-02: autenticação `Authorization: Bearer fsk_<52 caracteres base32>`; chave desconhecida ou revogada → 401
  (`error: invalid_key`); na 9002 toda rota exige chave exceto `health` e `openapi.yaml`; na 9003 a chave é opcional
  (sem chave, o `site` vale para qualquer domínio e os limites são os globais) e um `Authorization` que não seja
  `Bearer fsk_...` é ignorado, porque o forwardAuth repassa os cabeçalhos do visitante (ADR 0055 item 5).
- RF-03: domínios da chave (ADR 0051 item 3): o `site` do recurso pedido tem de casar com um domínio da chave; senão
  404 `not_found`, igual a recurso inexistente.
- RF-04: limites (ADR 0051 item 4): balde por chave e cota diária → 429 `rate_limited` com `Retry-After` em
  segundos; global: 200 conexões na 9002, 64 clientes SSE, corpo do ingest até 4 MiB por lote → 413.
- RF-05: rotas (detalhe no openapi):
  - `GET /bot/v1/auth` (forwardAuth): sujeito = requisição descrita por `X-Forwarded-Method`, `X-Forwarded-Host`,
    `X-Forwarded-Uri` e `X-Fs-*` (spec 019 RF-06); espera a visão até `FS_BOT_VIEW_WAIT`; 200 com `X-Fs-Verdict`,
    `X-Fs-Score`, `X-Fs-Signals` (ids separados por vírgula, até 1 KiB) e corpo `Verdict`; 403 com o mesmo corpo
    quando a chave/site está em modo `block` e `class=bot`. Sem os `X-Fs-*` do traefix → 400 `missing_fork_headers`;
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
    1024 por cliente com descarte e evento `stream.dropped`; ping a cada 15 s.
  - `POST /bot/v1/ingest/traefik`: corpo `TraefikIngestBatch`; 202 com `accepted`/`rejected`; registro inválido
    conta e é ignorado sem rejeitar o lote.
  - `GET /bot/v1/health`, `GET /bot/v1/openapi.yaml`.
- RF-06: webhook (ADR 0051 item 5): corpo `VerdictEvent`, cabeçalhos `X-Fs-Signature`, `X-Fs-Timestamp`,
  `X-Fs-Key-Prefix`; prazo de 5 s; novas tentativas 1 s, 5 s, 30 s; fila de 1000 por chave.
- RF-07: erros JSON `{"error": "<código>", "detail": "..."}` com os códigos `invalid_key`, `rate_limited`,
  `not_found`, `bad_request`, `missing_fork_headers`, `payload_too_large`, `forbidden_origin`, `internal`.
- RF-08: CORS: `Access-Control-Allow-Origin` só para os domínios da chave nas rotas `GET` (consulta pelo navegador
  não é o uso previsto; a chave fica no backend do site).

## Critérios de aceite
- [ ] Teste de contrato: respostas de cada rota validadas contra o openapi do bot (`redocly lint` limpo).
- [ ] 401/404/429 conforme RF-02–RF-04, inclusive domínio fora da chave indistinguível de recurso inexistente.
- [ ] forwardAuth com o traefix (spec 019) dá 200 com os `X-Fs-*` e, em `block`, 403 para um cliente `bot`.
- [ ] Webhook assinado verificável pelo exemplo do `docs/`; nova tentativa em 5xx; fila cheia conta descarte.

## Fora de escopo
- Cadastro, painel de chaves na web, cobrança.

## Clientes externos
Os dois casos valem (resposta do humano à antiga pendência P3, ADR 0054 item 7): (a) veredito por probe, com o site
externo fazendo o navegador do visitante abrir uma conexão a `<id>.finger-west-01.badblock.net.br:8443`; e (b) o
site externo rodando a imagem pública do traefix (`tmsoftbrasil/traefix`) com `ingestURL` na 9002 e a própria chave
(visão de aplicação sem a visão IP/TCP, que só existe para o tráfego que chega ao finger-01).

## Decisões relacionadas
- specs/decisions/0051-api-de-vereditos-e-chaves.md
- specs/decisions/0047-fase-de-bots-servico-bot.md
- specs/decisions/0052-dados-pessoais-e-retencao-de-7-dias.md
- specs/decisions/0054-traefix-projeto-externo.md
- specs/decisions/0055-ajustes-da-primeira-onda-da-f8.md
