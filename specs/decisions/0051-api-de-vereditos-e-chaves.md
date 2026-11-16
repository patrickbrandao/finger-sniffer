# 0051 — API de vereditos: forwardAuth, consulta, probe, feed, webhook e chaves

Status: aceita (clientes externos: os dois casos, ver 0054 item 7; 400 do forwardAuth e `Authorization` na 9003: ver 0055)
Data: 2026-11-16

## Contexto
Decisão do humano (entrevista, seção 3): todas as formas de consumo — **forwardAuth do traefik** (veredito por
requisição, porta 9xxx direta), **consulta pelo site** (`GET` com IP/porta de origem) e **feed/webhook** de
vereditos; **clientes externos também**, com **chaves de API emitidas por nós** (CLI/tabela no servidor), limite por
chave e domínios autorizados, sem cadastro aberto, TLS na 9000. A porta pública do bot é a 9002 (ADR 0047 item 4):
a 9000 continua do store.

## Decisão
1. **Rotas** (contrato `cmd/finger-sniffer-bot/openapi.yaml`, prefixo `/bot/v1`; spec 020):
   - `GET /bot/v1/auth` — forwardAuth. Lê `X-Forwarded-*` e `X-Fs-*` do fork; responde 200 com `X-Fs-Verdict`,
     `X-Fs-Score`, `X-Fs-Signals` (para `authResponseHeaders`) no modo `observe` (padrão) e 403 com o mesmo corpo
     de `Verdict` para `class=bot` no modo `block` do site/chave;
   - `GET /bot/v1/verdict?src_ip=&src_port=&site=` — consulta pelo site (o backend lê os `X-Fs-*` que o fork
     acrescentou); `GET /bot/v1/verdict/conn/{fs_conn_id}` pelo id do fork;
   - `GET /bot/v1/probes/{id}/verdict` — veredito de um probe (clientes externos sem traefik);
   - `GET /bot/v1/ip/{ip}` — agregados de 7 dias do IP restritos aos domínios da chave, mais as listas em que ele
     está; `GET /bot/v1/fingerprints/{kind}/{value}` — contagens por fingerprint (sem IP);
   - `GET /bot/v1/stream` — feed SSE dos vereditos dos domínios da chave (mesmas regras do SSE do store: sem
     replay, fila limitada, `stream.dropped`);
   - `POST /bot/v1/ingest/traefik` — envio do fork (ADR 0048);
   - `GET /bot/v1/health` — sem chave; `GET /bot/v1/openapi.yaml`.
2. **Chaves**: emitidas só pelo humano/operador com a CLI `finger-sniffer-bot key create --name --domains
   [--rate --burst --daily --mode --webhook-url]` no finger-01 (`list`, `revoke`, `rotate`); formato `fsk_` + 32
   bytes aleatórios em base32 minúsculo, mostrada uma vez; o banco guarda o SHA-256, um prefixo de 8 caracteres
   para exibição, nome, domínios, limites, modo, webhook e datas. Sem cadastro, sem rota de criação na API.
   Envio: `Authorization: Bearer fsk_...`. Na 9003 (rede do traefik local) a chave é opcional; na 9002, obrigatória
   em toda rota exceto `health` e `openapi.yaml`.
3. **Domínios autorizados**: cada chave lista domínios (`example.com` ou `*.example.com`). O veredito de uma
   conexão/requisição só é devolvido se o `site` dela (SNI ou `Host` vistos pelo fork) estiver na lista; o de um
   probe, se o `Origin`/`Referer` da requisição do probe estiver na lista; senão 404 (sem revelar a existência).
4. **Limites por chave**: balde de fichas (`rate` padrão 20/s, `burst` 40) e cota diária (padrão 100 000); acima,
   429 com `Retry-After`; uso diário gravado por chave (`key_usage_daily`). Sem chave válida: 401. Limite global da
   9002: 200 conexões simultâneas e 64 clientes SSE.
5. **Webhook**: opcional por chave (URL https e segredo gerado na emissão); `POST` JSON com o `Verdict` para as
   classes escolhidas (padrão `bot` e `suspect`), assinado `X-Fs-Signature: sha256=<HMAC-SHA256(segredo,
   ts + "." + corpo)>` e `X-Fs-Timestamp`; até 3 novas tentativas (1 s, 5 s, 30 s) em 5xx/erro de rede; fila de 1000
   por chave com descarte contado (`bot_webhook_dropped_total`); 4xx não repete.
6. **TLS**: a 9002 usa os certificados da 9000 (`pkg/certs`, A e B por SNI); sem HTTP em claro para fora.

## Alternativas consideradas
- Rotas na 9000 do store — ver ADR 0047.
- Cadastro aberto com e-mail — o humano decidiu sem cadastro.
- Chave em query string — vaza em logs e `Referer`.
- Webhook sem assinatura — o receptor não distingue o nosso envio de um forjado.

## Consequências
- Altera a spec 000 ("Fora de escopo: contas, login, autorização"): passa a haver chaves de API emitidas pelo
  operador, sem contas de usuário.
- Clientes externos sem o fork só têm o veredito por probe (sem visão de aplicação dos sites deles) ou pelo
  ingest do fork rodando com a imagem pública, se a pendência P3 confirmar esse uso.
