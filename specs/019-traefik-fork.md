# 019 — Traefik modificado (fork em `./traefik/`)

Status: aprovada (pendências P1, P2 e P8 abertas para o humano; ver o fim)
Depende de: 001, 018, 020

## Contexto
Os sites atrás do traefik terminam o TLS no traefik, não no web: o espelho vê os pacotes (store) mas não o
ClientHello analisado nem o h2/HTTP. O fork do traefik (ADR 0048), mantido pelo `implementer-traefik`, copia esses
dados para o bot e marca as requisições encaminhadas para o backend consultar o veredito.

## Requisitos
- RF-01: `./traefik/` contém o upstream `traefik/traefik` numa tag v3 estável, importado por `git subtree add
  --squash`; `traefik/FORK.md` registra a tag base, os patches (um por linha, com o commit) e o procedimento de
  atualização. Módulo Go separado (`traefik/go.mod`); nenhuma dependência nova além das do upstream sem o humano
  (ADR 0048 item 2).
- RF-02: código nosso em `traefik/pkg/fingersniffer/` (comentários em pt-BR, identificadores em inglês); ganchos
  mínimos no upstream, cada um marcado com o comentário `// finger-sniffer:` para o rebase.
- RF-03: **captura por conexão** nas entradas listadas em `experimental.fingerSniffer.entryPoints`:
  - TLS: bytes do primeiro registro de handshake do cliente até o fim do ClientHello (até 16 KiB; acima, marca
    `client_hello_truncated` e envia o prefixo), SNI, ALPN oferecido e negociado, versão e cifra negociadas;
  - h2: bytes do cliente depois do prefácio até o fim do primeiro frame `HEADERS` (com `CONTINUATION`), até 16 KiB;
  - h3: Initial do cliente decifrado (ClientHello do QUIC) e os primeiros frames de controle — **segunda onda**;
  - origem e destino como o socket do traefik vê (`RemoteAddr`/`LocalAddr`; com o DNAT do host, a origem é a do
    cliente), id `fs_conn_id` (ULID) e `ts` do accept em ns UTC.
  A cópia é feita sobre os bytes lidos pelo traefik (wrapper do `net.Conn`, como o `tap` do web): nunca muda o que o
  traefik lê nem escreve, e para de copiar depois dos limites.
- RF-04: **resumo por requisição**: método, `authority`, caminho sem query (até 256 bytes), versão HTTP, nomes dos
  campos na ordem recebida, valores só de `User-Agent`, `Accept`, `Accept-Language`, `Accept-Encoding`,
  `Sec-CH-UA*`, `Sec-Fetch-*` (até 512 bytes cada), nomes dos cookies na ordem, JA4H completo calculado pelo fork
  com os valores dos cookies (o fork calcula o JA4H porque o bot não recebe valores de cookie), status, `ts` de início e
  fim, e o router/serviço do traefik.
- RF-05: **envio ao bot**: lotes JSON (`TraefikIngestBatch`, openapi do bot) por `POST` em
  `experimental.fingerSniffer.ingestURL` (no finger-01 `http://<IP da bridge>:9003/bot/v1/ingest/traefik`; fora,
  `https://finger-01.badblock.net.br:9002/...` com `apiKey`), a cada 100 ms ou 64 registros; fila de
  `queueSize` (4096) registros; cheia ou bot indisponível → descarta e conta (métrica do traefik
  `fingersniffer_ingest_dropped_total`); prazo de 2 s por envio; nunca bloqueia o caminho da requisição.
- RF-06: **cabeçalhos ao backend** nas entradas cobertas: `X-Fs-Src-Ip`, `X-Fs-Src-Port`, `X-Fs-Dst-Port`,
  `X-Fs-Conn-Id`, `X-Fs-Proto` (`h1`|`h2`|`h3`); qualquer campo `X-Fs-*` vindo do cliente é removido antes dos
  middlewares (inclusive antes do forwardAuth).
- RF-07: **forwardAuth com fail-open**: opções novas `failOpen` (bool, padrão false = comportamento do upstream) e
  `timeout` (padrão 200 ms) no middleware `forwardAuth`; com `failOpen`, erro de rede, prazo vencido ou 5xx do
  servidor de auth deixam a requisição seguir com `X-Fs-Verdict: unavailable`; 2xx/4xx seguem a regra do upstream.
  Os `X-Fs-*` da RF-06 também vão na requisição de auth.
- RF-08: sem `experimental.fingerSniffer` e sem `failOpen`, o fork se comporta como o upstream (testes do upstream
  dos pacotes tocados passam sem mudança).
- RF-09: **imagem** `tmsoftbrasil/traefik-finger-sniffer` (ADR 0048 item 7) por `traefik/Dockerfile.fs`,
  `linux/amd64`, binário estático, rótulos OCI de origem, versão e licença; `traefik version` mostra
  `<tag-upstream>-fs.<n>`.
- RF-10: testes: unidade dos wrappers (ClientHello fragmentado em vários registros e leituras, h2 com
  `CONTINUATION`, limites), do envio (fila cheia, bot fora), da remoção de `X-Fs-*`, do fail-open; integração com um
  backend e um servidor de auth de teste; benchmark do custo por conexão (meta: < 5% de CPU a mais que o upstream no
  mesmo teste).

## Interfaces e contratos
- `POST /bot/v1/ingest/traefik` e `GET /bot/v1/auth` (`cmd/finger-sniffer-bot/openapi.yaml`, spec 020).
- Configuração estática:
  ```yaml
  experimental:
    fingerSniffer:
      ingestURL: http://10.249.0.1:9003/bot/v1/ingest/traefik
      apiKey: ""            # obrigatório só fora do finger-01
      entryPoints: [websecure]
      queueSize: 4096
  ```
- Middleware (dinâmica): `forwardAuth: { address: http://10.249.0.1:9003/bot/v1/auth, failOpen: true, timeout:
  200ms, authResponseHeaders: [X-Fs-Verdict, X-Fs-Score, X-Fs-Signals] }`. O IP da bridge é confirmado pelo infra.

## Critérios de aceite
- [ ] `go build ./cmd/traefik` e os testes da RF-10 verdes no passo próprio do verify e no CI.
- [ ] Com o fork num container de teste no finger-01, `curl`, Go e Chrome por um router de teste geram no bot
      conexões com JA4/Akamai iguais aos que o web do espelho calcula para o mesmo cliente.
- [ ] Bot parado: o site de teste continua respondendo (fail-open) e o traefik conta os descartes.
- [ ] Imagem construída localmente com a versão certa; publicação só depois da P2 e dos segredos.

## Fora de escopo
- Plugins Yaegi, middlewares de bloqueio próprios (o bloqueio é a resposta 403 do forwardAuth).
- Atualizar o traefik do humano sem aval (P8).

## Pendências para o humano
- **P1 — dependências do fork**: confirmar que o `go.mod` do upstream no `traefik/` fica fora da lista da ADR 0009
  (ADR 0048 item 2).
- **P2 — imagem e credencial**: confirmar o nome `tmsoftbrasil/traefik-finger-sniffer` (e se mais alguma imagem deve
  ir ao Docker Hub) e criar no GitHub os segredos `DOCKERHUB_USERNAME` e `DOCKERHUB_TOKEN` (token de acesso do
  Docker Hub, nunca a senha num arquivo); até lá a publicação fica bloqueada.
- **P8 — troca no finger-01**: quando trocar a imagem do `traefik-app` pela do fork e em quais sites ligar o
  forwardAuth (primeiro um site de teste), nos scripts de `tmsoft-servers`.

## Decisões relacionadas
- specs/decisions/0048-fork-do-traefik.md
- specs/decisions/0047-fase-de-bots-servico-bot.md
- specs/decisions/0053-uso-nao-comercial-e-licencas.md
