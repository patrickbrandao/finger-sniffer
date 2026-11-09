# 014 — Site estático (htdocs)

Status: aprovada
Depende de: 004, 005

## Contexto
Página informativa em inglês, servida nas portas capturadas a partir de `/finger-sniffer/htdocs`. Ela **não**
mostra o resultado da própria conexão no HTML: o JavaScript busca os dados na porta 9000 (não capturada) e exibe
ao vivo o feed global, sem que o fluxo de informação gere novo tráfego capturado em loop.

## Requisitos
- RF-01: o web serve somente arquivos de `FS_HTDOCS` (`.html`, `.css`, `.js`, `.mjs`, `.json`, `.svg`, `.png`,
  `.jpg`, `.webp`, `.ico`, `.woff2`, `.txt`), MIME pela extensão, `index.html` para diretórios; nada dinâmico.
- RF-02: HTML semântico + JS puro (ES modules), sem build, **sem CDN nem recursos de terceiros**, sem cookies,
  sem analytics.
- RF-03: o JS abre `wss://vps602.tmsoft.com.br:9000/api/v1/ws` (fallback SSE em `/api/v1/stream`) e mostra o
  **feed global**: conexões, requisições, consultas DNS e pacotes avulsos, com filtros locais (porta, protocolo,
  IP, probe) e pausa.
- RF-04: clique numa conexão abre o detalhe (`GET /api/v1/connections/{conn_id}`) e link para baixar o pcap.
- RF-05: botão "run probe": gera probe ID aleatório e dispara sondagens a `<id>.dns-monitor.tmsoft.com.br`
  (fetch h1/h2/h3, WebSocket) para o visitante ver as próprias conexões chegando no feed.
- RF-06: textos em inglês; contraste e navegação por teclado (WCAG AA no razoável).
- RF-07: a página explica: o que é o espelho, portas capturadas, como usar a API, retenção de 10 min e o aviso de
  que **todo o tráfego é público** na API.

## Comportamento
- A API fica em `https://vps602.tmsoft.com.br:9000` (constante no JS; com `?api=<origem>` na URL da página para
  testes, aceita só `https://` ou `http://` com porta 9000/9001). WebSocket primeiro; se falhar em 3 s, SSE; se
  cair, reconecta com espera crescente (1, 2, 4… até 30 s) e mostra o estado (live, reconnecting, paused).
- O feed guarda no máximo 500 linhas (as mais antigas saem); pausa congela a lista sem fechar o WS (eventos que
  chegam na pausa contam num aviso "N new"); `stream.dropped` aparece como linha de aviso.
- Filtros locais (porta, protocolo, IP, probe) só escondem linhas; o filtro de probe do "run probe" pode também
  reabrir o WS com `?probe=`.
- "run probe": probe ID de 12 caracteres `[a-z0-9]` por `crypto.getRandomValues`; dispara, em sequência,
  `fetch` com `mode: "no-cors"` e `cache: "no-store"` para `https://<id>.dns-monitor.tmsoft.com.br/p/<id>/`
  (duas vezes, para o Alt-Svc levar a segunda a h3), `http://<id>.dns-monitor.tmsoft.com.br/p/<id>/` só quando a
  própria página veio por `http:` (o navegador bloqueia conteúdo misto) e um
  WebSocket `wss://<id>.dns-monitor.tmsoft.com.br/p/<id>/r?upgrade=ws` com uma mensagem; o resultado aparece pelo
  feed filtrado e pelo `GET /api/v1/probes/<id>?wait=10s`.
- Arquivos: `index.html`, `app.mjs` (ES module), `style.css`, `favicon.svg`; nenhum outro host além da API e de
  `*.dns-monitor.tmsoft.com.br`. Os textos dinâmicos entram com `textContent`, nunca `innerHTML` (os dados da API
  vêm de terceiros).
- Sem armazenamento no navegador além de `localStorage` para as preferências de filtro (tolerante a falha).

## Interfaces e contratos
- Consome a API da spec 004.

## Critérios de aceite
- [ ] Abrir a página em Chrome e Firefox mostra o feed em < 1 s após cada requisição.
- [ ] A carga da página não gera nenhuma requisição a hosts de terceiros.
- [ ] A navegação na página não gera tráfego capturado além do carregamento dos arquivos e das sondagens explícitas.
- [ ] Teste estático (`htdocs/htdocs_test.go`): nenhum `http(s)://`/`ws(s)://` fora da API e da zona dos probes,
      nenhum `innerHTML`, todos os arquivos com extensão de RF-01.

## Fora de escopo
- Comparação entre caminhos, contas, i18n.

## Decisões relacionadas
- specs/decisions/0007-api-aberta-e-feed-global.md
- specs/decisions/0001-decisoes-iniciais.md
- specs/decisions/0020-tempo-real-sem-replay.md
