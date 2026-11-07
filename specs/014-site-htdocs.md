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

## Interfaces e contratos
- Consome a API da spec 004.

## Critérios de aceite
- [ ] Abrir a página em Chrome e Firefox mostra o feed em < 1 s após cada requisição.
- [ ] A carga da página não gera nenhuma requisição a hosts de terceiros.
- [ ] A navegação na página não gera tráfego capturado além do carregamento dos arquivos e das sondagens explícitas.

## Fora de escopo
- Comparação entre caminhos, contas, i18n.

## Decisões relacionadas
- specs/decisions/0007-api-aberta-e-feed-global.md
- specs/decisions/0001-decisoes-iniciais.md
