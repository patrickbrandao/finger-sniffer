# 0050 — Listas de referência: base própria, ja4db da FoxIO e listas de IP de bots

Status: aceita (provisória quanto à ja4db — revisar se a pendência P4 da spec 018 mudar o uso; ja4db desligada por padrão até a P4, ver 0056; robôs sem DNS reverso no item 4: ver 0057)
Data: 2026-11-16

## Contexto
Decisão do humano (entrevista, seção 3): os sinais de lista usam a **base própria medida no espelho e versionada**,
a **ja4db da FoxIO** e as **listas de IP de bots** publicadas por buscadores e nuvens. Nenhuma delas exige
dependência nova: são arquivos JSON/CSV/texto lidos com a stdlib.

## Decisão
1. **Base própria** (`internal/bot/lists/known_clients.json`, versionada no repositório, formato na spec 018):
   para cada cliente medido (nome, versão, SO), as impressões vistas no espelho — `ja4`, `ja4_r`, `akamai`,
   `ja4h` (sem a parte de cookies), `ja4t`, p0f, TTL inicial e ALPN — com a data e o commit da medida. É gerada pelo
   e2e (`FS_E2E_UPDATE=1`, tester) a partir das mesmas execuções da conferência FoxIO/tshark (task 067) e de clientes
   novos que a F8 acrescentar (python-requests, Go `net/http`, navegador headless). Versão da base = hash do
   arquivo; vai em `lists_version`.
2. **ja4db da FoxIO**: baixada pelo bot de `FS_BOT_JA4DB_URL` (padrão `https://ja4db.com/api/read/`) uma vez por dia,
   gravada em `/finger-sniffer/var/bot/lists/ja4db.json` com SHA-256 e data; falha mantém a cópia anterior e deixa o
   health do bot `degraded` (`list ja4db stale`) depois de 72 h sem atualizar. **Não** é versionada no repositório
   (redistribuição depende da licença, pendência P4); os testes usam uma amostra sintética em `testdata`.
3. **Listas de IP**: catálogo fixo no código (`internal/bot/lists`), cada uma com URL, formato e uso:
   - robôs verificáveis (`good_bot` com DNS reverso/direto): Googlebot e demais robôs do Google
     (`googlebot.json`, `special-crawlers.json`, `user-triggered-fetchers.json`), Bingbot (`bingbot.json`),
     Applebot, GPTBot/OAI-SearchBot da OpenAI, DuckDuckBot;
   - nuvens e datacenters (`ip_cloud`): AWS (`ip-ranges.json`), Google Cloud (`cloud.json`), Azure (Service Tags,
     arquivo semanal), Oracle Cloud, DigitalOcean, Cloudflare (faixas publicadas);
   - a URL de cada lista pode ser trocada por env (`FS_BOT_LIST_<NOME>_URL`), sem acrescentar lista nova sem
     mudança de código.
   Atualização diária com `If-Modified-Since`/ETag, cópia em `var/bot/lists/`, validação do formato e do tamanho
   (lista vazia ou com queda de > 50% das faixas não substitui a anterior), métrica por lista
   (`bot_list_age_seconds{list}`, `bot_list_entries{list}`) e `lists_version` = hash dos hashes.
4. **Verificação de robô**: DNS reverso do IP e direto do nome (stdlib `net.Resolver`, resolvedor do host), com
   cache de 24 h; sufixos aceitos por robô fixados no código (ex.: `googlebot.com`, `google.com`,
   `search.msn.com`, `applebot.apple.com`). GPTBot, OAI-SearchBot e DuckDuckBot não publicam sufixo: a
   verificação por DNS dá `unknown` e a prova é a lista de IP do operador (ADR 0057 item 1).
5. **Tráfego de saída**: o bot é o único serviço que baixa listas; só HTTPS, prazo de 30 s, até 64 MiB por lista,
   `User-Agent: finger-sniffer-bot/<versão>`; é tráfego iniciado pelo servidor e aparece na captura como os outros
   (spec 003 RF-02).

## Alternativas consideradas
- Versionar a ja4db no repositório — depende de a licença permitir redistribuição (P4).
- Baixar listas no deploy (Mac) e enviar por rsync — as listas envelhecem entre deploys.
- Lista de IP de "bots ruins" de terceiros pagos — fora do uso não comercial e sem decisão do humano.

## Consequências
- O bot faz requisições de saída diárias a ja4db.com e aos publicadores das listas.
- A base própria cresce com cada cliente medido e é revisada no PR que a regrava.
