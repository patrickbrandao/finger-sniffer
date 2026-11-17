# 0060 — `ja4h_library` sem os campos de contexto e veredito do probe fora do feed

Status: aceita (pesos e regras seguem provisórios, ADRs 0049 e 0057)
Data: 2026-11-17

## Contexto
Fatos do e2e da F8 (task 284, PR #265, contra o bot da `main` no finger-01):
- **Probe com `Origin`**: o veredito por probe só sai quando o host de `Origin`/`Referer` da requisição está nos
  domínios da chave (ADR 0051 item 3), então todo cliente do caso (a) da spec 020 manda um desses campos. O `Origin`
  entra na contagem e no hash da parte b do JA4H; `ja4h_library` casa o `ja4h_ab` exato da base própria, medida sem
  `Origin`. Exemplo do curl: `ge20nn030000_ba3fe9136eb1` pelo probe contra `ge20nn020000_5594a17e7e7e` na base.
  Resultado: curl, Go e python-requests saem `suspect` 55 e o Googlebot falso `suspect` 65 pelo probe, onde a ADR
  0057 item 1 espera `bot` 70 e 80. Pelo traefix simulado (sem `Origin`) saem `bot`. O `Referer` não entra na
  contagem nem no hash, só muda o sinalizador `r`/`n` da parte a.
- **Feed e probe**: o bot publica no feed SSE e no webhook só os vereditos por requisição (forwardAuth e ingest). O
  do probe é calculado na consulta e nunca é publicado. A spec 018 não pedia; a task 284 pedia.

## Decisão
1. **`ja4h_library` ignora os campos de contexto** (rules `v1.3`): a regra compara com a base própria o `ja4h_ab`
   recalculado **sem `Origin` e sem `Referer`**, a partir de `FieldOrder` do resumo da requisição:
   - parte a: método, versão e sinalizador de cookie do JA4H medido; sinalizador de referer `n`; contagem dos campos
     sem `Cookie`, `Referer`, `Origin` e pseudo-cabeçalhos; idioma `0000` (a regra só vale sem `Accept-Language`);
   - parte b: o hash12 do JA4H (mesmas regras de `pkg/fingerprint/ja4plus`, inclusive nomes sem caixa) dos nomes de
     `FieldOrder` sem `Cookie`, `Referer`, `Origin` e pseudo-cabeçalhos.
   Vale em todos os caminhos (probe, traefix, conexão direta), sem marcar o probe na entrada: uma biblioteca que
   manda `Origin` a um site continua biblioteca. O `ja4h_ab` medido também casa (sem `FieldOrder`, só ele). O
   JA4H publicado no veredito e nos agregados é o medido, sem mudança; o formato da base própria não muda.
   `detail` do sinal diz `normalized` quando só o recalculado casou. Goldens do caminho do probe (com `Origin` e,
   nos navegadores, `Referer`) entram junto com os atuais; as classes da ADR 0057 item 1 valem pelo probe.
2. **Veredito do probe fica fora do feed e do webhook**: o probe não tem momento de "fim" (as conexões chegam e mudam
   enquanto o navegador abre o probe), então publicar exigiria um prazo arbitrário ou vários eventos por probe. O
   cliente do caso (a) já tem o `probe_id` e consulta `GET /bot/v1/probes/{id}/verdict` (com `wait`). Feed SSE,
   webhook e `bot_verdicts_total{source}` continuam só com os vereditos por requisição. A spec 018 e a 020 dizem
   isso explicitamente; o e2e confere a ausência em vez de registrar aviso.

## Alternativas consideradas
- Tabela da ADR 0057 valer só para o traefix — tiraria o caso (a) da spec 020, que é a única visão IP/TCP dos sites
  externos.
- Medir na base própria também o JA4H com `Origin` — depende da posição em que cada cliente insere o campo e da
  forma de cada teste; o recálculo funciona para qualquer posição.
- Marcar a entrada como probe e normalizar só lá — mais um campo na entrada sem ganho: o `Origin` não distingue
  biblioteca de navegador (navegadores mandam `Accept-Language` e não chegam à regra).
- Publicar o veredito do probe uma vez, num prazo depois da primeira conexão — o prazo é arbitrário e o veredito
  publicado podia divergir do consultado depois.

## Consequências
- rules `v1.3`, goldens regravados; `ja4h_library` dispara pelo probe (curl/Go/python-requests `bot` 70, Googlebot
  falso `bot` 80, além de `tunnel_mss` e comportamento que o caminho acrescentar).
- Sem mudança de contrato (openapi do bot, asyncapi, migrations) nem da base própria.
- Tarefa 295 (implementer-bot, com o e2e da F8 e `docs/bot.md` delegados).
