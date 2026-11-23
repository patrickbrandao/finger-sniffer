# 0072 — Regras v1.5: robô declarado sem operador, pilha de biblioteca com UA de navegador e JA4 stable

Status: aceita (pesos provisórios como os da 0049; revisar com as medidas novas da base própria)
Data: 2026-11-23

## Contexto
Fatos da revisão completa de 2026-11-21 (commit `b30a5b1`, tasks 333, 334 e 335), provados com o motor real e a base
própria (`tmp/revisao-2026-11-21/provas/bot-engine/_proof/proof_rules_test.go`, ja4db desligada, ADR 0056 item 1):

- **Robô declarado sem operador sai `human`** (333). `ParseUA` testa os robôs antes das famílias; um robô sem
  operador na tabela (Yandex, Baidu, Ahrefs, Semrush, MJ12, DotBot, PetalBot, Bytespider, ClaudeBot, CCBot,
  facebookexternalhit, Twitterbot, LinkedInBot, Slackbot e todo `crawler:other`) não dispara `ua_claims_crawler`
  (exige operador), nem `library_client` (ADR 0057 item 1: "nunca com UA de robô", supondo que `ua_claims_crawler` e a
  verificação o cobririam), nem `ua_automation`. Go com o UA do YandexBot sai `human` 20; e basta a uma biblioteca pôr
  `bot/1.0`, `(+crawler)` ou `spider` no UA para cair de `bot` 70 para `human` 20 (`curl/8.23.0 mybot/1.0`).
- **Biblioteca com UA de Safari ou de iOS sai `human`** (334). `ua_tls_mismatch` e o ramo Akamai de `ua_h2_mismatch`
  só avaliam quando a pilha declarada (`ua.Stack`) tem medida na base; a base não tem Safari, e todo navegador no iOS
  tem `Stack = safari`. curl h2 com UA de Safari/macOS e Go h2 com UA `CriOS` saem `human` 20; o mesmo Go com UA de
  Chrome sai `bot` 95.
- **Navegador real com JA4 diferente da única medida sai `suspect`, e `bot` com VPN** (335). A base tem um JA4 por
  navegador e protocolo (Chrome 157 e Firefox 159, macOS). O JA4 completo conta e hasheia `pre_shared_key` (0x0029),
  `padding` (0x0015) e `session_ticket` (0x0023): a retomada TLS 1.3 muda o JA4 da mesma pilha. O espelho já calcula
  o **JA4 stable** (spec 008 RF-03, `pkg/fingerprint/ja4`) sem essas extensões, mas o bot não o usa. Além da retomada,
  versão e plataforma mudam as extensões (o Chrome no Windows do golden FoxIO,
  `t13d1516h2_8daaf6152771_e5627efa2ab1`, tem a mesma lista de cifras do Chrome medido no macOS, parte b
  `8daaf6152771`, e outra lista de extensões): Chrome/Windows real sai `suspect` 45, e com `ip_cloud` e `tunnel_mss`
  sai `bot` 70.

As três mudam a mesma `rules_version` e se cruzam (334 usa o mesmo JA4 que 335 decidir); por isso uma ADR e uma
versão só.

## Decisão
`rules_version` passa a **`v1.5`**; os goldens das regras são regravados (ADR 0049 item 6). Os pesos que não aparecem
aqui não mudam.

### 1. Identidade TLS pelo JA4 stable (task 335)
1. **De onde vem o stable**, por visão (quem monta a entrada preenche o campo novo `rules.TLS.JA4Stable`):
   - registro de conexão do traefix com ClientHello cru: `ja4.Compute(...).Stable`, guardado num campo novo
     `ForkTLS.JA4Stable` (`index.go`; preenchido em `analyzeClientHelloAs`, `ingest.go`, e contado no custo do fork);
   - fingerprints prontas do traefix (sem `tls.clientHello`, ADR 0063 item 4): derivado do `ja4r` pronto;
   - cabeçalhos do forwardAuth: derivado de `X-Traefix-Ja4r` quando vier (com `headerDetail` `full` ou `raw`);
   - registro do store: `tls.ja4_stable` (ou `http3.client_hello.ja4_stable`) do `Record`, lido em `recordTLS`
     (`judge.go`); sem ele, derivado do `ja4_r`;
   - base própria: derivado do `ja4_r` de cada medida ao carregar. **O formato de `known_clients.json` não muda**
     (`version` 1): o `ja4_r` já é obrigatório na prática e passa a ser validado (item 1.3).
   Nas regras, `JA4Stable` vazio com `JA4R` presente é derivado ali mesmo; sem os dois, não há stable.
2. **Derivação** (`pkg/fingerprint/ja4`, função nova `FromRaw(raw string) (ja4, stable string, ok bool)`, escrita pelo
   implementer-bot por delegação desta ADR, ADR 0023): lê o JA4_r `a_cifras_extensões[_assinaturas]` (cifras e
   extensões já ordenadas, sem GREASE, extensões sem SNI e ALPN), recalcula o JA4 (`a` + `hash12(cifras)` +
   `hash12(extensões[_assinaturas])`) e o stable (tira 0015, 0023 e 0029 da lista, desconta da contagem de extensões
   da parte a quantas tirou e recalcula o hash da parte c), com as mesmas regras de `assemble` e `hash12` de `Compute`.
   `ok=false` quando o texto não tem o formato, quando a contagem de extensões é 99 (teto: a contagem real não se
   recupera) ou quando a contagem fica negativa. Teste obrigatório: para todo ClientHello dos pcaps de
   `pkg/fingerprint/internal/pcaptest/testdata/tls` e dos Initials QUIC golden, `FromRaw(f.JA4R) == (f.JA4, f.Stable,
   true)`.
3. **Validação da base**: `lists.ParseKnownClients` recusa a medida cujo `ja4_r` não reproduz o `ja4` por
   `ja4.FromRaw` (erro na carga, como os demais campos inválidos). Assim o stable da base é sempre o do mesmo
   ClientHello.
4. **Tipos de impressão novos** em `rules.FPKind`: `KindJA4Stable` (`ja4_stable`) e `KindJA4Ciphers` (parte b do JA4,
   **só de JA4 TCP**, prefixo `t`). `knownSource` indexa os dois a partir de cada medida; `Measured(family,
   KindJA4Stable)` vale quando a família tem ao menos um stable derivado. A interface `Coherent` recebe o tipo:
   `Coherent(kind FPKind, ja4, akamai, ja4t string) []string`, com `kind` `KindJA4Stable` ou `KindJA4`
   (`lists.Observed` ganha `JA4Stable` e `lists.KnownClients` um índice por stable).
5. **`known_client`** (−20, sem outra mudança): coerência pelo **stable** (+ Akamai + JA4T sem o MSS, como na v1.2)
   quando a entrada tem stable; sem stable (só `X-Traefix-Ja4`, com `headerDetail` `basic`), pelo JA4 completo como na
   v1.4. Sem stable, a retomada perde o desconto, mas não ganha incoerência (item 1.6).
6. **`ua_tls_mismatch`** (continua **45**), avaliado para UA de navegador ou headless, nesta ordem, um sinal só:
   1. **pilha só de biblioteca** (item 3 abaixo);
   2. **fora do conjunto da família**: a pilha (`ua.Stack`) tem medida (`Measured(stack, KindJA4Stable)`), o stable
      visto não está no conjunto dela **e**, em JA4 TCP (`t`), a parte b do JA4 visto (cifras) também não está nas
      partes b medidas dela; e o rótulo da ja4db (quando ligada) não é de navegador da família. Em QUIC (`q`) a parte
      b não conta (as cifras do TLS 1.3 no QUIC são as mesmas em todas as pilhas medidas, `55b375c5d22e`): vale só o
      stable. Sem stable (só `X-Traefix-Ja4`), vale só a parte b em TCP; em QUIC sem stable, não avalia;
   3. **rótulo da ja4db** sem medida da pilha: como na v1.4 (JA4 completo, que é a chave da ja4db).
   `detail`: `ua <família>, ja4 stable <stable> not in <pilha> set` (ou `ja4 <ja4> ciphers not in <pilha> set` sem
   stable). A exigência da parte b em TCP é o que separa "outra versão ou plataforma do mesmo navegador" (mesma lista
   de cifras, extensões diferentes) de "outra pilha": com uma medida por família, 45 sozinho (`suspect`) continua
   valendo só para a outra pilha.
7. **`library_client` caminho (b)**: as famílias do **stable** (`Families(KindJA4Stable, stable)`), ou do JA4
   completo sem stable, todas de biblioteca.
8. **ja4db** (`ja4db_match` e o rótulo do item 1.6.3) continua pelo JA4 completo.

### 2. Robô declarado sem operador (task 333)
1. **Sinal novo `ua_declares_crawler`**: tipo `list`, peso **50**, `detail` = `ua declares crawler <nome>` (nome da
   tabela de robôs ou `other`; nunca o texto do UA). Dispara quando o UA declara um robô (`ua.Crawler != ""`) **sem
   operador** (`ua.Operator == ""`); o robô com operador continua só com `ua_claims_crawler` (60) e a verificação.
   Nunca é `good_bot` (não há lista a conferir). Como o `library_client` (ADR 0057 item 1): sozinho é `suspect`; com
   `ja4h_library`, `library_client` ou `ip_cloud`, `bot`.
2. **A família de biblioteca não se apaga por um marcador de robô**: em `ParseUA`, quando o UA casa um robô **sem
   operador** (da tabela ou genérico), testa também `matchFamily`; se der família de biblioteca (`IsLibraryFamily`),
   `Family`, `Major` e `Stack` ficam os da biblioteca e `Crawler` guarda o nome do robô (`other` para os genéricos).
   O robô com operador (Googlebot, Bingbot, Applebot, GPTBot, DuckDuckBot...) continua com `Family = crawler:<nome>`,
   para a verificação. `Result.UAFamily` (e `fp_daily.ua_family`) mostra a biblioteca nesse caso; a doc de `UA.Crawler`
   passa a dizer "nome do robô declarado, também com família de biblioteca".
3. **`library_client` caminho (b) também para robô sem operador**: além de UA vazio ou `other`, vale para
   `crawler:<nome>` sem operador (ex.: Go com o UA do YandexBot): o JA4 stable que a base só viu em bibliotecas dá
   `library_client` `ja4 of measured <biblioteca>`. Com operador, não (a verificação decide).
4. Ordem estável na tabela de sinais: `ua_declares_crawler` logo depois de `library_client`.

### 3. Pilha de biblioteca com UA de navegador (task 334)
1. **`ua_tls_mismatch` por pilha só de biblioteca**, sem depender de medida da família declarada: UA de navegador ou
   headless (qualquer `Stack`, inclusive `safari`) e o stable visto (ou o JA4 completo, sem stable) está na base só em
   famílias de biblioteca (`allLibrary(Families(KindJA4Stable, stable))`, o mesmo teste do item 1.7). `detail`:
   `ua <família>, ja4 of measured <biblioteca>` (`firstLibrary`). É o primeiro caso avaliado (item 1.6.1).
2. **`ua_h2_mismatch` por Akamai só de biblioteca**: UA de navegador ou headless e o Akamai visto está na base só em
   famílias de biblioteca. `detail`: `ua <família>, akamai of measured <biblioteca>`. Avaliado antes do ramo "fora do
   conjunto da família" (que segue exigindo medida da pilha) e do ramo HTTP/1.1 sem `h2`; um sinal só.
3. A base ganha Safari (macOS, e iOS quando houver como medir) pelo tester; até lá vale só o item 3.1/3.2 para o
   Safari, e Safari real com qualquer pilha que não seja de biblioteca fica sem incoerência TLS (limite conhecido).

### 4. Pesos v1.5 (o que muda na tabela da spec 018)
| Sinal | Tipo | Peso | Mudança |
| --- | --- | --- | --- |
| `ua_tls_mismatch` | incoerência | 45 | stable; parte b em TCP; pilha só de biblioteca (itens 1.6 e 3.1) |
| `ua_h2_mismatch` | incoerência | 30 | Akamai só de biblioteca (item 3.2) |
| `library_client` | lista | 50 | caminho (b) pelo stable e também para robô sem operador; família de biblioteca mantida com marcador de robô (itens 1.7, 2.2 e 2.3) |
| `ua_declares_crawler` | lista | 50 | novo (item 2.1) |
| `known_client` | lista | −20 | coerência pelo stable (item 1.5) |

### 5. Goldens (ADR 0049 item 6)
Todos os goldens existentes são regravados com `v1.5` e **mantêm classe, score e ids de sinais** (os stables da base
são os de handshakes novos; nenhum caso atual muda de classe); só o `detail` pode mudar (ex.: `chrome_ua_curl_tls`
passa a `ua chrome, ja4 of measured curl`). Se algum golden atual mudar de classe ou de sinais, o implementer-bot para
e volta ao architect. Goldens novos (ja4db desligada, IP residencial salvo indicação):

| Golden | Entrada | Classe esperada | Sinais |
| --- | --- | --- | --- |
| `yandexbot_unverifiable` | Go h2 + UA do YandexBot | `bot` 100 | `ja4h_library`, `library_client` (b), `ua_declares_crawler` |
| `curl_ua_bot_token` | curl h2 + `curl/8.23.0 mybot/1.0` | `bot` 100 | `ja4h_library`, `library_client`, `ua_declares_crawler` |
| `python_ua_crawler_token` | python h1 + `python-requests/2.32.3 (+crawler)` | `bot` 100 | `ja4h_library`, `library_client`, `ua_declares_crawler` |
| `crawler_other_chrome_stack` | Chrome h2 (com `Accept-Language`) + UA `Mozilla/5.0 (compatible; ExampleBot/1.0; +https://example.com/bot)` | `suspect` 50 | `ua_declares_crawler` |
| `curl_ua_safari` | curl h2 + UA de Safari/macOS | `bot` 95 | `ua_tls_mismatch`, `ua_h2_mismatch`, `ja4h_library` |
| `go_ua_crios` | Go h2 + UA `CriOS` (iPhone) | `bot` 95 | `ua_tls_mismatch`, `ua_h2_mismatch`, `ja4h_library` |
| `go_ua_iphone_accept_language` | Go h2 + UA de Safari/iPhone, `HasAcceptLanguage`, IP de nuvem | `bot` 95 | `ua_tls_mismatch`, `ua_h2_mismatch`, `ip_cloud` |
| `chrome_resumed` | Chrome h2 com 0029 acrescida ao `ja4_r` (JA4 `t13d1518h2_…` recalculado por `ja4.FromRaw`) | `human` 0 | `known_client` |
| `chrome_resumed_header_only` | a mesma, só com o JA4 (sem `JA4R`) | `human` 0 | nenhum |
| `chrome_windows_foxio` | UA Chrome/Windows, JA4 `t13d1516h2_8daaf6152771_e5627efa2ab1` sem `JA4R` (o golden FoxIO não traz o `ja4_r`: avalia pela parte b), Akamai do Chrome, TTL 128 | `human` 0 | nenhum |
| `chrome_windows_foxio_vpn` | a mesma com IP de nuvem e MSS 1360 | `human` 25 | `tunnel_mss`, `ip_cloud` |
| `curl_ua_chrome_header_only` | curl h2 só com o JA4 (sem `JA4R`) + UA Chrome | `bot` 95 | `ua_tls_mismatch`, `ua_h2_mismatch`, `ja4h_library` |
| `go_h3_ua_chrome` | Go h3 + UA Chrome (QUIC: sem a parte b) | `suspect` 65 | `ua_tls_mismatch`, `ja4h_library` |
| `firefox_ua_chrome_stack` | Chrome h2 + UA Firefox (limite do item 1.6.2: mesmas cifras) | `human` 30 | `ua_h2_mismatch` |

`rules_test.go`: o caso do YandexBot confere a classe; `ua_test.go`: `curl/8.23.0 mybot/1.0` dá `Family=curl`,
`Crawler=other`; `python-requests/2.32.3 ClaudeBot/1.0` dá `Family=python`, `Crawler=claudebot`; Googlebot com
`python-requests` continua `crawler:googlebot`.

### 6. Pendências do tester (não bloqueiam a v1.5)
Medir na base própria, com navegador real: Safari no macOS (e iOS, se houver como); a segunda conexão (retomada) de
Chrome e Firefox contra o espelho, conferindo stable igual e veredito igual (`tls.negotiated.resumed=true`); Chrome e
Edge no Windows e no Android. Com as medidas, o tester revê os goldens `chrome_windows_foxio*` e
`firefox_ua_chrome_stack`.

## Alternativas consideradas
- **`ua_claims_crawler` (60) também para robô sem operador** (sugestão da ADR 0049 item 4): o sinal significa "diz ser
  um robô verificável e a prova falhou"; para robô sem lista não há prova, e o mesmo id misturaria os dois casos nos
  agregados e no webhook. Um id novo com o peso do `library_client` deixa o robô honesto sem `Accept-Language`
  (quase todos) em `bot` e o que imita navegador em `suspect`.
- **`ua_declares_crawler` com 70 (bot sozinho, como `ua_automation`)**: bloquearia no modo `block` as prévias de link
  (Slackbot, Twitterbot, facebookexternalhit) que mandam `Accept-Language`; o site decide com `suspect`.
- **Baixar `ua_tls_mismatch` para 30 ou 40** para o navegador de outra versão: deixaria `human` a biblioteca com UA de
  navegador que hoje é `suspect`/`bot`, e o Chrome/Windows real continuaria `suspect` com 40. A parte b em TCP separa
  versão de pilha sem tirar peso da detecção.
- **Aceitar JA4 com contagem ±1 e parte b igual** quando só há `X-Traefix-Ja4`: o hash da parte c muda inteiro, e a
  regra seria só a parte b com um ruído; o item 1.6.2 já usa a parte b, sem a falsa precisão.
- **Campo `ja4_stable` novo em `known_clients.json`**: duplicaria o que o `ja4_r` já determina e poderia divergir; a
  derivação com a validação do item 1.3 garante o mesmo ClientHello.
- **Derivação dentro de `internal/bot/rules`**: o teste contra `ja4.Compute` precisa dos pcaps de
  `pkg/fingerprint/internal`, inacessíveis de fora; a função fica ao lado de `Compute`.

## Consequências
- Robôs de SEO e de IA sem operador saem `bot` (ou `suspect` quando imitam o navegador por inteiro); biblioteca que
  põe "bot" no UA continua `bot`; biblioteca com UA de Safari/iOS sai `bot` pela própria base.
- Retomada TLS e outra versão/plataforma do Chrome ou do Firefox deixam de dar `ua_tls_mismatch`; a retomada mantém o
  `known_client` quando há stable.
- **Limite conhecido**: em TCP, UA de um navegador com a pilha de outro navegador de mesma lista de cifras (Chrome ↔
  Firefox medidos têm a mesma parte b) não dá `ua_tls_mismatch`; só o Akamai (`ua_h2_mismatch`, em h2) o acusa. É o
  mesmo tipo de limite da ADR 0057 item 1 (navegador conduzido com a pilha real).
- `pkg/fingerprint/ja4` ganha `FromRaw` (delegado ao implementer-bot pela task 335); o openapi do bot não muda (os ids
  de sinal não são enum, e `Fingerprints` não ganha campo).
- Altera a ADR 0057 item 1 (`library_client` "nunca com UA de robô" vale agora só para robô com operador) e completa
  a ADR 0049 item 4 (robô sem lista tem sinal próprio).
