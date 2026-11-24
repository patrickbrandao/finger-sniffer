# 0065 — Tempos do traefix (relay), TTL em h3, cabeçalhos de detalhe e ALPN vazio pelo JA4

Status: aceita (pesos provisórios, com o gatilho de revisão da ADR 0049; adendo de 2026-11-19 com os números da task 313)
Data: 2026-11-19

## Contexto
**Fato novo**: o traefix publicou duas entregas em 19/11/2026 sobre a `fork-point-218` (relatório do agente do
traefix, `tmp/relatorio-traefix-para-finger-sniffer.md`; commits `84e4a8838`..`59c901c7b`, `latest` =
`fork-point-223-g59c901c7b`) e a página "Fingerprint Signals"
(`docs/content/reference/install-configuration/entrypoints-fingerprint-signals.md`):
- **`headerDetail`** (`basic` | `full`, padrão | `raw`): com `full`, ~28 cabeçalhos `X-Traefix-*` (~3,5 KB num
  navegador em h2) ao backend e ao forwardAuth — `Tls`, `Tls-Hello`, `Ja3-String`, `Ja3n`, `Ja3n-String`, `Ja4r`,
  `Ja4o`, `Ja4h-R`, `P0f`, `H2-Detail`, `H3`, `Header-Order`, `Cookie-Names`, `Transport`, `Ttl`, `Server-Ip`,
  `Server-Port`, `Time`, `Timing`; com `basic`, só as fingerprints e os dados da conexão. **No código do traefix
  (`pkg/fingerprint/entrypoint.go`), a medida dos tempos só é ligada com `headerDetail` diferente de `basic`**: com
  `basic`, nem o cabeçalho nem o objeto `timing` do registro existem;
- **tempos da conexão** (`X-Traefix-Timing` e `timing` no registro de conexão): em TCP `tcp_rtt_us` (handshake TCP,
  medido pelo kernel com o par da conexão TCP; precisa de `tcp`), `est_to_first_us` (accept → primeiro byte do
  cliente), `ch_us`, `srv_us`, `tls_rtt_us` (voo do servidor → resposta do cliente, uma volta com o **cliente TLS**),
  `tls_us`, `rtt_gap_us` = `tls_rtt_us` − `tcp_rtt_us`, `req_us`; `src=kernel` (horários do kernel, com `tcp` no
  Linux) ou `src=user`; em h3 `initial_to_hs_us`, `quic_rtt_us`, `quic_min_rtt_us`. Receita do traefix para
  **relay** (SOCKS5, HTTP CONNECT, relays TCP): cliente direto tem `rtt_gap_us` ≈ 0 e `est_to_first_us` de 0–2 ms;
  atrás de um relay, os dois ficam perto da volta cliente ↔ relay; marcar com `rtt_gap_us` > 15–20 ms e > 30% de
  `tcp_rtt_us`, confirmado por `est_to_first_us` da mesma ordem, agregando as conexões do mesmo cliente; relay perto
  do cliente e VPN de camada 3 não aparecem (a VPN aparece no MSS);
- **TTL em h3** (`udp` no registro: `ttl`, `dscp`, `ecn`; `X-Traefix-Ttl` também em h3; chaves `ttl`, `ttl_init`,
  `hops` em `X-Traefix-Transport` com `proto=udp`), em Linux, macOS e FreeBSD, sem a opção `tcp`; `X-Traefix-Ttl` em
  TCP com `tcp`; ausência = desconhecido, nunca 0; sinal sugerido: o mesmo cliente com `ttl_init` diferente em TCP e
  em h3 indica duas pilhas ou caminhos (ex.: SOCKS5 que só leva TCP);
- **contrato** escrito na página: valor ausente = desconhecido; chave ou cabeçalho novo pode aparecer; remover ou
  mudar o sentido só com `traefix.fingerprint/v2`;
- **mudança incompatível em `X-Traefix-Transport`** na `fork-point-222`: `ipid` passou a hexadecimal, `flow` virou
  `flow_label` e entrou `accepted` — contra a regra do PT-01, mas o bot não lê esse cabeçalho;
- esquema do lote com `timing` e `udp` (aditivo, `v1`); o padrão de `tcp.ja4t` ainda exige 2 dígitos na escala
  (PT-11 aberto); `Forwarded`/`X-Real-Port` seguem (PT-12 aberto); o relatório não trata PT-10, PT-13, PT-14, PT-15.

Fatos do lado de cá: o espelho existe para dizer se o tráfego é interceptado e por onde chega (spec 000, ADR 0028),
e o bot não tinha sinal de relay; h3 não tinha visão de TTL (ADR 0063 item 5); a ADR 0063 adendo item 2 esperava
`X-Traefix-Alpn` vazio para "TLS sem ALPN", mas o contrato do traefix diz que ausência é desconhecido e nunca manda
vazio. O JA4 FoxIO codifica o ALPN nos dois últimos caracteres da parte a (`00` = sem ALPN).

## Decisão
1. **Perfil com `headerDetail: full`** (spec 019 RF-03): os tempos só existem com ele. O backend recebe os ~28
   `X-Traefix-*` (dentro dos limites comuns, segundo o traefix); para os sites do humano isso entra na mesma
   decisão da troca do `traefik-app` (task 306, junto do PT-12), que pode usar `basic` e abrir mão dos tempos.
2. **Tempos no bot** (registro e cabeçalho; aditivo):
   - ingest: o objeto `timing` vai para a visão TLS/transporte da conexão do traefix (`tcpRttMicros`,
     `estToFirstMicros`, `tlsRttMicros`, `rttGapMicros`, `source`; em h3 `quicRttMicros`, `quicMinRttMicros`);
   - forwardAuth: `X-Traefix-Timing` (chaves desconhecidas ignoradas, valor fora de inteiro = ausente, cabeçalho até
     2 KiB), com a mesma prioridade das outras visões (registro do ingest, senão cabeçalho);
   - veredito: `Fingerprints` ganha `tcp_rtt_us`, `tls_rtt_us`, `rtt_gap_us`, `est_to_first_us` (opcionais) e
     `timing_source` (`kernel`|`user`).
3. **Sinal `relay_rtt_gap`** (rules `v1.4`, peso 15, tipo `incoherence`, provisório): dispara com `rtt_gap_us` > 20
   ms **e** > 30% de `tcp_rtt_us` **e** `est_to_first_us` > 10 ms, na mesma conexão, só em TCP com `tcp_rtt_us`
   conhecido; `detail` com os três valores em ms. Peso baixo porque relay não é bot (VPN corporativa, proxy do
   usuário): soma com as incoerências de UA e com comportamento. Com o store casado, `tcp_rtt_us` do traefix é o
   que vale (é o par da conexão TCP com o traefix). A agregação por cliente sugerida pelo traefix fica para uma
   regra futura (o cache de comportamento por IP + site já existe).
4. **TTL em h3 e no cabeçalho**: em h3, a visão de transporte da conexão do traefix tem o TTL inicial estimado de
   `udp.ttl` (ou `X-Traefix-Ttl` no forwardAuth), com a regra do store (spec 013); vale para a parte de TTL de
   `ua_os_tcp_mismatch` (sem JA4T nem p0f). Em TCP, `X-Traefix-Ttl` completa a visão TCP do cabeçalho (ADR 0063 item 5)
   com o TTL inicial. Mesmo descarte por origem privada. A comparação `ttl_init` TCP × h3 do mesmo IP fica para uma
   regra futura (task 314).
5. **ALPN vazio pelo JA4** (substitui o adendo item 2 da ADR 0063 e retira o PT-15): no forwardAuth, sem
   `X-Traefix-Alpn` e com `X-Traefix-Ja4` cujo ALPN da parte a é `00`, o ALPN oferecido é a lista vazia conhecida;
   com outro valor, desconhecido como antes. `X-Traefix-Alpn` presente e vazio continua lido como vazio (inofensivo).
6. **Cabeçalhos de detalhe**: `X-Traefix-Ja3n`, `X-Traefix-Ja4r`, `X-Traefix-Ja4o` entram em `Fingerprints` do
   veredito do forwardAuth quando a visão TLS vem do cabeçalho (padrões do openapi); os demais (`Tls`, `Tls-Hello`,
   `H2-Detail`, `H3`, `Header-Order`, `Cookie-Names`, `Transport`, `Server-*`, `Time`, `P0f`, `Syn`,
   `Client-Hello`) são ignorados nesta versão. O bot nunca guarda `X-Traefix-Cookie-Names` nem `Header-Order` do
   forwardAuth (a ordem já vem do ingest, ADR 0052).
7. **Esquema**: a cópia `cmd/finger-sniffer-bot/traefix-fingerprint-v1.schema.json` é atualizada para a
   `fork-point-223` e a tradução no openapi do bot ganha `timing` e `udp` (openapi 0.5.0, aditivo).
8. **Pedidos ao traefix**: PT-15 retirado (item 5); PT-16 novo: cumprir o PT-01 também nas chaves dos cabeçalhos
   (`X-Traefix-Transport` mudou de sentido na `fork-point-222` sem `v2`); PT-17 novo: tempos (`timing`) também com
   `headerDetail: basic` (ou uma opção separada), para os sites que não querem os cabeçalhos de detalhe; PT-10, PT-11,
   PT-12, PT-13 e PT-14 seguem pedidos (PT-13 e PT-14 conferidos na task 313).
9. **Conferência real** (task 313): traefix `latest` num container à parte no finger-01, como a task 273, com
   `headerDetail: full`; cliente direto e por relay (SOCKS5 por `ssh -D` até o finger-01, que dá `tcp_rtt` local e
   `tls_rtt` do Mac) para medir `rtt_gap_us`; TTL em h3; PT-13/PT-14; lotes reais novos no teste de contrato.

## Alternativas consideradas
- `headerDetail: basic` no perfil — menos cabeçalhos aos backends, mas sem tempos (o traefix só mede com `full`).
- Sinal de relay com peso alto — relay é comum entre humanos (VPN, proxy corporativo); como incoerência isolada,
  daria falso `bot`.
- Esperar o PT-15 — o JA4 já carrega a informação.
- Ler todos os cabeçalhos de detalhe já — volume e superfície de parsing sem regra que os use.

## Consequências
- openapi do bot 0.5.0; rules `v1.4` (goldens sem mudança de classe: o sinal só dispara com tempos); spec 018 (sinal,
  métricas), 019 (perfil `full`, RF-06/RF-07/RF-08, pedidos), 020 (forwardAuth).
- Tasks: 312 (bot: tempos, `relay_rtt_gap`, TTL em h3 e no cabeçalho, ALPN pelo JA4, detalhe no `fingerprints`),
  313 (conferência real com relay, depois da 312), 314 (regra futura de TTL TCP × h3 e relay agregado, baixa
  prioridade); nota na task 306 sobre `headerDetail`.

## Adendo (2026-11-19, task 313)
Fatos da conferência real (traefix `fork-point-223`, digest `sha256:5a1d2156…92d9`, `docs/dev/traefix-finger-01.md`):
- relay SOCKS5 (`ssh -D` até o finger-01) × direto, 10 conexões por caminho, medianas em ms: direto `rtt_gap`
  3,8–4,6 e `est_to_first` 0,1–0,4; relay `rtt_gap` 14,6–21,3 e `est_to_first` 13,0–17,5 (`tcp_rtt` 0,02, par
  local). Com os limiares do item 3, o sinal saiu em 14 de 50 conexões por relay e 2 de 40 diretas; com `rtt_gap` >
  15 ms e `est_to_first` > 5 ms, 35 de 50 e as mesmas 2 de 40 (picos do Wi-Fi do cliente, que só a agregação da task
  314 tira); `est_to_first` abaixo de 5 ms segurou os diretos com `tls_rtt` de até 265 ms;
- TTL em h3 ok (`udp.ttl` 56 → `ttl_initial` 64); PT-13 entregue (`dst.ip` real em h3); PT-10, PT-11, PT-12, PT-14
  seguem; `basic` ~1,1 KB e `full` ~3,2–3,4 KB de `X-Traefix-*` no backend em h1/h2;
- a requisição sem router (ex.: `/favicon.ico` do Chrome) e a h3 sem `http3HeaderOrder` chegam sem `fieldNames`,
  `fields` e `ja4h`, e o veredito da conexão (que segue a última requisição) saía `ua_missing`.

Decisão:
1. **Limiares** do item 3: `rtt_gap_us` > 15 ms e > 30% de `tcp_rtt_us` e `est_to_first_us` > 5 ms (peso 15
   mantido, provisório; amostra de um cliente só).
2. **Resumo sem cabeçalhos = desconhecido**: um registro de requisição sem `fieldNames`, `fields` e `ja4h` não é
   "sem User-Agent"; a visão HTTP da conexão vem da requisição anterior mais recente que tem os cabeçalhos e, sem
   nenhuma, a visão HTTP fica ausente (`view.http=false`, sem `ua_missing`).
3. **PT-18** novo: exportar `fieldNames`/`fields`/`ja4h` também nas requisições sem router.
