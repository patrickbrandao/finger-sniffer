# 0062 — traefix consumido como está: esquema `traefix.fingerprint/v1`, fingerprints prontas no forwardAuth e perfil de configuração

Status: aceita (prefixo `X-Fs-` do item 5 e visão TLS sem ALPN do item 4 substituídos pela 0063)
Data: 2026-11-18

## Contexto
**Fato novo**: o humano avisou em 2026-11-18 que o traefix foi publicado (projeto `patrickbrandao/traefix`,
`master` em `5c011b2f3`, imagem `tmsoftbrasil/traefix:latest` = `fork-point-213-g5c011b2f3`, `linux/amd64` e
`linux/arm64`). Junto veio o documento "Traefix para o finger-sniffer: o que mudou em relação à spec 019". O traefix
**não implementou a spec 019 como escrita**: ele oferece recursos genéricos, com nomes e formatos próprios, e o
finger-sniffer passa a ser um consumidor entre outros. Pontos principais:
- configuração por entrada (`entryPoints.<nome>.fingerprint`) com `headerPrefix` (padrão `X-Traefix-`), `export.url`,
  `export.headers` (a chave vai em `Authorization`), `rawBytes` (bytes crus do ClientHello e do prefixo h2) e
  `http3HeaderOrder`; filas e lotes com os mesmos padrões da RF-05 da versão anterior da spec 019;
- lote JSON próprio, `schema: "traefix.fingerprint/v1"`, com nomes em camelCase, registros `connection`
  (`connId`, `time`, `src`, `dst`, `proto`, `tls.*`, `http2.*`, `http3.*`) e `request` (`start`, `end`, `fields` como
  lista `{name, value}` na ordem recebida, `headersTruncated`, `status: 0` quando a conexão foi assumida);
- JA3 (MD5), JA4 (`t…` e `q…`), Akamai h2 e JA4H **calculados no traefix** (conferidos com a FoxIO em 208 casos) e
  enviados no lote e nos cabeçalhos `X-Fs-Ja3`, `X-Fs-Ja4`, `X-Fs-H2` (novos) e `X-Fs-Ja4h`, ao backend **e à auth**;
- registro de conexão enviado na primeira requisição (ou no fechamento sem requisição, inclusive handshake
  interrompido), e não no fim do handshake;
- forwardAuth genérico: `requestHeaders` (a chave), `authRequestHeaders` (lista do que vai do visitante),
  `failOpen.denyRequiresResponseHeader` e `failOpen.header` (o mesmo efeito das RF-07/RF-07a da versão anterior da spec 019), `timeout`
  explícito (o padrão segue 30 s); métricas `traefik_fingerprint_*` e `traefik_forwardauth_failopen_total`;
- h3 entregue (RF-13): ID e `Proto: h3`, JA4 `q`, ClientHello do Initial como **mensagem de handshake pura** (sem
  registros TLS), transport parameters, `SETTINGS` e JA4H em h3 só com `http3HeaderOrder: true`;
- **não entregue** (numeração da versão anterior da spec 019): base em tag estável (sai do `master`, sobre `v3.8.0-rc.3`, RF-01); tags
  `<upstream>-traefix.<n>`, rótulos OCI `version`/`revision`/`licenses` e `NOTICE` (RF-09); custo ≤ 5% (medido +14%
  em TLS + h2 e +31% em TLS + h1 num Apple M2, cliente e servidor na mesma máquina; não medido em Linux, RF-11);
  teste de contrato contra o openapi do bot (RF-12); recusa na carga de chave vazia em host público (RF-07a).

Fatos do código do bot (v0.5.0) que pesam na decisão:
- `FS_BOT_VIEW_WAIT` é 100 ms, o mesmo `flushInterval` do lote. Com o registro de conexão saindo na primeira
  requisição, o forwardAuth da primeira requisição de cada conexão quase sempre é julgado **sem a visão TLS e h2**:
  `ua_tls_mismatch` e `ua_h2_mismatch` não disparam justamente no cliente de uma requisição só.
- As regras usam da visão TLS só o JA4 e o ALPN oferecido, e da h2 só o Akamai; JA3N, JA4_r e JA4_o só aparecem na
  consulta e nos agregados.
- O bot calcula JA3/JA4/Akamai com os mesmos pacotes do web do espelho, e a base própria (`known_clients.json`) foi
  medida por eles.

A ADR 0054 item 3 só deixa mudar `/bot/v1` de forma aditiva.

**Decisão do humano** (2026-11-18, resposta à P9 aberta na primeira versão desta ADR, nas palavras dele): "Rodar
traefix:latest sempre, todas as necessidades desse projeto serão implementadas em paralelo no traefix:latest e
devemos sempre andar juntos." Isso responde à base RC e ao custo de CPU no `traefik-app` e substitui a fixação por
digest proposta antes.

## Decisão
1. **O finger-sniffer consome o traefix como está** (substitui o item 2 da ADR 0054 e, no item 3, a ideia de que o
   formato do ingest é definido aqui). A spec 019 deixa de ser a lista de requisitos do traefix e passa a ser
   **"Integração com o traefix"**: o perfil de configuração usado com o bot, o que o bot lê de cada parte da entrega
   e as divergências aceitas. O formato `traefix.fingerprint/v1` é do projeto traefix; aqui ele é descrito no
   openapi do bot como um esquema aceito pela rota de ingest, para o teste de contrato do lado de cá.
2. **Ingest com os dois esquemas na mesma rota** (aditivo em `/bot/v1`): `POST /bot/v1/ingest/traefik` escolhe o
   esquema pelo campo `schema` do lote:
   - `"traefix.fingerprint/v1"` → `TraefixFingerprintBatch` (novo);
   - ausente → `TraefikIngestBatch` (o atual, mantido para o simulador do e2e, a carga e clientes antigos; sai só
     numa `/bot/v2`);
   - qualquer outro valor → 400 `bad_request` (lote inteiro).
   Mesmos limites: 4 MiB e 1024 registros por lote, `path` até 256 bytes, valor de campo até 512, registro fora do
   contrato contado em `rejected` sem recusar o lote, conferência de `sni`/`authority` contra os domínios da chave e
   lista permitida de campos (task 298). Correspondência dos campos:
   - lote: `sender` (`traefix/<versão>`) igual; `entryPoint` do lote vale para os registros sem `entryPoint`;
     `sentAt` é aceito e ignorado;
   - `connId` = `fs_conn_id`; `time` (conexão) e `start` (requisição) = `ts`; `end` = `ended`; `src`/`dst` iguais;
     `tls.sni`, `tls.alpnOffered`, `tls.alpn`, `tls.version`, `tls.cipher`, `tls.clientHello`,
     `tls.clientHelloTruncated`, `http2.prefix`, `http2.prefixTruncated` = os campos homônimos do formato atual;
     `httpVersion`, `fieldNames`, `cookieNames`, `ja4h`, `status`, `router`, `service` iguais;
   - `fields` é lista `{name, value}`: o bot guarda, da lista permitida, o **primeiro** valor de cada nome (sem
     diferenciar caixa), como o UA do web; os nomes repetidos continuam em `fieldNames`;
   - `status: 0` (conexão assumida, ex.: WebSocket) é aceito; `headersTruncated` é aceito e só informativo;
   - `tls.quicTransportParameters` e `http3.settings` são aceitos e ignorados (não há regra de h3; evolução futura).
3. **Fingerprints no ingest: bytes crus primeiro, prontas como reserva**:
   - com `tls.clientHello`, o bot calcula como hoje; em QUIC (`proto: h3`, ou bytes que começam pela mensagem de
     handshake `0x01` e não por registro TLS `0x16`), analisa a **mensagem de handshake pura** e calcula o JA4 com
     transporte QUIC (`q…`), com os mesmos pacotes do web (`pkg/tlsparse`, `pkg/fingerprint`); acaba o
     `parse_error` do ClientHello do QUIC;
   - com `http2.prefix`, o bot analisa como hoje;
   - sem os bytes crus (`rawBytes: false`), a visão usa as prontas: `tls.ja4` → JA4, `tls.ja3` → JA3 (MD5),
     `http2.akamai` → Akamai; JA3N, JA4_r e JA4_o ficam nulos; formato malformado é tratado como ausente;
   - com as duas, vale a calculada pelo bot (a base própria foi medida com ela) e a divergência conta em
     `bot_ingest_fingerprint_mismatch_total{kind}` (`ja3`|`ja4`|`akamai`), no máximo uma linha de log por minuto.
     Divergência no e2e é falha (a base própria deixaria de valer para o traefix).
4. **forwardAuth com as fingerprints dos cabeçalhos** (aditivo; complementa a ADR 0058 item 1): o bot lê
   `X-Fs-Ja4`, `X-Fs-Ja3` e `X-Fs-H2` (um único valor, bem formado: JA4 no formato FoxIO com prefixo `t` ou `q`, JA3
   com 32 hex minúsculos, Akamai no formato do web do espelho até 512 bytes; malformado ou repetido é ignorado).
   - Origem da visão TLS/h2 do veredito do forwardAuth: o registro de conexão do ingest quando já chegou; senão os
     cabeçalhos; senão nenhuma. Métrica `bot_auth_fingerprint_total{kind,source}` (`kind` = `tls`|`h2`, `source` =
     `ingest`|`header`|`none`).
   - A visão TLS vinda só do cabeçalho **não tem ALPN oferecido**: `ua_alpn_mismatch`, e o ramo de
     `ua_h2_mismatch` que olha o ALPN, não são avaliados nela (nunca disparam por falta do dado).
   - Com `X-Fs-Ja4` (e, em `X-Fs-Proto: h2`, também `X-Fs-H2`) presentes, a espera de `FS_BOT_VIEW_WAIT` deixa de
     esperar a visão do traefix e espera só a do store (spec 018 RF-04).
   - O veredito e o agregado guardam o JA4/JA3/Akamai usado, como hoje.
5. **Perfil de configuração** (spec 019): `headerPrefix: X-Fs-` (mantém os nomes `X-Fs-*` da spec 020, do bot e
   do backend); `export.url` na 9003 do finger-01 ou na 9002 para site externo; chave em
   `export.headers.Authorization`; `rawBytes: true`; forwardAuth com `timeout: 200ms`,
   `authRequestHeaders: [User-Agent, Accept, Accept-Language, Accept-Encoding]` (nunca vazio: vazio mandaria o
   `Cookie` e o `Authorization` do visitante à auth), chave em `requestHeaders.Authorization`,
   `authResponseHeaders: [X-Fs-Verdict, X-Fs-Score, X-Fs-Signals]` e
   `failOpen: { denyRequiresResponseHeader: X-Fs-Verdict, header: { name: X-Fs-Verdict, value: unavailable } }`.
   `http3HeaderOrder` fica desligado até a medida do item 9 (sem ele, a requisição h3 não tem JA4H e o bot usa o da
   última requisição do ingest, ou nenhum).
6. **Métricas do traefix**: valem os nomes `traefik_fingerprint_export_*`, `traefik_fingerprint_capture_truncated_total`
   e `traefik_forwardauth_failopen_total` nos critérios, no e2e e nos docs, no lugar de `fingersniffer_*`.
7. **Imagem: sempre `tmsoftbrasil/traefix:latest`** (decisão do humano; substitui o item 4 da ADR 0054 quanto à
   tag): o container de teste e o `traefik-app` usam `latest`, sem fixar tag nem digest. Cada teste, e2e ou troca
   registra o digest e o `sender` que viu (diagnóstico e caminho de volta, não fixação). A atualização da `latest`
   no finger-01 é do humano (como hoje com a imagem do `traefik-app`).
8. **Andar juntos** (decisão do humano): o traefix evolui junto com o finger-sniffer.
   - Toda necessidade nova do finger-sniffer que dependa do traefix entra na spec 019, seção "Pedidos ao traefix"
     (id `PT-nn`, estado `pedido`|`entregue`), pelo architect, e é avisada ao humano, que a implementa na `latest`.
   - O bot trata cada pedido como opcional até ele aparecer no dado (campo, cabeçalho, métrica): nunca falha sem
     ele, e campo desconhecido do traefix é ignorado.
   - Mudança incompatível no lote ou nos cabeçalhos só com `schema` novo (`traefix.fingerprint/v2`, …) combinado
     antes: o bot passa a aceitar o novo esquema antes de o traefix publicá-lo (pedido PT-01).
   - Como a `latest` muda sem aviso prévio a este repositório, o e2e da F8 pelo router de teste (spec 017 RF-17)
     registra o `sender`; `rejected`, `parse_errors` ou `fingerprint_mismatch` subindo com um `sender` novo é
     regressão do traefix, reportada ao humano.
9. **Divergências aceitas** (RF da versão anterior da spec 019):
   - RF-12 (contrato): o lado de cá valida o esquema com lotes de exemplo e, quando a task 273 rodar, com lotes
     reais do traefix gravados em `testdata` (o teste de contrato do lado do traefix não existe);
   - RF-07a (chave vazia em host público): aceita sem mudança; o bot responde 401 e o fail-open de 4xx segue;
   - RF-09 (rótulos OCI, `NOTICE`): recomendação ao projeto traefix, sem bloqueio (ADR 0054 item 10);
   - RF-01 (base em tag estável): aceita pela decisão do humano; o traefix segue a base que a `latest` tiver;
   - RF-11 (custo ≤ 5%): aceita pela decisão do humano; a task 273 mede a CPU no finger-01 (`rawBytes` ligado e
     desligado, `http3HeaderOrder`) como registro e para escolher `rawBytes`/`http3HeaderOrder`, sem bloquear a troca.
10. **Momento do registro de conexão**: aceito como o traefix faz. O casamento da spec 018 RF-04 (origem, porta de
   destino pública e início a menos de 5 s, pelo `time` do accept) não muda; o item 4 cobre a primeira requisição.

## Alternativas consideradas
- Pedir ao traefix que implemente a spec 019 como escrita — contrária ao desenho do humano (traefix genérico, o
  finger-sniffer é um consumidor entre outros) e atrasa a integração sem ganho de dado.
- Trocar o formato da rota sem manter o atual — incompatível em `/bot/v1` (ADR 0054 item 3) e quebra o simulador do
  e2e e a carga da F8.
- Rota nova (`/bot/v1/ingest/traefix`) — funciona, mas obriga a mudar `export.url` conforme a versão; o campo
  `schema` já distingue os formatos.
- Usar só as fingerprints prontas e desligar `rawBytes` — economiza CPU no traefix, mas perde JA3N, JA4_r, JA4_o e o
  `parse_error`, e a base própria passaria a depender de outro código; fica como plano B se a medida do item 9 pedir.
- Fixar tag ou digest no finger-01 (proposta da primeira versão desta ADR, como a ADR 0054 item 4) — reprodutível,
  mas contrária à decisão do humano de andar juntos com a `latest`.
- Aumentar `FS_BOT_VIEW_WAIT` para cobrir o lote do traefix — piora o forwardAuth de todas as requisições; os
  cabeçalhos resolvem sem espera.

## Consequências
- openapi do bot 0.3.0 (aditivo): `TraefixFingerprintBatch` e registros no `requestBody` do ingest (escolha por
  `schema`), cabeçalhos opcionais `X-Fs-Ja4`, `X-Fs-Ja3`, `X-Fs-H2` no `/bot/v1/auth`.
- Spec 019 reescrita (integração); specs 016 RF-15, 017 RF-14/RF-17, 018 (métricas) e 020 RF-02/RF-04 ajustadas.
- Tarefas: 302 (ingest `traefix.fingerprint/v1` e QUIC), 303 (forwardAuth com as fingerprints dos cabeçalhos), 304
  (e2e simulado e carga com o esquema novo), 305 (docs), 273 refeita (teste à parte, medida de custo, lotes reais e
  e2e pelo router de teste) e 306 (troca do `traefik-app` para a `latest`, depois da 273).
- Pedidos ao traefix iniciais: PT-01 (mudança incompatível só com `schema` novo) e PT-02 (rótulos OCI e `NOTICE`,
  recomendação), avisados ao humano no PR desta ADR.
- O calendário do traefix segue do humano; mudança de formato do lado dele chega como fato novo e nova ADR aqui.
