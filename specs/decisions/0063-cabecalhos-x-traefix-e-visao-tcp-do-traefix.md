# 0063 — Cabeçalhos `X-Traefix-*`, visão TCP do traefix, ALPN no forwardAuth e esquema publicado pelo traefix

Status: aceita
Data: 2026-11-18

## Contexto
**Fato novo**: o traefix respondeu aos pedidos feitos a ele depois da ADR 0062 (relatório do agente do traefix de
2026-11-18, commit `9f480d2e7`, imagem `fork-point-218-g9f480d2e7` = `latest`):
- **prefixo**: a recomendação de `headerPrefix: X-Fs-` foi retirada; todos os cabeçalhos usam o padrão
  `X-Traefix-`, inclusive os do veredito do bot (`X-Traefix-Verdict`, `X-Traefix-Score`, `X-Traefix-Signals`),
  porque o traefix só remove do cliente os cabeçalhos com o prefixo dele: um `X-Fs-Verdict` forjado pelo cliente
  chegaria ao backend. Cabeçalhos ao backend e à auth: `X-Traefix-Src-Ip`, `-Src-Port`, `-Dst-Port`, `-Conn-Id`,
  `-Proto`, `-Ja4h`, `-Ja3`, `-Ja4`, `-H2`, e os novos `-Alpn` e `-Ja4t`;
- **versão do esquema** (PT-01): campo, tipo de registro, cabeçalho ou valor novo mantém `traefix.fingerprint/v1`;
  remover, renomear, mudar tipo/unidade/sentido ou tornar obrigatório vai a `v2`, avisado antes. O receptor ignora
  campos e tipos de registro que não conhece. O traefix publica o JSON Schema
  `traefix-fingerprint-v1.schema.json` (2020-12) e valida nele os lotes reais nos testes dele;
- **`sender`** = `traefix/fork-point-<n>-g<sha>`; rótulos OCI e `NOTICE` (PT-02) entregues;
- **goldens do espelho** (`test/golden/tls/pcaps`, `test/golden/pcaps`) copiados para o traefix: JA3, JA4, JA4_r,
  Akamai, JA4H, JA4T e a assinatura p0f batem com as referências; JA4_o sem golden;
- **visão TCP** (`fingerprint.tcp: true`, só Linux): `TCP_SAVE_SYN` no listener; registro de conexão com
  `tcp.ja4t`, `tcp.p0f` (`raw_sig` do p0f v3, sem palpite de SO), `tcp.ttl` (recebido), `tcp.rttMicros` e
  `tcp.syn` (SYN cru desde o cabeçalho IP, com `rawBytes`); cabeçalho `X-Traefix-Ja4t`. Sem visão TCP com
  `proxyProtocol`; atrás de LB/CDN o SYN é o do LB; pelo `docker-proxy` (ex.: IPv6 num container só IPv4) o SYN é o
  do proxy, com o IP do gateway do Docker; sem SYN salvo em SYN cookies; h3 não tem TCP. IPv6 validado só em
  container;
- **fingerprints prontas completas**: `tls.ja3n`, `tls.ja3nString`, `tls.ja4r`, `tls.ja4o`,
  `http2.headersPriority`; o resto do h2 está no Akamai;
- **`X-Traefix-Alpn`**: ALPN oferecido na ordem do cliente, separado por vírgulas, com `%XX` fora do ASCII visível,
  para a vírgula e para o `%`; ausente sem TLS;
- **chave vazia** em `requestHeaders` (ou só `Bearer `) falha na carga do middleware, em qualquer endereço;
- **CPU no Linux** (Xeon 6148, sem backend, teto): +40% em h1 e +29% em h2 com export e `rawBytes`; tirar `rawBytes`
  não reduz CPU com keep-alive (só o tamanho do lote). Aceito pelo humano (ADR 0062 item 9).

A ADR 0054 item 3 só deixa mudar `/bot/v1` de forma aditiva; a ADR 0062 item 5 tinha `headerPrefix: X-Fs-`.

## Decisão
1. **Prefixo `X-Traefix-`** (substitui o `headerPrefix: X-Fs-` da ADR 0062 item 5 e os nomes `X-Fs-*` da ADR
   0058 entre traefix, bot e backend; aditivo em `/bot/v1`):
   - o perfil da spec 019 usa o prefixo padrão do traefix, sem `headerPrefix`;
   - o `/bot/v1/auth` lê os `X-Traefix-*`; os `X-Fs-*` antigos só valem quando **nenhum** cabeçalho
     `X-Traefix-` de origem veio (`X-Traefix-Conn-Id` ausente), e nunca se misturam: com `X-Traefix-Conn-Id`
     presente, todo `X-Fs-*` da requisição é ignorado (o traefix novo não remove `X-Fs-*` do cliente);
   - as respostas 200 e o 403 do modo `block` trazem `X-Traefix-Verdict`, `X-Traefix-Score`,
     `X-Traefix-Signals` **e** os `X-Fs-*` equivalentes (obsoletos, saem numa `/bot/v2`); nenhuma resposta de erro
     traz nenhum dos dois `Verdict` (fail-open de 4xx);
   - backends leem só `X-Traefix-*`: com o traefix atual, um `X-Fs-*` que chega ao backend pode ter vindo do
     cliente;
   - os cabeçalhos do webhook (`X-Fs-Signature`, `X-Fs-Timestamp`, `X-Fs-Key-Prefix`) não passam pelo traefix e
     não mudam.
2. **Ingest tolerante** (PT-01): campos e tipos de registro desconhecidos são ignorados; um tipo desconhecido não
   conta em `rejected` e conta em `bot_ingest_ignored_total{type}`. O bot continua aceitando registros que o
   esquema do traefix declararia incompletos, desde que tenham o que a RF-07 da spec 019 lê.
3. **Esquema publicado pelo traefix** (sugestão do traefix): o arquivo vira cópia neste repositório,
   `cmd/finger-sniffer-bot/traefix-fingerprint-v1.schema.json` (contrato, papel architect), sem edição. O
   openapi do bot traz a **tradução** dela em componentes (`TraefixFingerprintBatch` e registros), porque o
   documento servido em `/bot/v1/openapi.yaml` e o teste de contrato precisam ser autossuficientes (um `$ref` ao
   arquivo deixa o servido com referência solta). O commit de origem fica na descrição do openapi. O architect
   atualiza a cópia e a tradução quando o traefix muda o esquema (andar juntos, ADR 0062 item 8); um teste do bot
   valida os lotes de exemplo e os reais contra as duas formas, e a divergência entre elas aparece ali.
4. **Fingerprints prontas completas** (complementa a ADR 0062 item 3): sem os bytes crus, a visão usa também
   `tls.ja3n`, `tls.ja4r`, `tls.ja4o` e `http2.headersPriority` (e as partes do Akamai), sem campos nulos. Com os
   bytes crus, vale a calculada e a divergência conta em `bot_ingest_fingerprint_mismatch_total{kind}` com `kind`
   também `ja3n`|`ja4r`|`ja4o`|`ja4t`; divergência de `ja4o` só é falha no e2e depois de um golden (o traefix não tem
   referência).
5. **Visão TCP do traefix** (`tcp.*` e `X-Traefix-Ja4t`): nova visão da conexão do traefix, usada pelas regras de
   TCP (`ua_os_tcp_mismatch`, `tunnel_mss`, `known_client`):
   - origem: a visão do **store** quando casada (espelho, captura própria) vence; sem ela, a do registro de conexão
     do traefix; sem ele, no forwardAuth, o JA4T de `X-Traefix-Ja4t`; com as duas (finger-01), a divergência do JA4T
     conta em `mismatch{kind="ja4t"}`;
   - dados: JA4T; TTL inicial estimado do `tcp.ttl` como o store (spec 013); MSS, `mss_reduction` e `mtu_implied`
     do MSS do JA4T com as regras da spec 013 RF-06a; palpite de SO do p0f a partir de `tcp.syn` com
     `pkg/fingerprint/p0f` e o mesmo `p0f.fp` do store (`FS_BOT_P0F_DB`, padrão `/finger-sniffer/etc/p0f.fp`); sem
     `tcp.syn` ou sem o banco, sem palpite de SO (a regra que precisa dele não avalia). `tcp.p0f` e `tcp.rttMicros`
     são guardados e mostrados, sem regra nova;
   - a visão TCP do traefix é **descartada** quando `src.ip` do registro é loopback, link-local ou de rede privada
     (SYN de um proxy local, ex.: `docker-proxy`), e não existe em h3;
   - JA4T vindo só do cabeçalho: só JA4T e o MSS dele (sem TTL nem SO).
6. **ALPN no forwardAuth**: `X-Traefix-Alpn` (decodificado de `%XX`, até 16 valores) dá o ALPN oferecido à visão
   TLS do cabeçalho; com ele, `ua_alpn_mismatch` e o ramo de ALPN de `ua_h2_mismatch` voltam a ser avaliados na
   primeira requisição (substitui a restrição da ADR 0062 item 4 quando o cabeçalho vem).
7. **Espera da RF-04** (complementa a ADR 0062 item 4): na 9002 (site externo) o store nunca tem a conexão, então o
   forwardAuth não espera visão nenhuma do store; na 9003 a espera segue como na ADR 0062 (com `X-Traefix-Ja4`, só o
   store).
8. **Perfil**: `fingerprint.tcp: true` nas entradas cobertas do finger-01 e no exemplo para sites externos;
   `rawBytes: true` mantido no finger-01 (comparação calculada × pronta e SO do p0f pelo SYN); para site externo,
   `rawBytes: true` recomendado (sem ele não há palpite de SO).
9. **Pedidos ao traefix**: PT-01 a PT-09 entregues (tabela da spec 019; PT-08, custo, entregue como medida e
   otimização parcial, com o teto aceito pelo humano); novo PT-10: marcar no registro de conexão
   quando o SYN salvo pode não ser do cliente (vindo de `docker-proxy` ou de um proxy local), para o bot não
   depender só da faixa do IP de origem.
10. **Licenças**: JA4T e JA4H seguem a FoxIO License 1.1 (ADR 0053, uso não comercial, já em vigor); o `p0f.fp`
    (LGPL) é lido em tempo de execução pelo bot como já é pelo store, sem embutir.

## Alternativas consideradas
- Trocar `X-Fs-*` por `X-Traefix-*` sem manter os antigos — incompatível em `/bot/v1` (ADR 0054 item 3) e quebra o
  simulador do e2e e a carga sem ganho; os antigos saem numa `/bot/v2`.
- Pedir ao traefix para manter `headerPrefix: X-Fs-` — funciona, mas o veredito do bot (`X-Fs-Verdict`) não seria
  removido do cliente pelo traefix, que só limpa o prefixo dele.
- Usar a visão TCP do traefix acima da do store no finger-01 — o store vê todos os pacotes (RTT, relógio,
  segmentação) e é a fonte medida da base própria; o traefix fica como reserva e conferência.
- Palpite de SO só pelo `tcp.p0f` (`raw_sig`) — exige casar a assinatura textual com o `p0f.fp` sem o pacote; o SYN
  cru já passa pelo mesmo código do store.
- Referenciar o esquema por URL do GitHub — o lint e o teste de contrato não devem depender da rede.

## Consequências
- openapi do bot 0.4.0 (aditivo): cabeçalhos `X-Traefix-*` no `/bot/v1/auth` (os `X-Fs-*` marcados obsoletos),
  respostas com os dois conjuntos, `TraefixFingerprintBatch` traduzido da cópia do esquema do traefix (`visão TCP`, `ja3n`, `ja4r`, `ja4o`,
  `headersPriority`, tipo de registro desconhecido).
- Specs 001, 016, 017, 018, 019 e 020 ajustadas; tasks 302–305 e 273 revistas; `FS_BOT_P0F_DB` no `.env.example` delegado à
  302 (a unit do bot já lê `/finger-sniffer/etc` com `ProtectSystem=strict`; spec 016 RF-14).
