# 013 — Análise IP e TCP

Status: aprovada
Depende de: 003, 004

## Contexto
Responde "qual fingerprint TCP chega, é estável, e o que denuncia o proxy (RTT TCP × RTT da aplicação)?" e
"quantas conexões, quem fechou, quando e como". Calculada **no store** a partir dos pacotes do capture (ADR 0004).

## Requisitos
### Linha do tempo e fechamento
- RF-01: tempos (ns UTC): SYN recebido, SYN-ACK enviado, ACK do handshake, primeiro byte do cliente, cada
  requisição e resposta (vindas dos eventos de aplicação: `request_started_at`, `request_ended_at`,
  `response_started_at`, `response_ended_at` em `http[]`, `http2.streams[]` e `http3.requests[]`, publicados pelo
  web e copiados pelo store, ADR 0029), FIN/RST de cada lado, fim. Em UDP o primeiro
  datagrama é o `started` do resumo e o fim é o `ended`; o objeto `times` é da linha do tempo TCP e, em UDP, só
  aparece com camada QUIC (`tls_done`) (ADR 0023).
- RF-02: quem fechou primeiro (`client`/`server`), como (`fin`/`rst`/`timeout`), meio-fechamento, tempo ocioso
  entre a última resposta e o fechamento.
- RF-03: totais por sentido: bytes de aplicação, segmentos, segmentos com dados, retransmissões, fora de ordem.

### IP (cada pacote do handshake e o primeiro com dados; resumo do resto)
Os campos planos de `ip` são o resumo (TTL/DF/IP ID/flow label do SYN, TOS/ECN do primeiro segmento com dados,
padrão de IP ID e fragmentação da conexão). `ip.packets` traz os mesmos dados **por pacote** (ADR 0029): `syn`
(primeiro SYN do cliente), `ack` (primeiro segmento do cliente com ACK e sem SYN depois do SYN-ACK, com ou sem
dados) e `first_data` (primeiro segmento do cliente com dados: pode ser o próprio SYN com TFO ou o próprio `ack`),
cada um com `ttl`, `df`, `ip_id`, `tos`, `dscp`, `ecn`, `flow_label`, `total_length`, `options_hex` e
`fragmented`, ou nulo se o pacote não existiu. Em UDP, `syn` e `ack` são nulos e `first_data` é o primeiro
datagrama do cliente.
- RF-04: TTL / hop limit observado, TTL inicial estimado (32/64/128/255), distância em saltos.
- RF-05: IP ID no SYN e padrão na conexão (`zero`, `incremental`, `random`), DF, TOS/DSCP, ECN, opções IP,
  fragmentação; IPv6: flow label e traffic class.
- RF-05a: **tipo do endereço de origem** (`ip.src_kind`, ADR 0031), do endereço do cliente, em TCP e UDP, pela
  primeira regra que casa: `loopback`, `link_local`, `private` (RFC 1918, ULA `fc00::/7`), `shared`
  (`100.64.0.0/10`), `teredo` (`2001::/32`), `6to4` (`2002::/16`), `nat64` (`64:ff9b::/96`, `64:ff9b:1::/48`;
  só com tradutor SIIT/NAT46 na frente do servidor, não indica NAT64 do cliente), `other` (não unicast e blocos de
  uso especial da tabela da ADR 0031) e `global` (o resto). Sem valor por família: ela está em `family`.

### TCP
- RF-06: SYN completo: porta de origem, ISN, janela, flags (inclusive ECE/CWR), ponteiro urgente, tamanho do
  cabeçalho, **opções na ordem exata com valores** (MSS, NOP, WScale, SACK-permitted, Timestamps val/ecr, TFO, EOL,
  MD5, desconhecidas em hex), payload no SYN (TFO; o espelho concede cookie TFO nos listeners do web e do raw,
  ADR 0029, então um cliente que repete a conexão pode mandar dados no SYN).
- RF-06a: **MSS e MTU implícito** (ADR 0031), só do primeiro SYN do cliente (retransmissão não substitui):
  `tcp.syn_mss` (primeira opção MSS), `tcp.mtu_implied` (`syn_mss + 40` no IPv4, `+ 60` no IPv6; sem somar os
  12 B de timestamps, que o MSS do SYN não desconta) e `tcp.mss_reduction` (`1460 − syn_mss` no IPv4,
  `1440 − syn_mss` no IPv6; negativo acima de MTU 1500). Os três nulos sem a opção MSS ou sem SYN. É o valor que
  chegou ao espelho: MTU reduzido e MSS clamping no caminho dão o mesmo número. A causa provável (PPPoE, túnel,
  VPN) é interpretação do cliente e fica em `docs/probes.md`, não no contrato.
- RF-07: fingerprints: **JA4T** (`pkg/fingerprint/ja4plus`, FoxIO License), assinatura **p0f** e palpite de SO pelo
  banco `p0f.fp` (`FS_P0F_DB`, arquivo de dados externo, LGPL-2.1, instalado pelo deploy).
- RF-08: comportamento: janela anunciada ao longo da conexão (escala aplicada), padrão de ACK
  (atrasado/imediato), uso de PSH, keepalive TCP recebido (intervalo entre sondas e tamanho), zero-window, RST com
  ou sem dados.
- RF-09: **segmentação**: tamanho e tempo de cada um dos primeiros `FS_TCP_SEGMENTS_TRACKED` (≥ 32) segmentos com
  dados de cada sentido.
- RF-10: **relógio de timestamps**: frequência estimada do TSval (Hz) e TSval inicial; com várias conexões do
  mesmo IP de origem (ou de IPs diferentes na mesma janela), indicar se vêm do mesmo relógio (mesmo host):
  `ts_clock_group` junta as conexões cujo TSval cai na mesma reta TSval × tempo (mesma frequência e mesmo
  deslocamento extrapolado). Clientes que deslocam o TSval por conexão (macOS, `randomize_timestamps=1`) ou por
  par de endereços (Linux ≥ 4.10, `tcp_timestamps=1`) ganham grupos distintos; é o esperado, não erro (ADR 0023).
- RF-11: **RTT**: do handshake (SYN-ACK → ACK) e da aplicação (resposta do espelho → próximo byte do cliente que
  dependa dela: Finished do TLS, próxima requisição).
- RF-12: indicação de SYN cookie usado pelo servidor (o SYN-ACK do espelho veio de cookie) — vem do contador do
  kernel e da comparação de opções.

## Interfaces e contratos
- Campos `ip`, `tcp`, `times`, `close` do registro em [openapi.yaml](../cmd/finger-sniffer-store/openapi.yaml).

## Dados
Calculados e guardados pelo store junto do registro.

## Critérios de aceite
- [ ] JA4T de Linux, macOS e Windows bate com FoxIO `ja4` (`ja4t`) sobre o mesmo pcap.
- [ ] p0f do registro igual ao `p0f -r` sobre o mesmo pcap.
- [ ] RTT do handshake e RTT da aplicação conferem com tshark (diferença < 0,1 ms).
- [ ] `ip.packets.syn`, `ack` e `first_data` conferem com o tshark (TTL, DF, IP ID, TOS, total length) no pcap
      da mesma conexão; em UDP, `syn`/`ack` nulos.
- [ ] Cliente com TFO (`curl --tcp-fastopen`, segunda conexão) aparece com `tcp.syn.tfo: true` e
      `tcp.syn.payload_b64` não nulo, e `ip.packets.first_data` é o SYN.
- [ ] Mesmo relógio sem deslocamento por IPs de origem diferentes → mesmo `ts_clock_group` (pcap sintético);
      duas conexões Linux pelo mesmo par de IPs → mesmo grupo; macOS com `randomize_timestamps=1` → grupos
      distintos (ADR 0023).
- [ ] SYN IPv4 com MSS 1460, 1452, 1440 e 1380 → `syn_mss`/`mtu_implied`/`mss_reduction` = 1460/1500/0,
      1452/1492/8, 1440/1480/20, 1380/1420/80; IPv6 com 1440, 1432 e 1220 → 1440/1500/0, 1432/1492/8,
      1220/1280/220; SYN sem MSS, conexão sem SYN e UDP → os três nulos; MSS 8960 (jumbo IPv4) → redução −7500.
- [ ] Um endereço de origem por valor de `ip.src_kind` (tabela da ADR 0031, inclusive as bordas de cada prefixo:
      `64:ff9b::/96` casa e `64:ff9b:0:0:1::` não; `2001::/32` casa e `2001:1::` não) classificado certo.

## Fora de escopo
- Fingerprint TCP do lado servidor (JA4TS).
- Causa provável da redução do MSS no contrato (`mss_hint`) e decodificação do IPv4 embutido em Teredo/6to4
  (ADR 0031: interpretação do cliente).

## Decisões relacionadas
- specs/decisions/0004-pacotes-pelo-nats.md
- specs/decisions/0010-licenca-apache-e-ja4plus.md
- specs/decisions/0011-rede-offloads-e-pilha-tcp.md
- specs/decisions/0029-campos-da-auditoria-de-requisitos.md
- specs/decisions/0031-mss-mtu-e-tipo-da-origem.md
