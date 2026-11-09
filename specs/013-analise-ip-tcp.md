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

### TCP
- RF-06: SYN completo: porta de origem, ISN, janela, flags (inclusive ECE/CWR), ponteiro urgente, tamanho do
  cabeçalho, **opções na ordem exata com valores** (MSS, NOP, WScale, SACK-permitted, Timestamps val/ecr, TFO, EOL,
  MD5, desconhecidas em hex), payload no SYN (TFO; o espelho concede cookie TFO nos listeners do web e do raw,
  ADR 0029, então um cliente que repete a conexão pode mandar dados no SYN).
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

## Fora de escopo
- Fingerprint TCP do lado servidor (JA4TS).

## Decisões relacionadas
- specs/decisions/0004-pacotes-pelo-nats.md
- specs/decisions/0010-licenca-apache-e-ja4plus.md
- specs/decisions/0011-rede-offloads-e-pilha-tcp.md
- specs/decisions/0029-campos-da-auditoria-de-requisitos.md
