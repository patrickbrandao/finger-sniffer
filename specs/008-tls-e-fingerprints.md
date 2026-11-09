# 008 — TLS e fingerprints

Status: aprovada
Depende de: 005

## Contexto
Responde "o ClientHello que chegou é byte a byte o do cliente?". Vale para qualquer porta onde o primeiro byte é
TLS (web e raw) e para o ClientHello dentro do QUIC Initial (spec 011). Técnicas portadas do fingerproxy
(Apache-2.0), JA4 da FoxIO (BSD-3), JA3 da Salesforce (BSD-3); JA4H em pacote separado sob FoxIO License (ADR 0010).

## Requisitos
- RF-01: captura do **ClientHello cru** (registro TLS completo, base64) por wrapper de `net.Conn` antes do
  `crypto/tls`; informa se veio em mais de um registro TLS e em mais de um segmento TCP (este último vem do store).
- RF-02: parser próprio (`pkg/tlsparse`) — campos, sem normalizar:
  versão do registro e do handshake, random, tamanho do session ID, cipher suites na ordem (GREASE marcado),
  compressão, **extensões na ordem com os dados crus (hex)**, SNI, ALPN, supported_groups, ec_point_formats,
  signature_algorithms, supported_versions, key_share (grupos e tamanhos), psk_key_exchange_modes,
  pre_shared_key/early_data (retomada, 0-RTT), padding (tamanho), compress_certificate, record_size_limit,
  application_settings (ALPS), encrypted_client_hello (presença), session_ticket, status_request,
  delegated_credentials; nomes legíveis pela tabela IANA própria (`pkg/iana`).
- RF-03: fingerprints (`pkg/fingerprint`): **JA3** (texto e MD5), **JA3N** (extensões ordenadas), **JA4**,
  **JA4_r**, **JA4_o**, **JA4 stable** (sem extensões dependentes de estado, como no fingerproxy). Prefixo `t` para
  TCP, `q` para QUIC.
- RF-04: resultado do handshake: versão, cifra, grupo e ALPN negociados, retomada, tempo de handshake (`handshake_ms`, milissegundos em float, como as demais durações do contrato),
  alertas (nível e descrição) dos dois sentidos durante o handshake (ADR 0029): primeiro todo registro de alerta
  (tipo `0x15`) em texto claro visto nos bytes de cada sentido, com nível e descrição exatos dos bytes, na ordem
  (`in` do cliente, `out` do espelho); depois o alerta que o `crypto/tls` informar (`remote error` → `in`,
  `local error` → `out`: alertas cifrados, que só ele vê), só se não houver um igual (mesma direção e
  descrição) vindo dos bytes. O parser de registros é de `pkg/tlsparse`, usado pelo web e pelo raw.
- RF-05: depois do handshake, o conteúdo segue para HTTP/1 ou h2 como se fosse em claro.
- RF-06: o servidor TLS do espelho usa configuração fixa e documentada (versões 1.0–1.3 habilitadas para observar
  clientes antigos; lista de cifras do Go padrão + legadas), exposta em `/api/v1/health`.

## Interfaces e contratos
- Eventos `fs.v1.web.tls.client_hello` e `fs.v1.web.tls.handshake` (também usados pelo raw). Campo `tls` do
  registro em [openapi.yaml](../cmd/finger-sniffer-store/openapi.yaml).

## Dados
Pertencem ao registro da conexão (store).

## Critérios de aceite
- [ ] JA4 bate com os snapshots dos pcaps oficiais da FoxIO (portados do `ja4pcap` do fingerproxy).
- [ ] JA3/JA4 de curl, Go, Chrome e Firefox batem com `tshark`/FoxIO `ja4` sobre o pcap da mesma conexão.
- [ ] ClientHello partido em 2 registros e em 2 segmentos é reconhecido e marcado.
- [ ] Cliente que aborta o handshake com alerta em texto claro (ex. `openssl s_client` sem CA confiável,
      `unknown_ca` 48) aparece em `tls.alerts` com `dir: in`, `description: 48`, igual ao tshark.
- [ ] Fuzz do parser sem pânico: 10 s por alvo no verify-full e 60 s antes de cada release (spec 017, ADR 0023).

## Fora de escopo
- JA4S, JA4X (lado servidor/certificados).

## Decisões relacionadas
- specs/decisions/0010-licenca-apache-e-ja4plus.md
- specs/decisions/0009-stack-go-estatico.md
- specs/decisions/0029-campos-da-auditoria-de-requisitos.md
