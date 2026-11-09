# Changelog

Formato: [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/). Versionamento: [SemVer](https://semver.org/lang/pt-BR/).
Detalhe das decisões em `specs/decisions/`.

## [Não lançado]

### Adicionado
- Esqueleto: go.mod, 5 stubs de serviço com `-version`, Makefile (build estático, lint, tools), golangci-lint v2, lefthook, LICENSE Apache-2.0, NOTICE (task 001).
- `make verify-quick`/`verify-full` (scripts/verify.sh), banco-modelo SQLite por hash das migrations (scripts/testdb), CI GitHub Actions com verify-full (task 002).
- VPS: unit de rede (offloads off, sysctl TCP fixado), 7 units systemd + target com hardening, NATS v2.15.2 e p0f.fp com checksum, journald 24 h/200 MB, `make deploy [SVC=]` idempotente com trava remota e smoke test (task 003).
- Contratos 0.1.0: OpenAPI com esquemas completos dos registros, AsyncAPI 3.1 com payloads, lote de pacotes binário FSPB v1 (ADR 0015), migration SQLite 00001 com cascata; validação dos contratos no verify (task 004).
- `pkg/detect` (protocolo pelos primeiros bytes, bytes reentregues) e `pkg/probe` (probe ID em host, caminho e linha PROBE, rótulos de controle), 100% de cobertura e fuzz (task 005).
- Spike de carga (test/spike, docs/dev/spike-carga.md): 50 conexões/s em 1 vCPU com CPU ~22%; gargalo no JetStream em arquivo (p95 ~1–2 s), resolvido com stream em memória (p95 178 ms); SQLite com BLOBs viável (task 006).
- ADRs 0004 e 0005 aceitas; ADR 0016: stream FS_EVENTS em memória (32 MiB) e NATS com MemoryMax 192M (task 006).
- `pkg/event` (envelope v1, FSPB v1), `pkg/service` (config FS_*, slog JSON, NATS com reconexão, buffer 30 s/16 MiB, heartbeat 5 s); store mínimo: SQLite migrado, stream FS_EVENTS em memória, `/api/v1/health`, `/api/v1/openapi.yaml` e `/metrics` na 9001; os 5 serviços publicam heartbeat (task 007).
- Serviço capture: AF_PACKET TPACKET_V3 com block timeout de 10 ms, filtro BPF de exclusão no kernel (IPv4/IPv6/VLAN), direção pelos IPs locais, lotes FSPB v1 pelo produtor com buffer, health `degraded` com offload de agregação ligado (ethtool), perdas no kernel ou frame > MTU+14 (task 008).
- Store: ingest do stream (ack após commit), correlação 5-tupla → conn_id ULID (iniciador = cliente, reuso da 5-tupla), pcap no fechamento com teto e truncamento por cabeçalho, pacotes avulsos (TCP sem handshake, UDP sem resposta, ICMP), retenção por tempo e tamanho, modo degradado, recuperação de conexões órfãs (task 009).
- API de consulta: `/connections` (filtros, mais novas primeiro), `/connections/{id}` (abertas ao vivo), `/pcap` (parcial para abertas), `/raw`, `/packets`, `/dns`, `/probes/{id}` com long-poll `wait`, `DELETE /probes/{id}`; pool de leitura separado; exemplos golden de cada resposta validados contra o openapi (task 010).
- `pkg/fingerprint/ja4plus`: JA4T a partir do SYN (FoxIO License 1.1, isolado); `pkg/fingerprint/p0f`: assinatura p0f v3, leitor do `p0f.fp` e palpite de SO como o p0f 3.09b; conferidos contra `ja4` da FoxIO e `p0f -r` em 28 pcaps (106 fluxos JA4T, 153 observações p0f) (task 011).
- `.gitignore`: gabaritos `*.log` em `testdata/` são versionados (o `p0f.golden.log` da task 011 tinha ficado fora do commit) (task 011).
- Store: análise IP/TCP no registro (spec 013): IP do cliente (TTL inicial, saltos, IP ID e padrão, DF, DSCP/ECN, opções, fragmento, flow label), SYN completo com opções na ordem, JA4T, assinatura e palpite p0f (`FS_P0F_DB`), janela com escala, padrão de ACK, PSH, keepalives, janela zero, RST com dados, retransmissões e fora de ordem por sentido, primeiros `FS_TCP_SEGMENTS_TRACKED` segmentos, relógio TSval (Hz) e agrupamento por relógio entre conexões, RTT do handshake, SYN cookie do servidor (task 012).
- Golden pcaps (`test/golden/`): curl macOS (IPv4/IPv6), curl Linux (IPv4/IPv6), Go, Chrome, keepalive, retransmissão (netem) e RST, com saídas de referência do tshark 4.4, `ja4` da FoxIO e `p0f -r`; `collect.sh` regenera e limpa a vps602; `internal/store/golden_test.go` confere o registro contra elas (task 013).
- Store: retransmissão, fora de ordem e keep-alive classificados como o tshark (Wireshark 4.4: retransmissão rápida e espúria, limite de fora de ordem pelo iRTT, FIN na sequência, atualização de janela com SACK como ACK duplicado) (task 013).
- E2E da F2 (`test/e2e/`, `make verify-full ARGS="--e2e"`): curl e nc a uma porta capturada com SYN, JA4T, p0f, RTT, close e pcap aberto no tshark; SYN para porta fechada em `/packets`; portas 48022/9000/9001/48161 ausentes; respostas reais validadas contra o openapi pelo Redocly; retenção de 10 min com `FS_E2E_LONG=1` (task 014).

- `pkg/h1`: parser HTTP/1.x sem normalização (caixa, ordem, separador literal, CRLF/LF, duplicatas, obs-fold, teto de 1 MiB → `ErrHeadTooLarge`/431), corpo Content-Length/chunked (tamanho literal, extensões, trailers)/até o fechamento com tamanho e SHA-256 do conteúdo e bytes crus até o teto, bytes no buffer para pipelining, `Expect: 100-continue` e Upgrade h2c/websocket, sinais de proxy configuráveis (absolute-form direto, Host ≠ SNI), escritor de respostas byte a byte (1xx, chunked com trailers, hsize) com captura do enviado; fuzz e 99% de cobertura (task 020).
- Contratos 0.2.0 para a F3 (aditivos): `fs.v1.web.raw.session`, `fs.v1.store.conn_id`, `truncated` no fluxo, `ja4h`/offsets/tamanho da resposta no HTTP/1, `frames_truncated`, `raw_truncated`; semântica de conjunto do TXT ACME; `pkg/certs` com nomes fixos em `FS_CERT_DIR` e `FS_ACME_ENABLE`; regras de correlação e montagem do registro no store (task 015).
- `htdocs/` mínimo da F3: `index.html` em inglês (o que é o espelho, portas capturadas, aviso de tráfego público e retenção de 10 min, como sondar por `/p/<id>/` e `PROBE`, resultado em `/api/v1/probes/<id>`, link para o openapi), sem JS, cookies nem terceiros; `robots.txt` com `Disallow: /p/`; teste em `htdocs/htdocs_test.go` (task 034).
- `pkg/certs`: TLS fixo do espelho (TLS 1.0–1.3, cifras do Go + CBC/RSA/3DES explícitas, `godebug tlssha1=1` no go.mod), `Describe` para `host.tls_server`; certificados A/B de `FS_CERT_DIR` com recarga a quente por fsnotify (tolerante a rename atômico e par trocado em momentos diferentes), escolha por SNI, autoassinado RSA em memória quando falta arquivo, `State`/`Reasons` (`cert_self_signed`, `cert_expiring`) e `WritePair` atômico (task 019).
- Infra da F3: `.env.example` com `FS_ACME_ENABLE=0`, `FS_ACME_DIR`, `FS_EVENT_INLINE_MAX`, `FS_RAW_STREAM_MAX_BYTES` e `FS_RAW_BODY_MAX_BYTES` de 128 KiB (ADR 0018); deploy acrescenta ao env do servidor as chaves novas sem sobrescrever e avisa dos valores que diferem do padrão (`deploy/env-merge.sh`); Pebble v2.10.1 em `make tools`/`tools-ci`, exportado como `FS_TEST_PEBBLE` pelo verify e obrigatório no CI (task 035).
- Store: request/reply `fs.v1.store.conn_id` (devolve o ID da conexão aberta ou reserva um ULID por 30 s para a próxima conexão da 5-tupla), stream `FS_EVENTS` com a lista explícita de subjects da ADR 0017 (ajustado no deploy sem perda); `pkg/event` com todos os subjects do asyncapi 0.2.0, payloads `StreamBytes`/`TLSHandshake`/`WebSocketFrame`/`ConnID*`/`ACME*` e limites da ADR 0018; `pkg/service.RequestConnID` (250 ms) e `FS_EVENT_INLINE_MAX`/`FS_RAW_STREAM_MAX_BYTES` (task 021).
- Serviço dns: autoritativo de `FS_DNS_ZONE` em UDP/TCP 53 (miekg/dns v1.1.73), sem recursão, REFUSED fora da zona, SOA/NS no apex, NOERROR/NODATA com SOA para o resto (CAA do Let's Encrypt), EDNS 1232/BADVERS, TC=1 acima do limite UDP, FORMERR; TXT `_acme-challenge` por request/reply `fs.v1.dns.acme.set|clear` com conjunto de valores e expiração de 10 min; listener que não sobe deixa o health `degraded` e é tentado de novo (task 016).
- Store: ingest dos eventos de aplicação (`fs.v1.web.*`, `fs.v1.raw.*`, `fs.v1.dns.query`) correlacionados pela 5-tupla e `ts` (folga de 2 s, fila pendente de 2 s, conexão só com os eventos quando não há pacotes, atualização de conexões já gravadas), `app_events`, `raw_streams` por offset com teto `FS_RAW_STREAM_MAX_BYTES` e `raw_truncated`, `probe_id` pelo primeiro envelope com probe e tabela `probes`, `dns_queries` com `conn_id` para DNS por TCP (task 031).
- Store: API HTTPS na 9000 (`FS_API_HTTPS_PORT`) com `pkg/certs` (certificado por SNI, recarga a quente, ALPN h2/http1.1), sem `/metrics`; health com `host.tls_server` e `host.certificates`; certificado autoassinado ou expirando deixa o store `degraded` (task 033).

### Decidido
- Espelho genérico de conexões; consumidor principal go-xproxy (ADR 0001).
- 5 serviços (capture, web, raw, dns, store), 1 binário cada, Go 1.27 estático (ADR 0002, 0009).
- NATS + JetStream local; todos os pacotes pelo barramento (provisório) (ADR 0003, 0004).
- SQLite com BLOBs, goose, retenção 10 min / 2 GiB (provisório) (ADR 0005, 0012).
- Portas capturadas do §3 + QUIC; API 9000 HTTPS / 9001 HTTP sem captura, aberta, feed global (ADR 0006, 0007).
- Zona `dns-monitor.tmsoft.com.br`, ACME embutido DNS-01/HTTP-01 (ADR 0008).
- Offloads off, sysctls TCP fixados (ADR 0011).
- Apache-2.0; JA4+ isolado (FoxIO License) (ADR 0010).
- Verificação em dois níveis, CI = full, deploy local (ADR 0013).
- 10 papéis de agente, worktree por agente, trunk-based (ADR 0014).
- Stream `FS_EVENTS` com lista explícita de subjects de eventos (request/reply fora); `fs.v1.store.conn_id` reserva o `conn_id` para o web (ADR 0017) (task 015).
- Eventos ≤ 900 KiB: campos inline ≤ 128 KiB com `*_truncated`, bytes completos pelo fluxo até 16 MiB por sentido, `in_offset`/`out_offset` por requisição; `FS_RAW_BODY_MAX_BYTES` passa a 128 KiB (ADR 0018) (task 015).
