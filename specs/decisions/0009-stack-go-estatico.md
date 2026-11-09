# 0009 — Stack: Go estático, HTTP próprio, bibliotecas e sem Docker

Status: aceita (dependências que vêm na API pública de uma permitida: ver 0023)
Data: 2026-11-07

## Contexto
A VPS não tem compilador; o Mac tem Go 1.27.3. O espelho precisa controlar cada byte recebido e enviado.

## Decisão
- Go 1.27, `CGO_ENABLED=0`, binários estáticos linux/amd64 compilados no Mac e enviados por rsync.
- HTTP/1.x: parser e escritor próprios (`pkg/h1`) sobre `net.Conn`.
- HTTP/2: `x/net/http2` **sem fork** + parser passivo (`pkg/h2passive`) sobre cópia dos bytes.
- HTTP/3: `quic-go` + `http3`.
- **Dependências permitidas** (versões de referência em 2026-11-07):
  gopacket/gopacket v1.7 (afpacket, layers, pcapgo), miekg/dns v1.1, caddyserver/certmagic v0.25,
  quic-go v0.65, golang.org/x/net v0.62, golang.org/x/crypto, coder/websocket v1.8, nats-io/nats.go v1.55,
  nats-io/nats-server/v2 (somente em testes), prometheus/client_golang v1.25, oklog/ulid/v2 v2.1,
  modernc.org/sqlite, pressly/goose/v3, fsnotify/fsnotify; stdlib (log/slog etc.).
  Qualquer outra exige escalar ao humano.
- JA3/JA4/Akamai portados do fingerproxy para código próprio; tabela IANA própria (sem utls).
- Sem Docker: systemd direto com hardening (capabilities mínimas).
- Repositório GitHub privado `patrickbrandao/finger-sniffer`; docs em Markdown em `./docs/`; openapi servido pela API.

## Alternativas consideradas
- Rust; Go com cgo/libpcap; `net/http` com wrappers; fork do x/net/http2; lego; miekg/dns v2; Docker com host
  network; compilar no servidor.

## Consequências
- Controle total do que se mede e do que se envia, ao custo de manter um parser HTTP/1 próprio (fuzz obrigatório).
- Mesma pilha TCP do host que é documentada e medida.
