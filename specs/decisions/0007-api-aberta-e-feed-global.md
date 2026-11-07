# 0007 — API aberta e feed global

Status: aceita
Data: 2026-11-07

## Contexto
O servidor é público e captura também scanners e terceiros, inclusive bytes crus que podem conter credenciais
(ex.: `Proxy-Authorization` vazado).

## Decisão
- API 9000/9001 **totalmente aberta**, sem token, inclusive listagens, pcap e pacotes avulsos.
- A página mostra o **feed global** de todo o tráfego (SSE `/api/v1/stream`, WebSocket `/api/v1/ws`).
- Sem autenticação, sem administrador, sem bootstrap de admin.
- A página avisa que todo o tráfego é público.

## Alternativas consideradas
- Probe aberto e resto com token (recomendado); tudo com token; página filtrando por probe/IP do visitante.

## Consequências
- Risco aceito: tráfego de terceiros visível por até 10 min (mitigado só pela retenção curta, ADR 0012).
- Simplicidade máxima para qualquer cliente consumir.
