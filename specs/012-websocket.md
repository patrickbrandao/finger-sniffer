# 012 — WebSocket

Status: aprovada
Depende de: 005, 009

## Contexto
Testa se proxies repassam `ws://` e `wss://` intactos (caso 9 da matriz).

## Requisitos
- RF-01: Upgrade pela requisição HTTP/1.1 (já registrada pela spec 009) com `/p/<id>/r?upgrade=ws` ou qualquer
  caminho `/p/<id>/ws`; resposta 101 registrada byte a byte.
- RF-02: WebSocket sobre h2 (RFC 8441, `:protocol websocket`) quando o cliente oferecer.
- RF-03: eco de frames (coder/websocket para o protocolo; parser próprio na cópia dos bytes para registro).
- RF-04: por frame recebido: opcode, FIN, RSV1–3, máscara (e a chave), fragmentação, tamanho, tempo.
- RF-05: extensões negociadas (permessage-deflate e parâmetros), subprotocolos.
- RF-06: fechamento: código e razão de cada lado, quem fechou.

## Interfaces e contratos
- Evento `fs.v1.web.websocket.frame`; campo `websocket` do registro.

## Critérios de aceite
- [ ] `websocat wss://<id>.dns-monitor.tmsoft.com.br/p/<id>/ws` ecoa e o registro lista os frames.
- [ ] permessage-deflate negociado aparece com os parâmetros.

## Fora de escopo
- Subprotocolos específicos de aplicação.

## Decisões relacionadas
- specs/decisions/0009-stack-go-estatico.md
