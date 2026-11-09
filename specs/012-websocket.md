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
- RF-06: fechamento: quem iniciou (`close.by`) e o código e a razão do close de quem iniciou; o close de
  resposta do outro lado fica registrado só como frame (`frames[]`: `dir`, opcode 8, tamanho), sem código nem
  razão. Quando o cliente inicia, a resposta é do próprio espelho e não diz nada sobre o caminho; quando o espelho
  inicia (1001 por ociosidade), basta saber se a resposta chegou. Depois da troca de closes o espelho fecha o TCP
  primeiro (RFC 6455 §7.1.1; exceção da spec 005 RF-08, ADR 0023).

## Interfaces e contratos
- Evento `fs.v1.web.websocket.frame`; campo `websocket` do registro.

## Critérios de aceite
- [ ] `websocat wss://<id>.dns-monitor.tmsoft.com.br/p/<id>/ws` ecoa e o registro lista os frames.
- [ ] permessage-deflate negociado aparece com os parâmetros.

## Fora de escopo
- Subprotocolos específicos de aplicação.

## Decisões relacionadas
- specs/decisions/0009-stack-go-estatico.md
