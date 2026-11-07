# 0006 — Portas capturadas e API fora da captura

Status: aceita
Data: 2026-11-07

## Contexto
A página e os clientes consultam o que trafegou sem que a consulta entre na captura (evita loop). O IP é
compartilhado com sshd (48022) e snmpd (48161).

## Decisão
- Portas capturadas: TCP 80, 443, 8080, 8443 (web); TCP 7, 21, 22, 25, 110, 143, 587, 993 (raw); UDP/TCP 53 (dns);
  UDP 443 (QUIC).
- Detecção de protocolo pelos primeiros bytes em todas as portas web e raw.
- API em **9000 HTTPS** (mesmo certificado) e **9001 HTTP**, CORS `*`, fora da captura.
- sshd e snmpd permanecem; BPF exclui 48022, 48161, 9000, 9001 (lista em `FS_CAPTURE_EXCLUDE_PORTS`).

## Alternativas consideradas
- HTTPS e HTTP na mesma 9000 por detecção de primeiro byte; só HTTPS; IP adicional dedicado; remover snmpd.

## Consequências
- O documento de origem pedia IP dedicado; a exclusão por BPF garante que nada de gerência entre nos registros.
