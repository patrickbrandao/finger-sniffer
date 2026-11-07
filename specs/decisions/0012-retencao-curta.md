# 0012 — Retenção curta, logs e sem backup

Status: aceita
Data: 2026-11-07

## Contexto
O documento de origem pedia ≥ 24 h; o usuário pediu 10 min configuráveis. A VPS tem 22 GB livres e o servidor é
público.

## Decisão
- Pacotes e registros: `FS_RETENTION` = 10 min e `FS_STORE_MAX_BYTES` = 2 GiB; o primeiro limite atingido expurga
  o mais antigo.
- journald: 24 h / 200 MB; logs sem payload; nível `info` (`FS_LOG_LEVEL`).
- Site sem cookies.
- **Sem backup** (dados efêmeros, código no Git).

## Alternativas consideradas
- 24 h; só tempo sem teto; journald 7 dias / 500 MB; backup diário de certificados e conta ACME.

## Consequências
- Clientes precisam consultar a API logo após cada teste.
- Reinstalar a VPS exige nova emissão de certificados (risco de rate limit do Let's Encrypt).
