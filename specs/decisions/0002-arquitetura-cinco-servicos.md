# 0002 — Arquitetura de cinco serviços, um binário cada

Status: aceita
Data: 2026-11-07

## Contexto
A análise junta duas fontes no mesmo `conn_id` (captura e aplicação). A VPS tem 1 vCPU e 967 MiB.

## Decisão
Um serviço por protocolo, cada um com sua unit systemd e seu binário:
capture, web (TCP 80/443/8080/8443 + UDP 443), raw (TCP 7/21/22/25/110/143/587/993), dns (53), store (dados,
correlação, análise IP/TCP, API 9000/9001). Binários em `cmd/finger-sniffer-<svc>`; um único `go.mod`; código comum
em `pkg/`. Detecção por primeiros bytes numa biblioteca comum usada por web e raw.

## Alternativas consideradas
- Monólito modular num binário (recomendado na entrevista: menos IPC e RAM) — rejeitado pelo usuário.
- Dois processos (captura + servidor); separar API do store; separar web por protocolo.
- Um binário com subcomandos — rejeitado (preferência por 1 binário por serviço).

## Consequências
- Correlação exige barramento (ADR 0003) e um envelope comum versionado.
- Risco de versões desencontradas no deploy: mitigado por versão única no envelope, deploy de todos juntos e
  alerta no health.
- Mais RAM total; limites `MemoryMax` por serviço (ADR 0005).
