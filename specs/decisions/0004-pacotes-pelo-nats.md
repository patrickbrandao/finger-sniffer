# 0004 — Todos os pacotes pelo NATS; análise IP/TCP no store

Status: aceita (confirmada pelo spike da task 006 em 2026-11-07: CPU média de 22% a 50 conexões/s; ver
`docs/dev/spike-carga.md`)
Data: 2026-11-07

## Contexto
A captura precisa chegar ao store para montar pcap e análise TCP. Em 1 vCPU, cada pacote como mensagem tem custo.

## Decisão
- O capture publica **todos os pacotes** (em lotes de até 5 ms / 256 pacotes) em `fs.v1.capture.packet`.
- O **store calcula** a análise IP/TCP (spec 013) e monta o pcap de cada conexão.
- Captura inclui fluxos iniciados pelo próprio servidor; excluem-se só as portas 48022, 48161, 9000, 9001.

## Alternativas consideradas
- capture grava pcap em disco e publica só análises (recomendado) — rejeitado pelo usuário.
- capture calcula IP/TCP e store só correlaciona (recomendado) — rejeitado pelo usuário.
- Excluir fluxos iniciados pelo servidor (recomendado) — rejeitado pelo usuário.

## Consequências
- Store é o serviço mais pesado; o spike da F1 mede se cabe.
- Se não couber, a ADR substituta deve, nesta ordem: mover a análise IP/TCP para o capture; gravar pcaps no capture.
