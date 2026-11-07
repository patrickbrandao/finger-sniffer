# 0004 — Todos os pacotes pelo NATS; análise IP/TCP no store

Status: provisória (revisar se o spike de carga da task 006 ou o teste de carga da F5 não atingir RNF-01..04 da
spec 000 por CPU/RAM do NATS ou do store)
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
