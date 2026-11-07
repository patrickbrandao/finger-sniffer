# 0015 — Lote de pacotes em formato binário (FSPB v1)

Status: aceita
Data: 2026-11-07

## Contexto
A ADR 0004 manda todos os pacotes pelo NATS em lotes (até 5 ms / 256 pacotes). Em JSON, cada frame iria em
base64 (+33% de bytes) e custaria codificação/decodificação de texto nos dois lados, em 1 vCPU, no subject de
maior volume do sistema. A task 004 pediu decidir JSON × binário.

## Decisão
- `fs.v1.capture.packet` usa corpo binário **FSPB v1** (little-endian), sequência de registros:
  `ts_ns u64 | dir u8 | flags u8 | reserved u16 | wire_len u32 | cap_len u32 | frame[cap_len]`
  (cabeçalho de 20 bytes; frame Ethernet completo; `flags` bit0 = offload_suspect, bit1 = truncado).
- O envelope vai nos cabeçalhos NATS: `Fs-Schema-Version: 1`, `Fs-Service: capture`, `Fs-Service-Version`,
  `Fs-Format: fspb1`, `Fs-Count`, `Fs-Iface`.
- Todos os outros subjects continuam JSON com o `Envelope` comum.
- Contrato detalhado em `eventbus/nats/asyncapi.yaml` (mensagem `PacketBatch`).

## Alternativas consideradas
- JSON com frames em base64 — mais simples de inspecionar, mais CPU e bytes.
- pcap/pcapng por mensagem — formato conhecido, mas sem campo de direção e com cabeçalho de arquivo repetido.
- Protobuf/CBOR — exigiria dependência fora da lista da ADR 0009.

## Consequências
- Menos CPU e ~25% menos bytes no NATS; o spike (task 006) mede com este formato.
- Inspecionar o subject exige um decodificador (o `pkg/event` fornece encode/decode e testes).
- Mudança de layout exige `Fs-Format: fspb2` convivendo com o v1 (ADR 0001).
