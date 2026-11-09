# 0018 — Tamanho dos eventos de aplicação e bytes completos pelo fluxo

Status: aceita
Data: 2026-11-08

## Contexto
`nats.conf` tem `max_payload: 1MB` e o stream `FS_EVENTS` tem 32 MiB em memória (ADR 0016). As specs pedem, dentro
de um único evento `fs.v1.web.http1.request`, o cabeçalho cru (até 1 MiB, spec 009 RF-10), o corpo cru (até
`FS_RAW_BODY_MAX_BYTES` = 1 MiB, spec 009 RF-03) e a resposta enviada (cabeçalho até 1 MiB por `hsize`, corpo até
64 MiB por `size`), tudo em base64 (+33%). Um evento assim não passa no NATS, e respostas de dezenas de MiB
encheriam o stream e descartariam pacotes de outras conexões.

## Decisão
- **Nenhum evento JSON passa de 900 KiB.** O produtor garante o teto.
- Campos inline de bytes crus (`raw_head_b64`, `body.raw_b64`, `response_sent_b64`, `client_hello_b64`, `raw_b64`
  do DNS) levam no máximo **`FS_EVENT_INLINE_MAX` (128 KiB) de bytes crus cada**; acima disso o campo é cortado e
  marcado `*_truncated: true`. `FS_RAW_BODY_MAX_BYTES` passa a valer 128 KiB por padrão e nunca acima de
  `FS_EVENT_INLINE_MAX`.
- Listas analisadas longas (campos de cabeçalho, pedaços chunked, frames h2 e WebSocket) são cortadas para caber no
  teto, com `fields_truncated`/`frames_truncated`.
- Os **bytes completos** de cada sentido vão pelo fluxo de aplicação (`fs.v1.web.stream.bytes` e `fs.v1.raw.read`),
  em pedaços de até 64 KiB, até **`FS_RAW_STREAM_MAX_BYTES` (16 MiB) por sentido e por conexão** (o mesmo teto do
  pcap); passado o teto, o produtor manda um último pedaço vazio com `truncated: true` e para.
- Cada requisição HTTP/1 registra `in_offset` e `out_offset`: onde começam a requisição e a resposta nos fluxos
  `in` e `out`, para que `GET /connections/{id}/raw?dir=` devolva os bytes exatos mesmo quando o inline foi cortado.
- `response_sent_size` registra o tamanho total da resposta enviada.
- O modo degradado (spec 004 RF-11) continua valendo: nele o store não guarda os fluxos.

## Alternativas consideradas
- Subir `max_payload` para 8 MB: cabem os campos, mas poucos eventos encheriam o stream de 32 MiB e o web (96M de
  `MemoryMax`) teria picos de memória de vários MiB por requisição.
- Mandar bytes grandes por um canal fora do NATS (arquivo compartilhado): mais um caminho de dados e de falha.

## Consequências
- Para cabeçalhos ou corpos acima de 128 KiB, quem quer os bytes exatos lê `/raw?dir=` pelo offset; o registro
  analisado continua completo até o teto de 900 KiB.
- O fluxo `out` de respostas acima de 16 MiB (`size=` até 64 MiB) fica truncado, como o pcap.
