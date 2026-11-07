# 0008 — Zona dos probes e ACME embutido

Status: aceita
Data: 2026-11-07

## Contexto
Nomes disponíveis: `vps602`, `*.vps602`, CNAMEs `fingerprint`, `tcp`, `udp` (zona tmsoft.com.br no udns.com.br) e
`dns-monitor` delegada (NS) para vps602 — delegação conferida em 2026-11-07.

## Decisão
- Zona principal dos probes: `<id>.dns-monitor.tmsoft.com.br`; nosso dns responde A/AAAA (TTL 5 s) e HTTPS RR.
  A mesma sondagem passa pelo DNS e chega no HTTP/TLS com o mesmo nome.
- Nomes alternativos (`*.vps602`, `vps602`, `fingerprint`, `tcp`, `udp`) funcionam, sem log DNS.
- ACME embutido no web com certmagic: `*.dns-monitor` + apex por DNS-01 respondido pelo nosso dns (request NATS);
  `vps602`/`fingerprint`/`tcp`/`udp` por HTTP-01. Sem certbot.
- Falha: mantém o anterior; sem nenhum, autoassinado; backoff até 1 h; health `degraded`.

## Alternativas consideradas
- `*.vps602` como zona principal; certbot + hook; autoassinado.

## Consequências
- Nenhum cliente precisa de `-k`.
- Dependência do udns apenas para a delegação e nomes alternativos.
