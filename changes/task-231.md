- Primeiro deploy no finger-01 (`v0.2.1-68-g7fb82fb`): bootstrap sem passo manual, 7 units na fatia com os limites da
  ADR 0039, offloads desligados, sysctls aplicados e smoke verde; deploy seguinte idempotente. Certificado A
  (`finger-west-01.badblock.net.br` e curinga) por DNS-01 do nosso dns: LE staging e depois produção (1 emissão).
