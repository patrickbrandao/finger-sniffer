- docs/bot.md: forwardAuth do bot (ADR 0058) com `fingerSniffer`, `apiKey` por site, `failOpen` de 4xx sem `X-Fs-Verdict` e
  `X-Fs-Ja4h`; contrato 0.2.0, regras `v1.2` (JA4T sem MSS no `known_client`) e limitação da primeira requisição só
  com traefix sem `X-Fs-Ja4h` (task 293).
