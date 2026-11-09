# 0010 — Licença Apache-2.0 e isolamento do JA4+

Status: aceita
Data: 2026-11-07

## Contexto
Código de referência: fingerproxy (Apache-2.0), JA4 TLS da FoxIO (BSD-3), JA3 da Salesforce (BSD-3).
JA4+ (JA4T, JA4H, JA4S, JA4X…) está sob a FoxIO License 1.1, que restringe uso comercial. O banco `p0f.fp` é
LGPL-2.1.

## Decisão
- finger-sniffer sob **Apache-2.0**, com `NOTICE` creditando fingerproxy, FoxIO e Salesforce.
- JA4T e JA4H em pacote isolado `pkg/fingerprint/ja4plus` com o aviso da FoxIO License 1.1 no diretório.
- `p0f.fp` como arquivo de dados externo (`/finger-sniffer/etc/p0f.fp`), baixado no deploy, não embutido no binário.

## Alternativas consideradas
- MIT; proprietária.

## Consequências
- Uso comercial de JA4T/JA4H por terceiros pode exigir licença da FoxIO.
