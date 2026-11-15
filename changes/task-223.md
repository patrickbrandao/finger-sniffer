- specs: servidor finger-01 e coexistência com o traefik do host (ADR 0038, decisão do humano): zona dos probes
  `finger-west-01.badblock.net.br`, API em `finger-01.badblock.net.br:9000/9001`, web em TCP 8080/8443 e UDP 8443,
  HTTPS RR com prefixo de porta, certificado B por TLS-ALPN-01, captura da `ens192` inteira; limites por unit, fatia
  de 6G/800%, orçamento do web de 192 MiB e RNF-01 de 400/100 (ADR 0039); contratos openapi 0.6.1 e asyncapi 0.5.1
  documentais (task 223).
