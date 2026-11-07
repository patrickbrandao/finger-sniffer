# 015 — ACME e certificados

Status: aprovada
Depende de: 005, 007

## Contexto
Com certificado válido nenhum cliente precisa de `-k`, e clientes que imitam navegadores se comportam como
navegadores. Somos autoritativos de `dns-monitor`, então o DNS-01 é respondido pelo nosso próprio dns.

## Requisitos
- RF-01: ACME embutido no web com certmagic (sem certbot), CA `FS_ACME_CA` (Let's Encrypt produção na vps602).
- RF-02: certificado A (DNS-01): `dns-monitor.tmsoft.com.br`, `*.dns-monitor.tmsoft.com.br`
  (`FS_CERT_NAMES_DNS01`). Provedor DNS-01 próprio (interface libdns) que chama `fs.v1.dns.acme.set|clear`.
- RF-03: certificado B (HTTP-01 na porta 80): `vps602.tmsoft.com.br`, `fingerprint.tmsoft.com.br`,
  `tcp.tmsoft.com.br`, `udp.tmsoft.com.br` (`FS_CERT_NAMES_HTTP01`). Escolha por SNI.
- RF-04: armazenamento em `FS_CERT_DIR` (`var/certs`) e conta em `var/acme`; web, raw e store leem os mesmos
  arquivos com recarga a quente (fsnotify, técnica do certwatcher do fingerproxy).
- RF-05: renovação automática (30 dias antes). Falha: mantém o anterior; sem nenhum, gera autoassinado; tenta de
  novo com backoff até 1 h. Health `degraded` se faltar < 14 dias para expirar ou se estiver autoassinado.
- RF-06: no máximo 3 emissões de produção por semana sem perguntar ao humano (spec 002); testes automatizados
  usam Pebble (local) ou LE staging.
- RF-07: sem certificado para nomes desconhecidos: usa o B como padrão.

## Interfaces e contratos
- NATS request `fs.v1.dns.acme.set|clear` ([asyncapi.yaml](../eventbus/nats/asyncapi.yaml)).
- Estado do certificado em `/api/v1/health`.

## Critérios de aceite
- [ ] `curl https://abcdefgh.dns-monitor.tmsoft.com.br/` sem `-k` funciona.
- [ ] `curl https://vps602.tmsoft.com.br:9000/api/v1/health` sem `-k` funciona.
- [ ] Teste com Pebble cobre emissão, renovação e falha → autoassinado.

## Fora de escopo
- Certificados de cliente (mTLS).

## Decisões relacionadas
- specs/decisions/0008-zona-dns-e-acme.md
- specs/decisions/0012-retencao-curta.md
