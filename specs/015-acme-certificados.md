# 015 — ACME e certificados

Status: aprovada
Depende de: 005, 007

## Contexto
Com certificado válido nenhum cliente precisa de `-k`, e clientes que imitam navegadores se comportam como
navegadores. Somos autoritativos de `finger-west-01.badblock.net.br`, então o DNS-01 é respondido pelo nosso
próprio dns. A porta 80 do servidor é do traefik do host (ADR 0038), então os nomes fora da zona usam TLS-ALPN-01,
que o traefik entrega ao web por passthrough.

## Requisitos
- RF-01: ACME embutido no web com certmagic (sem certbot), CA `FS_ACME_CA` (Let's Encrypt produção no finger-01,
  depois de validar com a LE staging).
  O ACME só roda com `FS_ACME_ENABLE=1` (padrão `0`): sem ele, o web usa os certificados que já estiverem em
  `FS_CERT_DIR` ou o autoassinado. Isso protege o limite de emissões (RF-06) contra deploys de código ACME ainda
  em teste; a emissão de produção é um passo explícito.
- RF-02: certificado A (DNS-01): `finger-west-01.badblock.net.br`, `*.finger-west-01.badblock.net.br`
  (`FS_CERT_NAMES_DNS01`). Provedor DNS-01 próprio (interface libdns) que chama `fs.v1.dns.acme.set|clear`.
- RF-03: certificado B: `finger-01.badblock.net.br`, `finger-01.tmsoft.com.br` (`FS_CERT_NAMES_HTTP01`, nome
  mantido por compatibilidade), por **TLS-ALPN-01** (RFC 8737): o web responde `acme-tls/1` com o certificado de
  desafio em qualquer porta TLS; a validação chega pela 443 do traefik, que encaminha esses nomes por passthrough
  para a 8443 (ADR 0038). HTTP-01 só quando `FS_WEB_TCP_PORTS` contém 80 (não é o caso do finger-01); o certmagic
  nunca abre listener próprio. Escolha por SNI.
- RF-04: o certmagic guarda o próprio estado (conta, chaves, certificados, travas) em `FS_ACME_DIR`
  (`var/acme`). A cada emissão ou renovação, o web **exporta** o certificado em PEM para `FS_CERT_DIR`
  (`var/certs`) com nomes fixos: `dns01.crt`/`dns01.key` (A) e `http01.crt`/`http01.key` (B); `.crt` com a cadeia
  completa, `.key` com modo 0600; escrita atômica (arquivo temporário + rename, a chave antes do certificado).
  Web, raw e store leem só `FS_CERT_DIR`, pelo pacote comum `pkg/certs`, com recarga a quente (fsnotify, técnica do
  certwatcher do fingerproxy). `pkg/certs` também tem a configuração TLS fixa do servidor (spec 008 RF-06), a
  escolha por SNI (RF-07), o autoassinado em memória quando falta arquivo e o estado dos certificados para o
  health (`host.certificates`, `host.tls_server`). Um par que continua inválido é relido com espera dobrando (de
  0,5 s até o intervalo de varredura), zerada na recarga bem-sucedida ou em evento de um dos arquivos, e o aviso
  sai uma vez por erro distinto.
- RF-05: renovação automática (30 dias antes). Falha: mantém o anterior; sem nenhum, gera autoassinado; tenta de
  novo com backoff até 1 h. Health `degraded` se faltar < 14 dias para expirar ou se estiver autoassinado.
- RF-06: no máximo 3 emissões de produção por semana sem perguntar ao humano (spec 002); testes automatizados
  usam Pebble (local) ou LE staging.
- RF-07: sem certificado para nomes desconhecidos: usa o B como padrão.

## Interfaces e contratos
- NATS request `fs.v1.dns.acme.set|clear` ([asyncapi.yaml](../eventbus/nats/asyncapi.yaml)).
- Estado do certificado em `/api/v1/health`.

## Critérios de aceite
- [ ] `curl https://abcdefgh.finger-west-01.badblock.net.br:8443/` sem `-k` funciona.
- [ ] `curl https://finger-01.badblock.net.br:9000/api/v1/health` sem `-k` funciona.
- [ ] `curl https://finger-01.badblock.net.br/` (pelo traefik) sem `-k` mostra a página com o certificado B.
- [ ] Teste com Pebble cobre emissão (DNS-01 e TLS-ALPN-01), renovação e falha → autoassinado.

## Fora de escopo
- Certificados de cliente (mTLS).

## Decisões relacionadas
- specs/decisions/0008-zona-dns-e-acme.md
- specs/decisions/0012-retencao-curta.md
- specs/decisions/0038-servidor-finger-01-e-coexistencia-com-o-traefik.md
