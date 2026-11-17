# Documentação do finger-sniffer

Documentação de uso, derivada das [specs](../specs/INDEX.md) (a fonte da verdade) e do contrato
[openapi.yaml](../cmd/finger-sniffer-store/openapi.yaml). Em caso de divergência, valem as specs e o contrato.

O finger-sniffer é um espelho de análise de conexões: recebe conexões nas portas capturadas do servidor
`finger-01.badblock.net.br` (HTTP/1.x, h2, h3/QUIC, WebSocket, TLS, TCP cru, DNS autoritativo de
`finger-west-01.badblock.net.br`), registra **como** os pacotes e as conexões chegaram e devolve tudo, cru e
analisado, por uma API em portas que não são capturadas.

> **Todo o tráfego é público.** Qualquer pessoa lê pela API o que chegou às portas capturadas, inclusive
> cabeçalhos, cookies e corpos. Não mande segredos. Os registros duram cerca de 10 minutos. O espelho captura
> toda a interface do servidor, inclusive o tráfego dos sites atrás do traefik do host.

## Servidor, nomes e portas

Valores da [ADR 0038](../specs/decisions/0038-servidor-finger-01-e-coexistencia-com-o-traefik.md) e da
[ADR 0039](../specs/decisions/0039-limites-e-metas-no-finger-01.md).

| Item | Valor |
| --- | --- |
| Servidor | `finger-01.badblock.net.br` (para ssh também `finger-01.tmsoft.com.br`, que fica com o traefik do host), IPv4 `170.247.40.86`, IPv6 `2804:231c:e500:cafe::86`; interface capturada `ens192` |
| Zona dos probes | `finger-west-01.badblock.net.br`, delegada para `finger-01.badblock.net.br`; probe em `<id>.finger-west-01.badblock.net.br` |
| API | `https://finger-01.badblock.net.br:9000` e `http://finger-01.badblock.net.br:9001`, diretas (nunca pelo traefik, nunca capturadas) |
| Web do espelho | TCP **8080** e **8443** (protocolo pelos primeiros bytes: TLS na 8080 e HTTP em claro na 8443 também funcionam), UDP **8443** para QUIC/HTTP/3 |
| Alt-Svc | `h3=":8443"; ma=60` nas respostas sobre TLS, enquanto o listener UDP está de pé |
| HTTPS RR | em `_8443._https.<nome>` (e `_8080._https.<nome>`), RFC 9460 §2.3; o nome sem prefixo responde NODATA, porque a 443 é do traefik |
| Raw e DNS | TCP 7, 21, 22, 25, 110, 143, 587, 993; UDP e TCP 53 |
| Do traefik | TCP 80, 443 e 8081, UDP 443: capturadas como tráfego alheio; a página também é servida em `https://finger-01.badblock.net.br/` por passthrough TLS para a 8443 |

Toda sondagem web leva a porta explícita: `https://<id>.finger-west-01.badblock.net.br/` sem porta cai no traefik.

### Certificados

- **A**: `finger-west-01.badblock.net.br` e `*.finger-west-01.badblock.net.br`, por DNS-01 no dns do espelho.
- **B**: só `finger-01.badblock.net.br` (ADR 0044), por TLS-ALPN-01 (a validação chega à 8443 pelo
  passthrough do traefik). A API na 9000 escolhe por SNI: A para nomes da zona, B para `finger-01.badblock.net.br`.
- `*.finger-01.badblock.net.br` não tem certificado válido (o curinga fica na zona do provedor).

### Limites

- As 7 units ficam em `finger-sniffer.slice` com `MemoryMax=10G` e `CPUQuota=800%`; por unit, `MemoryMax` store 6G
  (com o tmpfs de 4G do banco, [ADR 0045](../specs/decisions/0045-banco-do-store-em-ram.md)), nats 1G, web 768M,
  capture 512M, raw 256M e dns 256M.
- Modo degradado: `FS_MAX_CONNS=1000` e `FS_MAX_NEW_CONNS_PER_S=250`; garantia do RNF-01: 400 conexões simultâneas
  e 100 novas/s com análise completa ([ADR 0046](../specs/decisions/0046-rnf-01-400-100-com-o-banco-em-ram.md)).
- Limite conhecido da `v0.3.0` no finger-01 (ADR 0043), **resolvido na F7**: na `v0.3.0` a garantia era 200/50 e, a
  200/50, feed p99 ~1,9 s e registro p95 ~1,5 s (metas < 1 s e ≤ 500 ms), por IO do disco da VM. Com o banco do store
  em RAM (ADR 0045), a carga oficial a 400/100 deu feed p99 352 ms e registro p95 TCP 193 / QUIC 188 ms (ADR 0046).
- Orçamento de entrada do web (`FS_WEB_INPUT_BUDGET`): 192 MiB (faixa 8–256 MiB).
- Banco do store (`FS_STORE_MAX_BYTES`): 3 GiB num tmpfs de 4G (ADR 0045); retenção de 10 min; stream `FS_EVENTS` de 128 MiB.
  O tmpfs some no reinício do host (probes anteriores dão 404); com o tmpfs quase cheio o store fica `degraded`
  com `db space <n>% free` ou `db full` (veja [api.md](api.md#saúde) e [metrics.md](metrics.md)).

### Valores do host que moldam a resposta

O espelho não fixa estes sysctls do host, e eles aparecem no que o cliente vê do servidor:
`net.ipv4.ip_default_ttl=128` (TTL IPv4 dos pacotes do espelho), `net.ipv4.tcp_mtu_probing=1`,
`rmem_default`/`wmem_default` de 30 MiB e `tcp_no_metrics_save=1`. O health lê os sysctls do kernel (veja
[api.md](api.md#saúde)).

## Guias

| Documento | Conteúdo |
| --- | --- |
| [api.md](api.md) | Portas 9000/9001, rotas, filtros, long-poll `wait`, pcap e bytes crus, erros, retenção |
| [probes.md](probes.md) | Como sondar com um probe ID; `Date` e controles de resposta; uma receita por caso da matriz (1–13) com campos estáveis e diferenças esperadas por caminho (proxy HTTP, túnel CONNECT, HTTPS-proxy) para o cliente comparar |
| [realtime.md](realtime.md) | Feed ao vivo: `/api/v1/stream` (SSE) e `/api/v1/ws` (WebSocket), tipos de evento, filtros, descarte |
| [http3.md](http3.md) | O que o registro `http3` traz (Initial, parâmetros de transporte, JA4 `q`, QPACK) e como forçar h3 |
| [bot.md](bot.md) | API de vereditos de bot (portas 9002/9003): classes, sinais, chaves, rotas, feed, webhook com verificação da assinatura, integração com o traefix e por probe, retenção de 7 dias |
| [metrics.md](metrics.md) | Métricas Prometheus em `/metrics` (porta 9001), inclusive as `fs_bot_*` |

## Para quem desenvolve

- [dev/README.md](dev/README.md): índice do que é de desenvolvimento (spike de carga da F1, teste de carga da F5).
- Visão geral do repositório e comandos: [README de raiz](../README.md).
- Organização do trabalho, papéis e Definition of Done: [specs/002](../specs/002-organizacao-do-trabalho.md).
- Verificação (`make verify-quick`, `make verify-full`): [specs/017](../specs/017-verificacao.md).

## Site

A página em `https://finger-01.badblock.net.br/` (pelo traefik, passthrough para a 8443) ou direto em
`https://<nome>:8443/` (spec 014) mostra o feed global ao vivo, o detalhe de cada conexão e um botão "Run probe",
que sonda `<id>.finger-west-01.badblock.net.br` na 8443 (duas vezes, a segunda por h3) e na 8080 (só com a página
em `http:`). Ela é servida pelas portas capturadas, mas busca os dados na API da porta 9000. Pelo traefik, a
conexão da página chega ao web pela bridge do Docker (`ip.src_kind=private`), sem pacotes capturados.
