# Documentação do finger-sniffer

Documentação de uso, derivada das [specs](../specs/INDEX.md) (a fonte da verdade) e do contrato
[openapi.yaml](../cmd/finger-sniffer-store/openapi.yaml). Em caso de divergência, valem as specs e o contrato.

O finger-sniffer é um espelho de análise de conexões: recebe conexões nas portas capturadas de
`vps602.tmsoft.com.br` (HTTP/1.x, h2, h3/QUIC, WebSocket, TLS, TCP cru, DNS autoritativo de
`dns-monitor.tmsoft.com.br`), registra **como** os pacotes e as conexões chegaram e devolve tudo, cru e analisado,
por uma API em portas que não são capturadas.

> **Todo o tráfego é público.** Qualquer pessoa lê pela API o que chegou às portas capturadas, inclusive
> cabeçalhos, cookies e corpos. Não mande segredos. Os registros duram cerca de 10 minutos.

## Guias

| Documento | Conteúdo |
| --- | --- |
| [api.md](api.md) | Portas 9000/9001, rotas, filtros, long-poll `wait`, pcap e bytes crus, erros, retenção |
| [probes.md](probes.md) | Como sondar com um probe ID: HTTP/1, h2, h3, WebSocket, portas cruas, DNS e controles de resposta; receita do go-xproxy |
| [realtime.md](realtime.md) | Feed ao vivo: `/api/v1/stream` (SSE) e `/api/v1/ws` (WebSocket), tipos de evento, filtros, descarte |
| [http3.md](http3.md) | O que o registro `http3` traz (Initial, parâmetros de transporte, JA4 `q`, QPACK) e como forçar h3 |
| [metrics.md](metrics.md) | Métricas Prometheus em `/metrics` (porta 9001) |

## Para quem desenvolve

- [dev/spike-carga.md](dev/spike-carga.md): relatório do spike de carga da F1 (NATS e SQLite com BLOBs).
- Organização do trabalho, papéis e Definition of Done: [specs/002](../specs/002-organizacao-do-trabalho.md).
- Verificação (`make verify-quick`, `make verify-full`): [specs/017](../specs/017-verificacao.md).

## Site

A página em `https://vps602.tmsoft.com.br/` (spec 014) mostra o feed global ao vivo, o detalhe de cada conexão e um
botão "Run probe". Ela é servida pelas portas capturadas, mas busca os dados na API da porta 9000.
