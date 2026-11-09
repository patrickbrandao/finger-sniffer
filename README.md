# finger-sniffer

Servidor espelho de análise de conexões. Ele recebe conexões em portas capturadas (HTTP/1.x, h2, h3/QUIC,
WebSocket, TLS, TCP cru e DNS autoritativo), registra **como** os pacotes e as conexões chegaram (IP, TCP, TLS,
HTTP, DNS e tempos) e devolve tudo, cru e analisado, por uma API em portas que não são capturadas.

Serve para qualquer cliente descobrir se o seu tráfego é interceptado e com quais características ele chega ao
servidor: a mesma sondagem, repetida por caminhos diferentes (direto, por um proxy, por uma VPN), mostra o que cada
caminho mudou. O consumidor principal é o teste de não-interferência do go-xproxy.

Instância pública: `vps602.tmsoft.com.br`, zona de sondagem `<id>.dns-monitor.tmsoft.com.br`. A página
`https://vps602.tmsoft.com.br/` mostra o feed global ao vivo.

> **Todo o tráfego é público.** Qualquer pessoa lê pela API, por cerca de **10 minutos**, o que chegou às portas
> capturadas, inclusive cabeçalhos, cookies e corpos. Não mande segredos ao espelho. Para apagar antes do prazo:
> `DELETE /api/v1/probes/<id>`.

## Portas

| Porta | Uso |
| --- | --- |
| TCP 80, 443, 8080, 8443 | web: HTTP/1.x, h2, h2c, WebSocket, TLS em qualquer uma (protocolo detectado pelos primeiros bytes) |
| UDP 443 | QUIC / HTTP/3 |
| TCP 7, 21, 22, 25, 110, 143, 587, 993 | portas cruas: eco, banner, sink, source; TLS na 993 |
| UDP e TCP 53 | DNS autoritativo de `dns-monitor.tmsoft.com.br` |
| TCP 9000 (HTTPS), 9001 (HTTP) | API, tempo real (SSE e WebSocket) e `/metrics` (só 9001); **não capturadas**; escutam só em `127.0.0.1` e nos IPs públicos (`FS_LISTEN_IPV4`/`FS_LISTEN_IPV6`) |

## Sondar em 3 comandos

```sh
id=$(LC_ALL=C tr -dc 'a-z0-9' </dev/urandom | head -c 12)
curl -s "https://$id.dns-monitor.tmsoft.com.br/p/$id/"
curl -s "https://vps602.tmsoft.com.br:9000/api/v1/probes/$id?wait=10s" | jq .
```

O probe ID (8 a 32 caracteres `[a-z0-9]`) vai no nome e no caminho; o registro junta a consulta DNS, a conexão
TCP, o ClientHello, a requisição HTTP e a resposta mandada. `?wait=10s` espera a conexão fechar. Receitas para
cada caso (HTTP/1, h2, h3, WebSocket, portas cruas, DNS, respostas provocadas) e a lista de campos estáveis para
comparar caminhos estão em [docs/probes.md](docs/probes.md).

## Documentação

- [docs/](docs/README.md): uso da API, sondagens, tempo real, HTTP/3 e métricas (derivada das specs).
- [specs/](specs/INDEX.md): especificações, a fonte da verdade; decisões em
  [specs/decisions/HISTORY.md](specs/decisions/HISTORY.md).
- Contratos: API HTTP em [openapi.yaml](cmd/finger-sniffer-store/openapi.yaml) (OpenAPI 3.1, também em
  `/api/v1/openapi.yaml`), eventos NATS em [asyncapi.yaml](eventbus/nats/asyncapi.yaml) (AsyncAPI 3.0).
- [CHANGELOG.md](CHANGELOG.md).

## Arquitetura em uma linha

Cinco serviços Go estáticos (capture, web, raw, dns, store) e um NATS JetStream, em units systemd numa única VM:
o capture lê a `eth0` por AF_PACKET, os serviços de protocolo publicam o que viram, e o store correlaciona tudo
por conexão e probe num SQLite com retenção curta. Detalhes na [spec 001](specs/001-arquitetura.md).

## Desenvolvimento

Requisitos: Go 1.27, `make`, `ssh` para a vps602 (deploy e testes Linux).

```sh
make tools          # golangci-lint, gofumpt, goose, lefthook, govulncheck
make build          # 5 binários linux/amd64 estáticos em ./bin/
make verify-quick   # padrão: lint, vet e testes só do que mudou desde a main
make verify-full    # tudo: -race, contratos, govulncheck, build, testes Linux na vps602
make deploy         # implanta na vps602 (make deploy SVC=web para um serviço)
```

O trabalho é organizado em tarefas, papéis e Definition of Done ([spec 002](specs/002-organizacao-do-trabalho.md));
os dois níveis de verificação e a matriz de testes estão na [spec 017](specs/017-verificacao.md). Instruções para
agentes em [AGENTS.md](AGENTS.md).

## Licença

[Apache-2.0](LICENSE). Veja [NOTICE](NOTICE) para os créditos (fingerproxy, JA4 da FoxIO, JA3 da Salesforce).

JA4T e JA4H ficam isolados em [pkg/fingerprint/ja4plus](pkg/fingerprint/ja4plus/LICENSE-FoxIO-1.1), sob a
**FoxIO License 1.1**, que restringe uso comercial: quem usa esses métodos comercialmente pode precisar de licença
da FoxIO ([ADR 0010](specs/decisions/0010-licenca-apache-e-ja4plus.md)). O banco de assinaturas do p0f (LGPL-2.1)
é baixado no deploy e não faz parte do binário.
