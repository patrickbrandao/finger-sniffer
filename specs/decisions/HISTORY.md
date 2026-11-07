# Histórico de decisões

Índice das ADRs. Consulte antes de propor mudanças de stack, arquitetura ou processo. Uma decisão aceita só é
reaberta diante de um fato novo, com uma nova ADR que a substitui.

| ADR | Título | Status | Conteúdo |
| --- | --- | --- | --- |
| [0001](0001-decisoes-iniciais.md) | Decisões iniciais (agrupadas) | aceita | nome, escopo genérico, uso do fingerproxy como referência, MVP com h3, metas numéricas, fora de escopo, rotas, tetos, modos raw, tipos DNS, endereços, SemVer, compatibilidade, config, observabilidade, ambiente único, ameaças, sem limite por IP |
| [0002](0002-arquitetura-cinco-servicos.md) | Cinco serviços, um binário cada | aceita | capture, web, raw, dns, store; units e binários próprios |
| [0003](0003-nats-jetstream.md) | NATS local com JetStream | aceita | barramento, subjects fs.v1, stream FS_EVENTS, buffer do produtor |
| [0004](0004-pacotes-pelo-nats.md) | Pacotes pelo NATS; IP/TCP no store | provisória | todos os pacotes publicados; store analisa; captura inclui tráfego do servidor |
| [0005](0005-sqlite-com-blobs.md) | SQLite com BLOBs e goose | provisória | modernc sqlite, BLOBs, migrations, teto 2 GiB, MemoryMax |
| [0006](0006-portas-e-api-sem-captura.md) | Portas capturadas e API sem captura | aceita | lista de portas, 9000 HTTPS / 9001 HTTP, exclusões do BPF |
| [0007](0007-api-aberta-e-feed-global.md) | API aberta e feed global | aceita | sem autenticação, feed global, risco de dados de terceiros |
| [0008](0008-zona-dns-e-acme.md) | Zona dos probes e ACME embutido | aceita | dns-monitor, certmagic, DNS-01 próprio, HTTP-01, falhas |
| [0009](0009-stack-go-estatico.md) | Stack Go estático | aceita | Go 1.27, HTTP/1 próprio, h2 passivo, quic-go, lista de dependências, sem Docker, GitHub |
| [0010](0010-licenca-apache-e-ja4plus.md) | Licença Apache-2.0 e JA4+ | aceita | Apache-2.0, NOTICE, JA4T/JA4H isolados, p0f.fp externo |
| [0011](0011-rede-offloads-e-pilha-tcp.md) | Offloads e pilha TCP | aceita | offloads off, verificação MTU+14, sysctls fixados, sem conntrack |
| [0012](0012-retencao-curta.md) | Retenção curta, logs e sem backup | aceita | 10 min / 2 GiB, journald 24 h / 200 MB, sem backup |
| [0013](0013-verificacao-dois-niveis.md) | Verificação em dois níveis | aceita | verify quick/full, níveis de teste, cobertura, lint, CI, deploy local |
| [0014](0014-organizacao-agentes.md) | Organização dos agentes | aceita | Claude Code, 10 papéis, propriedade, Git, DoD, escalonamento |
