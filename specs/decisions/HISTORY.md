# Histórico de decisões

Índice das ADRs. Consulte antes de propor mudanças de stack, arquitetura ou processo. Uma decisão aceita só é
reaberta diante de um fato novo, com uma nova ADR que a substitui.

| ADR | Título | Status | Conteúdo |
| --- | --- | --- | --- |
| [0001](0001-decisoes-iniciais.md) | Decisões iniciais (agrupadas) | aceita | nome, escopo genérico, uso do fingerproxy como referência, MVP com h3, metas numéricas, fora de escopo, rotas, tetos, modos raw, tipos DNS, endereços, SemVer, compatibilidade, config, observabilidade, ambiente único, ameaças, sem limite por IP |
| [0002](0002-arquitetura-cinco-servicos.md) | Cinco serviços, um binário cada | aceita | capture, web, raw, dns, store; units e binários próprios |
| [0003](0003-nats-jetstream.md) | NATS local com JetStream | aceita (stream: ver 0016; subjects: ver 0017) | barramento, subjects fs.v1, stream FS_EVENTS, buffer do produtor |
| [0004](0004-pacotes-pelo-nats.md) | Pacotes pelo NATS; IP/TCP no store | aceita | todos os pacotes publicados; store analisa; captura inclui tráfego do servidor (confirmada pelo spike) |
| [0005](0005-sqlite-com-blobs.md) | SQLite com BLOBs e goose | aceita | modernc sqlite, BLOBs, migrations, teto 2 GiB, MemoryMax |
| [0006](0006-portas-e-api-sem-captura.md) | Portas capturadas e API sem captura | aceita | lista de portas, 9000 HTTPS / 9001 HTTP, exclusões do BPF |
| [0007](0007-api-aberta-e-feed-global.md) | API aberta e feed global | aceita | sem autenticação, feed global, risco de dados de terceiros |
| [0008](0008-zona-dns-e-acme.md) | Zona dos probes e ACME embutido | aceita | dns-monitor, certmagic, DNS-01 próprio, HTTP-01, falhas |
| [0009](0009-stack-go-estatico.md) | Stack Go estático | aceita | Go 1.27, HTTP/1 próprio, h2 passivo, quic-go, lista de dependências, sem Docker, GitHub |
| [0010](0010-licenca-apache-e-ja4plus.md) | Licença Apache-2.0 e JA4+ | aceita | Apache-2.0, NOTICE, JA4T/JA4H isolados, p0f.fp externo |
| [0011](0011-rede-offloads-e-pilha-tcp.md) | Offloads e pilha TCP | aceita | offloads off, verificação MTU+14, sysctls fixados, sem conntrack |
| [0012](0012-retencao-curta.md) | Retenção curta, logs e sem backup | aceita | 10 min / 2 GiB, journald 24 h / 200 MB, sem backup |
| [0013](0013-verificacao-dois-niveis.md) | Verificação em dois níveis | aceita | verify quick/full, níveis de teste, cobertura, lint, CI, deploy local |
| [0014](0014-organizacao-agentes.md) | Organização dos agentes | aceita | Claude Code, 10 papéis, propriedade, Git, DoD, escalonamento |
| [0015](0015-lote-binario-de-pacotes.md) | Lote de pacotes binário (FSPB v1) | aceita | formato binário de fs.v1.capture.packet, envelope nos cabeçalhos NATS |
| [0016](0016-stream-em-memoria.md) | Stream FS_EVENTS em memória | aceita (subjects: ver 0017) | stream em memória de 32 MiB (resultado do spike), MemoryMax 192M no NATS |
| [0017](0017-request-reply-e-conn-id.md) | Request/reply fora do stream e conn_id reservado | aceita | stream com lista explícita de subjects de eventos; request/reply NATS core; `fs.v1.store.conn_id` reserva o ULID para o web |
| [0018](0018-tamanho-dos-eventos.md) | Tamanho dos eventos de aplicação | aceita | eventos ≤ 900 KiB, campos inline ≤ 128 KiB com `*_truncated`, bytes completos pelo fluxo até 16 MiB por sentido, offsets por requisição |
