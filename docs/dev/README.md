# Desenvolvimento

Material para quem desenvolve o espelho; o uso está nos guias de [docs/](../README.md).

| Documento | Conteúdo |
| --- | --- |
| [auditoria-f5.md](auditoria-f5.md) | Auditoria F5 (spec × implementação, reviewer, task 071) sobre bfa81d7; divergências viraram as tarefas 077–088 |
| [ingest-vazao.md](ingest-vazao.md) | Vazão do ingest do store a 400/100 no finger-01 (task 246): gargalo no disco, expurgo atrás da criação, opções para o architect |
| [traefix-finger-01.md](traefix-finger-01.md) | traefix:latest num container de teste no finger-01 (task 273): configuração, digest, conferências contra o espelho, custo de CPU e achados (PT-12 a PT-14) |
| [spike-carga.md](spike-carga.md) | Spike de carga da F1: pacotes pelo NATS e BLOBs no SQLite a 200 conexões e 50 novas/s (ADRs 0004 e 0005); registro, protótipo removido (task 358) |
| `test/load/RESULTS.md` | Cargas de 10 min (F5 no servidor anterior; F6–F8 e v0.5.1 no finger-01; spec 017 RF-13, ADR 0022): metas de RNF por percentil e decomposição do atraso do feed; gerado pela tarefa de carga |
| [test/e2e](../../test/e2e) | Matriz e2e pelo caminho direto (`make verify-full ARGS="--e2e"`) |
| [test/golden](../../test/golden/README.md) | Capturas golden de curl, Go, Chrome e Firefox e como regravá-las |

Processo: papéis, Git e Definition of Done na [spec 002](../../specs/002-organizacao-do-trabalho.md);
verificação em dois níveis e matriz na [spec 017](../../specs/017-verificacao.md); implantação na
[spec 016](../../specs/016-infra-e-deploy.md).
