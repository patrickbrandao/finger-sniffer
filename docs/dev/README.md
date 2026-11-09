# Desenvolvimento

Material para quem desenvolve o espelho; o uso está nos guias de [docs/](../README.md).

| Documento | Conteúdo |
| --- | --- |
| [auditoria-f5.md](auditoria-f5.md) | Auditoria F5 (spec × implementação, reviewer, task 071) sobre bfa81d7; divergências viraram as tarefas 077–088 |
| [spike-carga.md](spike-carga.md) | Spike de carga da F1: pacotes pelo NATS e BLOBs no SQLite a 200 conexões e 50 novas/s (ADRs 0004 e 0005) |
| `test/load/RESULTS.md` | Teste de carga da F5 (spec 017 RF-13, ADR 0022): metas de RNF por percentil e decomposição do atraso do feed; gerado pela tarefa de carga |
| [test/e2e](../../test/e2e) | Matriz e2e pelo caminho direto (`make verify-full ARGS="--e2e"`) |
| [test/golden](../../test/golden/README.md) | Capturas golden de curl, Go, Chrome e Firefox e como regravá-las |

Processo: papéis, Git e Definition of Done na [spec 002](../../specs/002-organizacao-do-trabalho.md);
verificação em dois níveis e matriz na [spec 017](../../specs/017-verificacao.md); implantação na
[spec 016](../../specs/016-infra-e-deploy.md).
