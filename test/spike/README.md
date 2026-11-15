# Spike de carga (task 006)

Protótipo **descartável** para medir, na vps602 (1 vCPU, 967 MiB), a arquitetura das ADRs 0004/0005/0015:
captura AF_PACKET → lotes FSPB v1 no NATS JetStream → consumidor que grava pacotes e pcaps como BLOB no SQLite.
Não é código de produção; os serviços reais nascem nas fases F2+.

> Servidor anterior (vps602): os números da F1 foram medidos lá. Desde a ADR 0038 os padrões do `run.sh` apontam
> para o finger-01 (`ens192`, alvo do spike na porta 7710, porque a 8080 é do web); a tabela abaixo descreve o
> spike como rodou na F1.

| Programa | Onde roda | Papel |
| --- | --- | --- |
| `cmd/spikecap` | vps602 (root) | captura na eth0, filtra portas de gerência, publica lotes FSPB v1 em `fs.v1.capture.packet` |
| `cmd/spikestore` | vps602 | consumidor durável do stream `FS_EVENTS`; correlaciona por fluxo, grava `connections`/`packets`, materializa `pcaps` no fechamento, expurga por retenção, mede latências |
| `cmd/spikeweb` | vps602 | servidor HTTP alvo na porta 8080 (`/small` 1 KiB, `/big` 256 KiB) |
| `cmd/spikeload` | máquina cliente | gerador: N conexões novas/s, cada uma com R requisições keep-alive |
| `cmd/spikemon` | vps602 | CPU e RSS por processo a cada 5 s, a partir de `/proc` |

Reproduzir: `test/spike/run.sh` (a partir do Mac). Resultado: `docs/dev/spike-carga.md`.
