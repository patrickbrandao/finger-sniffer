# 0045 — Banco do store em RAM (tmpfs dedicado) e limites de memória para 400/100

Status: aceita
Data: 2026-11-16

## Contexto
A task 246 (PR #226, relatório `docs/dev/ingest-vazao.md`) mediu a vazão do ingest a 100 novas/s e 400 simultâneas
no finger-01, depois da task 248 (ADR 0043):
- o store não é limitado por CPU nem pelo custo por mensagem (45–53% de um núcleo, ingest 66% ocioso no `Fetch`);
- o gargalo é o **disco da VM** (VMware NVMe, ~37 IOPS de escrita aleatória 4 KiB com fsync): o checkpoint copia
  ~1 250 páginas/s para um arquivo de 3–6 GB, o `fsync` do banco leva 1–2,7 s, `io.pressure` full 20–31%; o
  recomeço do WAL para o escritor por 1–4,6 s e o checkpoint automático dentro do COMMIT por 2,3–4,7 s;
- backlog máximo 2,2–4,5 s (meta < 1 s); feed p99 2,0–2,7 s; registro p95 0,9–1,3 s;
- o banco em regime a 100/s com 10 min de retenção tem **~2,4 GB**, passa do `MemoryMax=2G` do store, o expurgo
  passa a ler páginas frias do disco (~5 ms por conexão contra 0,025 ms no cache) e cai para 20–30 conexões/s
  contra 100 criadas: o banco cresce sem limite até o teto de tamanho;
- nenhuma mudança dentro do store, mantendo disco, durabilidade e schema, leva 100/s a backlog < 1 s.

Fato novo para os limites: o finger-01 tem **32 GB de RAM (31 GB livres)**, 16 vCPU e swap de 6 GB; a fatia
`finger-sniffer.slice` usa `MemoryMax=6G` (ADR 0039 item 1), e a soma dos `MemoryMax` das units é 4 864 MiB.

Decisão do humano (2026-11-16): **plano B, banco em RAM** (uma das alternativas listadas na ADR 0043).

Os dados do store são de diagnóstico com retenção de 10 min (ADRs 0007 e 0012, RNF-05); perder o banco num
reinício do host não fere nenhum requisito, e a privacidade melhora (nada vai ao disco).

## Decisão
1. **Banco num tmpfs dedicado.** `/finger-sniffer/var/store` passa a ser um ponto de montagem **tmpfs só do
   store**, com tamanho fixo: `size=4G`, `mode=0700`, dono `finger-sniffer:finger-sniffer` (uid/gid numéricos
   resolvidos na instalação), `nosuid,nodev,noexec`. O caminho do banco não muda (`FS_STORE_DB`,
   `/finger-sniffer/var/store/finger-sniffer.sqlite`); banco, `-wal` e `-shm` ficam todos no tmpfs.
   - Mecanismo: uma **mount unit** do systemd em `deploy/systemd/` (`finger\x2dsniffer-var-store.mount`), puxada
     pelo store com `RequiresMountsFor=/finger-sniffer/var/store`. Não se usa `TemporaryFileSystem=` nem
     `RuntimeDirectory=`: o primeiro some a cada reinício do store e fica invisível ao host; o segundo fica no
     `/run` do sistema (tmpfs comum, ~10% da RAM, sem tamanho próprio).
   - **Vida do banco**: sobrevive ao reinício do store (deploy, `Restart=always`, panic), de modo que a spec 004
     RF-04a continua valendo (o desligamento normal copia os buffers para `packets` e a recuperação de órfãs monta
     o pcap no reinício; "deploy não perde pacotes" fica). **Perde-se** no reinício do host ou se a mount unit for
     parada; o store sobe com o banco vazio e o goose aplica o schema (como numa instalação nova). O deploy nunca
     para nem reinicia a mount unit: mudança de tamanho é aplicada com `mount -o remount,size=…`, sem perder o
     conteúdo.
   - Ferramentas do host (carga, `budget.sh`, `sqlite3` de diagnóstico) continuam a achar o banco no mesmo caminho.
   - Na primeira instalação, o banco em disco que estiver em `/finger-sniffer/var/store` é apagado antes de montar
     (senão fica escondido debaixo do tmpfs ocupando disco).
2. **Memória cobrada do store.** As páginas do tmpfs são `shmem`, cobradas do cgroup de quem as escreve (o store) e,
   com `MemorySwapMax=0` no store e na fatia, nunca vão para swap: não há recuperação de memória para o tmpfs, então
   o tamanho do tmpfs mais o heap Go tem de caber no `MemoryMax` com folga, e o tmpfs enche (ENOSPC) **antes** de o
   cgroup chegar ao `MemoryMax`. Depois de um reinício do store, as páginas antigas passam ao cgroup pai (a fatia)
   até serem apagadas; a fatia continua sendo o teto conjunto.
3. **Limites** (substitui em parte a ADR 0039 itens 1, 2 e 5):

   | Item | Antes (ADR 0039) | Agora | Conta |
   | --- | --- | --- | --- |
   | tmpfs do banco | — (disco) | **4G** | banco em regime a 100/s: ~2,4 GB; teto de uso 3 GiB (abaixo) + WAL ≤ 64 MiB + `-shm` + páginas livres e folga de ~900 MiB |
   | `FS_STORE_MAX_BYTES` (padrão) | 8 GiB | **3 GiB** (3221225472) | 75% do tmpfs; medido como páginas usadas (`page_count − freelist_count`, ADR 0034 item 9), cobre 10 min a 100/s com ~25% de folga; acima do perfil (modo degradado 1000/250) a retenção efetiva fica menor que 10 min, como já previsto ("o primeiro atingido expurga") |
   | store `MemoryMax` | 2G | **6G** | tmpfs 4G + `GOMEMLIMIT` 1,5G (`anon` medido ≤ 130 MiB, mais buffers de pacotes do RF-04a até 64 MiB, ~130 MiB de pktbuf em pico) + ~512 MiB de kernel, `sock` e binário |
   | store `GOMEMLIMIT` | 1792MiB | **1536MiB** | heap medido ≤ 130 MiB; o resto do `MemoryMax` é do tmpfs |
   | fatia `finger-sniffer.slice` `MemoryMax` | 6G | **10G** | soma das units 6G + 1G + 768M + 512M + 256M + 256M = 8,8 GiB, com 1,2 GiB de folga; ~31% dos 32 GB, o host fica com ≥ 22 GB para o traefik e os sites |

   Ficam: `CPUQuota` (store 400%, fatia 800%), os limites das demais units, `MemorySwapMax=0`,
   `GODEBUG=disablethp=1`, a retenção `FS_RETENTION` de 10 min, o stream de 128 MiB.
4. **Pragmas e o que fica obsoleto.**
   - `synchronous=OFF` no escritor (e na conexão de finalização): `fsync` no tmpfs não faz nada, e no WAL uma queda
     do processo não corrompe o banco (os dados já estão no kernel); queda do host apaga o tmpfs de todo jeito.
   - `journal_mode=WAL` fica (leitores da API e do feed em paralelo com o escritor), `auto_vacuum=INCREMENTAL` e
     `foreign_keys=ON` ficam.
   - `wal_autocheckpoint` volta a **16384** quadros (64 MiB) e `journal_size_limit` a **64 MiB**: o WAL agora custa
     RAM do tmpfs, e o motivo dos 256/512 MiB da task 246 (não realocar blocos do ext4 a cada recomeço) não existe
     no tmpfs. O laço de recomeço do WAL da task 248 fica (limita o WAL), com os limiares abaixo dos 64 MiB.
   - Obsoletos: a durabilidade por `fsync` (ADR 0005 implícita, `synchronous=NORMAL` da spec 004), o
     `WALJournalLimit` de 512 MiB, a hipótese do cache de página no cgroup (o banco **é** a memória; `mmap_size` e
     `cache_size` ficam no padrão), o `fsync` por passada do checkpoint testado na 246 e a alternativa "disco
     melhor". O orçamento do expurgo (100 ms/s) fica: com o banco em RAM ele cobre ~4 000 conexões/s.
   - **Pcap e ingest não mudam**: os BLOBs (`pcaps`, `raw_streams`, `packets`) ficam no mesmo banco, agora no tmpfs;
     formato, RF-04a, correlação e contratos sem mudança. Nada muda no openapi (`health.store.db_bytes` e
     `max_bytes` mantêm o sentido) nem no asyncapi.
5. **tmpfs cheio: o store degrada, não trava nem morre.**
   - **Prevenção**: o expurgo por tamanho (ADR 0034 item 9) também dispara quando o espaço livre do tmpfs
     (`statfs` do diretório do banco) fica abaixo de **10%** do tamanho do sistema de arquivos, mesmo com o uso
     abaixo de `FS_STORE_MAX_BYTES`, e só para quando volta a ≥ 15%; o `incremental_vacuum` devolve as páginas ao
     tmpfs.
   - **Erro `SQLITE_FULL`** (ENOSPC) numa transação do ingest: rollback pelo caminho já existente (ADR 0034 item
     6: a tabela de fluxos é desfeita), expurgo de emergência fora do orçamento de 100 ms/s (do mais antigo para o
     mais novo, até o livre voltar a ≥ 15% ou por no máximo 2 s), checkpoint `TRUNCATE` do WAL e **uma** nova
     tentativa do lote. Se falhar de novo, o store entra em **modo banco cheio**: as conexões novas são gravadas como
     no modo degradado da spec 004 RF-11 (resumo sem pcap e sem bytes crus, `degraded=true`) e os lotes seguintes
     são tentados assim; se até o lote sem BLOBs der `SQLITE_FULL`, o lote é confirmado (`Ack`) e descartado, com
     métrica — nunca `Nak` em laço, nunca espera sem prazo. O modo banco cheio termina quando o livre volta a
     ≥ 15%.
   - Erro de `SQLITE_FULL` na finalização ou no expurgo segue as regras de tentativa da ADR 0034 (5 tentativas e
     fechamento com o que houver); leituras da API não precisam de espaço e continuam.
   - **Visibilidade**: health do store `degraded` com o motivo `db full` enquanto o modo banco cheio durar e por
     5 min depois do último `SQLITE_FULL`, e `db space <n>% free` enquanto o livre estiver abaixo de 10%. Métricas
     novas: `fs_store_db_fs_bytes{kind=size|free}` (do `statfs`), `fs_store_db_full_total` (erros `SQLITE_FULL`),
     `fs_store_db_full_dropped_total` (mensagens descartadas) e `fs_store_purged_total{reason=space}` (expurgo pelo
     livre do tmpfs ou de emergência).
   - **Sem OOM**: o tmpfs (4G) mais o `GOMEMLIMIT` (1,5G) ficam ~512 MiB abaixo do `MemoryMax` do store (6G); a
     carga não deve ver `memory.events max` nem `oom_kill` no store.
6. **Prova** (task 247, sem mudança de metas): a carga oficial 400/100 da ADR 0042 item 3 registra também
   `fs_store_db_fs_bytes`, `memory.stat shmem` do store e da fatia, e `memory.events` (meta: `max` e `oom_kill`
   sem crescer, `fs_store_db_full_total` Δ 0, expurgo por idade ≥ criação depois de 10 min).

## Alternativas consideradas
- **Disco melhor** para `var/store` — fora do espelho e do repositório; o humano escolheu o banco em RAM.
- **`MemoryMax` do store ≥ 4 GB com o banco em disco** — o banco caberia no cache e o expurgo voltaria a 0,03 ms
  por conexão, mas o recomeço do WAL e o `fsync` continuariam parando o escritor (medido na 246).
- **`synchronous=OFF` com o banco em disco** (ADR 0043) — tira o `fsync` do recomeço, mas não a saturação do disco
  nem o expurgo atrasado.
- **Schema que escreve menos** (pcap fora do SQLite, expurgo por faixa) — migration e mudança grande; não resolve
  sozinho as leituras frias; pode voltar se o tmpfs se mostrar caro.
- **`TemporaryFileSystem=`** na unit do store — tmpfs com tamanho próprio e cobrado do store, mas some a cada
  reinício do store (deploy apagaria o banco e quebraria a recuperação de órfãs da RF-04a) e fica invisível ao host.
- **`RuntimeDirectory=`** (em `/run`) — sem tamanho próprio; encher o banco encheria o `/run` do sistema.
- **SQLite `:memory:` ou `memdb` no processo** — perde o banco a cada reinício do store e as leituras paralelas
  por conexões separadas do mesmo arquivo; o tmpfs mantém tudo como está.

## Consequências
- O disco sai do caminho do ingest: o escritor não espera `fsync` nem leituras frias, e o expurgo acompanha a
  criação. As metas RNF-02/04 a 400/100 voltam a depender só de CPU e do desenho do ingest.
- O banco some no reinício do host (dados de diagnóstico de até 10 min); probes e IDs anteriores dão 404, como
  depois da retenção. O consumidor durável retoma do último ack e o que ainda estiver no stream (≤ 60 s) entra no
  banco novo; fluxos partidos viram avulsos de meio de fluxo (ADR 0041).
- O espelho passa a usar até 10G de RAM (fatia); o host fica com ≥ 22 GB.
- Código: store (pragmas, `FS_STORE_MAX_BYTES` 3 GiB, expurgo pelo livre do tmpfs, `SQLITE_FULL`, métricas,
  health) — task 255; infra (mount unit, `RequiresMountsFor`, limites do store e da fatia, `.env.example`,
  instalação e deploy sem desmontar) — task 254. Spec 000 RNF-05, spec 004 RF-05/RF-06/RF-09 e dados, spec 016
  RF-06/RF-07 e layout, spec 001 (falhas) atualizadas nesta ADR.
- Altera: ADR 0039 (itens 1, 2 e 5: fatia 10G, store 6G/1536MiB, `FS_STORE_MAX_BYTES` 3 GiB), ADR 0043 (a
  correção escolhida é esta), ADR 0005 (banco em RAM, sem durabilidade em disco). A ADR 0042 (400/100 na F7) fica.
