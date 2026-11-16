# 0039 — Limites por serviço e metas de RNF no finger-01

Status: aceita (RNF-01 de 400/100 do item 5 substituído por 0042: 200/50 na v0.3.0, 400/100 na fase F7; a 1ª carga
falhou por causa pontual: ver 0041; fatia 10G, store 6G/1536MiB e `FS_STORE_MAX_BYTES` 3 GiB dos itens 1, 2 e 5
substituídos por 0045, banco em RAM)
Data: 2026-11-15

## Contexto
O humano decidiu redimensionar os limites para o finger-01 (ADR 0038): 16 vCPU, 32 GB, NVMe de 111 GB,
compartilhado com o traefik (`--cpus 2`, `--memory 512M`), sites futuros e outros containers. Os limites vigentes
vêm da vps602 (1 vCPU, 967 MiB, 25 GB):
- `MemoryMax`: store 384M, nats 192M, demais 96M; `GOMEMLIMIT` store 320MiB, nats 170MiB, web 64MiB, outros 80MiB;
  sem limite de CPU (ADRs 0005, 0016, 0036; spec 016 RF-07);
- stream `FS_EVENTS` com 32 MiB (ADR 0016); `FS_STORE_MAX_BYTES` 2 GiB (ADR 0005, RNF-05);
- RNF-01 de 200 simultâneas e 50 novas/s, modo degradado em 250/60 (ADR 0030);
- web com orçamento de entrada de 24 MiB (8–32 MiB) e a conta das ADRs 0036/0037 para 96M.

Medidas que sustentam a conta (vps602):
- carga oficial `official-50k` (`v0.1.0-13`, 200/50 por 10 min, todas as metas da ADR 0022): CPU do host 56% de
  1 vCPU; store 30,3% (p95 34,7%), web 15,9%, nats 5,0%, raw 2,1%, capture 1,9%, dns ~0; `anon` máximo store 76,
  nats 88, web 30, raw 12, capture 10, dns 4 MiB;
- carga do orçamento 215c (`v0.2.1-58`): web com `anon` máximo de 63,8 MiB e o orçamento cheio (24 MiB), `sock`
  7,7–12,1 MiB e `kernel` ~2 MiB por janela de 30 s (a ADR 0037 resolveu o kernel), mas 22,6–27,9 MiB de páginas
  anônimas cobradas do cgroup e não mapeadas, com `thp_fault_alloc` no cgroup e `thp_deferred_split_page` no host:
  provável THP `always` + devolução de memória do runtime Go em pedaços de páginas de 2 MiB. O finger-01 também
  tem THP `always`, e mudar o THP do host não é nosso (ADR 0038 item 9).

## Decisão
1. **Fatia própria.** As 7 units entram em `finger-sniffer.slice` com `MemoryMax=6G` e `CPUQuota=800%`: o espelho
   nunca passa de metade das vCPU nem de ~19% da RAM, e o resto fica para o host, o traefik e os sites. Os
   caminhos de cgroup mudam para `/sys/fs/cgroup/finger.slice/finger-sniffer.slice/<unit>` (o systemd aninha pelo
   hífen); quem lê cgroup (carga, `budget.sh`) passa a usar esse caminho.
2. **Limites por unit** (substitui spec 016 RF-07 e os números das ADRs 0005 e 0016). Todas com
   `MemorySwapMax=0` (a conta de memória não se esconde em swap), `LimitNOFILE=65536` e, nas units Go (os 5
   serviços e o `nats-server`), `Environment=GODEBUG=disablethp=1` (o runtime marca o heap com
   `MADV_NOHUGEPAGE`; o THP do host continua `always`). O `GOMAXPROCS` segue o `CPUQuota` (runtime Go ≥ 1.25).

   | Unit | `MemoryMax` | `GOMEMLIMIT` | `CPUQuota` | Base |
   | --- | --- | --- | --- | --- |
   | store | 2G | 1792MiB | 400% | `anon` 76 MiB a 200/50; RNF-01 ×2, banco de 8 GiB (cache de página recuperável) |
   | nats | 1G | 896MiB | 200% | `anon` 88 MiB com stream de 32 MiB; stream passa a 128 MiB (item 3) |
   | web | 768M | 512MiB | 400% | conta do item 4 |
   | capture | 512M | 384MiB | 200% | anel TPACKET_V3 e lotes; tráfego dos sites agora capturado |
   | raw | 256M | 192MiB | 100% | até 1000 sessões (`FS_MAX_CONNS`) |
   | dns | 256M | 192MiB | 100% | `rmem_default` de 30 MiB do host nos sockets UDP (v4 e v6) |

   Soma dos `MemoryMax`: 4864 MiB, abaixo dos 6G da fatia. Os `CPUQuota` somam 1400%: a fatia é o teto conjunto,
   a cota por unit só segura um serviço descontrolado. Na carga oficial, `cpu.stat nr_throttled` de cada unit não
   cresce (meta).
3. **NATS** (altera a ADR 0016): stream `FS_EVENTS` com `max_bytes` **128 MiB** (×4: ×2 do RNF-01 novo e ×2
   pelo tráfego dos sites, que antes não existia), `max_age` 60 s mantido; `max_memory_store` **256MB** no
   `nats.conf`. Com o store parado, a folga deixa de cair abaixo dos ~17 s medidos na ADR 0016.
4. **Web** (altera a conta e o padrão das ADRs 0033, 0036 e 0037; os tetos fixos por conexão ficam).
   - `FS_WEB_INPUT_BUDGET`: padrão **201326592** (192 MiB), faixa **8388608–268435456** (8–256 MiB); fora dela o web
     não sobe. Ficam: h1 1 MiB e 1024 campos, h2 1 MiB e 100 streams, h3 2 MiB e 10 s, WebSocket 32 sessões de
     2 MiB com eco de prazo 30 s, `bufio` de 16 KiB, `SO_RCVBUF`/`SO_SNDBUF` de 16 KiB no `accept`, UDP do QUIC com
     1 MiB, tracker de Initials com 4096 entradas e 8 MiB.
   - Conta (cgroup do web, `MemoryMax=768M`, `FS_MAX_CONNS`=1000):

     | Parcela | Teto |
     | --- | --- |
     | Go (`GOMEMLIMIT`): base de ~80 MiB com 1000 conexões (~20 MiB medidos por 250), tracker QUIC 8, orçamento 192, sobra para TLS, quic-go e GC | 512 MiB |
     | TCP: 1000 × (32 + 32) KiB (o kernel dobra os 16 KiB) | 62,5 MiB |
     | UDP do QUIC: 2 sockets × 2 MiB × 2 sentidos | 8 MiB |
     | slab e kernel (2 MiB medidos com 250 conexões, ×8) | 16 MiB |
     | arquivo (binário, htdocs) | ≤ 8 MiB |
     | total | 606,5 MiB (margem de 161 MiB, 21%) |

   - Metas medidas na carga do orçamento no finger-01 (fecha a task 215), nos cenários A (o da 214:
     `-h1 220 -ws 16 -h3 14`) e A4 (perto do teto: `-h1 900 -ws 32 -h3 56`): `memory.peak` do web ≤ **738197504**
     (704 MiB = `MemoryMax` − 64 MiB), `memory.events max` sem crescer, `anon` máximo ≤ **603979776** (576 MiB),
     `NRestarts` 0, `oom_kill` 0, mesmo `MainPID`, `web_input_budget_used_bytes` ≤ o orçamento,
     `web_input_budget_denied_total` crescendo. Registrar sem meta: `thp_fault_alloc`/`thp_split_page` do cgroup
     (esperado ~0 com `disablethp`), `active_anon + inactive_anon − anon`, `sock`, `kernel`. O passo "orçamento de
     16 MiB" previsto na task 215 sai.
5. **Metas da spec 000** (altera RNF-01 e RNF-05; ADRs 0022 e 0030 nos números).
   - **RNF-01: 400 conexões simultâneas e 100 novas/s** com análise completa (×2). Justificativa proporcional: o
     store, maior consumidor, usou 30% de 1 vCPU a 50/s na `official-50k`, disputando a única vCPU com os outros;
     ×2 dá ~61% de um núcleo. Não se usa ×16: o caminho do ingest é serial (um escritor SQLite) e não foi medido
     acima de 50/s.
   - Modo degradado (ADR 0030): `FS_MAX_CONNS` padrão **1000** (store, web e raw) e `FS_MAX_NEW_CONNS_PER_S`
     **250** (×2,5 da garantia), com margem para o tráfego dos sites, agora capturado e contado. A regra da ADR
     0030 fica: carga oficial com `degraded` = 0 e o tráfego alheio presente; janela descartada só se o alheio
     passar dos limites.
   - **RNF-05**: retenção de 10 min mantida (privacidade, ADRs 0007 e 0012); `FS_STORE_MAX_BYTES` padrão
     **8589934592** (8 GiB: disco 4,4× maior, tráfego ×2 e os pcaps dos sites; < 8% do disco).
   - RNF-02 (< 1 s), RNF-03 (p95 < 100 ms), RNF-04 (p95 ≤ 500 ms), RNF-06, RNF-07 e RNF-08 sem mudança: são
     latências e propriedades, mais CPU só as melhora, e não há medida que justifique apertar.
   - Capture (spec 003 RNF-01): < 30% de um núcleo na carga do RNF-01.
   - Ficam: tabela de fluxos do store com 8192 entradas (meta na carga: `fs_store_flows_dropped_total` sem
     crescer), probe com 1000 conexões, 64 `wait`, 4 downloads, 64 clientes ao vivo e as filas da ADR 0034,
     `FS_PCAP_MAX_BYTES_PER_CONN` 16 MiB, RRL de 20/s.
6. **Prova.** A carga oficial de 10 min no finger-01 (spec 017 RF-13) passa a usar o perfil 400/100 com as metas da
   ADR 0022, mais `degraded` = 0, `nr_throttled` sem crescer e o estado do conntrack (`conntrack -S`) antes e
   depois. Se falhar: tarefa de otimização; se a release não puder esperar, uma ADR nova volta o RNF-01 para
   200/50 com a medida (a meta nunca muda sem registro).

## Alternativas consideradas
- Escalar tudo por 16 (vCPU) ou 33 (RAM) — sem medida acima de 50/s e com o ingest serial, seria meta sem base.
- Sem fatia, só limites por unit — nada seguraria a soma (7 units com cotas de CPU somando 1400%).
- THP `madvise` no host — mexe em configuração do humano que vale para os sites; `GODEBUG=disablethp=1` resolve
  dentro do espelho.
- Manter o web em 96M e reduzir o orçamento para 16 MiB — a 215c mostrou que a parcela que falta não é do
  orçamento.

## Consequências
- O espelho cabe em 6 GiB e 8 vCPU; o host fica com ≥ 26 GB e 8 vCPU para o resto.
- Código: padrões de `FS_MAX_CONNS`/`FS_MAX_NEW_CONNS_PER_S` (store, web, raw), `FS_STORE_MAX_BYTES`, stream do
  store e orçamento do web mudam; units, fatia, `nats.conf` e `.env.example` também. O env já instalado no
  finger-01 não existe ainda, então o primeiro deploy instala os valores novos.
- Contratos: só a descrição do asyncapi (stream de 128 MiB), documental.
