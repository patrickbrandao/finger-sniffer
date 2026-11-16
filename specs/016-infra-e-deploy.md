# 016 — Infra, rede e deploy

Status: aprovada
Depende de: 001

## Contexto
O espelho depende de uma pilha TCP conhecida e de uma interface que entregue os pacotes como vieram do fio.
Tudo do espelho roda direto no systemd, sem Docker, no finger-01, e o deploy é um comando a partir do Mac. O host é
compartilhado com o traefik e os sites do humano (Docker): o espelho não mexe no que não é dele (ADR 0038).

## Requisitos
### Rede (unit `finger-sniffer-net.service`, oneshot, antes de todas)
- RF-01: desliga na interface `FS_CAPTURE_IFACE` (`ens192`, vmxnet3): `gro`, `rx-gro-hw`, `lro`, `tso`, `gso`,
  `tx-checksumming`, `rx-udp-gro-forwarding`, `tx-udp-segmentation` (`ethtool -K`; o último pela ADR 0019). Recurso que o
  driver não tem aparece como `unknown` e recurso fixo com o valor que o ethtool mostra; falha em algum que existe →
  registra e segue; o capture reporta `degraded` só com agregador ligado.
- RF-02: aplica `deploy/sysctl/90-finger-sniffer.conf` (versionado, carregado depois dos arquivos do host, sem
  reduzir valores do host, ADR 0038): `tcp_syncookies=1`, `somaxconn=65535`, `tcp_max_syn_backlog=65535`, `tcp_timestamps=1`, `tcp_ecn=2`, `tcp_sack=1`, `tcp_window_scaling=1`,
  `tcp_congestion_control=htcp`, `default_qdisc=fq_codel`, `tcp_fastopen=3` (cliente e servidor; o servidor só concede cookie nos listeners que ligam `TCP_FASTOPEN`:
  web e raw, ADR 0029),
  `ip_local_port_range=32768 60999`, `net.core.rmem_max=134217728` e `net.core.wmem_max=134217728` (o valor do
  host; acima dos 7 MiB do quic-go, ADR 0019; o web pede no máximo 1 MiB, ADR 0037); o arquivo é a documentação
  oficial da resposta TCP do espelho. Valores do host que o espelho não fixa e que moldam a resposta
  (`ip_default_ttl=128`, `tcp_mtu_probing=1`, `rmem_default`/`wmem_default`, `tcp_no_metrics_save=1`) ficam
  registrados em `docs/` e aparecem no health (lidos do kernel).
- RF-03: nenhuma regra de NAT, redirecionamento ou filtro toca as portas do espelho (web TCP 8080/8443 e UDP 8443,
  raw, 53, 9000, 9001); `nf_conntrack` e o ruleset do host (Docker) são tolerados. O estado de rede grava
  `conntrack_loaded`, `nft_ruleset_lines` e `nat_on_mirror_ports`; no health, `conntrack_loaded` e `nft_ruleset_lines`
  são informativos e só `nat_on_mirror_ports` verdadeiro deixa `degraded` (`nat on mirror ports`) e reprova o deploy. O espelho não cria regra de firewall (ADR 0038).
- RF-04: NTP: systemd-timesyncd ativo; health `degraded` se não sincronizado.

### Units
- RF-05: `deploy/systemd/`: `finger-sniffer-net`, `-nats`, `-store`, `-capture`, `-web`, `-raw`, `-dns`, o target
  `finger-sniffer.target` e a fatia `finger-sniffer.slice` (`Slice=` em todas as units). Ordem: net → nats → store
  → demais. `Restart=always`, backoff.
- RF-06: hardening: usuário de sistema `finger-sniffer`; `ProtectSystem=strict`, `ReadWritePaths=/finger-sniffer/var`,
  `NoNewPrivileges`, `AmbientCapabilities` mínimas (NET_BIND_SERVICE para raw/dns; NET_RAW para capture;
  nenhuma para web, com portas acima de 1024, e para store/nats), `EnvironmentFile=/finger-sniffer/etc/finger-sniffer.env`.
- RF-07: limites (ADRs 0039 e 0045): fatia `finger-sniffer.slice` com `MemoryMax=10G` e `CPUQuota=800%`; por unit
  `MemoryMax`/`GOMEMLIMIT`/`CPUQuota`: store 6G/1536MiB/400% (inclui o tmpfs do banco), nats 1G/896MiB/200%, web 768M/512MiB/400%, capture
  512M/384MiB/200%, raw 256M/192MiB/100%, dns 256M/192MiB/100%; todas com `MemorySwapMax=0` e
  `LimitNOFILE=65536`; as units Go (5 serviços e `nats-server`) com `Environment=GODEBUG=disablethp=1` (o THP do
  host fica `always`). Web com `Environment=QUIC_GO_DISABLE_GSO=true QUIC_GO_DISABLE_ECN=true` (ADR 0019).
- RF-07a: banco do store em RAM (ADR 0045): mount unit `finger\x2dsniffer-var-store.mount` (tmpfs em
  `/finger-sniffer/var/store`, `size=4G,mode=0700,nosuid,nodev,noexec`, uid/gid numéricos do `finger-sniffer`
  resolvidos na instalação); o store com `RequiresMountsFor=/finger-sniffer/var/store`. O deploy nunca para nem
  reinicia a mount unit (mudança de tamanho por `mount -o remount`); a primeira instalação apaga o banco em disco
  antes de montar. O banco sobrevive ao reinício do store e some no do host.
- RF-08: journald drop-in: `MaxRetentionSec=24h`, `SystemMaxUse=200M`.

### NATS
- RF-09: binário oficial `nats-server` v2 estável, versão fixada em `deploy/versions.env`, baixado do GitHub com
  verificação de checksum, em `/finger-sniffer/bin/nats-server`; config `eventbus/nats/nats.conf`.

### Layout no servidor
```
/finger-sniffer/
  bin/        binários (5 serviços + nats-server)
  htdocs/     site estático
  etc/        finger-sniffer.env (instalado de .env.example só se ausente), p0f.fp
  var/        store/ (SQLite num tmpfs de 4G, ADR 0045), certs/, acme/, nats/   — nunca tocado pelo rsync
  (fontes do repositório, para referência)
```

### Deploy (`make deploy`, script `deploy/deploy.sh`)
- RF-10: compila os 5 binários (linux/amd64, ldflags com versão/commit) → rsync do repositório inteiro para
  `root@finger-01.tmsoft.com.br:/finger-sniffer` (porta 48022), excluindo `.git/`, `tasks/`, `tmp/`, `var/`, `.grill/`,
  `etc/*.env` → instala usuário, units, sysctl, journald, NATS → aplica rede → `systemctl daemon-reload` →
  reinicia (todos ou `SVC=<svc>`) → smoke test (`GET :9001/api/v1/health` com os 5 serviços presentes e nenhum
  `down`; `degraded` só passa por motivo da lista de tolerados do smoke — hoje `cert_self_signed` e, só com
  `SVC=<svc>`, a versão desencontrada (`version X differs from store Y`, que o store marca em quem roda outra
  versão; implantar um serviço só desencontra as versões de propósito) —, com `AVISO` e os `reasons` no log, e
  reprova por qualquer outro; `versions_match` falso reprova o deploy completo e, com `SVC`, sai como `AVISO`;
  `GET :8080/`,
  `GET :8443/` com TLS válido, `Alt-Svc: h3=":8443"` na resposta da 8443 e listener UDP 8443 do web de pé —
  `ss -Hlun` no finger-01; com um cliente h3 disponível no Mac, também um `GET` por h3; `GET
  https://finger-01.badblock.net.br/` pelo traefik com a página do espelho, quando a rota do traefik existir).
- RF-11: idempotente; trava remota `flock /run/finger-sniffer/deploy.lock` (espera até 5 min). O deploy grava, por
  unit, o hash da configuração aplicada (unit + env ou `nats.conf`); um deploy com `SVC` reinicia só o serviço
  pedido, e a configuração que ele instalou para os demais é aplicada no deploy completo seguinte, que reinicia
  toda unit cujo hash mudou.
- RF-12: sem aprovação (servidor de testes), dentro do que é do espelho (ADR 0038 item 9).
- RF-13: traefik do host: a rota que entrega `finger-01.badblock.net.br` ao web (ADR 0044; TLS
  passthrough por SNI para `170.247.40.86:8443`) fica no script do traefik do repositório do humano
  (`tmsoft-servers/tmsoft-finger-01/setup-902-docker-traefik-app.sh`); o infra só edita esse script e o reaplica
  (ADR 0038 item 6).

## Interfaces e contratos
- [eventbus/nats/nats.conf](../eventbus/nats/nats.conf), `.env.example`.

## Critérios de aceite
- [ ] Num Debian 13 sem `/finger-sniffer` (primeiro deploy no finger-01, ou uma VM recém-instalada),
      `make deploy` deixa tudo no ar sem passo manual.
- [ ] Depois de reboot, offloads continuam desligados e sysctls aplicados (conferido pelo health).
- [ ] `make deploy` duas vezes seguidas não muda nada no segundo (idempotente).

## Fora de escopo
- Docker para o espelho (o Docker do host é do humano), Kubernetes, outros sistemas operacionais.

## Decisões relacionadas
- specs/decisions/0011-rede-offloads-e-pilha-tcp.md
- specs/decisions/0003-nats-jetstream.md
- specs/decisions/0016-stream-em-memoria.md
- specs/decisions/0009-stack-go-estatico.md
- specs/decisions/0013-verificacao-dois-niveis.md
- specs/decisions/0029-campos-da-auditoria-de-requisitos.md
- specs/decisions/0038-servidor-finger-01-e-coexistencia-com-o-traefik.md
- specs/decisions/0039-limites-e-metas-no-finger-01.md
