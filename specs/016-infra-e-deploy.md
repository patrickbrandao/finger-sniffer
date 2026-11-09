# 016 — Infra, rede e deploy

Status: aprovada
Depende de: 001

## Contexto
O espelho depende de uma pilha TCP conhecida e de uma interface que entregue os pacotes como vieram do fio.
Tudo roda direto no systemd, sem Docker, na vps602, e o deploy é um comando a partir do Mac.

## Requisitos
### Rede (unit `finger-sniffer-net.service`, oneshot, antes de todas)
- RF-01: desliga na `eth0`: `gro`, `rx-gro-hw`, `lro`, `tso`, `gso`, `tx-checksumming`, `rx-udp-gro-forwarding`,
  `tx-udp-segmentation` (`ethtool -K`; o último pela ADR 0019). Falha em algum → registra e segue; o capture
  reporta `degraded`.
- RF-02: aplica `deploy/sysctl/90-finger-sniffer.conf` (versionado): `tcp_syncookies=1`, `somaxconn=4096`,
  `tcp_max_syn_backlog=4096`, `tcp_timestamps=1`, `tcp_ecn=2`, `tcp_sack=1`, `tcp_window_scaling=1`,
  `tcp_congestion_control=htcp`, `default_qdisc=fq_codel`, `tcp_fastopen=3` (cliente e servidor; o servidor só concede cookie nos listeners que ligam `TCP_FASTOPEN`:
  web e raw, ADR 0029),
  `ip_local_port_range`, `net.core.rmem_max=7340032` e `net.core.wmem_max=7340032` (buffer UDP do quic-go,
  ADR 0019); o arquivo é a documentação oficial da resposta TCP do espelho.
- RF-03: sem firewall com estado, sem conntrack/NAT: o deploy confere que `nft list ruleset` está vazio e que
  `nf_conntrack` não está carregado; se estiver, avisa no health.
- RF-04: NTP: systemd-timesyncd ativo; health `degraded` se não sincronizado.

### Units
- RF-05: `deploy/systemd/`: `finger-sniffer-net`, `-nats`, `-store`, `-capture`, `-web`, `-raw`, `-dns`, e o target
  `finger-sniffer.target`. Ordem: net → nats → store → demais. `Restart=always`, backoff.
- RF-06: hardening: usuário de sistema `finger-sniffer`; `ProtectSystem=strict`, `ReadWritePaths=/finger-sniffer/var`,
  `NoNewPrivileges`, `AmbientCapabilities` mínimas (NET_BIND_SERVICE para web/raw/dns; NET_RAW para capture;
  nenhuma para store/nats), `EnvironmentFile=/finger-sniffer/etc/finger-sniffer.env`.
- RF-07: `MemoryMax` (ADR 0005, ADR 0016): store 384M, nats 192M, demais 96M; `LimitNOFILE=65536`. Web com
  `Environment=QUIC_GO_DISABLE_GSO=true QUIC_GO_DISABLE_ECN=true` (ADR 0019).
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
  var/        store/ (SQLite), certs/, acme/, nats/   — nunca tocado pelo rsync
  (fontes do repositório, para referência)
```

### Deploy (`make deploy`, script `deploy/deploy.sh`)
- RF-10: compila os 5 binários (linux/amd64, ldflags com versão/commit) → rsync do repositório inteiro para
  `root@vps602.tmsoft.com.br:/finger-sniffer` (porta 48022), excluindo `.git/`, `tasks/`, `tmp/`, `var/`, `.grill/`,
  `etc/*.env` → instala usuário, units, sysctl, journald, NATS → aplica rede → `systemctl daemon-reload` →
  reinicia (todos ou `SVC=<svc>`) → smoke test (`GET :9001/api/v1/health` com os 5 serviços `ok`, `GET :80/`,
  `GET :443/` com TLS válido, `Alt-Svc: h3` na resposta da 443 e listener UDP 443 do web de pé — `ss -Hlun` na
  vps602; com um cliente h3 disponível no Mac, também um `GET` por h3).
- RF-11: idempotente; trava remota `flock /run/finger-sniffer/deploy.lock` (espera até 5 min).
- RF-12: sem aprovação (servidor de testes).

## Interfaces e contratos
- [eventbus/nats/nats.conf](../eventbus/nats/nats.conf), `.env.example`.

## Critérios de aceite
- [ ] Em uma VPS recém-formatada (Debian 13), `make deploy` deixa tudo no ar sem passo manual.
- [ ] Depois de reboot, offloads continuam desligados e sysctls aplicados (conferido pelo health).
- [ ] `make deploy` duas vezes seguidas não muda nada no segundo (idempotente).

## Fora de escopo
- Docker, Kubernetes, outros sistemas operacionais.

## Decisões relacionadas
- specs/decisions/0011-rede-offloads-e-pilha-tcp.md
- specs/decisions/0003-nats-jetstream.md
- specs/decisions/0016-stream-em-memoria.md
- specs/decisions/0009-stack-go-estatico.md
- specs/decisions/0013-verificacao-dois-niveis.md
- specs/decisions/0029-campos-da-auditoria-de-requisitos.md
