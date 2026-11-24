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
- RF-05: `deploy/systemd/`: `finger-sniffer-net`, `-nats`, `-store`, `-capture`, `-web`, `-raw`, `-dns`, `-bot`
  (RF-14), a mount unit do banco do store (RF-07a), o target `finger-sniffer.target` e a fatia
  `finger-sniffer.slice` (`Slice=` em todas as units). Ordem: net → nats → store → demais. `Restart=always`, backoff.
- RF-06: hardening: usuário de sistema `finger-sniffer` (o mesmo em todas as units; usuário por serviço fora, limite
  conhecido da ADR 0075 item 2.3); `ProtectSystem=strict`, `NoNewPrivileges`, `AmbientCapabilities` mínimas
  (NET_BIND_SERVICE para raw/dns; NET_RAW para capture; nenhuma para web, com portas acima de 1024, e para
  store/nats/bot), `EnvironmentFile=/finger-sniffer/etc/finger-sniffer.env` (menos o NATS). **`ReadWritePaths` só
  com o que a unit grava** e `InaccessiblePaths` (prefixo `-`) com o que ela nem lê (ADR 0075 item 2.1; `var/x` =
  `/finger-sniffer/var/x`, "senhas x" = `/finger-sniffer/etc/nats/x.password`, `auth.conf` =
  `/finger-sniffer/etc/nats/auth.conf`):

  | Unit | `ReadWritePaths` | Lê | `InaccessiblePaths` |
  | --- | --- | --- | --- |
  | capture | — | — | `/finger-sniffer/var`, `auth.conf`, senhas web, raw, dns, store, bot |
  | dns | — | — | `/finger-sniffer/var`, `auth.conf`, senhas capture, web, raw, store, bot |
  | raw | — | `var/certs` | `var/acme`, `var/bot`, `var/store`, `var/nats`, `auth.conf`, senhas capture, web, dns, store, bot |
  | web | `var/certs`, `var/acme` | — | `var/bot`, `var/store`, `var/nats`, `auth.conf`, senhas capture, raw, dns, store, bot |
  | store | `var/store` | `var/certs` | `var/acme`, `var/bot`, `var/nats`, `auth.conf`, senhas capture, web, raw, dns, bot |
  | bot | `var/bot` | `var/certs` | `var/acme`, `var/store`, `var/nats`, `auth.conf`, senhas capture, web, raw, dns, store |
  | nats | `var/nats` | `auth.conf` | `var/acme`, `var/bot`, `var/certs`, `var/store`, todas as senhas |

  Nas 7 units de longa duração (NATS e os 6 serviços), também `ProtectClock=yes`, `ProtectKernelLogs=yes`,
  `ProtectHostname=yes`, `UMask=0077` e `ProtectProc=invisible`; sem `ProcSubset=pid` (o health do store lê
  `/proc/sys`, `/proc/net/netstat` e `/proc/modules`). A unit de rede (oneshot, root) fica sem esses itens. Cada unit
  de serviço leva `Environment=FS_NATS_USER=<svc> FS_NATS_PASSWORD_FILE=/finger-sniffer/etc/nats/<svc>.password`
  (RF-09a).
- RF-07: limites (ADRs 0039 e 0045): fatia `finger-sniffer.slice` com `MemoryMax=10G` e `CPUQuota=800%`; por unit
  `MemoryMax`/`GOMEMLIMIT`/`CPUQuota`: store 6G/1536MiB/400% (inclui o tmpfs do banco), nats 1G/896MiB/200%, web 768M/512MiB/400%, capture
  512M/384MiB/200%, raw 256M/192MiB/100%, dns 256M/192MiB/100%; todas com `MemorySwapMax=0` e
  `LimitNOFILE=65536`; as units Go (6 serviços e `nats-server`) com `Environment=GODEBUG=disablethp=1` (o THP do
  host fica `always`). Web com `Environment=QUIC_GO_DISABLE_GSO=true QUIC_GO_DISABLE_ECN=true` (ADR 0019).
- RF-07a: banco do store em RAM (ADR 0045): mount unit `finger\x2dsniffer-var-store.mount` (tmpfs em
  `/finger-sniffer/var/store`, `size=4G,mode=0700,nosuid,nodev,noexec`, uid/gid numéricos do `finger-sniffer`
  resolvidos na instalação); o store com `RequiresMountsFor=/finger-sniffer/var/store`. O deploy nunca para nem
  reinicia a mount unit (mudança de tamanho por `mount -o remount`); a primeira instalação apaga o banco em disco
  antes de montar. O banco sobrevive ao reinício do store e some no do host.
- RF-08: journal próprio do espelho (ADR 0075 item 3): as 8 units com processo (net, nats e os 6 serviços) com
  `LogNamespace=finger-sniffer`; `deploy/journald/finger-sniffer.conf` instalado em
  `/etc/systemd/journald@finger-sniffer.conf` com `MaxRetentionSec=24h`, `SystemMaxUse=200M` e `RuntimeMaxUse=200M`
  (ADRs 0012 e 0052); mudança nele reinicia só `systemd-journald@finger-sniffer.service`. Nenhum arquivo do espelho em
  `/etc/systemd/journald.conf.d/`: o deploy apaga o drop-in antigo `finger-sniffer.conf` de lá, se existir, e reinicia
  o `systemd-journald` do sistema só nessa remoção. Leitura: `journalctl --namespace=finger-sniffer -u
  'finger-sniffer-*'`.

### NATS
- RF-09: binário oficial `nats-server` v2 estável, versão fixada em `deploy/versions.env`, baixado do GitHub com
  verificação de checksum, em `/finger-sniffer/bin/nats-server`; config `eventbus/nats/nats.conf`, só em
  `127.0.0.1:4222`, sem monitoração HTTP (`http:` fora; ADR 0075 item 1.5).
- RF-09a: autenticação (ADR 0075 item 1): bloco `authorization` no `nats.conf` com os usuários `capture`, `web`,
  `raw`, `dns`, `store` e `bot`, permissões da tabela da ADR 0075 item 1.1, sem `no_auth_user`; senhas de 32 bytes
  aleatórios em hexadecimal geradas pelo deploy quando faltam, em `/finger-sniffer/etc/nats/<usuário>.password`
  (diretório 0700, arquivos 0600, dono `finger-sniffer`; nunca reescritas; rotação = apagar e fazer o deploy
  completo); o deploy deriva delas `/finger-sniffer/etc/nats/auth.conf` (0600, variáveis `FS_NATS_PW_<USUÁRIO>`),
  incluído pelo `nats.conf` antes do `authorization`. Clientes: `FS_NATS_USER`, `FS_NATS_PASSWORD_FILE` e
  `FS_NATS_PASSWORD` (testes) definidos por unit, nunca no env compartilhado; usuário vazio = sem autenticação; usuário
  sem senha → o serviço não sobe. O smoke confere que uma conexão sem credencial ao 4222 é recusada.

### Layout no servidor
```
/finger-sniffer/
  bin/        binários (6 serviços + nats-server)
  htdocs/     site estático
  etc/        finger-sniffer.env (instalado de .env.example só se ausente), p0f.fp,
              nats/ (<usuário>.password e auth.conf, 0600, gerados pelo deploy; ADR 0075)
  var/        store/ (SQLite num tmpfs de 4G, ADR 0045), certs/, acme/, nats/, bot/   — nunca tocado pelo rsync
  (fontes do repositório, para referência)
```

### Deploy (`make deploy`, script `deploy/deploy.sh`)
- RF-10: compila os binários de `SERVICES` do `Makefile` (os 6 serviços, RF-14; linux/amd64, ldflags com
  versão/commit) → rsync do repositório inteiro para `root@finger-01.tmsoft.com.br:/finger-sniffer` (porta 48022), excluindo `.git/`, `tasks/`, `tmp/`, `var/`, `.grill/`,
  `etc/*.env` → instala usuário, senhas do NATS (se faltam), units, sysctl, `journald@finger-sniffer.conf`, NATS → aplica rede → `systemctl daemon-reload` →
  reinicia (todos ou `SVC=<svc>`) → smoke test (`GET :9001/api/v1/health` com os 6 serviços presentes e nenhum
  `down`; `degraded` só passa por motivo da lista de tolerados do smoke — hoje `cert_self_signed` e, só com
  `SVC=<svc>`, a versão desencontrada (`version X differs from store Y`, que o store marca em quem roda outra
  versão; implantar um serviço só desencontra as versões de propósito) —, com `AVISO` e os `reasons` no log, e
  reprova por qualquer outro; `versions_match` falso reprova o deploy completo e, com `SVC`, sai como `AVISO`;
  `GET :8080/`,
  `GET :8443/` com TLS válido, `Alt-Svc: h3=":8443"` na resposta da 8443 e listener UDP 8443 do web de pé —
  `ss -Hlun` no finger-01; com um cliente h3 disponível no Mac, também um `GET` por h3; `GET
  https://finger-01.badblock.net.br/` pelo traefik com a página do espelho, quando a rota do traefik existir).
- RF-11: idempotente; trava remota `flock /run/finger-sniffer/deploy.lock` (espera até 5 min). O deploy grava, por
  unit, o hash da configuração aplicada (unit + env, ou `nats.conf` + `etc/nats/auth.conf` para o NATS); um deploy com `SVC` reinicia só o serviço
  pedido, e a configuração que ele instalou para os demais é aplicada no deploy completo seguinte, que reinicia
  toda unit cujo hash mudou.
- RF-12: sem aprovação (servidor de testes), dentro do que é do espelho (ADR 0038 item 9).
- RF-13: traefik do host: a rota que entrega `finger-01.badblock.net.br` ao web (ADR 0044; TLS
  passthrough por SNI para `170.247.40.86:8443`) fica no script do traefik do repositório do humano
  (`tmsoft-servers/tmsoft-finger-01/setup-902-docker-traefik-app.sh`); o infra só edita esse script e o reaplica
  (ADR 0038 item 6).

- RF-14: serviço bot (F8, ADR 0047): unit `finger-sniffer-bot.service` no target e na fatia, depois do store,
  `MemoryMax=1G`, `GOMEMLIMIT=768MiB`, `CPUQuota=200%`, `MemorySwapMax=0`, `GODEBUG=disablethp=1`, sem capabilities;
  `ReadWritePaths` com `/finger-sniffer/var/bot` (no disco, **fora** do tmpfs do store); leitura do
  `/finger-sniffer/etc/p0f.fp` (`FS_BOT_P0F_DB`, ADR 0063 item 5); `FS_CAPTURE_EXCLUDE_PORTS`
  com 9002 e 9003; `FS_BOT_INTERNAL_LISTEN` = IP do host na bridge `br-net-public` do traefik, descoberto e fixado
  pelo infra; `make build`/`make deploy` com 6 binários e `SVC=bot`; o smoke exige o bot `ok` e `GET
  https://finger-01.badblock.net.br:9002/bot/v1/health` 200. O deploy nunca apaga `var/bot`.
- RF-15: traefix (ADR 0054): o deploy do espelho não instala nem reinicia o traefik; a troca da imagem do
  `traefik-app` pela do traefix é tarefa própria (task 273), depois do aviso do humano: teste num container à parte,
  sempre `tmsoftbrasil/traefix:latest` com o digest e o `sender` registrados (ADR 0062 item 7), configuração estática
  `entryPoints.<nome>.fingerprint` do perfil da spec 019 RF-03 com `export.url` na 9003, troca do `traefik-app` depois
  da task 273 (task 306), nenhum forwardAuth nos routers dos sites (só num router de teste, `observe` e `failOpen`) e volta à imagem
  anterior se algum site mudar de resposta.

## Interfaces e contratos
- [eventbus/nats/nats.conf](../eventbus/nats/nats.conf), `.env.example`.

## Critérios de aceite
- [ ] Num Debian 13 sem `/finger-sniffer` (primeiro deploy no finger-01, ou uma VM recém-instalada),
      `make deploy` deixa tudo no ar sem passo manual.
- [ ] Depois de reboot, offloads continuam desligados e sysctls aplicados (conferido pelo health).
- [ ] `make deploy` duas vezes seguidas não muda nada no segundo (idempotente).
- [ ] Nenhum arquivo do espelho em `/etc/systemd/journald.conf.d/`; `journalctl --namespace=finger-sniffer
      --disk-usage` ≤ 200 MB (ADR 0075).
- [ ] Conexão sem credencial ao NATS recusada; nenhuma unit além do bot alcança `var/bot` (ADR 0075).

## Fora de escopo
- Docker para o espelho (o Docker do host é do humano; o traefix tem imagem própria no projeto dele, ADR 0054), Kubernetes,
  outros sistemas operacionais.

## Decisões relacionadas
- specs/decisions/0011-rede-offloads-e-pilha-tcp.md
- specs/decisions/0003-nats-jetstream.md
- specs/decisions/0016-stream-em-memoria.md
- specs/decisions/0009-stack-go-estatico.md
- specs/decisions/0013-verificacao-dois-niveis.md
- specs/decisions/0029-campos-da-auditoria-de-requisitos.md
- specs/decisions/0038-servidor-finger-01-e-coexistencia-com-o-traefik.md
- specs/decisions/0039-limites-e-metas-no-finger-01.md
- specs/decisions/0054-traefix-projeto-externo.md
- specs/decisions/0075-isolamento-do-espelho-no-host-compartilhado.md
