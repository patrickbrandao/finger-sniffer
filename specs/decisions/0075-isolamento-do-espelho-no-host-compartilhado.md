# 0075 — Isolamento do espelho no host compartilhado: NATS com autenticação, caminhos por unit e journal próprio

Status: aceita (provisória no detalhe do `include` de variáveis no `nats.conf`: revisar se o teste da task 353 mostrar
que o nats-server não resolve variável definida em arquivo incluído; recuo no item 1.4)
Data: 2026-11-23

## Contexto
Fato novo: a ADR 0038 levou o espelho para o finger-01, host **compartilhado** (traefik e sites do humano em Docker,
`snmpd`, `opencode` em 127.0.0.1). Três controles que bastavam na vps602 dedicada viraram problema lá (revisão
completa de 2026-11-21, commit `b30a5b1`):
- **task 353**: o NATS escuta em `127.0.0.1:4222` sem autenticação. Qualquer processo do host publica e assina
  qualquer subject: grava o TXT `_acme-challenge` da zona dos probes pelo `fs.v1.dns.acme.set` (certificado curinga
  válido de `*.finger-west-01.badblock.net.br`, interceptação dos probes que o espelho não veria), forja
  `fs.v1.store.connection` (vereditos e agregados do bot envenenados; com `block`, IPs reais bloqueados nos sites),
  apaga o stream pela `$JS.API.STREAM.DELETE.FS_EVENTS` e enche o conjunto do `SetACME` até o `MemoryMax` do dns.
  A tabela de ameaças da spec 001 não trata o acesso local ao barramento. O sigilo não muda: os pacotes já são
  públicos pela API (ADR 0007); o ganho é de integridade.
- **task 355**: os seis serviços rodam com o mesmo usuário `finger-sniffer`, e capture, dns, raw, web e store têm
  `ReadWritePaths=/finger-sniffer/var` inteiro (spec 016 RF-06). Um bug explorável num parser exposto à internet dá
  escrita no banco do bot (chaves, domínios, `webhook_secret` em claro), em `var/certs` e `var/acme` e leitura das
  chaves privadas. Nenhum desses serviços precisa disso: capture e dns não gravam em `var/`, raw só lê `var/certs`,
  store só grava `var/store`, web só grava `var/certs` e `var/acme`. Bot e NATS já têm o recorte mínimo.
- **task 352**: o drop-in `/etc/systemd/journald.conf.d/finger-sniffer.conf` (24 h / 200 MB, ADR 0012) vale para o
  journal do host inteiro: os logs do humano (sshd, Docker, snmpd, kernel) somem em 24 h e dividem 200 MB com um pico
  de log do espelho. A ADR 0038 item 9 diz que o resto do host não é tocado; o journal do sistema não é do espelho.
  A ADR 0052 conta com as 24 h para os IPs em log de erro, então o prazo continua valendo para os logs do espelho.

## Decisão

### 1. NATS com um usuário por serviço e permissões mínimas (task 353)
1. **Bloco `authorization` no `eventbus/nats/nats.conf`** (versionado, testável), com um usuário por serviço, sem
   `no_auth_user`, sem `accounts` (conta global, JetStream nela como hoje). Permissões em lista de permissão (o que
   não está listado é negado); `_INBOX.>` só para quem faz request/reply como requerente, e `allow_responses` para
   quem responde (o nats-server libera a resposta ao inbox do pedido, uma por pedido, sem abrir `_INBOX.>` para
   publicação). Tabela tirada do asyncapi 0.7.0 e do código (`pkg/event/subjects.go`, `internal/*`):

   | Usuário | `publish` | `subscribe` | `allow_responses` | Por quê |
   | --- | --- | --- | --- | --- |
   | `capture` | `fs.v1.capture.packet`, `fs.v1.svc.heartbeat` | nenhum | não | lote FSPB (`internal/capture/batch.go`) |
   | `web` | `fs.v1.web.>`, `fs.v1.svc.heartbeat`, `fs.v1.dns.acme.set`, `fs.v1.dns.acme.clear`, `fs.v1.store.conn_id` | `_INBOX.>` | não | eventos web, DNS-01 (`internal/web/acmedns.go`) e `conn_id` (`service.RequestConnID`) como requerente |
   | `raw` | `fs.v1.raw.>`, `fs.v1.web.tls.client_hello`, `fs.v1.web.tls.handshake`, `fs.v1.svc.heartbeat` | nenhum | não | sessões e leituras; o TLS opcional do raw publica nos subjects de TLS do web (`internal/raw/tls.go`) |
   | `dns` | `fs.v1.dns.query`, `fs.v1.svc.heartbeat` | `fs.v1.dns.acme.set`, `fs.v1.dns.acme.clear` | sim | responde ao DNS-01 (`internal/dns/acme.go`) |
   | `store` | `fs.v1.store.connection`, `fs.v1.svc.heartbeat`, `$JS.API.>`, `$JS.ACK.FS_EVENTS.>` | `fs.v1.svc.heartbeat`, `fs.v1.store.conn_id`, `_INBOX.>` | sim | dono do stream `FS_EVENTS` e do consumidor `store` (cria, recria, `Fetch` e `Ack`; respostas da API JetStream e do `Fetch` chegam no inbox), responde ao `conn_id` |
   | `bot` | `fs.v1.svc.heartbeat` | `fs.v1.store.connection`, `fs.v1.svc.heartbeat` | não | spec 018 RF-02 |

   Só o `store` alcança a API do JetStream; só o `web` pede TXT ao dns; só o `store` publica
   `fs.v1.store.connection`. Os produtores publicam no stream por NATS core (sem `$JS.API`). Resíduo aceito: o
   subject do heartbeat é comum, então um serviço comprometido ainda forja o heartbeat de outro (o campo `service` do
   envelope não é autenticado).
2. **Segredos.** Senha aleatória por usuário, gerada pelo `remote-install.sh` no primeiro deploy (ou quando o arquivo
   falta): 32 bytes do `/dev/urandom` em hexadecimal (64 caracteres, sem caracteres que exijam escape no conf), um
   arquivo por usuário em `/finger-sniffer/etc/nats/<usuário>.password` (diretório `0700`, arquivos `0600`, dono
   `finger-sniffer`; `etc/` já fica fora do rsync). Nunca reescrita por deploy; rotação = apagar o arquivo e rodar o
   deploy completo (reinicia o NATS e todos). A partir desses arquivos o deploy gera, a cada execução e só se mudar
   (`install_if_changed`), `/finger-sniffer/etc/nats/auth.conf` (`0600`, `finger-sniffer`), só com definições de
   variáveis do conf: `FS_NATS_PW_CAPTURE: "<hex>"`, `FS_NATS_PW_WEB`, `FS_NATS_PW_RAW`, `FS_NATS_PW_DNS`,
   `FS_NATS_PW_STORE`, `FS_NATS_PW_BOT`. O `nats.conf` faz `include "../../etc/nats/auth.conf"` (caminho relativo ao
   próprio conf em `/finger-sniffer/eventbus/nats/`) **antes** do bloco `authorization`, que usa
   `password: $FS_NATS_PW_<USUÁRIO>`. Mudança no `auth.conf` conta como mudança do `nats.conf` no plano de reinícios
   (spec 016 RF-11: o hash do NATS passa a cobrir os dois arquivos).
3. **Clientes (`pkg/service`).** Três chaves novas, **definidas por unit** (`Environment=` em cada
   `finger-sniffer-<svc>.service`), nunca no env compartilhado: `FS_NATS_USER` (nome do usuário, igual ao do
   serviço), `FS_NATS_PASSWORD_FILE` (caminho do arquivo da senha; lido uma vez no start, espaços e quebra de linha
   finais removidos) e `FS_NATS_PASSWORD` (a senha direta, para testes e desenvolvimento). Regras: `FS_NATS_USER`
   vazio = sem autenticação (testes com NATS embutido, desenvolvimento local); `FS_NATS_USER` com senha vazia, ou
   `FS_NATS_PASSWORD` e `FS_NATS_PASSWORD_FILE` juntos, ou arquivo ilegível → erro de configuração e o serviço não
   sobe (falha cedo, sem reconectar para sempre sem credencial). Com usuário, `nats.UserInfo(user, password)` na
   `nats.Connect`. A senha nunca vai para log, health, métricas nem mensagem de erro. Motivo de não estarem no
   `.env.example`: no systemd, `EnvironmentFile=` vence `Environment=`, então uma chave vazia no env compartilhado
   apagaria o usuário de todas as units; o `.env.example` as cita só em comentário e o teste de chaves
   (`deploy/envkeys_test.go`) as aceita como "chaves de unit". Cada unit leva
   `Environment=FS_NATS_USER=<svc> FS_NATS_PASSWORD_FILE=/finger-sniffer/etc/nats/<svc>.password`. `FS_NATS_URL`
   continua sem credencial na URL.
4. **Recuo do `include`.** Se o nats-server fixado (`deploy/versions.env`) não resolver uma variável definida no
   arquivo incluído (o teste da task 353 com `server.ProcessConfigFile` decide), o `auth.conf` passa a ser gerado pelo
   deploy com o bloco `authorization` inteiro a partir de um modelo versionado em `deploy/nats/` com as mesmas
   permissões do item 1 (e o teste confere o modelo). Nenhum outro ponto desta ADR muda.
5. **Monitoração `127.0.0.1:8222` sai do `nats.conf`.** Nenhum código, script ou contrato a lê (`git grep 8222`), e
   ela mostra a qualquer processo do host conexões, nomes e o estado do JetStream sem autenticação. Diagnóstico manual:
   religar por um deploy de diagnóstico ou usar o health do store e o journal do espelho (item 3).
6. **Teto do conjunto ACME no dns (defesa em profundidade, task 415).** `SetACME` aceita no máximo **8 valores por
   nome**, **16 nomes** e **64 valores no total** vivos (cada valor ≤ 255 bytes, como hoje); acima de qualquer teto,
   nada é guardado e a resposta é `{"ok":false,"error":"acme limit"}` (o `set` idempotente de um valor que já existe
   só renova a expiração e não conta como novo). O certificado A usa um nome com 2 valores; o plano B da ADR 0038 item
   5, outro nome com 2. Contrato sem mudança (o `ACMEReply` já tem `error` livre). Spec 007 RF-05 registra o teto.
7. **Limite conhecido.** Com o mesmo usuário Unix em todas as units (item 2.3), um serviço com execução de código
   arbitrário ainda lê a memória e o `/proc/<pid>` dos outros (mesmo uid, `ptrace_scope` do host fora do espelho) e,
   portanto, as senhas deles. O ganho principal é fechar o barramento para os outros usuários, containers com a rede
   do host e processos do host; o secundário, que um bug de leitura de arquivo num serviço (ex.: travessia de caminho
   no web) não entregue a senha dos outros (item 2.2). `LoadCredential=` não muda isso (o diretório de credenciais e o
   processo ficam legíveis pelo mesmo uid) e não entra.

### 2. Caminhos por unit e endurecimentos (task 355)
1. **Spec 016 RF-06**: `ReadWritePaths` só com o que o serviço grava e `InaccessiblePaths` (com prefixo `-`, não
   falha se o caminho não existir) para o que ele nem lê. Tabela:

   | Unit | `ReadWritePaths` | Lê (sem escrita) | `InaccessiblePaths` |
   | --- | --- | --- | --- |
   | `finger-sniffer-capture` | nenhum | — | `/finger-sniffer/var`, `/finger-sniffer/etc/nats/auth.conf`, senhas `web`, `raw`, `dns`, `store`, `bot` |
   | `finger-sniffer-dns` | nenhum | — | `/finger-sniffer/var`, `auth.conf`, senhas `capture`, `web`, `raw`, `store`, `bot` |
   | `finger-sniffer-raw` | nenhum | `var/certs` | `var/acme`, `var/bot`, `var/store`, `var/nats`, `auth.conf`, senhas `capture`, `web`, `dns`, `store`, `bot` |
   | `finger-sniffer-web` | `var/certs`, `var/acme` | — | `var/bot`, `var/store`, `var/nats`, `auth.conf`, senhas `capture`, `raw`, `dns`, `store`, `bot` |
   | `finger-sniffer-store` | `var/store` | `var/certs` | `var/acme`, `var/bot`, `var/nats`, `auth.conf`, senhas `capture`, `web`, `raw`, `dns`, `bot` |
   | `finger-sniffer-bot` | `var/bot` | `var/certs` | `var/acme`, `var/store`, `var/nats`, `auth.conf`, senhas `capture`, `web`, `raw`, `dns`, `store` |
   | `finger-sniffer-nats` | `var/nats` | `etc/nats/auth.conf` | `var/acme`, `var/bot`, `var/certs`, `var/store`, senhas `*.password` (o `auth.conf` já as contém) |

   "Senhas `x`" = `/finger-sniffer/etc/nats/x.password`; `var/…` = `/finger-sniffer/var/…`. A unit de rede (oneshot,
   root, `ethtool`/`sysctl`) fica como está. `/finger-sniffer/etc/p0f.fp` e o env continuam legíveis por todos.
2. **Endurecimentos novos nas 7 units de longa duração (NATS e os 6 serviços)**: `ProtectClock=yes`,
   `ProtectKernelLogs=yes`, `ProtectHostname=yes`, `UMask=0077` e `ProtectProc=invisible`. Conferido contra o código:
   nada lê `/dev/kmsg` nem muda relógio ou hostname; o store lê `/proc/sys`, `/proc/net/netstat` e `/proc/modules`
   (`internal/store/health.go`), que o `ProtectProc=invisible` não esconde (ele só esconde `/proc/<pid>` de outros
   usuários); o capture usa AF_PACKET e `ethtool` por netlink, sem relação com esses itens; `UMask=0077` deixa os
   certificados do web em `0600`, legíveis por raw, store e bot porque o dono é o mesmo. `ProcSubset=pid` **não
   entra** (esconderia `/proc/sys` e `/proc/net` do store). `SystemCallFilter` fica fora desta ADR (sem medida do que
   o quic-go e o AF_PACKET pedem).
3. **Usuário por serviço: fora (limite conhecido).** Exige grupo de leitura para `var/certs`, ids próprios na mount
   unit do tmpfs, `chown` por diretório no deploy e senhas por usuário, para fechar só o que o item 1.7 descreve
   (leitura da memória entre serviços). Reabrir se um serviço passar a guardar segredo que outro com parser exposto
   não deva alcançar nem por execução de código (hoje: banco do bot e conta ACME, já inacessíveis por caminho).
4. Conferência no host: `systemd-analyze security finger-sniffer-<svc>` no smoke da task 355 (informativo, sem
   meta numérica), além dos 6 serviços `ok` e da renovação ACME gravando em `var/certs`.

### 3. Journal próprio do espelho (task 352)
1. As 8 units do espelho com processo (`finger-sniffer-net`, `-nats` e os 6 serviços; a mount unit não tem
   processo) levam `LogNamespace=finger-sniffer` (systemd ≥ 245; Debian 13 tem 257). O journald abre a instância
   `systemd-journald@finger-sniffer.service` sob demanda.
2. A retenção das ADRs 0012 e 0052 vale **para esse journal**: `deploy/journald/finger-sniffer.conf` passa a ser
   instalado em `/etc/systemd/journald@finger-sniffer.conf` com `[Journal]` `MaxRetentionSec=24h`,
   `SystemMaxUse=200M` e `RuntimeMaxUse=200M` (o teto vale com o journal persistente ou volátil, conforme o
   `Storage=` do host). Mudança nele reinicia só `systemd-journald@finger-sniffer.service`.
3. O deploy apaga o drop-in antigo `/etc/systemd/journald.conf.d/finger-sniffer.conf` quando o encontra e só então
   reinicia o `systemd-journald` do sistema, **uma vez**; daí em diante o deploy nunca toca o journald do sistema nem
   escreve em `/etc/systemd/journald.conf.d/`.
4. **Não conflita com a ADR 0038 item 9**: o drop-in foi instalado pelo espelho (task 225); apagá-lo desfaz um efeito
   nosso no host e devolve o journal do sistema à configuração do humano. O reinício único do journald é o mesmo que
   todo deploy com o drop-in alterado já fazia. O que não volta: os logs do host com mais de 24 h já apagados pelo
   drop-in; o PR da task 352 avisa o humano disso.
5. Comandos: `journalctl --namespace=finger-sniffer -u 'finger-sniffer-*'` (com `-f` para seguir). Sem
   `--namespace`, o `journalctl` deixa de mostrar o espelho. Trocam o `remote-install.sh` (smoke e mensagens), as docs
   e o `AGENTS.md` (seção "Comandos", "Logs no servidor"), este pela task 352 junto com a implementação (o comando só
   funciona com o namespace criado), com o texto exato:
   `` - Logs no servidor: `ssh -p 48022 root@finger-01.tmsoft.com.br journalctl --namespace=finger-sniffer -u 'finger-sniffer-*' -f` ``

### 4. Ordem de implementação
- infra, em série (as três mexem nas units e em `deploy/config_test.go`): **355 → 352 → 353**.
- implementer-store, em paralelo desde já: **414** (`pkg/service` lê `FS_NATS_USER`/`FS_NATS_PASSWORD_FILE`/
  `FS_NATS_PASSWORD`; sem usuário nada muda). A 353 depende da 414 e da 352: o NATS só passa a exigir senha depois
  que todos os clientes implantados sabem mandá-la.
- implementer-dns, em paralelo e sem bloquear: **415** (teto do `SetACME`, item 1.6).
- Deploy da 353 de uma vez (gera senhas, troca units e `nats.conf`, reinicia NATS e todos); o smoke confere os 6
  serviços `ok` e que uma conexão sem credencial ao `127.0.0.1:4222` é recusada.

## Alternativas consideradas
- **Token único no `nats.conf`** (alternativa mínima da task 353): fecha o barramento para o resto do host com
  menos peças, mas qualquer serviço comprometido (até sem execução de código, por um bug que o faça publicar subject
  arbitrário) grava TXT ACME e apaga o stream. O custo do usuário por serviço é só a tabela do item 1.1 e cinco
  arquivos a mais; rejeitado.
- **nkeys ou JWT/contas**: mais forte contra vazamento do conf do servidor (só chaves públicas), mas exige gerar
  nkeys no deploy sem o CLI `nsc`/`nk` (dependência fora da ADR 0009 ou código novo) e não muda o limite do item 1.7;
  rejeitado por ora.
- **Senhas no `FS_NATS_URL` de cada unit** (`nats://user:pass@…`): a URL vai para log e para o health com facilidade
  e o `EnvironmentFile` compartilhado vence o `Environment=`; rejeitado.
- **Bcrypt no `auth.conf`**: só protege contra leitura do conf, que já é inacessível às outras units (item 2.1);
  exige ferramenta de hash no deploy; rejeitado.
- **`LoadCredential=` por unit**: ver item 1.7.
- **Só apagar o drop-in do journald** e deixar os logs do espelho no journal do host com o padrão dele: derruba as 24
  h das ADRs 0012 e 0052; rejeitado.
- **Usuário Unix por serviço**: ver item 2.3.

## Consequências
- Spec 001: linha nova "processo local no barramento" e linha "Privilégios" revista na tabela de ameaças; NATS sem
  `:8222`. Spec 016: RF-06 (tabela de caminhos e endurecimentos), RF-08 (journal próprio), RF-09 (autenticação),
  RF-10/RF-11 (deploy instala senhas e `journald@`, hash do NATS cobre o `auth.conf`), layout (`etc/nats/`). Spec 007
  RF-05: teto do conjunto ACME.
- Contratos: asyncapi sem mudança (subjects, payloads e request/reply iguais; a autenticação é da implantação).
  `.env.example` só com comentário das chaves de unit.
- Testes com NATS embutido seguem sem autenticação (usuário vazio); a 353 acrescenta testes com autenticação
  (conexão sem credencial recusada, `capture` sem permissão para `fs.v1.dns.acme.set` e
  `$JS.API.STREAM.DELETE.FS_EVENTS`).
- Operação: `nats pub`/`nats sub` no servidor passam a exigir `--user`/`--password` (ex.: a senha do `store` lida como
  root); `journalctl` precisa de `--namespace=finger-sniffer`.
- ADRs 0003 (barramento), 0012 (journald) e 0038 (o que é do espelho no host) ficam com nota de status apontando para
  esta.
