# 0038 — Servidor finger-01, zona finger-west-01 e coexistência com o traefik

Status: aceita
Data: 2026-11-15

## Contexto
Decisão do humano (entrevista de 2026-11-15, registrada aqui como decisão do humano): a vps602 é **abandonada e
fica intocada** (nada é parado nem apagado lá) e o espelho passa para um servidor novo, compartilhado com sites
atrás de um traefik. Fatos do servidor novo, informados pelo humano e lidos nos scripts dele
(`tmsoft-servers/tmsoft-finger-01/setup-*.sh`, repositório do humano, fora deste):
- `finger-01.tmsoft.com.br` (também `finger-01.badblock.net.br`): Debian 13 (kernel 6.12), VM VMware com NIC
  `ens192` (driver vmxnet3), **16 vCPU, 32 GB de RAM**, NVMe de 111 GB; IPv4 170.247.40.86/27, IPv6
  2804:231c:e500:cafe::86/64; NTP ok; THP em `always`; ssh na porta 48022, root por chave.
- Zona `badblock.net.br` (udns, já publicada): `finger-01` e `*.finger-01` com A/AAAA do servidor e
  `finger-west-01 NS finger-01`; a delegação responde nos autoritativos.
- Já rodam: o container `traefik-app` (traefik, rede Docker `network_public` 10.249.0.0/16 na bridge
  `br-net-public`, publica TCP 80/443/8081 e UDP 443, ACME HTTP-01 próprio na entrada `web`), `traefik-certs`
  (container com um roteador do traefik em `Host(finger-01.tmsoft.com.br)`), `snmpd` (48161) e `opencode`
  (127.0.0.1). O Docker roda com `iptables: false`; `nftables` e `conntrack` estão instalados.
- Sysctls do host em `/etc/sysctl.d/51-*.conf` a `67-*.conf`: `somaxconn` e `tcp_max_syn_backlog` 65535,
  `rmem_max`/`wmem_max` 134217728, `rmem_default`/`wmem_default` 31457280, `tcp_mtu_probing=1`,
  `ip_default_ttl=128`, `ip_local_port_range=1024 65535`, `tcp_no_metrics_save=1`, forwarding ligado, além de
  valores iguais aos nossos (`tcp_sack`, `tcp_timestamps`, `htcp`, `fq_codel`, `tcp_fastopen=3`).

Pontos que as ADRs vigentes fixavam para a vps602 e que mudam: endereços e interface (0001, 0011), portas do web
(0006), zona e certificados (0008, spec 015), HTTPS RR só com UDP 443 (0019), "sem conntrack/NAT" (0011),
verificação e e2e contra a vps602 (0013) e o escalonamento "fora da vps602" (specs/002, 0014). Os limites de
recursos e as metas ficam na ADR 0039.

## Decisão
1. **Servidor (decisão do humano).** O ambiente único (dev = teste, ADR 0001) passa a ser o **finger-01**: ssh
   `-p 48022 root@finger-01.tmsoft.com.br`, projeto em `/finger-sniffer`, interface capturada `ens192`
   (`FS_CAPTURE_IFACE`, também o padrão no código), `FS_LISTEN_IPV4=170.247.40.86`,
   `FS_LISTEN_IPV6=2804:231c:e500:cafe::86`. A vps602 não recebe mais ssh, deploy, carga nem e2e, nem como
   padrão de script; os nomes `vps602` e `dns-monitor.tmsoft.com.br` saem de specs, código, scripts e docs. Os
   registros históricos (ADRs, `CHANGELOG.md`, `docs/dev/`, `test/load/RESULTS.md` e `test/load/results/`)
   mantêm o nome como registro do que foi medido lá, com nota quando forem reeditados. O finger-01 só é usado
   por e2e e carga depois que a tarefa de deploy declarar o servidor pronto (deploy completo e smoke ok).
2. **Nomes (decisão do humano).**
   - Zona dos probes: **`finger-west-01.badblock.net.br`** (`FS_DNS_ZONE`), delegada para
     `finger-01.badblock.net.br`; o dns é autoritativo dela, com `SOA`/`NS` do apex em
     `finger-01.badblock.net.br.`. Probe: `<id>.finger-west-01.badblock.net.br`.
   - API: `finger-01.badblock.net.br` portas 9000 (HTTPS) e 9001 (HTTP), diretas: nunca pelo traefik, nunca
     capturadas.
   - Nomes alternativos, sem log DNS: `finger-01.badblock.net.br`, `*.finger-01.badblock.net.br` (sem
     certificado válido: o curinga fica na zona do udns) e `finger-01.tmsoft.com.br`. Zonas em que o rótulo mais à
     esquerda é probe (`pkg/probe`): `finger-west-01.badblock.net.br` e `finger-01.badblock.net.br`.
   - Qualquer registro novo em `badblock.net.br` ou `tmsoft.com.br` é do humano (specs/002, item 4).
3. **Portas do web (fixadas pelo architect dentro da decisão do humano de tirar o web de 80/443).** TCP **8080**
   e **8443**, UDP **8443** para QUIC/HTTP/3 (`FS_WEB_TCP_PORTS=8080,8443`, `FS_WEB_UDP_PORTS=8443`, também os
   padrões no código). A detecção pelos primeiros bytes continua em todas as portas (TLS na 8080, HTTP em claro
   na 8443). O UDP usa o mesmo número do TCP com TLS para que `curl --http3-only https://<nome>:8443/`, o Alt-Svc e
   o HTTPS RR com prefixo de porta (item 4) apontem para a mesma origem. Alt-Svc nas respostas sobre TLS:
   `h3=":<U>"; ma=60`, com `U` = primeira porta de `FS_WEB_UDP_PORTS` com listener de pé (no finger-01,
   `h3=":8443"`); com portas UDP pedidas e nenhum listener de pé, nada é anunciado e o heartbeat fica `degraded`
   (`h3_listener_down`). TCP 80/443 e UDP 443 são do traefik. Raw (7, 21, 22, 25, 110, 143, 587, 993), dns (53)
   e API (9000/9001) sem mudança. Como as portas do web passam de 1024, a unit do web deixa de ter
   `CAP_NET_BIND_SERVICE` (raw e dns continuam).
4. **HTTPS RR com prefixo de porta (altera a ADR 0019 e a spec 007 RF-02).** A origem de um probe passa a ser
   `<nome>:8443` (e `:8080`, que também aceita TLS). Pelo RFC 9460 §2.3, o dns responde `HTTPS` em
   `_<P>._https.<nome>` para cada `P` de `FS_WEB_TCP_PORTS` (env compartilhado): ServiceMode, prioridade 1,
   `TargetName` = `<nome>` sem o prefixo (com "." o alvo seria o nome prefixado, que não tem A/AAAA),
   `alpn="h3,h2"` se `P` está em `FS_WEB_UDP_PORTS`, senão `alpn="h2"`, `ipv4hint`/`ipv6hint`, TTL `FS_DNS_TTL`.
   O nome sem prefixo (porta 443) só tem `HTTPS` se 443 estiver em `FS_WEB_TCP_PORTS` (regra antiga); no
   finger-01 responde NODATA, porque a 443 é do traefik. `_<P>._https` com `P` fora da lista e outros rótulos com
   `_` sem registro próprio → NODATA. O probe da consulta é o primeiro rótulo à esquerda depois de pular os
   rótulos iniciados por `_` (`_8443._https.<id>.finger-west-01…` e `_acme-challenge.<id>…` registram o probe).
   Rótulos de controle sem mudança (`noh3` tira o HTTPS RR).
5. **Certificados (altera a ADR 0008 e a spec 015).**
   - **A** (DNS-01 pelo nosso dns): `finger-west-01.badblock.net.br` e `*.finger-west-01.badblock.net.br`.
   - **B**: `finger-01.badblock.net.br` e `finger-01.tmsoft.com.br`, por **TLS-ALPN-01** (RFC 8737). O HTTP-01
     não é possível: a porta 80 é do traefik, cujo roteador interno de desafio ACME pega todo
     `/.well-known/acme-challenge/` da entrada `web`. O traefik encaminha esses dois nomes com **TLS passthrough**
     (roteador TCP `HostSNI`) para o web na 8443 (item 6), então a validação da Let's Encrypt na 443 chega ao
     web, que responde `acme-tls/1` com o certificado de desafio em qualquer porta TLS. O HTTP-01 fica só quando
     `FS_WEB_TCP_PORTS` contém 80 (não é o caso do finger-01); o certmagic nunca abre listener próprio (nem 80
     nem 443).
   - Variável e arquivos mantêm os nomes (`FS_CERT_NAMES_HTTP01`, `http01.crt`/`http01.key`), por compatibilidade
     do env instalado; nas specs passam a ser "certificado B". `vps602`, `fingerprint`, `tcp` e `udp`
     `.tmsoft.com.br` saem. A API na 9000 escolhe por SNI (A para nomes da zona, B para `finger-01.*`), como hoje.
   - Emissões: validar primeiro com a LE staging; em produção, a primeira emissão são 2 certificados (A e B),
     dentro do limite de 3 por semana (specs/002, item 4).
   - Plano B, que depende do humano: se o passthrough não levar o TLS-ALPN-01, o B passa a DNS-01 com um
     `CNAME` `_acme-challenge.finger-01.badblock.net.br` → `_acme-challenge.finger-01.finger-west-01.badblock.net.br`
     na zona do udns, criado pelo humano.
6. **Coexistência com o traefik (decisão do humano; mecanismo fixado pelo architect).**
   - O traefik continua dono de TCP 80/443/8081 e UDP 443 e roteia `https://finger-01.badblock.net.br` e
     `https://finger-01.tmsoft.com.br` para a página do espelho (htdocs) por passthrough TCP para
     `170.247.40.86:8443`; o `http://` na 80 segue o redirecionamento para https que o traefik já faz. A mudança
     fica no script do traefik em `tmsoft-servers` (repositório do humano, mudança combinada): o infra edita só
     o script/config do traefik e o reaplica no finger-01, sem mexer em outros containers. Se o roteador do
     `traefik-certs` em `Host(finger-01.tmsoft.com.br)` estiver ativo, a rota desse nome só entra com o aval do
     humano (o passthrough tem precedência e tiraria a rota do container dele).
   - As conexões da página pelo traefik chegam ao web pela bridge (`br-net-public`, origem 10.249.0.0/16), fora da
     `ens192`: o web as registra (`ip.src_kind=private`) sem pacotes capturados; o ClientHello do visitante chega
     intacto (passthrough). O lado visitante → traefik (TCP 443) é capturado como tráfego do traefik.
   - **Captura (decisão do humano)**: todo o tráfego da `ens192`, inclusive 80/443/8081 do traefik e o tráfego
     dos sites; o BPF exclui o mesmo de hoje (48022, 48161, 9000, 9001). As bridges do Docker não são capturadas.
     Esse tráfego conta no modo degradado como qualquer tráfego alheio (ADRs 0026 e 0030; limites na ADR 0039).
   - **Privacidade**: a API aberta (ADR 0007) passa a expor, por até 10 min, os pacotes dos visitantes dos sites
     atrás do traefik: IPs, SNI e, em claro, a requisição HTTP na 80 antes do redirecionamento. É consequência da
     decisão do humano de capturar tudo, dentro do risco aceito na ADR 0007; o tratamento de LGPD entra nas specs
     da fase de bots.
7. **Pilha do host (altera a ADR 0011).**
   - `deploy/sysctl/90-finger-sniffer.conf` continua a fonte das chaves que lista e carrega depois dos arquivos
     do host; não reduz valores do host: `somaxconn` e `tcp_max_syn_backlog` **65535**, `rmem_max`/`wmem_max`
     **134217728** (acima dos 7 MiB do quic-go; o web limita os próprios sockets pela ADR 0037). As demais chaves
     ficam como estão, inclusive `ip_local_port_range=32768 60999` (mantém 8080/8443/9000/9001 fora da faixa
     efêmera do host). Valores do host que moldam a resposta e que o espelho não fixa ficam registrados nas docs e
     no health (sysctls lidos do kernel): `ip_default_ttl=128`, `tcp_mtu_probing=1`, `rmem_default`/
     `wmem_default`, `tcp_no_metrics_save=1`.
   - **conntrack e nftables**: substitui "sem firewall com estado, sem conntrack/NAT". Nenhuma regra de NAT,
     redirecionamento ou filtro pode tocar as portas do espelho (web 8080/8443 TCP e UDP 8443, raw, 53, 9000,
     9001); o `nf_conntrack` carregado é tolerado (não altera pacotes de fluxos sem NAT; o AF_PACKET vê a entrada
     antes do netfilter e a saída depois). O estado de rede (arquivo interno da unit de rede) passa a
     informar `conntrack_loaded`, `nft_ruleset_lines` e `nat_on_mirror_ports`; no health, os dois primeiros ficam
     informativos (sem contrato novo) e só o último deixa `degraded` (motivo `nat on mirror ports`) e reprova o
     deploy. O
     espelho não cria regra de firewall. Reabrir se a carga mostrar perdas do conntrack (`conntrack -S`
     `drop`/`insert_failed`, "table full" no log do kernel).
   - **Offloads** na `ens192` (vmxnet3): a mesma lista da spec 016 RF-01; recurso que o driver não tem aparece como
     `unknown` e recurso fixo pelo driver com o valor que o ethtool mostra (valores do contrato: `on`, `off`,
     `unknown`); só um agregador ligado deixa o health `degraded`; a verificação MTU + 14 (RNF-07, 1514 bytes com MTU 1500) continua e detecta agregação
     residual do ESXi.
   - THP continua `always` no host (decisão do humano); o espelho evita THP nos heaps Go pela ADR 0039.
8. **Verificação e operação (altera as ADRs 0001 "ambiente único" e 0013).** `make deploy`, os testes
   `linux_priv` do verify-full, o e2e e as cargas usam o finger-01 (padrão `root@finger-01.tmsoft.com.br`, porta
   48022), com o cliente da carga e do e2e fora dele (Mac). Nenhum script tem a vps602 como padrão.
9. **Escalonamento (altera specs/002 item 4 e a ADR 0014).** "Fora da vps602" passa a "fora do espelho no
   finger-01": tudo do espelho no finger-01 (`/finger-sniffer`, units `finger-sniffer-*`, o nosso arquivo de
   sysctl) pode ser feito sem aprovação; o resto do host (containers, Docker, sysctls e THP do host, snmpd,
   opencode) não é tocado, exceto o script do traefik nos termos do item 6. Zonas do udns, GitHub e mais de 3
   emissões LE de produção por semana continuam com o humano.

## Alternativas consideradas
- Web em 80/443 e traefik em outras portas — rejeitada pelo humano (o servidor hospeda sites).
- Traefik terminando o TLS da página e encaminhando para o web na 8080 — a 9000 precisaria de um certificado de
  `finger-01.badblock.net.br` vindo de fora (o `acme.json` do traefik), acoplando o espelho ao container do humano;
  e o ClientHello do visitante não chegaria ao espelho.
- HTTP-01 do B encaminhado pelo traefik — o roteador interno de desafio do traefik intercepta o caminho.
- DNS-01 do B por `CNAME` no udns — exige o humano; fica como plano B.
- UDP 443 para o h3 do espelho — ocupado pelo traefik.
- HTTPS RR no nome sem prefixo com `port=8443` — desviaria para o espelho clientes que pedem a origem da 443 (que
  é do traefik), e o suporte a `port` nos navegadores é desigual.
- Regras `notrack` próprias para as portas do espelho — mais uma peça no firewall do host sem medida que a
  justifique; reavaliar se a carga mostrar perdas do conntrack.

## Consequências
- Toda sondagem web leva a porta explícita (`:8443`, `:8080`, `--http3-only https://<nome>:8443/`); `https://<id>.
  finger-west-01.badblock.net.br/` sem porta cai no traefik.
- O espelho deixa de depender de `tmsoft.com.br` para a zona dos probes; continua dependendo do udns para a
  delegação e para `finger-01.*`.
- A página tem duas entradas (pelo traefik e direto na 8443); a API fica só direta.
- Código: padrões do web (portas, Alt-Svc, ACME do B), do dns (zona, NS, HTTPS RR), do capture (`ens192`),
  `pkg/certs` e `pkg/probe` mudam; contratos só na documentação (servidores do openapi e exemplo do asyncapi).
