#!/usr/bin/env bash
# Instalação idempotente no finger-01 (ADR 0038), executada pelo deploy.sh como root e sob trava.
# Argumento: diretório de staging com o repositório e bin/.
set -euo pipefail

STAGING="$1"
DEST=/finger-sniffer
SVC="${SVC:-}"
FORCE="${FORCE:-0}"
CHANGED_CONFIG=0
ENV_CHANGED=0

log() { echo "[deploy] $*"; }

# shellcheck disable=SC1091
. "$STAGING/deploy/versions.env"
# shellcheck disable=SC1091
. "$STAGING/deploy/install-lib.sh"
UNITS="$FS_UNITS"

# install_if_changed <origem> <destino> <modo>: copia só se diferente; devolve 0 se mudou.
install_if_changed() {
	if [ -f "$2" ] && cmp -s "$1" "$2"; then
		return 1
	fi
	install -D -m "$3" "$1" "$2"
	log "atualizado $2"
	return 0
}

# 0. Bootstrap (Debian 13 sem /finger-sniffer, com Docker/traefik já rodando; task 225): só instala os pacotes das
#    ferramentas que faltam. Nada aqui toca outras units, containers, /etc/docker ou os sysctls do host: o espelho
#    instala apenas o próprio arquivo de sysctl, as próprias units (finger-sniffer-*, finger-sniffer.slice/.target)
#    e o drop-in do journald, e não cria regra de firewall.
missing=$(missing_packages | paste -sd' ' -)
if [ -n "$missing" ]; then
	log "instalando pacotes ausentes: $missing"
	# shellcheck disable=SC2086
	DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends $missing ||
		{ apt-get update -q && DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends $missing; }
fi

# 1. Usuário de sistema e layout
if ! id finger-sniffer >/dev/null 2>&1; then
	useradd --system --home-dir "$DEST/var" --no-create-home --shell /usr/sbin/nologin finger-sniffer
	log "usuário finger-sniffer criado"
fi
mkdir -p "$DEST/bin" "$DEST/etc" "$DEST/var/store" "$DEST/var/certs" "$DEST/var/acme" "$DEST/var/nats"
chown -R finger-sniffer:finger-sniffer "$DEST/var"
chmod 0750 "$DEST/var"

# 2. Repositório → /finger-sniffer (preserva var/, etc/ e bin/). bin/ e htdocs/ têm passos próprios.
conf_before=$(hash_file "$DEST/eventbus/nats/nats.conf")
rsync -a --delete --chown=root:root --exclude='/var/' --exclude='/etc/' --exclude='/bin/' --exclude='/htdocs/' \
	"$STAGING/" "$DEST/"
chmod 0755 "$DEST/deploy/net/finger-sniffer-net.sh"

# 3. Binários: só os da seleção (SVC=<svc> instala só o dele; task 078). Os reinícios (passo 9) comparam o
#    binário em disco com o que está em execução.
install_binaries "$STAGING" "$DEST" "$SVC"

# htdocs: só os arquivos servíveis (sem *.go nem testdata/; --delete-excluded limpa os que já estavam lá) e
# leitura pelo usuário finger-sniffer (web), qualquer que seja o umask de quem fez o checkout
install_htdocs "$STAGING" "$DEST"
chown -R root:root "$DEST/htdocs"

# 4. Configuração: env instalado só se ausente (nunca sobrescreve); depois, acrescenta as chaves novas do
#    .env.example sem mudar as existentes e avisa dos valores que diferem do padrão novo.
if [ ! -f "$DEST/etc/finger-sniffer.env" ]; then
	install -m 0640 -g finger-sniffer "$DEST/.env.example" "$DEST/etc/finger-sniffer.env"
	log "criado $DEST/etc/finger-sniffer.env a partir de .env.example"
else
	env_before=$(sha256sum "$DEST/etc/finger-sniffer.env" | cut -d' ' -f1)
	bash "$DEST/deploy/env-merge.sh" "$DEST/.env.example" "$DEST/etc/finger-sniffer.env"
	# chave nova muda o ambiente das units com EnvironmentFile (todas menos o NATS): reinicia essas
	[ "$env_before" = "$(sha256sum "$DEST/etc/finger-sniffer.env" | cut -d' ' -f1)" ] || ENV_CHANGED=1
fi

# 5. NATS fixado (download com checksum)
if [ "$("$DEST/bin/nats-server" --version 2>/dev/null | awk '{print $2}')" != "$NATS_VERSION" ]; then
	tmp=$(mktemp -d)
	curl -fsSL -o "$tmp/nats.tgz" "$NATS_URL"
	echo "$NATS_SHA256  $tmp/nats.tgz" | sha256sum -c --quiet
	tar -xzf "$tmp/nats.tgz" -C "$tmp" --strip-components=1
	install -m 0755 "$tmp/nats-server" "$DEST/bin/nats-server"
	rm -rf "$tmp"
	log "nats-server $NATS_VERSION instalado"
fi

# 6. p0f.fp (arquivo de dados externo)
if ! echo "$P0F_FP_SHA256  $DEST/etc/p0f.fp" | sha256sum -c --quiet >/dev/null 2>&1; then
	tmp=$(mktemp -d)
	curl -fsSL -o "$tmp/p0f.tgz" "$P0F_URL"
	echo "$P0F_TGZ_SHA256  $tmp/p0f.tgz" | sha256sum -c --quiet
	tar -xzf "$tmp/p0f.tgz" -C "$tmp" "p0f-$P0F_VERSION/p0f.fp"
	install -m 0644 "$tmp/p0f-$P0F_VERSION/p0f.fp" "$DEST/etc/p0f.fp"
	echo "$P0F_FP_SHA256  $DEST/etc/p0f.fp" | sha256sum -c --quiet
	rm -rf "$tmp"
	log "p0f.fp $P0F_VERSION instalado"
fi

# 7. sysctl, journald e units
install_if_changed "$DEST/deploy/sysctl/90-finger-sniffer.conf" /etc/sysctl.d/90-finger-sniffer.conf 0644 || true
if install_if_changed "$DEST/deploy/journald/finger-sniffer.conf" /etc/systemd/journald.conf.d/finger-sniffer.conf 0644; then
	systemctl restart systemd-journald
fi
for f in "$DEST"/deploy/systemd/*; do
	install_if_changed "$f" "/etc/systemd/system/$(basename "$f")" 0644 && CHANGED_CONFIG=1
done
if [ "$CHANGED_CONFIG" = 1 ]; then
	systemctl daemon-reload
	systemctl enable --quiet finger-sniffer.target finger-sniffer-net.service $(for u in $UNITS; do echo "$u.service"; done)
fi

# 8. Rede (sempre: é barato e garante o estado)
systemctl restart finger-sniffer-net.service

# 9. Reinícios: binário em execução ≠ binário em disco reinicia sempre (com ou sem SVC); com SVC, o serviço
#    pedido também; sem SVC, ainda config/env/nats.conf mudados (nesta execução ou instalados por um deploy com
#    SVC e não aplicados: carimbo em $DEST/etc/applied), FORCE=1 ou unit parada.
conf_after=$(hash_file "$DEST/eventbus/nats/nats.conf")
NATS_CONF_CHANGED=0
[ "$conf_before" = "$conf_after" ] || NATS_CONF_CHANGED=1
restart=""
while IFS=$'\t' read -r u why; do
	[ -n "$u" ] || continue
	log "${u#finger-sniffer-}: $why"
	restart="$restart $u"
done < <(FORCE="$FORCE" CHANGED_CONFIG="$CHANGED_CONFIG" ENV_CHANGED="$ENV_CHANGED" \
	NATS_CONF_CHANGED="$NATS_CONF_CHANGED" plan_restarts "$DEST" "$SVC")
if [ -n "$restart" ]; then
	log "reiniciando:$restart"
	# shellcheck disable=SC2086
	systemctl restart $restart
	# carimbo da configuração aplicada (task 172): com SVC, o dos outros fica desatualizado e o próximo deploy
	# completo reinicia quem tiver configuração instalada e ainda não aplicada
	for u in $restart; do mark_applied "$DEST" "$u"; done
else
	log "nada mudou; nenhum serviço reiniciado"
fi
systemctl start finger-sniffer.target

# 10. Smoke test: units ativas, offloads e sysctl; depois os serviços respondendo
sleep 2
fail=0
for u in finger-sniffer-net $UNITS; do
	state=$(systemctl is-active "$u" || true)
	slice=$(unit_slice "$u")
	printf "  %-24s %s %s\n" "$u" "$state" "$slice"
	[ "$state" = active ] || fail=1
	# todas na fatia comum (ADR 0039 item 1)
	[ "$slice" = finger-sniffer.slice ] || {
		echo "  $u: fora de finger-sniffer.slice"
		fail=1
	}
done
NET_STATUS=/run/finger-sniffer/net-status.json
if grep -q '"aggregating_offload":true' "$NET_STATUS"; then
	echo "  offloads: AGREGAÇÃO LIGADA"
	fail=1
else
	echo "  offloads: agregação desligada"
fi
# todas as chaves do nosso arquivo com o valor dele no kernel (ADR 0038 item 7: iguais às do host ou acima)
mismatch=$(sysctl_mismatches "$DEST/deploy/sysctl/90-finger-sniffer.conf")
if [ -n "$mismatch" ]; then
	echo "  sysctl: NÃO aplicado"
	printf '%s\n' "$mismatch" | sed 's/^/    /'
	fail=1
else
	echo "  sysctl: aplicado"
fi
# conntrack e nftables são tolerados e só informados; NAT/redirecionamento numa porta do espelho reprova
# (ADR 0038 item 7; o health fica degraded com "nat on mirror ports")
echo "  nft: $(grep -o '"nft_ruleset_lines":[0-9]*' "$NET_STATUS" | cut -d: -f2) linhas;" \
	"conntrack: $(grep -o '"conntrack_loaded":[a-z]*' "$NET_STATUS" | cut -d: -f2)"
if grep -q '"nat_on_mirror_ports":true' "$NET_STATUS"; then
	echo "  nat: REGRA DE NAT NUMA PORTA DO ESPELHO (journalctl -u finger-sniffer-net)"
	fail=1
else
	echo "  nat: nenhuma regra nas portas do espelho"
fi
# serviços respondendo (deploy/smoke.sh): com SVC=<svc>, só os passos daquele serviço + health
SVC="$SVC" bash "$DEST/deploy/smoke.sh" || fail=1
if [ "$fail" = 1 ]; then
	log "SMOKE TEST FALHOU"
	journalctl -u 'finger-sniffer-*' -n 30 --no-pager
	exit 1
fi
log "ok"
