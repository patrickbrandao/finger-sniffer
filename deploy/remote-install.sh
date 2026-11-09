#!/usr/bin/env bash
# Instalação idempotente na vps602, executada pelo deploy.sh como root e sob trava.
# Argumento: diretório de staging com o repositório e bin/.
set -euo pipefail

STAGING="$1"
DEST=/finger-sniffer
SVC="${SVC:-}"
FORCE="${FORCE:-0}"
UNITS="finger-sniffer-nats finger-sniffer-store finger-sniffer-capture finger-sniffer-web finger-sniffer-raw finger-sniffer-dns"
CHANGED_CONFIG=0
ENV_CHANGED=0

log() { echo "[deploy] $*"; }

# shellcheck disable=SC1091
. "$STAGING/deploy/versions.env"

# install_if_changed <origem> <destino> <modo>: copia só se diferente; devolve 0 se mudou.
install_if_changed() {
	if [ -f "$2" ] && cmp -s "$1" "$2"; then
		return 1
	fi
	install -D -m "$3" "$1" "$2"
	log "atualizado $2"
	return 0
}

# 1. Usuário de sistema e layout
if ! id finger-sniffer >/dev/null 2>&1; then
	useradd --system --home-dir "$DEST/var" --no-create-home --shell /usr/sbin/nologin finger-sniffer
	log "usuário finger-sniffer criado"
fi
mkdir -p "$DEST/bin" "$DEST/etc" "$DEST/var/store" "$DEST/var/certs" "$DEST/var/acme" "$DEST/var/nats"
chown -R finger-sniffer:finger-sniffer "$DEST/var"
chmod 0750 "$DEST/var"

# 2. Binários: guarda o hash anterior para reiniciar só o que mudou
declare -A before=()
for u in $UNITS; do
	b="$DEST/bin/${u}"
	[ "$u" = finger-sniffer-nats ] && b="$DEST/bin/nats-server"
	before[$u]=$(sha256sum "$b" 2>/dev/null | cut -d' ' -f1 || true)
done
conf_before=$(sha256sum "$DEST/eventbus/nats/nats.conf" 2>/dev/null | cut -d' ' -f1 || true)

# 3. Repositório → /finger-sniffer (preserva var/, etc/ e o nats-server instalado)
rsync -a --delete --chown=root:root --exclude='/var/' --exclude='/etc/' --exclude='/bin/nats-server' "$STAGING/" "$DEST/"
chmod 0755 "$DEST/deploy/net/finger-sniffer-net.sh"
# htdocs: leitura pelo usuário finger-sniffer (web), qualquer que seja o umask de quem fez o checkout
[ -d "$DEST/htdocs" ] && chmod -R a+rX "$DEST/htdocs"

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

# 9. Reinícios
conf_after=$(sha256sum "$DEST/eventbus/nats/nats.conf" | cut -d' ' -f1)
restart=""
for u in $UNITS; do
	b="$DEST/bin/${u}"
	[ "$u" = finger-sniffer-nats ] && b="$DEST/bin/nats-server"
	after=$(sha256sum "$b" | cut -d' ' -f1)
	short=${u#finger-sniffer-}
	if [ -n "$SVC" ]; then
		[ "$short" = "$SVC" ] && restart="$restart $u"
	elif [ "$FORCE" = 1 ] || [ "$CHANGED_CONFIG" = 1 ] || [ "${before[$u]}" != "$after" ] ||
		{ [ "$ENV_CHANGED" = 1 ] && [ "$u" != finger-sniffer-nats ]; } ||
		{ [ "$u" = finger-sniffer-nats ] && [ "$conf_before" != "$conf_after" ]; } ||
		! systemctl is-active --quiet "$u"; then
		restart="$restart $u"
	fi
done
if [ -n "$restart" ]; then
	log "reiniciando:$restart"
	# shellcheck disable=SC2086
	systemctl restart $restart
else
	log "nada mudou; nenhum serviço reiniciado"
fi
systemctl start finger-sniffer.target

# 10. Smoke test
sleep 2
fail=0
for u in finger-sniffer-net $UNITS; do
	state=$(systemctl is-active "$u" || true)
	printf "  %-24s %s\n" "$u" "$state"
	[ "$state" = active ] || fail=1
done
if grep -q '"aggregating_offload":true' /run/finger-sniffer/net-status.json; then
	echo "  offloads: AGREGAÇÃO LIGADA"
	fail=1
else
	echo "  offloads: agregação desligada"
fi
if [ "$(sysctl -n net.core.somaxconn)" != 4096 ]; then
	echo "  sysctl: NÃO aplicado"
	fail=1
else
	echo "  sysctl: aplicado"
fi
if [ "$fail" = 1 ]; then
	log "SMOKE TEST FALHOU"
	journalctl -u 'finger-sniffer-*' -n 30 --no-pager
	exit 1
fi
log "ok"
