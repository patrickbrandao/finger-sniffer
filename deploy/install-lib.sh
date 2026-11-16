#!/usr/bin/env bash
# Funções do remote-install.sh para binários e reinícios (task 078), separadas para o teste em
# deploy/install_test.go. Sem efeito ao ser carregado com ". install-lib.sh".
#
# Regras:
#   - com SVC=<svc>, só o binário daquele serviço é instalado (SVC=nats: nenhum; o nats-server vem do download);
#     sem SVC, os 6;
#   - um serviço é reiniciado sempre que o binário EM EXECUÇÃO (/proc/<pid>/exe) difere do binário em disco,
#     com ou sem SVC: um deploy completo do mesmo commit corrige versões desencontradas deixadas antes.
#
# Variáveis para os testes: FS_PROC_ROOT (padrão /proc); main_pid pode ser redefinida.

# o bot vem depois do store (assina fs.v1.store.connection; ADR 0047 item 1)
FS_UNITS="finger-sniffer-nats finger-sniffer-store finger-sniffer-bot finger-sniffer-capture finger-sniffer-web finger-sniffer-raw finger-sniffer-dns"
FS_SERVICES="store bot capture web raw dns"

# hash_file <arquivo>: SHA-256 do conteúdo ("" se ilegível). sha256sum no Linux, shasum no macOS (testes).
hash_file() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" 2>/dev/null | cut -d' ' -f1 || true
	else
		shasum -a 256 "$1" 2>/dev/null | cut -d' ' -f1 || true
	fi
	return 0
}

# unit_binary <dest> <unit>: caminho do binário da unit em <dest>/bin.
unit_binary() {
	if [ "$2" = finger-sniffer-nats ]; then
		echo "$1/bin/nats-server"
	else
		echo "$1/bin/$2"
	fi
}

# binaries_for <svc>: nomes dos binários do projeto a instalar nesta seleção (um por linha).
binaries_for() {
	local s
	case "$1" in
	"") for s in $FS_SERVICES; do echo "finger-sniffer-$s"; done ;;
	nats) ;;
	*) echo "finger-sniffer-$1" ;;
	esac
}

# install_binaries <staging> <dest> <svc>: copia de <staging>/bin só os binários da seleção que mudaram.
install_binaries() {
	local b src dst
	mkdir -p "$2/bin"
	for b in $(binaries_for "$3"); do
		src="$1/bin/$b"
		dst="$2/bin/$b"
		if [ ! -f "$src" ]; then
			echo "[deploy] binário ausente no staging: $src" >&2
			return 1
		fi
		if [ -f "$dst" ] && cmp -s "$src" "$dst"; then
			continue
		fi
		# cópia + rename: o processo em execução segue com o inode antigo até o reinício
		install -m 0755 "$src" "$dst.new"
		mv -f "$dst.new" "$dst"
		echo "[deploy] atualizado $dst"
	done
}

# install_htdocs <staging> <dest>: espelha <staging>/htdocs em <dest>/htdocs só com os arquivos servíveis
# (sem *.go nem testdata/; --delete-excluded apaga os que deploys antigos deixaram) e legíveis por todos.
install_htdocs() {
	[ -d "$1/htdocs" ] || return 0
	mkdir -p "$2/htdocs"
	rsync -a --delete --delete-excluded --exclude='*.go' --exclude='testdata/' "$1/htdocs/" "$2/htdocs/"
	chmod -R a+rX "$2/htdocs"
}

# main_pid <unit>: PID principal da unit ("" ou 0 se parada).
main_pid() { systemctl show -p MainPID --value "$1" 2>/dev/null || true; }

# running_hash <unit>: SHA-256 do binário em execução ("" se a unit não roda).
running_hash() {
	local pid
	pid=$(main_pid "$1")
	if [ -z "$pid" ] || [ "$pid" = 0 ]; then
		return 0
	fi
	hash_file "${FS_PROC_ROOT:-/proc}/$pid/exe"
}

# binary_drift <dest> <unit>: verdadeiro se a unit não roda o binário que está em disco (ou não roda).
binary_drift() {
	local disk run
	disk=$(hash_file "$(unit_binary "$1" "$2")")
	run=$(running_hash "$2")
	[ -z "$run" ] || [ "$run" != "$disk" ]
}

# unit_active <unit>: a unit está ativa?
unit_active() { systemctl is-active --quiet "$1"; }

# config_hash <dest> <unit>: hashes da configuração que só vale depois de um reinício: o arquivo da unit e o
# nats.conf (NATS) ou o env (demais). FS_SYSTEMD_DIR para os testes (padrão /etc/systemd/system).
config_hash() {
	local extra
	if [ "$2" = finger-sniffer-nats ]; then
		extra="$1/eventbus/nats/nats.conf"
	else
		extra="$1/etc/finger-sniffer.env"
	fi
	printf 'unit=%s conf=%s\n' "$(hash_file "${FS_SYSTEMD_DIR:-/etc/systemd/system}/$2.service")" "$(hash_file "$extra")"
}

# config_drift <dest> <unit>: verdadeiro se a configuração atual difere da gravada no último reinício da unit
# (carimbo ausente conta como diferente; task 172, spec 016 RF-11).
config_drift() {
	[ "$(cat "$1/etc/applied/$2" 2>/dev/null || true)" != "$(config_hash "$1" "$2")" ]
}

# mark_applied <dest> <unit>: grava o carimbo da configuração com que a unit acabou de ser reiniciada. Fica em
# <dest>/etc/applied, fora do rsync (que exclui /etc/).
mark_applied() {
	mkdir -p "$1/etc/applied"
	config_hash "$1" "$2" >"$1/etc/applied/$2"
}

# plan_restarts <dest> <svc>: units a reiniciar, uma por linha ("<unit>\t<motivo>"). Binário em execução ≠
# binário em disco reinicia sempre; com SVC, o serviço pedido também (o carimbo dos demais fica desatualizado
# de propósito); sem SVC, ainda FORCE=1, CHANGED_CONFIG=1 (units), ENV_CHANGED=1 (todas menos o NATS),
# NATS_CONF_CHANGED=1 (só o NATS), configuração instalada e ainda não aplicada (config_drift) ou unit parada.
plan_restarts() {
	local u short why
	for u in $FS_UNITS; do
		short=${u#finger-sniffer-}
		why=""
		if binary_drift "$1" "$u"; then
			why="binário em execução difere do disco"
		elif [ -n "$2" ]; then
			[ "$short" = "$2" ] && why="SVC=$2"
		elif [ "${FORCE:-0}" = 1 ]; then
			why="FORCE=1"
		elif [ "${CHANGED_CONFIG:-0}" = 1 ]; then
			why="units mudaram"
		elif [ "${ENV_CHANGED:-0}" = 1 ] && [ "$u" != finger-sniffer-nats ]; then
			why="env mudou"
		elif [ "$u" = finger-sniffer-nats ] && [ "${NATS_CONF_CHANGED:-0}" = 1 ]; then
			why="nats.conf mudou"
		elif config_drift "$1" "$u"; then
			why="configuração instalada e ainda não aplicada"
		elif ! unit_active "$u"; then
			why="parada"
		fi
		[ -z "$why" ] || printf '%s\t%s\n' "$u" "$why"
	done
	return 0
}

# env_upgrade <arquivo env> <chave> <valor antigo> <valor novo>: troca o valor instalado da chave só quando ele é
# exatamente o padrão antigo (o env-merge.sh só acrescenta chaves; um valor mudado à mão no servidor fica). Devolve
# 0 se trocou. Ex.: FS_CAPTURE_EXCLUDE_PORTS ganhou 9002 e 9003 com o bot (ADR 0047 item 4, task 269).
env_upgrade() {
	local cur n tmp
	cur=$(grep -E "^$2=" "$1" | tail -n1 | cut -d= -f2-)
	[ "$cur" = "$3" ] || return 1
	n=$(grep -cE "^$2=" "$1")
	tmp=$(mktemp)
	# só a linha ativa (a última ocorrência vale no EnvironmentFile); conteúdo copiado de volta: dono e modo ficam
	awk -v k="$2" -v v="$4" -v n="$n" 'index($0, k "=") == 1 { i++; if (i == n) { print k "=" v; next } } { print }' \
		"$1" >"$tmp"
	cat "$tmp" >"$1"
	rm -f "$tmp"
	echo "[env] $2=$3 trocado pelo padrão novo $4"
}

# Ferramentas que o deploy e o smoke usam no servidor, com o pacote Debian de cada uma (task 225). O bootstrap
# instala só o que falta, sem tocar no resto do host.
FS_TOOL_PACKAGES="ethtool:ethtool ss:iproute2 ip:iproute2 nft:nftables curl:curl dig:bind9-dnsutils"

# missing_packages: pacotes das ferramentas ausentes, um por linha e sem repetição (nada se nada falta).
missing_packages() {
	local tp
	for tp in $FS_TOOL_PACKAGES; do
		command -v "${tp%%:*}" >/dev/null 2>&1 || echo "${tp#*:}"
	done | sort -u
}

# sysctl_mismatches <arquivo>: chaves do arquivo de sysctl do espelho cujo valor no kernel difere, uma por linha
# ("<chave>: <no kernel> (esperado <valor>)"); espaços e tabs são normalizados (ip_local_port_range sai com tab).
sysctl_mismatches() {
	local k v got
	while IFS='=' read -r k v; do
		k=$(printf '%s' "$k" | tr -d ' \t')
		case "$k" in "" | "#"*) continue ;; esac
		v=$(printf '%s' "$v" | tr -s ' \t' '  ' | sed 's/^ //; s/ $//')
		got=$(sysctl -n "$k" 2>/dev/null | tr -s ' \t' '  ' | sed 's/^ //; s/ $//')
		[ "$got" = "$v" ] || printf '%s: %s (esperado %s)\n' "$k" "${got:-ausente}" "$v"
	done <"$1"
	return 0
}

# unit_slice <unit>: fatia em que a unit roda (ADR 0039: finger-sniffer.slice).
unit_slice() { systemctl show -p Slice --value "$1" 2>/dev/null || true; }

# --- Banco do store em tmpfs (ADR 0045, spec 016 RF-07a, task 254) ---
# A mount unit em deploy/systemd é um modelo com @FS_UID@/@FS_GID@; o deploy nunca a para, reinicia nem desmonta.
# Variável para os testes: FS_STORE_MNT (ponto de montagem).
FS_STORE_MOUNT_UNIT='finger\x2dsniffer-var-store.mount'

# render_store_mount <modelo> <uid> <gid>: a mount unit com os ids numéricos do finger-sniffer (stdout).
render_store_mount() { sed -e "s/@FS_UID@/$2/g" -e "s/@FS_GID@/$3/g" "$1"; }

# mount_unit_size <unit>: valor de size= em Options= da mount unit (ex.: 4G).
mount_unit_size() {
	grep '^Options=' "$1" | tail -n1 | cut -d= -f2- | tr ',' '\n' | sed -n 's/^size=//p' | tail -n1
}

# size_bytes <tamanho>: bytes de um tamanho do tmpfs (sufixos k/m/g, potências de 1024; sem sufixo: bytes).
size_bytes() {
	local n=${1%[kKmMgG]}
	case "$1" in
	*[kK]) echo $((n * 1024)) ;;
	*[mM]) echo $((n * 1024 * 1024)) ;;
	*[gG]) echo $((n * 1024 * 1024 * 1024)) ;;
	*) echo "$1" ;;
	esac
}

# store_mount_info <ponto>: "<fstype> <bytes>" do ponto de montagem ("" se não for um ponto de montagem).
store_mount_info() {
	findmnt -bno FSTYPE,SIZE --mountpoint "$1" 2>/dev/null | awk 'NR==1{print $1, $2}' || true
}

# ensure_store_tmpfs <mount unit instalada>: garante o tmpfs do banco sem perder o conteúdo.
#   - ponto ainda não montado (primeira instalação ou reinício do host): para o store, apaga o banco que estiver
#     em disco (senão fica escondido debaixo do tmpfs ocupando disco) e monta pela mount unit; o store sobe depois
#     no passo dos reinícios (unit parada);
#   - montado como tmpfs com outro tamanho: mount -o remount,size=… (o conteúdo fica);
#   - montado com o tamanho certo: nada;
#   - montado com outro tipo: erro.
ensure_store_tmpfs() {
	local mnt=${FS_STORE_MNT:-/finger-sniffer/var/store} size want info
	size=$(mount_unit_size "$1")
	want=$(size_bytes "$size")
	info=$(store_mount_info "$mnt")
	if [ -z "$info" ]; then
		echo "[deploy] $mnt sem tmpfs: parando o store, apagando o banco em disco e montando ($size)"
		systemctl stop finger-sniffer-store.service
		rm -f "$mnt"/finger-sniffer.sqlite "$mnt"/finger-sniffer.sqlite-*
		systemctl start "$FS_STORE_MOUNT_UNIT"
	elif [ "${info%% *}" != tmpfs ]; then
		echo "[deploy] $mnt montado como ${info%% *}, não tmpfs" >&2
		return 1
	elif [ "${info#* }" != "$want" ]; then
		echo "[deploy] tmpfs do banco de ${info#* } para $want bytes: remount (o conteúdo fica)"
		mount -o "remount,size=$size" "$mnt"
	fi
}

# store_tmpfs_check <mount unit instalada>: linha do smoke; falha se o ponto não for tmpfs do tamanho da unit.
store_tmpfs_check() {
	local mnt=${FS_STORE_MNT:-/finger-sniffer/var/store} size want info
	size=$(mount_unit_size "$1")
	want=$(size_bytes "$size")
	info=$(store_mount_info "$mnt")
	if [ "$info" = "tmpfs $want" ]; then
		echo "  banco do store: tmpfs $size em $mnt"
		return 0
	fi
	echo "  banco do store: $mnt NÃO é tmpfs de $size (${info:-não montado})"
	return 1
}
