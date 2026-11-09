#!/usr/bin/env bash
# Funções do remote-install.sh para binários e reinícios (task 078), separadas para o teste em
# deploy/install_test.go. Sem efeito ao ser carregado com ". install-lib.sh".
#
# Regras:
#   - com SVC=<svc>, só o binário daquele serviço é instalado (SVC=nats: nenhum; o nats-server vem do download);
#     sem SVC, os 5;
#   - um serviço é reiniciado sempre que o binário EM EXECUÇÃO (/proc/<pid>/exe) difere do binário em disco,
#     com ou sem SVC: um deploy completo do mesmo commit corrige versões desencontradas deixadas antes.
#
# Variáveis para os testes: FS_PROC_ROOT (padrão /proc); main_pid pode ser redefinida.

FS_UNITS="finger-sniffer-nats finger-sniffer-store finger-sniffer-capture finger-sniffer-web finger-sniffer-raw finger-sniffer-dns"
FS_SERVICES="store capture web raw dns"

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

# plan_restarts <dest> <svc>: units a reiniciar, uma por linha ("<unit>\t<motivo>"). Binário em execução ≠
# binário em disco reinicia sempre; com SVC, o serviço pedido também; sem SVC, ainda FORCE=1, CHANGED_CONFIG=1
# (units), ENV_CHANGED=1 (todas menos o NATS), NATS_CONF_CHANGED=1 (só o NATS) ou unit parada.
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
		elif ! unit_active "$u"; then
			why="parada"
		fi
		[ -z "$why" ] || printf '%s\t%s\n' "$u" "$why"
	done
	return 0
}
