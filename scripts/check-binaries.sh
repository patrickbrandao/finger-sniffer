#!/usr/bin/env bash
# Nenhum executável compilado versionado (task 070: o Mach-O finger-sniffer-raw da raiz).
#
#   scripts/check-binaries.sh [arquivos...]   # sem argumentos: todos os arquivos do git ls-files
#
# O fork do traefik (traefik/**, ADR 0048) fica de fora: é um módulo à parte, com o passo próprio (task 262).
# FS_CHECK_ROOT troca a raiz do repositório (usado por scripts/verify-test.sh).
# Falha se algum arquivo é ELF, Mach-O ou PE, ou se os binários soltos na raiz (/finger-sniffer-*)
# e bin/ ou dist/ não estão no .gitignore.
set -euo pipefail

ROOT="${FS_CHECK_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
cd "$ROOT"

fail=0
list() {
	local f
	if [ $# -gt 0 ]; then
		for f in "$@"; do
			case "$f" in
			traefik/*) ;;
			*) printf '%s\0' "$f" ;;
			esac
		done
	else
		git ls-files -z -- ':(exclude)traefik/'
	fi
}
while IFS= read -r -d '' f; do
	[ -f "$f" ] || continue
	kind=$(file -b "$f")
	case "$kind" in
	ELF* | Mach-O* | PE32* | "MS-DOS executable"*)
		echo "FAIL binário versionado: $f ($kind)"
		fail=1
		;;
	esac
done < <(list "$@")

for p in finger-sniffer-raw finger-sniffer-web bin/finger-sniffer-web dist/x.tar.gz; do
	if ! git check-ignore -q --no-index "$p"; then
		echo "FAIL .gitignore não cobre $p"
		fail=1
	fi
done
[ "$fail" = 0 ] && echo "ok: nenhum binário versionado"
exit "$fail"
