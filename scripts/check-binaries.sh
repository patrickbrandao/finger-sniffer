#!/usr/bin/env bash
# Nenhum executável compilado versionado (task 070: o Mach-O finger-sniffer-raw da raiz).
#
#   scripts/check-binaries.sh [arquivos...]   # sem argumentos: todos os arquivos do git ls-files
#
# Falha se algum arquivo é ELF, Mach-O ou PE, ou se os binários soltos na raiz (/finger-sniffer-*)
# e bin/ ou dist/ não estão no .gitignore.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail=0
list() {
	if [ $# -gt 0 ]; then
		printf '%s\0' "$@"
	else
		git ls-files -z
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
