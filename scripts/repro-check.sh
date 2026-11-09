#!/usr/bin/env bash
# Teste do build reproduzível (task 070; rodado no CI e por `make repro-check`).
#
#   scripts/repro-check.sh [SHA256SUMS]
#
# Compila os 5 binários três vezes: duas seguidas no repositório e uma numa cópia da árvore em outro
# diretório, com GOCACHE vazio. Os três conjuntos precisam ter o mesmo SHA-256. Com SHA256SUMS (do tar de
# release), os binários também são conferidos contra ele (linhas "bin/finger-sniffer-*").
#
# Variáveis: VERSION e COMMIT (padrão: git describe / git rev-parse, iguais aos do Makefile).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck source=scripts/lib-release.sh
. "$ROOT/scripts/lib-release.sh"

EXPECT="${1:-}"
VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo 0.0.0-dev)}"
COMMIT="${COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo unknown)}"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/fs-repro.XXXXXX")"
trap 'chmod -R u+w "$WORK" 2>/dev/null; rm -rf "$WORK"' EXIT

echo "== build reproduzível: $VERSION ($COMMIT), $(go version)"
build_into "$ROOT" "$WORK/a" "$VERSION" "$COMMIT"
build_into "$ROOT" "$WORK/b" "$VERSION" "$COMMIT"
copy_tree "$ROOT" "$WORK/outro/lugar/finger-sniffer-copia"
build_into "$WORK/outro/lugar/finger-sniffer-copia" "$WORK/c" "$VERSION" "$COMMIT" "$WORK/gocache"

fail=0
for s in $SERVICES; do
	f="finger-sniffer-$s"
	ha=$(sha256_of "$WORK/a/$f")
	hb=$(sha256_of "$WORK/b/$f")
	hc=$(sha256_of "$WORK/c/$f")
	if [ "$ha" = "$hb" ] && [ "$ha" = "$hc" ]; then
		echo "ok   $ha  $f"
	else
		echo "FAIL $f: seguido=$ha/$hb outro diretório=$hc"
		fail=1
	fi
	# a versão tem de estar no binário (o -version imprime "<nome> <versão> (<commit>)")
	if ! grep -aqF "$VERSION" "$WORK/a/$f"; then
		echo "FAIL $f: versão $VERSION ausente no binário"
		fail=1
	fi
	if [ "$(uname -s)/$(uname -m)" = Linux/x86_64 ]; then
		got=$("$WORK/a/$f" -version)
		if [ "$got" != "$f $VERSION ($COMMIT)" ]; then
			echo "FAIL $f -version: '$got', esperado '$f $VERSION ($COMMIT)'"
			fail=1
		fi
	fi
	if [ -n "$EXPECT" ]; then
		want=$(awk -v p="bin/$f" '$2 == p {print $1}' "$EXPECT")
		if [ "$want" != "$ha" ]; then
			echo "FAIL $f: SHA256SUMS diz '${want:-ausente}', rebuild deu $ha"
			fail=1
		fi
	fi
done

if [ "$fail" = 0 ]; then
	echo "== build reproduzível: OK"
else
	echo "== build reproduzível: FALHOU"
fi
exit "$fail"
