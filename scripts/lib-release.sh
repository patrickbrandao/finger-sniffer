#!/usr/bin/env bash
# Funções comuns de scripts/release.sh, scripts/repro-check.sh e scripts/release-test.sh (task 070).
# Uso: source "$(dirname "$0")/lib-release.sh"

# shellcheck disable=SC2034 # usada por quem faz o source
SERVICES="capture web raw dns store"

# sha256_of <arquivo>: imprime só o hash (sha256sum no Linux, shasum no macOS)
sha256_of() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{print $1}'
	else
		shasum -a 256 "$1" | awk '{print $1}'
	fi
}

# sums_of_dir <dir>: linhas "<hash>  <caminho relativo>" de todos os arquivos, em ordem estável
sums_of_dir() {
	local dir="$1" f
	(cd "$dir" && find . -type f ! -name SHA256SUMS | sed 's|^\./||' | LC_ALL=C sort) | while read -r f; do
		printf '%s  %s\n' "$(sha256_of "$dir/$f")" "$f"
	done
}

# build_into <diretório do código> <diretório de saída> <versão> <commit> [GOCACHE]
# Compila os 5 binários com as flags do Makefile, a partir de <diretório do código>.
build_into() {
	local src="$1" out="$2" ver="$3" commit="$4" cache="${5:-}"
	mkdir -p "$out"
	if [ -n "$cache" ]; then
		(cd "$src" && GOCACHE="$cache" make -s build BIN="$out" VERSION="$ver" COMMIT="$commit") >/dev/null
	else
		(cd "$src" && make -s build BIN="$out" VERSION="$ver" COMMIT="$commit") >/dev/null
	fi
}

# copy_tree <origem> <destino>: cópia dos arquivos versionados e dos novos não ignorados (sem .git)
copy_tree() {
	local src="$1" dst="$2"
	mkdir -p "$dst"
	(cd "$src" && git ls-files -co --exclude-standard -z | while IFS= read -r -d '' f; do
		[ -f "$f" ] && printf '%s\0' "$f"
	done | tar -cf - --null -T -) | (cd "$dst" && tar -xf -)
}
