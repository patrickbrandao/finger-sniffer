#!/usr/bin/env bash
# Pacote de release (task 070; `make release VERSION=vX.Y.Z`).
#
#   scripts/release.sh vX.Y.Z
#
# 1. confere árvore limpa e HEAD igual à origin/main (ou à tag vX.Y.Z, se ela já existir);
# 2. roda `make verify-full`;
# 3. compila os 5 binários (build reproduzível, versão = vX.Y.Z);
# 4. gera dist/finger-sniffer-<versão>-linux-amd64.tar.gz com bin/, units, sysctl, journald, rede, nats.conf,
#    htdocs, LICENSE/NOTICE/CHANGELOG e SHA256SUMS (de todos os arquivos do pacote), mais o .sha256 do tar.
#
# Não cria tag, não faz commit, não publica nada (isso é do architect, .github/release-checklist.md).
#
# Variáveis:
#   FS_RELEASE_SKIP_CHECKS=1  pula os passos 1 e 2 (teste local: scripts/release-test.sh)
#   FS_RELEASE_DIST=<dir>     diretório de saída (padrão: dist/)
#   COMMIT                    commit gravado nos binários (padrão: git rev-parse --short HEAD)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck source=scripts/lib-release.sh
. "$ROOT/scripts/lib-release.sh"

VERSION="${1:-}"
if ! echo "$VERSION" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$'; then
	echo "uso: scripts/release.sh vX.Y.Z[-pre]" >&2
	exit 2
fi
COMMIT="${COMMIT:-$(git rev-parse --short HEAD)}"
DIST="${FS_RELEASE_DIST:-$ROOT/dist}"
NAME="finger-sniffer-$VERSION-linux-amd64"

if [ "${FS_RELEASE_SKIP_CHECKS:-0}" != 1 ]; then
	echo "== árvore limpa"
	if [ -n "$(git status --porcelain)" ]; then
		git status --short
		echo "árvore com alterações: faça commit ou descarte antes da release" >&2
		exit 1
	fi
	echo "== main atualizada"
	git fetch -q origin main
	head=$(git rev-parse HEAD)
	if git rev-parse -q --verify "refs/tags/$VERSION" >/dev/null; then
		# refazendo o pacote de uma tag existente: o HEAD tem de ser a tag
		if [ "$head" != "$(git rev-parse "$VERSION^{commit}")" ]; then
			echo "a tag $VERSION existe e não aponta para o HEAD" >&2
			exit 1
		fi
	elif [ "$head" != "$(git rev-parse origin/main)" ]; then
		echo "HEAD ($head) difere de origin/main: atualize a main (git pull) antes da release" >&2
		exit 1
	fi
	echo "== verify-full"
	make verify-full
else
	echo "== AVISO FS_RELEASE_SKIP_CHECKS=1: sem conferência de Git e sem verify-full"
fi

echo "== build $VERSION ($COMMIT), $(go version)"
STAGE="$(mktemp -d "${TMPDIR:-/tmp}/fs-release.XXXXXX")"
trap 'rm -rf "$STAGE"' EXIT
PKG="$STAGE/$NAME"
build_into "$ROOT" "$PKG/bin" "$VERSION" "$COMMIT"

# arquivos de instalação (layout da spec 016: units, rede, NATS e site)
mkdir -p "$PKG/deploy" "$PKG/eventbus/nats"
cp -R deploy/systemd deploy/sysctl deploy/journald deploy/net "$PKG/deploy/"
cp deploy/versions.env "$PKG/deploy/"
cp eventbus/nats/nats.conf "$PKG/eventbus/nats/"
cp .env.example "$PKG/"
cp -R htdocs "$PKG/"
cp LICENSE NOTICE CHANGELOG.md "$PKG/"
find "$PKG" \( -name .DS_Store -o -name "*.go" -o -name "*_test.*" \) -delete

sums_of_dir "$PKG" >"$PKG/SHA256SUMS"

# tar com ordem, dono e datas fixos (a data é a do commit), para o tar também ser estável
epoch=$(git log -1 --format=%ct HEAD 2>/dev/null || date +%s)
mkdir -p "$DIST"
TAR="$DIST/$NAME.tar.gz"
files=$(cd "$STAGE" && find "$NAME" | LC_ALL=C sort)
if tar --version 2>/dev/null | grep -q 'GNU tar'; then
	# shellcheck disable=SC2086
	(cd "$STAGE" && tar --no-recursion --owner=0 --group=0 --numeric-owner --mtime="@$epoch" \
		-cf - $files) | gzip -n -9 >"$TAR"
else
	# bsdtar (macOS): fixa as datas com touch antes de empacotar
	stamp=$(date -r "$epoch" +%Y%m%d%H%M.%S)
	(cd "$STAGE" && find "$NAME" -exec touch -h -t "$stamp" {} +)
	# shellcheck disable=SC2086
	(cd "$STAGE" && tar -n --uid 0 --gid 0 --uname root --gname root -cf - $files) | gzip -n -9 >"$TAR"
fi
cp "$PKG/SHA256SUMS" "$DIST/$NAME.SHA256SUMS"
(cd "$DIST" && printf '%s  %s\n' "$(sha256_of "$NAME.tar.gz")" "$NAME.tar.gz" >"$NAME.tar.gz.sha256")

echo "== pacote: $TAR"
cat "$DIST/$NAME.tar.gz.sha256"
grep ' bin/' "$PKG/SHA256SUMS"
