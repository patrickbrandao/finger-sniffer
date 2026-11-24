#!/usr/bin/env bash
# Teste de `make release` (task 070; rodado no CI): gera o pacote de uma versão de teste num diretório
# temporário, sem conferência de Git nem verify-full, e confere que:
#   - o tar tem os 6 binários, units, nats.conf, htdocs e SHA256SUMS, e o SHA256SUMS bate com o conteúdo;
#   - o NOTICE do pacote cita as fontes de terceiros, inclusive a ja4db (ADR 0053 item 3, task 392);
#   - nada no Git mudou (HEAD, refs/tags, status).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck source=scripts/lib-release.sh
. "$ROOT/scripts/lib-release.sh"

VERSION="${1:-v0.0.0-test}"
NAME="finger-sniffer-$VERSION-linux-amd64"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/fs-release-test.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

git_state() {
	git rev-parse HEAD
	git for-each-ref refs/tags
	git status --porcelain
}
# shellcheck disable=SC2034 # lida dentro do eval de check
before=$(git_state)

FS_RELEASE_SKIP_CHECKS=1 FS_RELEASE_DIST="$WORK/dist" make -s release VERSION="$VERSION"

fail=0
check() {
	if eval "$2"; then echo "ok   $1"; else
		echo "FAIL $1"
		fail=1
	fi
}

TAR="$WORK/dist/$NAME.tar.gz"
check "tar gerado" "[ -s '$TAR' ]"
mkdir -p "$WORK/x"
tar -xzf "$TAR" -C "$WORK/x"
PKG="$WORK/x/$NAME"
for s in $SERVICES; do
	check "bin/finger-sniffer-$s" "[ -x '$PKG/bin/finger-sniffer-$s' ] && file -b '$PKG/bin/finger-sniffer-$s' | grep -q '^ELF 64-bit.*x86-64'"
	check "unit finger-sniffer-$s.service" "[ -f '$PKG/deploy/systemd/finger-sniffer-$s.service' ]"
done
check "nats.conf" "[ -f '$PKG/eventbus/nats/nats.conf' ]"
check "htdocs/index.html" "[ -f '$PKG/htdocs/index.html' ]"
# atribuições exigidas no NOTICE (ADR 0053 item 3)
notice_cites_all() {
	local w
	for w in Fingerproxy JA3 'FoxIO License 1.1' p0f 'ja4db (https://ja4db.com)'; do
		grep -qF "$w" "$1" || return 1
	done
}
check "NOTICE com as atribuições (ja4db inclusive)" "notice_cites_all '$PKG/NOTICE'"
check "SHA256SUMS confere com o conteúdo" "[ \"\$(sums_of_dir '$PKG')\" = \"\$(cat '$PKG/SHA256SUMS')\" ]"
check "SHA256SUMS cobre os binários" "[ \$(grep -c ' bin/finger-sniffer-' '$PKG/SHA256SUMS') = 6 ]"
check "SHA256SUMS ao lado do tar" "cmp -s '$PKG/SHA256SUMS' '$WORK/dist/$NAME.SHA256SUMS'"
check ".sha256 do tar" "[ \"\$(awk '{print \$1}' '$TAR.sha256')\" = \"\$(sha256_of '$TAR')\" ]"
check "versão nos binários" "grep -aqF '$VERSION' '$PKG/bin/finger-sniffer-web'"
# os binários saem da toolchain do go.mod, e o make a exporta para todos os alvos (build e deploy inclusive), mesmo
# com GOTOOLCHAIN=auto no ambiente; só a linha de comando a troca (task 395)
TOOLCHAIN=$(sed -n 's/^toolchain //p' go.mod)
check "toolchain do go.mod no go.mod ($TOOLCHAIN)" "[ -n '$TOOLCHAIN' ]"
check "make exporta GOTOOLCHAIN do go.mod" "[ \"\$(GOTOOLCHAIN=auto make -s toolchain)\" = '$TOOLCHAIN' ]"
check "GOTOOLCHAIN na linha de comando vale" "[ \"\$(make -s toolchain GOTOOLCHAIN=local)\" = local ]"
check "binário compilado com $TOOLCHAIN" "go version '$PKG/bin/finger-sniffer-web' | grep -qE ': $TOOLCHAIN\$'"
check "Git intocado" "[ \"\$(git_state)\" = \"\$before\" ]"
check "dist/ do repositório intocado" "[ ! -e '$ROOT/dist/$NAME.tar.gz' ]"

[ "$fail" = 0 ] && echo "== release-test: OK" || echo "== release-test: FALHOU"
exit "$fail"
