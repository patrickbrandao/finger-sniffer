#!/usr/bin/env bash
# Teste do próprio scripts/verify.sh (tasks 174 e 203), sem rede: carrega as funções (modo lib) e confere que
#   - o format do full lê só os .go versionados ou novos não ignorados (tmp/ fica de fora);
#   - a lista de pacotes linux_priv também ignora tmp/;
#   - os testes linux_priv usam um diretório remoto próprio por execução e apagam só ele, inclusive com duas
#     execuções simultâneas, falha de compilação, falha de scp e sinal.
# O ssh/scp da vps602 é trocado por stubs que executam localmente (o "remoto" é o /tmp desta máquina).
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
T="$(mktemp -d "${TMPDIR:-/tmp}/fs-verify-test.XXXXXX")"
LOG="$T/remote-dirs.log"
: >"$LOG"

# shellcheck source=scripts/verify.sh
. "$ROOT/scripts/verify.sh" lib
set +e
# Substitui o trap do verify.sh: apaga o WORK dele, o diretório do teste e qualquer sobra registrada no log.
final_cleanup() {
	rm -rf "$WORK"
	if [ -s "$LOG" ]; then
		while IFS= read -r d; do rm -rf "$d"; done <"$LOG"
	fi
	rm -rf "$T"
}
trap final_cleanup EXIT

fail=0
check() {
	if eval "$2"; then echo "ok   $1"; else
		echo "FAIL $1"
		fail=1
	fi
}

# ---- stubs de ssh e scp ------------------------------------------------------------------------------------
mkdir -p "$T/bin"
cat >"$T/bin/ssh" <<'EOF'
#!/usr/bin/env bash
# Stub: ignora -p/-o e o destino; roda o comando localmente. mktemp é registrado no log; a execução do binário
# de teste vira "existe e é executável" + espera (o binário é linux/amd64 e precisaria de root).
while [ $# -gt 0 ]; do
	case "$1" in
	-p | -o) shift 2 ;;
	-*) shift ;;
	*) break ;;
	esac
done
shift # destino
cmd="$*"
case "$cmd" in
mktemp*)
	out=$(sh -c "$cmd") || exit 1
	echo "$out" >>"$STUB_LOG"
	echo "$out"
	;;
*" -test.v -test.count=1")
	cmd=$(echo "$cmd" | sed -E 's#\./([^ ]+) -test\.v -test\.count=1#test -x ./\1 \&\& sleep '"${STUB_RUN_SLEEP:-0}"'#')
	sh -c "$cmd"
	;;
*) sh -c "$cmd" ;;
esac
EOF
cat >"$T/bin/scp" <<'EOF'
#!/usr/bin/env bash
# Stub: scp -q -P <porta> <origem> <destino>:<caminho> vira cp; STUB_SCP_FAIL=1 simula falha.
[ "${STUB_SCP_FAIL:-0}" = 1 ] && exit 1
src="${@: -2:1}"
dst="${@: -1}"
cp -p "$src" "${dst#*:}"
EOF
chmod +x "$T/bin/ssh" "$T/bin/scp"
export PATH="$T/bin:$PATH" STUB_LOG="$LOG"

# ---- módulo de teste ---------------------------------------------------------------------------------------
M="$T/mod"
mkdir -p "$M/p" "$M/q" "$M/bad" "$M/tmp/ref"
cat >"$M/go.mod" <<'EOF'
module example.com/verifytest

go 1.21
EOF
for pkg in p q; do
	cat >"$M/$pkg/x_test.go" <<EOF
//go:build linux_priv

package $pkg

import "testing"

func TestX(t *testing.T) {}
EOF
done
cat >"$M/bad/x_test.go" <<'EOF'
//go:build linux_priv

package bad

func broken() { undefinedFunc() }
EOF
cp "$M/p/x_test.go" "$M/tmp/ref/x_test.go"
# .go mal formatado dentro de tmp/ (ignorado) e um bem formatado versionado
printf 'package ref\nfunc   F( ) {  }\n' >"$M/tmp/ref/bad.go"
printf 'package p\n' >"$M/p/p.go"
printf '/tmp/\n' >"$M/.gitignore"
(
	cd "$M" && git init -q && git add .gitignore go.mod p q bad && git -c user.name=t -c user.email=t@t commit -qm init
) || {
	echo "FAIL git init do módulo de teste"
	exit 1
}

# ---- task 203: format e listas só do que o Git vê ---------------------------------------------------------
check "format ignora .go mal formatado em tmp/" '(cd "$M" && gofumpt_all >/dev/null)'
check "go_source_files não lista tmp/" '! (cd "$M" && go_source_files) | grep -q "^tmp/"'
check "linux_priv_pkgs ignora tmp/" '[ "$(cd "$M" && linux_priv_pkgs | tr "\n" " ")" = "./bad ./p ./q " ]'
printf 'package p\nfunc   G( ) {  }\n' >"$M/p/new.go"
check "format pega .go novo não ignorado" '! (cd "$M" && gofumpt_all >/dev/null)'
rm -f "$M/p/new.go"

# ---- task 174: diretório remoto por execução ---------------------------------------------------------------
# run_priv <rótulo> <pacotes>: roda linux_priv_tests num subshell com WORK próprio; grava o rc em $T/rc.<rótulo>
run_priv() {
	(
		WORK=$(mktemp -d "$T/work.XXXXXX")
		cd "$M" && linux_priv_tests "$2" >"$T/out.$1" 2>&1
		echo $? >"$T/rc.$1"
	)
}
leftovers() {
	local d n=0
	while IFS= read -r d; do [ -e "$d" ] && n=$((n + 1)); done <"$LOG"
	echo "$n"
}

: >"$LOG"
STUB_RUN_SLEEP=2 run_priv a "./p ./q" &
pa=$!
STUB_RUN_SLEEP=2 run_priv b "./p ./q" &
pb=$!
wait "$pa" "$pb"
check "duas execuções simultâneas passam" '[ "$(cat "$T/rc.a")" = 0 ] && [ "$(cat "$T/rc.b")" = 0 ]'
check "cada execução no seu diretório" '[ "$(sort -u "$LOG" | grep -c "^/tmp/fs-verify\.")" = 2 ]'
check "sem sobras depois das simultâneas" '[ "$(leftovers)" = 0 ]'

: >"$LOG"
run_priv c "./bad ./p"
check "falha de compilação falha o passo" '[ "$(cat "$T/rc.c")" != 0 ]'
check "falha de compilação não deixa diretório" '[ -s "$LOG" ] && [ "$(leftovers)" = 0 ]'

: >"$LOG"
STUB_SCP_FAIL=1 run_priv d "./p"
check "falha de scp falha o passo" '[ "$(cat "$T/rc.d")" != 0 ]'
check "falha de scp não deixa diretório" '[ -s "$LOG" ] && [ "$(leftovers)" = 0 ]'

# Sinal no meio do passo: o trap EXIT do verify.sh apaga o diretório remoto.
: >"$LOG"
STUB_RUN_SLEEP=2 bash -c '. "$1/scripts/verify.sh" lib; cd "$2" && linux_priv_tests ./p' _ "$ROOT" "$M" \
	>"$T/out.e" 2>&1 &
pe=$!
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
	[ -s "$LOG" ] && break
	sleep 0.2
done
kill -TERM "$pe" 2>/dev/null
wait "$pe"
check "TERM no meio do passo não deixa diretório" '[ -s "$LOG" ] && [ "$(leftovers)" = 0 ]'

check "nenhum caminho fixo /tmp/fs-verify/ no verify.sh" '! grep -q "/tmp/fs-verify/" "$ROOT/scripts/verify.sh"'

# Cadeia de suprimentos (task 175, spec 017 RF-08 e RF-11): CLIs npm só por package-lock + npm ci
# --ignore-scripts, e toda action fixada por SHA de 40 caracteres com a versão em comentário.
check "verify.sh sem npx" '! grep -Eq "(^|[^a-z])npx( |$)" "$ROOT/scripts/verify.sh"'
check "contracts-tools com package-lock" '[ -s "$ROOT/scripts/contracts-tools/package-lock.json" ]'
check "toda action por SHA com versão em comentário" '! grep -hE "^[[:space:]-]*uses:" "$ROOT"/.github/workflows/*.yml |
	grep -vE "uses:[[:space:]]+[^@[:space:]]+@[0-9a-f]{40}[[:space:]]+#[[:space:]]*v[0-9]"'
check "há actions nos workflows" 'grep -qE "uses:" "$ROOT"/.github/workflows/ci.yml'

# npm_deps: npm ci --ignore-scripts uma vez por package-lock.json (stub de npm registra as chamadas)
cat >"$T/bin/npm" <<'EOF'
#!/usr/bin/env bash
echo "$*" >>"$STUB_NPM_LOG"
while [ $# -gt 0 ]; do
	[ "$1" = --prefix ] && mkdir -p "$2/node_modules"
	shift
done
EOF
chmod +x "$T/bin/npm"
export STUB_NPM_LOG="$T/npm.log"
mkdir -p "$T/npmpkg"
echo '{"lockfileVersion":3}' >"$T/npmpkg/package-lock.json"
npm_deps "$T/npmpkg" && npm_deps "$T/npmpkg"
check "npm_deps roda npm ci --ignore-scripts uma vez" '[ "$(grep -c "^ci --prefix $T/npmpkg --ignore-scripts" "$STUB_NPM_LOG")" = 1 ]'
echo '{"lockfileVersion":3,"x":1}' >"$T/npmpkg/package-lock.json"
npm_deps "$T/npmpkg"
check "npm_deps reinstala quando o lock muda" '[ "$(grep -c "^ci " "$STUB_NPM_LOG")" = 2 ]'

if [ "$fail" != 0 ]; then
	for f in "$T"/out.*; do
		echo "--- $f"
		cat "$f"
	done
fi
[ "$fail" = 0 ] && echo "ok: verify.sh"
exit "$fail"
