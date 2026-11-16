#!/usr/bin/env bash
# Teste do próprio scripts/verify.sh (tasks 174 e 203), sem rede: carrega as funções (modo lib) e confere que
#   - o format do full lê só os .go versionados ou novos não ignorados (tmp/ fica de fora);
#   - a lista de pacotes linux_priv também ignora tmp/;
#   - os testes linux_priv usam um diretório remoto próprio por execução e apagam só ele, inclusive com duas
#     execuções simultâneas, falha de compilação, falha de scp e sinal;
#   - o fork do traefik (traefik/**) fica fora de format, lint, binários e listas do raiz e tem o passo próprio
#     "traefik" (build + testes do código nosso e dos ganchos), e o openapi do bot entra nos contratos (task 262).
# O ssh/scp do servidor (finger-01) é trocado por stubs que executam localmente (o "remoto" é o /tmp desta máquina).
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

# ---- task 262: fork do traefik fora do módulo raiz, com passo próprio --------------------------------------
# Fork de teste em $M/traefik: módulo próprio, um .go mal formatado no código nosso, um gancho
# `// finger-sniffer:` num pacote do "upstream", um pacote sem gancho com teste que falha (não pode rodar), um
# teste linux_priv e um "binário" ELF versionado.
TF="$M/traefik"
mkdir -p "$TF/cmd/traefik" "$TF/pkg/fingersniffer" "$TF/pkg/server" "$TF/pkg/other" "$TF/p"
printf 'module example.com/fork\n\ngo 1.21\n' >"$TF/go.mod"
printf 'package main\n\nfunc main() {}\n' >"$TF/cmd/traefik/main.go"
printf 'package fingersniffer\nfunc   F( ) {  }\n' >"$TF/pkg/fingersniffer/fs.go"
for pkg in fingersniffer server; do
	cat >"$TF/pkg/$pkg/mark_test.go" <<EOF
package $pkg

import (
	"os"
	"testing"
)

func TestMark(t *testing.T) {
	f, err := os.OpenFile(os.Getenv("FS_MARK"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("$pkg\n")
	_ = f.Close()
}
EOF
done
printf 'package server\n\n// finger-sniffer: gancho do listener\nfunc Serve() {}\n' >"$TF/pkg/server/server.go"
printf 'package other\n\nimport "testing"\n\nfunc TestUpstream(t *testing.T) { t.Fatal("suíte do upstream não roda") }\n' \
	>"$TF/pkg/other/other_test.go"
cp "$M/p/x_test.go" "$TF/p/x_test.go"
printf '\177ELF\002\001\001\000\000\000\000\000\000\000\000\000\002\000\076\000' >"$TF/fixture.bin"
printf '/tmp/\n/bin/\n/dist/\n/finger-sniffer-*\n' >"$M/.gitignore"
(cd "$M" && git add .gitignore traefik && git -c user.name=t -c user.email=t@t commit -qm traefik) || {
	echo "FAIL commit do fork de teste"
	exit 1
}

check "traefik: format do raiz ignora .go mal formatado em traefik/" '(cd "$M" && gofumpt_all >/dev/null)'
check "traefik: go_source_files não lista traefik/" '! (cd "$M" && go_source_files) | grep -q "^traefik/"'
check "traefik: linux_priv_pkgs ignora traefik/" '[ "$(cd "$M" && linux_priv_pkgs | tr "\n" " ")" = "./bad ./p ./q " ]'
check "traefik: fuzz e testes do raiz não leem traefik/" '! (cd "$M" && test_files_matching "^package") | grep -q "traefik/"'
check "traefik: quick tira traefik/ dos arquivos do raiz" '[ "$(printf "traefik/pkg/a.go\np/p.go\n" | root_only)" = "p/p.go" ]'
check "traefik: binário em traefik/ não falha o raiz" 'FS_CHECK_ROOT="$M" "$ROOT/scripts/check-binaries.sh" >/dev/null'
check "traefik: binário em traefik/ passado como alterado também não" 'FS_CHECK_ROOT="$M" "$ROOT/scripts/check-binaries.sh" traefik/fixture.bin >/dev/null'
cp "$TF/fixture.bin" "$M/p/fixture.bin"
check "traefik: binário fora de traefik/ ainda falha" '! FS_CHECK_ROOT="$M" "$ROOT/scripts/check-binaries.sh" p/fixture.bin >/dev/null'
rm -f "$M/p/fixture.bin"

# make fmt: só os .go do raiz (gofumpt/goimports trocados por stubs que registram os argumentos)
mkdir -p "$T/fmtbin"
for tool in gofumpt goimports; do
	printf '#!/usr/bin/env bash\necho "%s $*" >>"$STUB_FMT_LOG"\n' "$tool" >"$T/fmtbin/$tool"
	chmod +x "$T/fmtbin/$tool"
done
: >"$T/fmt.log"
(cd "$M" && PATH="$T/fmtbin:$PATH" STUB_FMT_LOG="$T/fmt.log" make -s -f "$ROOT/Makefile" fmt >/dev/null 2>&1)
check "traefik: make fmt formata o raiz" '[ "$(grep -c "p/p.go" "$T/fmt.log")" = 2 ]'
check "traefik: make fmt não toca em traefik/" '! grep -q "traefik/" "$T/fmt.log"'

# plano do passo: quick só com traefik/** alterado; sem go.mod pula com aviso; full sempre (menos FS_SKIP_TRAEFIK)
check "traefik: quick pula sem mudança" '[ "$(cd "$M" && traefik_plan quick "p/p.go")" = "traefik sem mudança" ]'
check "traefik: quick roda com traefik/** alterado" '[ "$(cd "$M" && traefik_plan quick "traefik/pkg/server/server.go")" = run ]'
check "traefik: full roda sempre" '[ "$(cd "$M" && traefik_plan full)" = run ]'
check "traefik: FS_SKIP_TRAEFIK pula no full" '[ "$(cd "$M" && FS_SKIP_TRAEFIK=1 traefik_plan full)" = FS_SKIP_TRAEFIK=1 ]'
check "traefik: sem traefik/go.mod pula com aviso" '(cd "$T" && traefik_plan full) | grep -q "^sem traefik/go.mod" &&
	(cd "$T" && MODE=full traefik_step full) | grep -q "^aviso: passo traefik pulado"'
check "traefik: pacotes do passo (nosso + ganchos)" '[ "$(cd "$M" && traefik_test_pkgs | tr "\n" " ")" = "./pkg/fingersniffer/... ./pkg/server " ]'

# o passo de verdade: build do cmd/traefik e testes só do código nosso e dos ganchos
: >"$T/mark"
(cd "$M" && FS_MARK="$T/mark" traefik_check >"$T/out.traefik" 2>&1)
tf_rc=$?
check "traefik: passo roda build e testes" '[ "$tf_rc" = 0 ] && [ "$(sort "$T/mark" | tr "\n" " ")" = "fingersniffer server " ]'
check "traefik: build não deixa binário em traefik/" '[ ! -e "$TF/traefik" ]'
printf 'package server\n\nimport "testing"\n\nfunc TestBroken(t *testing.T) { t.Fatal("quebrado") }\n' >"$TF/pkg/server/broken_test.go"
(cd "$M" && FS_MARK="$T/mark" traefik_check >"$T/out.traefik-fail" 2>&1)
tf_rc=$?
check "traefik: teste quebrado num gancho falha o passo" '[ "$tf_rc" != 0 ]'
rm -f "$TF/pkg/server/broken_test.go"

# contratos: o openapi do bot entra no passo (stubs de redocly/asyncapi registram os argumentos)
CT="$T/ct"
mkdir -p "$CT/node_modules/.bin"
echo '{"lockfileVersion":3}' >"$CT/package-lock.json"
git hash-object "$CT/package-lock.json" >"$CT/node_modules/.fs-lock-hash"
for tool in redocly asyncapi; do
	printf '#!/usr/bin/env bash\necho "%s $*" >>"$STUB_CT_LOG"\n' "$tool" >"$CT/node_modules/.bin/$tool"
	chmod +x "$CT/node_modules/.bin/$tool"
done
: >"$T/ct.log"
(CONTRACTS_TOOLS_DIR="$CT" STUB_CT_LOG="$T/ct.log" contracts_check >/dev/null 2>&1)
check "contratos: redocly no openapi do bot" 'grep -q "^redocly lint .*cmd/finger-sniffer-bot/openapi.yaml$" "$T/ct.log"'
check "contratos: redocly no openapi do store" 'grep -q "^redocly lint .*cmd/finger-sniffer-store/openapi.yaml$" "$T/ct.log"'
check "contratos: openapi do bot alterado dispara o passo no quick" '[ "$(echo cmd/finger-sniffer-bot/openapi.yaml | grep -cE "$(contracts_re)")" = 1 ]'
check "contratos: o openapi do bot existe" '[ -s "$ROOT/$BOT_OPENAPI_FILE" ]'

# configuração: lint, hooks, .gitignore e CI tratam traefik/ à parte
check "golangci exclui traefik/ (linters e formatters)" '[ "$(grep -c "^      - \^traefik/$" "$ROOT/.golangci.yml")" = 2 ]'
check "lefthook exclui traefik/ (fmt e lint)" '[ "$(grep -c "^        - \"traefik/\*\*\"$" "$ROOT/lefthook.yml")" = 2 ]'
check ".gitignore versiona os fixtures do upstream" '! git -C "$ROOT" check-ignore -q --no-index traefik/integration/fixtures/https/a.key &&
	! git -C "$ROOT" check-ignore -q --no-index traefik/pkg/x/testdata/b.pem'
check ".gitignore ainda ignora lixo de editor em traefik/" 'git -C "$ROOT" check-ignore -q --no-index traefik/.DS_Store'
check "CI: job traefik roda o passo" 'grep -qF "run: scripts/verify.sh traefik" "$ROOT"/.github/workflows/ci.yml'
check "CI: cache do módulo do fork" 'grep -qE "^[[:space:]]+traefik/go\.sum$" "$ROOT"/.github/workflows/ci.yml'
check "CI: verify-full não repete o passo traefik" 'grep -qF "FS_SKIP_TRAEFIK: \"1\"" "$ROOT"/.github/workflows/ci.yml'

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

# ADR 0038: o padrão do linux_priv é o finger-01 e nenhum script cita o servidor nem a zona antigos (o padrão
# do grep é escrito com classes para não casar com esta linha)
check "linux_priv no finger-01 por padrão" '[ "$(env -u FS_VPS_SSH -u FS_VPS_PORT bash -c ". \"\$1/scripts/verify.sh\" lib; echo \$VPS_SSH \$VPS_PORT \$VPS_LABEL" _ "$ROOT")" = "root@finger-01.tmsoft.com.br 48022 finger-01" ]'
check "FS_VPS_SSH muda o destino e o rótulo" '[ "$(FS_VPS_SSH=root@outro.example bash -c ". \"\$1/scripts/verify.sh\" lib; echo \$VPS_SSH \$VPS_LABEL" _ "$ROOT")" = "root@outro.example outro" ]'
check "nenhum script com o servidor ou a zona antigos" '! grep -rnE "vps[6]02|dns[-]monitor" "$ROOT/Makefile" "$ROOT/deploy" "$ROOT/scripts" "$ROOT/.github" "$ROOT/.env.example"'

check "nenhum caminho fixo /tmp/fs-verify/ no verify.sh" '! grep -q "/tmp/fs-verify/" "$ROOT/scripts/verify.sh"'

# Cadeia de suprimentos (task 175, spec 017 RF-08 e RF-11): CLIs npm só por package-lock + npm ci
# --ignore-scripts, e toda action fixada por SHA de 40 caracteres com a versão em comentário.
check "verify.sh sem npx" '! grep -Eq "(^|[^a-z])npx( |$)" "$ROOT/scripts/verify.sh"'
check "contracts-tools com package-lock" '[ -s "$ROOT/scripts/contracts-tools/package-lock.json" ]'
check "toda action por SHA com versão em comentário" '! grep -hE "^[[:space:]-]*uses:" "$ROOT"/.github/workflows/*.yml |
	grep -vE "uses:[[:space:]]+[^@[:space:]]+@[0-9a-f]{40}[[:space:]]+#[[:space:]]*v[0-9]"'
check "há actions nos workflows" 'grep -qE "uses:" "$ROOT"/.github/workflows/ci.yml'

# Concorrência do CI (task 219): cancela a execução anterior só em PR; na main o grupo é por SHA.
CI_GROUP='group: ci-${{ github.event_name == '\''pull_request'\'' && github.ref || github.sha }}'
CI_CANCEL='cancel-in-progress: ${{ github.event_name == '\''pull_request'\'' }}'
check "CI agrupa a main por SHA" 'grep -qF "$CI_GROUP" "$ROOT"/.github/workflows/ci.yml'
check "CI cancela execução anterior só em PR" 'grep -qF "$CI_CANCEL" "$ROOT"/.github/workflows/ci.yml'
check "CI sem cancel-in-progress fixo em true" '! grep -qE "cancel-in-progress:[[:space:]]*true" "$ROOT"/.github/workflows/ci.yml'

# Tempo do CI (task 253): o passo verify-full tem timeout próprio, menor que o do job, e anota o tempo esgotado.
check "CI verify-full com timeout do passo" 'grep -qF "timeout --kill-after=30s 25m make verify-full" "$ROOT"/.github/workflows/ci.yml'
check "CI anota tempo esgotado" 'grep -qF "title=verify-full: tempo esgotado" "$ROOT"/.github/workflows/ci.yml'
check "CI job verify-full com 30 min" '[ "$(awk "/^  verify-full:/{f=1} f&&/timeout-minutes:/{print \$2; exit}" "$ROOT"/.github/workflows/ci.yml)" = 30 ]'

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

# ---- task 253: fuzz curto em lotes paralelos ---------------------------------------------------------------
# Stub de go: registra os argumentos e quantos alvos rodam ao mesmo tempo; FuzzBad falha.
FZ="$T/fz"
mkdir -p "$FZ/bin" "$FZ/run" "$FZ/mod/a" "$FZ/mod/b"
cat >"$FZ/bin/go" <<'EOF'
#!/usr/bin/env bash
name=$(printf '%s\n' "$@" | sed -nE 's/^-fuzz=\^(Fuzz[A-Za-z0-9_]*)\$$/\1/p')
echo "$*" >>"$FZ/args.log"
touch "$FZ/run/$name"
ls "$FZ/run" | wc -l | tr -d ' ' >>"$FZ/conc.log"
sleep 1
rm -f "$FZ/run/$name"
echo "saida de $name"
[ "$name" != FuzzBad ]
EOF
chmod +x "$FZ/bin/go"
printf 'package a\n\nimport "testing"\n\nfunc FuzzOne(f *testing.F) {}\n\nfunc FuzzTwo(f *testing.F) {}\n' >"$FZ/mod/a/a_test.go"
printf 'package b\n\nimport "testing"\n\nfunc FuzzBad(f *testing.F) {}\n\nfunc FuzzFour(f *testing.F) {}\n\nfunc FuzzFive(f *testing.F) {}\n' >"$FZ/mod/b/b_test.go"
(cd "$FZ/mod" && git init -q && git add . && git -c user.name=t -c user.email=t@t commit -qm init) || {
	echo "FAIL git init do módulo de fuzz"
	exit 1
}
(cd "$FZ/mod" && PATH="$FZ/bin:$PATH" FZ="$FZ" FS_FUZZ_JOBS=2 fuzz_all >"$T/out.fuzz" 2>&1)
fz_rc=$?
check "fuzz: alvo que falha falha o passo" '[ "$fz_rc" != 0 ]'
check "fuzz: todos os 5 alvos rodam" '[ "$(wc -l <"$FZ/args.log" | tr -d " ")" = 5 ]'
check "fuzz: cada alvo com FUZZ_TIME" '[ "$(grep -c -- "-fuzztime=$FUZZ_TIME " "$FZ/args.log")" = 5 ]'
check "fuzz: no máximo FS_FUZZ_JOBS ao mesmo tempo" '[ "$(sort -n "$FZ/conc.log" | tail -1)" = 2 ]'
check "fuzz: workers por alvo (-parallel)" '[ "$(grep -c -- "-parallel=[1-9]" "$FZ/args.log")" = 5 ]'
check "fuzz: saída de cada alvo no log" '[ "$(grep -c "^saida de Fuzz" "$T/out.fuzz")" = 5 ] && grep -q "FuzzBad ($FUZZ_TIME): FALHOU" "$T/out.fuzz"'

# ---- task 253: TERM (timeout do CI) imprime o resumo com o passo interrompido ----------------------------
bash -c '. "$1/scripts/verify.sh" lib; MODE=full; run_step "passo lento" sleep 1' _ "$ROOT" >"$T/out.term" 2>&1 &
pt=$!
sleep 0.3
kill -TERM "$pt" 2>/dev/null
wait "$pt"
term_rc=$?
check "TERM sai com 143" '[ "$term_rc" = 143 ]'
check "TERM imprime o passo interrompido" 'grep -q "interrompido por TERM durante: passo lento" "$T/out.term" && grep -q "== resultado: FALHOU" "$T/out.term"'

if [ "$fail" != 0 ]; then
	for f in "$T"/out.*; do
		echo "--- $f"
		cat "$f"
	done
fi
[ "$fail" = 0 ] && echo "ok: verify.sh"
exit "$fail"
