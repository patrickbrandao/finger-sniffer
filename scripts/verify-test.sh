#!/usr/bin/env bash
# Teste do próprio scripts/verify.sh (tasks 174 e 203), sem rede: carrega as funções (modo lib) e confere que
#   - o format do full lê só os .go versionados ou novos não ignorados (tmp/ fica de fora);
#   - a lista de pacotes linux_priv também ignora tmp/;
#   - os testes linux_priv usam um diretório remoto próprio por execução e apagam só ele, inclusive com duas
#     execuções simultâneas, falha de compilação, falha de scp e sinal;
#   - o openapi do bot entra nos contratos (task 262);
#   - os testes -race do store em lotes no CI: repartição, união dos lotes = lista (falha com um teste omitido de
#     propósito), race-shard num módulo mínimo e o workflow (task 294);
#   - o passo e2e é recusado com a trava da carga no servidor, salvo FS_E2E_DURING_LOAD=1 (task 361);
#   - o quick acha os pacotes de mudanças fora de .go: testdata, arquivo embutido, diretório de dados, go.mod e o
#     pacote deploy (task 362).
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

# make fmt: os .go versionados (gofumpt/goimports trocados por stubs que registram os argumentos; task 272)
mkdir -p "$T/fmtbin"
for tool in gofumpt goimports; do
	printf '#!/usr/bin/env bash\necho "%s $*" >>"$STUB_FMT_LOG"\n' "$tool" >"$T/fmtbin/$tool"
	chmod +x "$T/fmtbin/$tool"
done
: >"$T/fmt.log"
(cd "$M" && PATH="$T/fmtbin:$PATH" STUB_FMT_LOG="$T/fmt.log" make -s -f "$ROOT/Makefile" fmt >/dev/null 2>&1)
check "make fmt formata os .go versionados" '[ "$(grep -c "p/p.go" "$T/fmt.log")" = 2 ]'
check "make fmt não toca em tmp/" '! grep -q "tmp/" "$T/fmt.log"'

# ---- task 262: openapi do bot nos contratos ----------------------------------------------------------------
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

# ---- task 269: banco-modelo do bot com hash próprio (spec 017 RF-16) ---------------------------------------
# modelo dentro de tmp/ do repositório (o verify exporta "$ROOT/<caminho relativo>"); store sem migrations
DBREL="tmp/verify-test-botdb-$$"
botdb() {
	(cd "$ROOT" && env -u FS_TEST_DB -u FS_TEST_DB_TEMPLATE -u FS_TEST_BOT_DB -u FS_TEST_BOT_DB_TEMPLATE \
		bash -c '. scripts/verify.sh lib; MIGRATIONS_DIR="$1/none" BOT_TEMPLATE_DB="$1/bot.sqlite"
		prepare_test_db >/dev/null && echo "$DB_RESULT|${FS_TEST_BOT_DB:-}|${FS_TEST_BOT_DB_TEMPLATE:-}|${FS_TEST_DB:-}"' _ "$DBREL")
}
botdb >"$T/out.botdb1" 2>&1
botdb >"$T/out.botdb2" 2>&1
check "banco-modelo do bot: criado e exportado (store sem migrations fica de fora)" \
	'[ "$(cat "$T/out.botdb1")" = "store=skipped bot=rebuilt|local|$ROOT/$DBREL/bot.sqlite|" ]'
check "banco-modelo do bot: segunda vez em dia" '[ "$(cut -d"|" -f1 "$T/out.botdb2")" = "store=skipped bot=fresh" ]'
check "banco-modelo do bot: migrado (goose_db_version)" 'grep -q goose_db_version "$ROOT/$DBREL/bot.sqlite"'
rm -rf "${ROOT:?}/$DBREL"

# ---- task 294: testes -race do store em lotes no CI --------------------------------------------------------
RC="$T/race"
mkdir -p "$RC"
# race_assign: cada teste em exatamente um lote de 1..n, o pesado sozinho, determinístico
printf 'TestHeavy 50\nTestMid 10\n' >"$RC/weights"
for i in 1 2 3 4 5 6 7 8; do echo "p/x Test$i"; done >"$RC/list"
printf 'p/x TestHeavy\np/x TestMid\np/y TestOther\n' >>"$RC/list"
RACE_WEIGHTS="$RC/weights" race_assign 3 <"$RC/list" >"$RC/assign1"
RACE_WEIGHTS="$RC/weights" race_assign 3 <"$RC/list" >"$RC/assign2"
awk '{ print $2, $3 }' "$RC/assign1" | LC_ALL=C sort >"$RC/assigned"
LC_ALL=C sort "$RC/list" >"$RC/listed"
check "lotes: cada teste em exatamente um lote" '[ -s "$RC/listed" ] && cmp -s "$RC/assigned" "$RC/listed"'
check "lotes: só lotes 1..n" '[ -z "$(awk "\$1 < 1 || \$1 > 3" "$RC/assign1")" ]'
check "lotes: determinístico" 'cmp -s "$RC/assign1" "$RC/assign2"'
heavy=$(awk '$3 == "TestHeavy" { print $1 }' "$RC/assign1")
check "lotes: teste pesado sozinho no lote" '[ "$(awk -v k="$heavy" "\$1 == k" "$RC/assign1" | wc -l | tr -d " ")" = 1 ]'
check "lotes: sem arquivo de pesos também reparte" '[ "$(RACE_WEIGHTS="$RC/nada" race_assign 4 <"$RC/list" | awk "{print \$1}" | sort -u | wc -l | tr -d " ")" = 4 ]'

# race_union_check: lista e resultados montados à mão (ok, um teste omitido, repetido, sobrando, listas diferentes)
union() {
	rm -rf "$RC/u" && mkdir -p "$RC/u"
	for k in 1 2 3; do cp "$RC/list" "$RC/u/expected-$k.txt"; done
	awk '{print $2, $3 > ("'"$RC"'/u/ran-" $1 ".txt")}' "$RC/assign1"
}
union
(race_union_check 3 "$RC/u") >"$T/out.union-ok" 2>&1
union_rc=$?
check "união dos lotes: completa passa" '[ "$union_rc" = 0 ] && grep -q "testes na lista: 11; com resultado: 11" "$T/out.union-ok"'
union
for k in 1 2 3; do
	{ grep -v " TestMid$" "$RC/u/ran-$k.txt" || true; } >"$RC/u/x"
	mv "$RC/u/x" "$RC/u/ran-$k.txt"
done
(race_union_check 3 "$RC/u") >"$T/out.union-miss" 2>&1
union_rc=$?
check "união dos lotes: teste omitido falha" '[ "$union_rc" != 0 ] && grep -q "fora de todos os lotes: p/x TestMid" "$T/out.union-miss"'
union
echo "p/x Test1" >>"$RC/u/ran-3.txt"
echo "p/x Test1" >>"$RC/u/ran-2.txt"
(race_union_check 3 "$RC/u") >"$T/out.union-dup" 2>&1
union_rc=$?
check "união dos lotes: teste repetido falha" '[ "$union_rc" != 0 ] && grep -q "em mais de um lote: p/x Test1" "$T/out.union-dup"'
union
echo "p/x TestNovo" >>"$RC/u/ran-1.txt"
(race_union_check 3 "$RC/u") >"$T/out.union-extra" 2>&1
union_rc=$?
check "união dos lotes: teste fora da lista falha" '[ "$union_rc" != 0 ] && grep -q "fora da lista: p/x TestNovo" "$T/out.union-extra"'
union
echo "p/x TestSoNoLote2" >>"$RC/u/expected-2.txt"
(race_union_check 3 "$RC/u") >"$T/out.union-lists" 2>&1
union_rc=$?
check "união dos lotes: listas diferentes entre lotes falham" '[ "$union_rc" != 0 ] && grep -q "lote 2: lista de testes diferente" "$T/out.union-lists"'
union
rm "$RC/u/ran-3.txt"
(race_union_check 3 "$RC/u") >"$T/out.union-lost" 2>&1
union_rc=$?
check "união dos lotes: lote sem resultado falha" '[ "$union_rc" != 0 ] && grep -q "lote 3: sem" "$T/out.union-lost"'

# full_test_pkgs: sem FS_RACE_SPLIT_PKGS, ./...; com, ./... sem os pacotes em lotes
check "full sem lotes roda ./..." '[ "$(RACE_SPLIT_PKGS="" full_test_pkgs)" = "./..." ]'
RACE_SPLIT_PKGS=./internal/store/... full_test_pkgs >"$T/out.fullpkgs" 2>&1
check "full com lotes tira só o store" '! grep -q "/internal/store$" "$T/out.fullpkgs" && grep -q "/internal/web$" "$T/out.fullpkgs" &&
	[ "$(($(wc -l <"$T/out.fullpkgs")))" = "$(($(go list ./... | wc -l) - $(go list ./internal/store/... | wc -l)))" ]'

# race_shard de ponta a ponta num módulo mínimo: 2 lotes rodam tudo (subteste e exemplo inclusive); um lote que
# omite um teste de propósito faz a união falhar com o nome dele
RM="$T/racemod"
mkdir -p "$RM/a" "$RM/b"
printf 'module racemod\n\ngo 1.22\n' >"$RM/go.mod"
cat >"$RM/a/a_test.go" <<'EOF'
package a

import (
	"fmt"
	"testing"
)

func TestOne(t *testing.T) { t.Run("sub", func(t *testing.T) {}) }

func TestTwo(t *testing.T) {}

func TestSkip(t *testing.T) { t.Skip("pulado") }

func Example_hello() {
	fmt.Println("oi")
	// Output: oi
}
EOF
printf 'package b\n\nimport "testing"\n\nfunc TestThree(t *testing.T) {}\n\nfunc FuzzSeed(f *testing.F) { f.Add(1); f.Fuzz(func(t *testing.T, _ int) {}) }\n' >"$RM/b/b_test.go"
shard_mod() { (cd "$RM" && RACE_SPLIT_PKGS=./... RACE_WEIGHTS=/nada race_shard "$@"); }
shard_mod 1 2 "$RM/out" >"$T/out.shard1" 2>&1
s1=$?
shard_mod 2 2 "$RM/out" >"$T/out.shard2" 2>&1
s2=$?
check "race-shard: os dois lotes passam" '[ "$s1" = 0 ] && [ "$s2" = 0 ]'
check "race-shard: lista com testes, exemplo e fuzz dos dois pacotes" '[ "$(wc -l <"$RM/out/expected-1.txt" | tr -d " ")" = 6 ]'
(race_union_check 2 "$RM/out") >"$T/out.shard-union" 2>&1
union_rc=$?
check "race-shard: união dos 2 lotes = lista" '[ "$union_rc" = 0 ] && grep -q "testes na lista: 6; com resultado: 6" "$T/out.shard-union"'
check "race-shard: cobertura de cada lote" '[ -s "$RM/out/cover-1.out" ] && [ -s "$RM/out/cover-2.out" ]'
check "race-shard: subteste não entra na lista de resultados" '! grep -q "/" <(cut -d" " -f2 "$RM/out/ran-1.txt" "$RM/out/ran-2.txt")'
# lotes que "esquecem" um teste: race_assign embrulhado para tirar TestTwo da repartição
(
	eval "orig_$(declare -f race_assign)"
	race_assign() { orig_race_assign "$@" | grep -v " TestTwo$"; }
	shard_mod 1 2 "$RM/out2"
	shard_mod 2 2 "$RM/out2"
) >"$T/out.shard-omit-run" 2>&1
(race_union_check 2 "$RM/out2") >"$T/out.shard-omit" 2>&1
omit_rc=$?
check "race-shard: teste omitido de propósito falha a união" '[ "$omit_rc" != 0 ] && grep -q "fora de todos os lotes: racemod/a TestTwo" "$T/out.shard-omit"'

# CI: o store sai do verify-full e roda nos lotes; race-check com o mesmo número de lotes da matriz e depois de tudo
CI_YML="$ROOT/.github/workflows/ci.yml"
check "CI: FS_RACE_SPLIT_PKGS do store no workflow" 'grep -qE "^  FS_RACE_SPLIT_PKGS: \./internal/store/\.\.\.$" "$CI_YML"'
ci_shards=$(sed -nE 's/^ +shard: \[([0-9, ]+)\]$/\1/p' "$CI_YML" | tr ',' '\n' | grep -c .)
check "CI: race-check com o número de lotes da matriz" '[ "$ci_shards" -ge 2 ] && grep -qE "verify\.sh race-check $ci_shards " "$CI_YML"'
check "CI: race-check depende do verify-full e dos lotes" 'grep -qF "needs: [verify-full, store-race]" "$CI_YML"'
check "CI: lote com race-shard e tamanho da matriz" 'grep -qF "race-shard \"\${{ matrix.shard }}\" \"\${{ strategy.job-total }}\"" "$CI_YML"'

# ---- task 362: mudanças fora de .go no quick (spec 017 RF-03) ----------------------------------------------
# Módulo mínimo: p com testdata; q embute data.txt e r importa q; c cita "q/data.txt" num teste; g tem um
# diretório de dados sem .go (pcaps) citado só por g/sub; s importa o módulo example.com/dep (replace local).
NG="$T/nongo"
mkdir -p "$NG/p/testdata" "$NG/q" "$NG/r" "$NG/c" "$NG/s" "$NG/g/pcaps" "$NG/g/sub" "$NG/g/other" "$NG/dep" "$NG/dep2" "$NG/docs"
cat >"$NG/go.mod" <<'EOM'
module example.com/ng

go 1.21

require example.com/dep v0.0.0

replace example.com/dep => ./dep
EOM
printf 'module example.com/dep\n\ngo 1.21\n' >"$NG/dep/go.mod"
printf 'package dep\n\nfunc D() int { return 1 }\n' >"$NG/dep/dep.go"
cp "$NG/dep/go.mod" "$NG/dep/dep.go" "$NG/dep2/"
printf 'package q\n\nimport _ "embed"\n\n//go:embed data.txt\nvar Data string\n' >"$NG/q/q.go"
echo um >"$NG/q/data.txt"
printf 'package r\n\nimport "example.com/ng/q"\n\nvar R = q.Data\n' >"$NG/r/r.go"
printf 'package s\n\nimport "example.com/dep"\n\nvar S = dep.D()\n' >"$NG/s/s.go"
for pkg in p c g; do printf 'package %s\n' "$pkg" >"$NG/$pkg/$pkg.go"; done
for pkg in p q r s; do printf 'package %s\n\nimport "testing"\n\nfunc TestX(t *testing.T) {}\n' "$pkg" >"$NG/$pkg/x_test.go"; done
printf 'package c\n\nimport "testing"\n\nfunc TestX(t *testing.T) { _ = "q/data.txt" }\n' >"$NG/c/c_test.go"
printf 'package sub\n\nimport "testing"\n\nfunc TestX(t *testing.T) { _ = "../pcaps" }\n' >"$NG/g/sub/sub_test.go"
printf 'package other\n\nimport "testing"\n\nfunc TestX(t *testing.T) {}\n' >"$NG/g/other/other_test.go"
echo '{}' >"$NG/p/testdata/x.json"
echo pcap >"$NG/g/pcaps/a.pcap"
echo doc >"$NG/docs/x.md"
(cd "$NG" && git init -q && git add . && git -c user.name=t -c user.email=t@t commit -qm init) || {
	echo "FAIL git init do módulo de mudanças fora de .go"
	exit 1
}
# ng_pkgs <tipo> <arquivos...>: pacotes (sem o prefixo do módulo) de nongo_pkgs do tipo dado, numa linha
ng_pkgs() {
	local kind="$1"
	shift
	(cd "$NG" && nongo_pkgs "$@") | awk -v k="$kind" '$1 == k { sub("^example.com/ng/", "", $2); print $2 }' |
		sort -u | tr '\n' ' '
}
check "fora de .go: testdata/ põe só o dono (p)" '[ "$(ng_pkgs owner p/testdata/x.json)" = "p " ] && [ -z "$(ng_pkgs test p/testdata/x.json)" ]'
check "fora de .go: arquivo embutido põe o dono (q)" '[ "$(ng_pkgs owner q/data.txt)" = "q " ]'
check "fora de .go: arquivo embutido testa quem importa (r) e quem cita o caminho (c)" '[ "$(ng_pkgs test q/data.txt)" = "c r " ]'
check "fora de .go: diretório de dados sem .go testa quem o cita abaixo do dono" '[ "$(ng_pkgs owner g/pcaps/a.pcap)" = "g " ] && [ "$(ng_pkgs test g/pcaps/a.pcap)" = "g/sub " ]'
check "fora de .go: docs/ e .md da raiz não afetam pacote" '[ -z "$(ng_pkgs owner docs/x.md README.md specs/x.md)" ]'
check "fora de .go: arquivo sem pacote acima (raiz) não afeta nada" '[ -z "$(cd "$NG" && nongo_pkgs Makefile)" ]'
# go.mod: replace trocado (módulo dep) testa só quem o importa; linha go alterada testa ./...
ng_gomod() { (cd "$NG" && gomod_test_pkgs HEAD) | sed "s|^example.com/ng/||" | sort -u | tr '\n' ' '; }
check "go.mod sem mudança: nenhum pacote" '[ -z "$(ng_gomod)" ]'
sed -i.bak 's|=> ./dep$|=> ./dep2|' "$NG/go.mod" && rm -f "$NG/go.mod.bak"
check "go.mod: dependência trocada testa quem a importa (s)" '[ "$(ng_gomod)" = "s " ]'
(cd "$NG" && git checkout -q go.mod)
sed -i.bak 's|^go 1.21$|go 1.22|' "$NG/go.mod" && rm -f "$NG/go.mod.bak"
check "go.mod: linha go alterada testa ./..." '[ "$(ng_gomod | wc -w | tr -d " ")" = "$(cd "$NG" && go list ./... | wc -l | tr -d " ")" ]'
(cd "$NG" && git checkout -q go.mod)
# pacote deploy: arquivos de deploy/, nats.conf, .env.example ou literal FS_* num .go fora de teste
printf 'package z\n\nconst k = "FS_NEW_KEY"\n' >"$T/fskey.go"
printf 'package z\n\nconst k = "FS_NEW_KEY"\n' >"$T/fskey_test.go"
check "deploy: unit alterada aciona o pacote deploy" 'deploy_triggered "deploy/systemd/finger-sniffer-web.service" ""'
check "deploy: nats.conf e .env.example acionam" 'deploy_triggered "eventbus/nats/nats.conf" "" && deploy_triggered ".env.example" ""'
check "deploy: chave FS_* num .go aciona; num _test.go, não" 'deploy_triggered "" "$T/fskey.go" && ! deploy_triggered "" "$T/fskey_test.go"'
check "deploy: docs/ não aciona" '! deploy_triggered "docs/x.md" ""'
# o verify.sh real: unit alterada sozinha põe o pacote deploy nos afetados (owner)
check "fora de .go: unit em deploy/systemd conta para o pacote deploy" '(cd "$ROOT" && nongo_pkgs deploy/systemd/finger-sniffer-web.service) | grep -qx "owner $MODULE/deploy"'

# ---- task 361: o passo e2e é recusado com a trava da carga no servidor --------------------------------------
# O ssh é o stub acima (o "servidor" é esta máquina); go é trocado por um stub que só registra a chamada.
LL="$T/loadlock"
mkdir -p "$LL/bin"
cat >"$LL/bin/go" <<'EOF'
#!/usr/bin/env bash
echo "go $*" >>"$LL_LOG"
EOF
chmod +x "$LL/bin/go"
ll_e2e() {
	(
		export LOAD_LOCK="$LL/fs-load-running" PATH="$LL/bin:$PATH" LL_LOG="$LL/go.log" FS_E2E_DURING_LOAD="$1"
		e2e_tests
	) >"$T/out.loadlock-$2" 2>&1
}
echo 2026-11-21T10:00:00Z >"$LL/fs-load-running"
ll_e2e 0 present
ll_rc=$?
check "e2e recusado com a trava da carga, sem rodar o go test (task 361)" \
	'[ "$ll_rc" != 0 ] && grep -q "e2e recusado" "$T/out.loadlock-present" && grep -q 2026-11-21T10:00:00Z "$T/out.loadlock-present" && [ ! -s "$LL/go.log" ]'
ll_e2e 1 forced
check "FS_E2E_DURING_LOAD=1 roda o e2e com a trava" 'grep -q "go test .*-tags e2e" "$LL/go.log"'
rm -f "$LL/fs-load-running" "$LL/go.log"
ll_e2e 0 absent
ll_rc=$?
check "e2e roda sem a trava" '[ "$ll_rc" = 0 ] && grep -q "go test .*-tags e2e" "$LL/go.log"'

if [ "$fail" != 0 ]; then
	for f in "$T"/out.*; do
		echo "--- $f"
		cat "$f"
	done
fi
[ "$fail" = 0 ] && echo "ok: verify.sh"
exit "$fail"
