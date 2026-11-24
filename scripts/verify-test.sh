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
#     pacote deploy (task 362);
#   - o passo "testes com tag" compila e roda os pacotes de cada tag e falha com um pacote fora dos padrões (task 359);
#   - o p0f.fp de deploy/versions.env (download, SHA, cache) e os testes sem -race: lista completa e job norace
#     (task 360);
#   - o e2e confere a versão implantada antes e depois, com um health falso (stub de curl) (task 356);
#   - todo passo do full aparece em algum job do CI e o race-check espera todos os jobs (task 397).
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
check "CI: race-check depende do verify-full e dos lotes" 'grep -qE "needs: \[verify-full, .*store-race" "$CI_YML"'
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

# ---- task 359: testes com tag (spec 017 RF-08a) ------------------------------------------------------------
# Módulo mínimo: l (load, teste que passa), e (só arquivos e2e), x (load, fora dos padrões quando pedido), lx
# ("loadx": não é a tag load).
TG="$T/tagged"
mkdir -p "$TG/l" "$TG/e" "$TG/x" "$TG/lx"
printf 'module example.com/tg\n\ngo 1.21\n' >"$TG/go.mod"
printf 'package l\n\nfunc L() int { return 1 }\n' >"$TG/l/l.go"
printf '//go:build load\n\npackage l\n\nimport "testing"\n\nfunc TestL(t *testing.T) {\n\tif L() != 1 {\n\t\tt.Fatal("L")\n\t}\n}\n' >"$TG/l/l_test.go"
printf '//go:build e2e\n\npackage e\n\nimport "example.com/tg/l"\n\nvar E = l.L()\n' >"$TG/e/e_test.go"
printf '//go:build load\n\npackage x\n' >"$TG/x/x.go"
printf '//go:build loadx\n\npackage lx\n' >"$TG/lx/lx.go"
(cd "$TG" && git init -q && git add . && git -c user.name=t -c user.email=t@t commit -qm init) || {
	echo "FAIL git init do módulo de testes com tag"
	exit 1
}
tg() {
	(cd "$TG" && TAGGED_LOAD="./l/... ./x/..." TAGGED_E2E=./e/... TAGGED_GOLDEN=./golden/... TAGGED_LINUX_PRIV=./priv/... "$@")
}
check "tag: pacotes com //go:build load (loadx fica de fora)" '[ "$(tg tag_pkgs load | tr "\n" " ")" = "example.com/tg/l example.com/tg/x " ]'
check "tag: pacote só com arquivos e2e" '[ "$(tg tag_pkgs e2e)" = "example.com/tg/e" ]'
tg tagged_tests >"$T/out.tagged-ok" 2>&1
tg_rc=$?
check "testes com tag: passa e roda o teste load" '[ "$tg_rc" = 0 ] && grep -q "^ok .*example.com/tg/l" "$T/out.tagged-ok"'
(cd "$TG" && TAGGED_LOAD=./l/... TAGGED_E2E=./e/... tagged_tests) >"$T/out.tagged-out" 2>&1
tg_rc=$?
check "testes com tag: pacote com tag fora dos padrões falha" '[ "$tg_rc" != 0 ] && grep -q "fora de" "$T/out.tagged-out" && grep -q "example.com/tg/x" "$T/out.tagged-out"'
sed -i.bak 's/L() != 1/L() != 2/' "$TG/l/l_test.go" && rm -f "$TG/l/l_test.go.bak"
tg tagged_tests >"$T/out.tagged-fail" 2>&1
tg_rc=$?
check "testes com tag: teste load que falha falha o passo" '[ "$tg_rc" != 0 ] && grep -q "^--- FAIL: TestL" "$T/out.tagged-fail"'
(cd "$TG" && git checkout -q l/l_test.go)
printf '//go:build e2e\n\npackage e\n\nvar E = undefinedThing\n' >"$TG/e/e_test.go"
tg tagged_tests >"$T/out.tagged-vet" 2>&1
tg_rc=$?
check "testes com tag: arquivo e2e que não compila falha o vet" '[ "$tg_rc" != 0 ] && grep -q undefinedThing "$T/out.tagged-vet"'
(cd "$TG" && git checkout -q e/e_test.go)
check "testes com tag no quick: só os candidatos" '[ "$(tg tagged_quick example.com/tg/e other | tr "\n" " ")" = "e2e example.com/tg/e " ]'
tg tagged_quick_run "$(printf 'load example.com/tg/l\ne2e example.com/tg/e\n')" >"$T/out.tagged-quick" 2>&1
tg_rc=$?
check "testes com tag no quick: roda cada tag com os seus pacotes" '[ "$tg_rc" = 0 ] && grep -q "^tag load: example.com/tg/l$" "$T/out.tagged-quick" && grep -q "^tag e2e: example.com/tg/e$" "$T/out.tagged-quick"'
check "testes com tag no quick: nenhum candidato com tag" '[ -z "$(tg tagged_quick example.com/tg/lx)" ]'
check "testes com tag: passo no full" 'grep -qE "run_step \"testes com tag\" tagged_tests" "$ROOT/scripts/verify.sh"'
check "lint com as tags e2e, load e golden" 'grep -qE "^  build-tags: \[e2e, load, golden\]$" "$ROOT/.golangci.yml"'
check "TestF8SimOffline sem a tag e2e" '! head -1 "$ROOT/test/e2e/f8_sim_offline_test.go" | grep -q "go:build" && grep -q "^func TestF8SimOffline(" "$ROOT/test/e2e/f8_sim_offline_test.go"'

# ---- task 360: p0f.fp real e testes sem -race (spec 017 RF-08b e RF-08c) -----------------------------------
# p0f_prepare com um tgz local (file://) e um versions.env próprio: baixa, confere os SHA, não baixa de novo e
# reprova SHA errado; FS_P0F_DB já definido fica.
PF="$T/p0f"
mkdir -p "$PF/src/p0f-9.9" "$PF/repo"
echo "assinaturas de teste" >"$PF/src/p0f-9.9/p0f.fp"
(cd "$PF/src" && tar -czf "$PF/p0f.tgz" p0f-9.9/p0f.fp)
pf_versions() {
	printf 'P0F_VERSION=9.9\nP0F_TGZ_SHA256=%s\nP0F_FP_SHA256=%s\nP0F_URL=file://%s\n' \
		"${1:-$(sha256_of "$PF/p0f.tgz")}" "${2:-$(sha256_of "$PF/src/p0f-9.9/p0f.fp")}" "$PF/p0f.tgz" >"$PF/versions.env"
}
pf() {
	(cd "$PF/repo" && env -u FS_P0F_DB ROOT="$PF/repo" P0F_VERSIONS_FILE="$PF/versions.env" bash -c \
		'. "$1/scripts/verify.sh" lib; cd "$2"; ROOT="$2" P0F_VERSIONS_FILE="$3"; p0f_prepare && echo "env=$FS_P0F_DB"' \
		_ "$ROOT" "$PF/repo" "$PF/versions.env")
}
pf_versions
pf >"$T/out.p0f1" 2>&1
pf_rc=$?
check "p0f.fp: baixado, conferido e exportado" '[ "$pf_rc" = 0 ] && grep -q "^env=$PF/repo/tmp/p0f/p0f.fp$" "$T/out.p0f1" && cmp -s "$PF/repo/tmp/p0f/p0f.fp" "$PF/src/p0f-9.9/p0f.fp"'
mv "$PF/p0f.tgz" "$PF/p0f.tgz.off"
pf >"$T/out.p0f2" 2>&1
pf_rc=$?
check "p0f.fp: com o SHA certo não baixa de novo" '[ "$pf_rc" = 0 ] && ! grep -q baixando "$T/out.p0f2"'
mv "$PF/p0f.tgz.off" "$PF/p0f.tgz"
rm -rf "$PF/repo/tmp"
pf_versions 0000
pf >"$T/out.p0f3" 2>&1
pf_rc=$?
check "p0f.fp: SHA do tgz errado reprova" '[ "$pf_rc" != 0 ] && grep -q "P0F_TGZ_SHA256" "$T/out.p0f3" && [ ! -f "$PF/repo/tmp/p0f/p0f.fp" ]'
pf_versions "" 0000
pf >"$T/out.p0f4" 2>&1
pf_rc=$?
check "p0f.fp: SHA do p0f.fp errado reprova" '[ "$pf_rc" != 0 ] && grep -q "P0F_FP_SHA256" "$T/out.p0f4"'
check "p0f.fp: FS_P0F_DB já definido fica" '[ "$(FS_P0F_DB=/x/p0f.fp bash -c ". \"\$1/scripts/verify.sh\" lib; p0f_prepare >/dev/null; echo \$FS_P0F_DB" _ "$ROOT")" = /x/p0f.fp ]'
check "p0f.fp: versão do deploy/versions.env" '(cd "$ROOT" && [ -n "$(versions_get P0F_VERSION)" ] && [ -n "$(versions_get P0F_FP_SHA256)" ])'

# testes sem -race: todo teste com `if raceEnabled {` + t.Skip está na lista
printf 'package z\n\nfunc TestA(t *testing.T) {\n\tif raceEnabled {\n\t\tt.Skip("x")\n\t}\n}\n\nfunc TestB(t *testing.T) {\n\tif !raceEnabled && x {\n\t}\n}\n' >"$T/race_skip_test.go"
check "sem -race: acha o teste que se pula com -race" '[ "$(race_skip_tests "$T/race_skip_test.go")" = TestA ]'
missing=""
for name in $(cd "$ROOT" && race_skip_tests $(go_source_files | grep -E "_test\.go$")); do
	case " $NORACE_TESTS " in *" $name "*) ;; *) missing="$missing $name" ;; esac
done
check "sem -race: todo teste com if raceEnabled { t.Skip na lista do passo${missing:+ (faltam:$missing)}" '[ -z "$missing" ]'
check "sem -race: TestDBFullRealTmpfs e TestRetentionDoesNotStallIngest na lista" 'case " $NORACE_TESTS " in *" TestDBFullRealTmpfs "*" "*|*" TestRetentionDoesNotStallIngest "*) true ;; *) false ;; esac'
check "norace: confere os testes do p0f.fp real" 'grep -q "run_step \"testes do p0f.fp real\" p0f_real_tests" "$ROOT/scripts/verify.sh" && [ "$P0F_REAL_TESTS" = "TestP0FGolden TestRealDBLoads" ]'
check "sem -race: passo e p0f.fp no full" 'grep -q "run_step \"testes sem -race\" norace_tests" "$ROOT/scripts/verify.sh" && grep -q "run_step \"p0f.fp\" p0f_prepare" "$ROOT/scripts/verify.sh"'
CI_YML="$ROOT/.github/workflows/ci.yml"
check "CI: job norace com verify.sh norace, tmpfs pequeno e FS_TEST_TMPFS" 'awk "/^  norace:/{f=1} /^  race-check:/{f=0} f" "$CI_YML" >"$T/norace.yml" &&
	grep -q "scripts/verify.sh norace" "$T/norace.yml" && grep -qE "mount -t tmpfs -o size=(16|32)m" "$T/norace.yml" && grep -q "FS_TEST_TMPFS: /mnt/fs-tmpfs" "$T/norace.yml"'
check "CI: verify-full pula os testes sem -race" 'grep -qE "^          FS_SKIP_NORACE: \"1\"$" "$CI_YML"'

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

# ---- task 356: o e2e confere a versão implantada antes e depois (spec 017 RF-09) ---------------------------
# curl é trocado por um stub que devolve, a cada chamada, o próximo health de $VV/health.N (o último se repete);
# go registra a chamada e sai com $VV_GO_RC. O ssh da trava da carga é o stub acima (trava ausente).
VV="$T/version"
mkdir -p "$VV/bin"
cat >"$VV/bin/curl" <<'EOS'
#!/usr/bin/env bash
n=$(($(cat "$VV/count" 2>/dev/null || echo 0) + 1))
echo "$n" >"$VV/count"
echo "$*" >>"$VV/curl.log"
f="$VV/health.$n"
[ -f "$f" ] || f=$(ls "$VV"/health.* | sort -t. -k2 -n | tail -1)
cat "$f"
EOS
cat >"$VV/bin/go" <<'EOS'
#!/usr/bin/env bash
echo "go $*" >>"$VV/go.log"
exit "${VV_GO_RC:-0}"
EOS
chmod +x "$VV/bin/curl" "$VV/bin/go"
health() { printf '{"versions_match":%s,"services":{"store":{"status":"ok","version":"%s"}}}' "$2" "$1"; }
# vv <rótulo> <rc do go> <health 1> [health 2]: roda e2e_steps (versão, e2e, versão depois) num subshell
vv() {
	rm -f "$VV"/health.* "$VV/count" "$VV/go.log" "$VV/curl.log"
	local i=1 label="$1" rc="$2"
	shift 2
	for h in "$@"; do
		echo "$h" >"$VV/health.$i"
		i=$((i + 1))
	done
	(
		export PATH="$VV/bin:$PATH" VV VV_GO_RC="$rc" FS_E2E_EXPECT_VERSION=v1.2.3 LOAD_LOCK="$VV/sem-trava"
		MODE=full STOP_ON_FAIL=1
		e2e_steps
	) >"$T/out.version-$label" 2>&1
}
vv igual 0 "$(health v1.2.3 true)"
vv_rc=$?
check "versão implantada: igual antes e depois passa e roda o e2e" '[ "$vv_rc" = 0 ] && grep -q "go test .*-tags e2e" "$VV/go.log" && [ "$(cat "$VV/count")" = 2 ]'
check "versão implantada: lê o health da 9001 do FS_E2E_HOST" 'grep -q "http://finger-01.badblock.net.br:9001/api/v1/health" "$VV/curl.log"'
vv diferente 0 "$(health v1.2.2 true)"
vv_rc=$?
check "versão implantada: versão diferente reprova antes do go test" '[ "$vv_rc" != 0 ] && [ ! -s "$VV/go.log" ] && grep -q "finger-01 roda v1.2.2, o teste é de v1.2.3: rode make deploy" "$T/out.version-diferente"'
vv desencontro 0 "$(health v1.2.3 false)"
vv_rc=$?
check "versão implantada: versions_match=false reprova antes do go test" '[ "$vv_rc" != 0 ] && [ ! -s "$VV/go.log" ] && grep -q "versions_match=false" "$T/out.version-desencontro"'
vv mudou 0 "$(health v1.2.3 true)" "$(health v1.2.4 true)"
vv_rc=$?
check "versão implantada: troca durante a suíte reprova o depois" '[ "$vv_rc" != 0 ] && [ -s "$VV/go.log" ] && grep -q "mudou durante o e2e" "$T/out.version-mudou" && grep -qE "✗ +versão implantada \(depois\)" "$T/out.version-mudou"'
vv e2efalha 1 "$(health v1.2.3 true)"
vv_rc=$?
check "versão implantada: o depois roda mesmo com o e2e reprovado" '[ "$vv_rc" != 0 ] && [ "$(cat "$VV/count")" = 2 ] && grep -qE "✓ +versão implantada \(depois\)" "$T/out.version-e2efalha"'
check "versão implantada: sem FS_E2E_EXPECT_VERSION vale o git describe local" '[ "$(cd "$M" && env -u FS_E2E_EXPECT_VERSION bash -c ". \"\$1/scripts/verify.sh\" lib; cd \"\$2\"; e2e_expected_version" _ "$ROOT" "$M")" = "$(cd "$M" && git describe --tags --always --dirty)" ]'
check "versão implantada: o full chama e2e_steps" 'grep -qE "^[[:space:]]+e2e_steps$" "$ROOT/scripts/verify.sh"'

# ---- task 397: passos do full em jobs paralelos do CI (spec 017 RF-11) -------------------------------------
# fn_body <arquivo> <função>: corpo da função (até o primeiro "}" na coluna 0).
fn_body() { awk -v f="$2() {" '$0 == f { on = 1; next } on && /^}/ { exit } on' "$1"; }
# job_body <workflow> <job>: trecho do job (até o próximo job de 2 espaços).
job_body() { awk -v j="  $2:" '$0 == j { on = 1; next } on && /^  [a-z][a-z0-9-]*:$/ { exit } on' "$1"; }
# ci_coverage <verify.sh> <workflow>: todo passo do full roda em algum job. Passo comum (run_step) roda no job
# verify-full; passo de split_step <VAR> roda no verify-full se o job não define VAR: "1", senão tem de estar no
# verify_<modo> do CI_SPLITS e algum job tem de rodar `verify.sh <modo>`. linux_priv e e2e ficam fora do CI
# (RF-11). Imprime os passos sem job.
ci_coverage() {
	local vsh="$1" yml="$2" full vf line var name mode split
	full=$(fn_body "$vsh" verify_full)
	vf=$(job_body "$yml" verify-full)
	echo "$vf" | grep -qE 'make verify-full|verify\.sh full' || echo "job verify-full não roda o full"
	echo "$full" | grep -oE '(split_step FS_SKIP_[A-Z_]+ |run_step )"[^"]+"' | while IFS= read -r line; do
		name=$(echo "$line" | sed -E 's/.*"([^"]+)"$/\1/')
		case "$name" in *linux_priv* | e2e* | "versão implantada"*) continue ;; esac
		case "$line" in
		run_step*) continue ;;
		esac
		var=$(echo "$line" | awk '{ print $2 }')
		echo "$vf" | grep -qE "^ +$var: \"1\"$" || continue
		split=$(echo " $CI_SPLITS " | grep -oE " $var:[a-z]+ " | tr -d ' ')
		mode="${split#*:}"
		if [ -z "$split" ]; then
			echo "$name: $var sem modo em CI_SPLITS"
		elif ! fn_body "$vsh" "verify_$mode" | grep -qF "\"$name\""; then
			echo "$name: pulado no verify-full ($var) e ausente de verify_$mode"
		elif ! grep -qE "verify\.sh $mode( |$)" "$yml"; then
			echo "$name: pulado no verify-full ($var) e nenhum job roda verify.sh $mode"
		fi
	done
}
CI_YML="$ROOT/.github/workflows/ci.yml"
ci_coverage "$ROOT/scripts/verify.sh" "$CI_YML" >"$T/out.ci-coverage" 2>&1
check "CI: todo passo do full em algum job" '[ ! -s "$T/out.ci-coverage" ]'
# workflow sem o job fuzz (e sem o static): o verify-test tem de reprovar
awk '/^  fuzz:$/ { skip = 1; next } skip && /^  [a-z][a-z0-9-]*:$/ { skip = 0 } !skip' "$CI_YML" >"$T/ci-sem-fuzz.yml"
ci_coverage "$ROOT/scripts/verify.sh" "$T/ci-sem-fuzz.yml" >"$T/out.ci-sem-fuzz" 2>&1
check "CI: workflow sem o job fuzz reprova a cobertura" 'grep -q "^fuzz curto.*nenhum job roda verify.sh fuzz" "$T/out.ci-sem-fuzz"'
sed 's/^\(  static\):$/\1-x:/; s|scripts/verify.sh static|true|' "$CI_YML" >"$T/ci-sem-static.yml"
ci_coverage "$ROOT/scripts/verify.sh" "$T/ci-sem-static.yml" >"$T/out.ci-sem-static" 2>&1
check "CI: workflow sem o static reprova lint, testes com tag e govulncheck" '[ "$(grep -c "nenhum job roda verify.sh static" "$T/out.ci-sem-static")" = 3 ]'
# verify.sh com um passo novo pulado no CI e fora do modo: reprova
sed 's/split_step FS_SKIP_STATIC "govulncheck" govulncheck/split_step FS_SKIP_STATIC "passo novo" true; split_step FS_SKIP_STATIC "govulncheck" govulncheck/' \
	"$ROOT/scripts/verify.sh" >"$T/verify-passo-novo.sh"
ci_coverage "$T/verify-passo-novo.sh" "$CI_YML" >"$T/out.ci-passo-novo" 2>&1
check "CI: passo novo do full fora de todo job reprova" 'grep -q "^passo novo: pulado no verify-full (FS_SKIP_STATIC) e ausente de verify_static" "$T/out.ci-passo-novo"'
# race-check depende de todos os outros jobs (um check só na proteção da branch)
ci_jobs=$(awk '/^jobs:$/ { on = 1; next } on && /^  [a-z][a-z0-9-]*:$/ { sub(/:$/, ""); sub(/^  /, ""); print }' "$CI_YML" | grep -vx race-check | sort)
ci_needs=$(job_body "$CI_YML" race-check | sed -nE 's/^    needs: \[(.*)\]$/\1/p' | tr ',' '\n' | tr -d ' ' | sort)
check "CI: race-check com needs em todos os outros jobs" '[ -n "$ci_jobs" ] && [ "$ci_jobs" = "$ci_needs" ]'
check "CI: verify-full pula static, fuzz e norace" '[ "$(job_body "$CI_YML" verify-full | grep -cE "^ +FS_SKIP_(STATIC|FUZZ|NORACE): \"1\"$")" = 3 ]'
check "CI: fuzz com um alvo por CPU do runner" 'job_body "$CI_YML" fuzz | grep -qF "FS_FUZZ_JOBS=\"\$(nproc)\""'
# split_step: pulado com a nota quando a variável vale 1; senão roda
(
	STEP_NAMES=() STEP_STATUS=() STEP_NOTES=() STEP_TIMES=()
	FS_SKIP_X=1 split_step FS_SKIP_X "pulado" false
	FS_SKIP_X=0 split_step FS_SKIP_X "rodado" true
	echo "${STEP_STATUS[*]}|${STEP_NOTES[0]}"
) >"$T/out.split" 2>&1
check "split_step: pula com a nota (job próprio no CI) ou roda" 'tail -1 "$T/out.split" | grep -qx "skip ok|FS_SKIP_X=1 (job próprio no CI)"'

if [ "$fail" != 0 ]; then
	for f in "$T"/out.*; do
		echo "--- $f"
		cat "$f"
	done
fi
[ "$fail" = 0 ] && echo "ok: verify.sh"
exit "$fail"
