#!/usr/bin/env bash
# Verificação em dois níveis (spec 017, ADR 0013).
#
#   scripts/verify.sh quick [-- <pacotes> [flags do go test]]
#   scripts/verify.sh full  [--e2e]
#   scripts/verify.sh race-shard <k> <n> <saída>   (CI: lote k de n dos testes -race de FS_RACE_SPLIT_PKGS)
#   scripts/verify.sh race-check <n> <diretório>   (CI: união dos lotes = lista de testes; cobertura total)
#
# quick: só o que mudou desde `git merge-base HEAD main` (commits, alterações e arquivos novos).
#        Roda todos os passos e sai com código != 0 se algum falhar.
# full:  tudo; para na primeira falha.
#
# Variáveis:
#   FS_VERIFY_BASE       ref base do quick (padrão: main; cai para origin/main)
#   FS_SKIP_LINUX_PRIV=1 pula os testes privilegiados no servidor (usado no CI)
#   FS_VPS_SSH           destino ssh (padrão root@finger-01.tmsoft.com.br, ADR 0038; o nome da variável fica)
#   FS_VPS_PORT          porta ssh (padrão 48022)
#   FS_TEST_PEBBLE       binário do Pebble para os testes de ACME (padrão: o do PATH, instalado por make tools);
#                        exportado para os testes; no CI (CI=true) a ausência dele falha o verify-full
#   FS_E2E_TIMEOUT       -timeout do go test no passo e2e (padrão 45m; com FS_E2E_LONG=1 a suíte passa dos
#                        10 min padrão do go test)
#   FS_E2E_DURING_LOAD=1 roda o e2e mesmo com uma carga em andamento no servidor (/tmp/fs-load-running; por padrão o
#                        passo é recusado, spec 017 RF-13, task 361). FS_LOAD_LOCK troca o caminho da trava (testes).
#   FS_RACE_SPLIT_PKGS   pacotes (padrões do go list) cujos testes -race saem do passo de testes do full e rodam
#                        em lotes (race-shard) nos jobs paralelos do CI (task 294); vazio (padrão, inclusive no
#                        full local): tudo de uma vez
#   FS_RACE_OUT          com FS_RACE_SPLIT_PKGS, diretório onde o full deixa o cover.out (cover-main.out) para o
#                        race-check somar à cobertura dos lotes
#
# Compatível com o bash 3.2 do macOS (sem arrays associativos nem mapfile).
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 2

MODULE="github.com/patrickbrandao/finger-sniffer"
MIGRATIONS_DIR="database/sqlite/migrations"
TEMPLATE_DB="tmp/testdb/template.sqlite"
# Banco-modelo do bot, com hash próprio (spec 017 RF-16, task 269)
BOT_MIGRATIONS_DIR="database/sqlite/bot"
BOT_TEMPLATE_DB="tmp/testdb/bot.sqlite"
COVER_STRICT_PKGS="pkg/detect pkg/probe pkg/tlsparse pkg/h1 pkg/h2passive pkg/quicparse pkg/fingerprint"
COVER_STRICT_MIN=80
COVER_TOTAL_MIN=60
OPENAPI_FILE="cmd/finger-sniffer-store/openapi.yaml"
# Contrato da API do bot (spec 017 RF-15, task 261)
BOT_OPENAPI_FILE="cmd/finger-sniffer-bot/openapi.yaml"
ASYNCAPI_FILE="eventbus/nats/asyncapi.yaml"
# Validadores dos contratos (Redocly CLI e AsyncAPI CLI; dependências travadas no package-lock.json do diretório,
# instaladas com npm ci --ignore-scripts; task 175)
CONTRACTS_TOOLS_DIR="scripts/contracts-tools"
# Validador dos examples do asyncapi (Node; dependências fixadas no package-lock.json do diretório)
ASYNCAPI_EXAMPLES_DIR="scripts/asyncapi-examples"
FUZZ_TIME="${FS_FUZZ_TIME:-10s}"
VPS_SSH="${FS_VPS_SSH:-root@finger-01.tmsoft.com.br}"
VPS_PORT="${FS_VPS_PORT:-48022}"
# Rótulo do servidor nos passos e nas mensagens: o primeiro rótulo do host (finger-01)
VPS_LABEL="${VPS_SSH#*@}"
VPS_LABEL="${VPS_LABEL%%.*}"
E2E_TIMEOUT="${FS_E2E_TIMEOUT:-45m}"
RACE_SPLIT_PKGS="${FS_RACE_SPLIT_PKGS:-}"
# Duração medida no CI dos testes lentos dos pacotes em lotes ("<Teste> <segundos>"); só equilibra os lotes:
# teste ausente pesa RACE_DEFAULT_WEIGHT e nenhum teste fica de fora por causa deste arquivo.
RACE_WEIGHTS="${FS_RACE_WEIGHTS:-scripts/race-weights.txt}"
RACE_DEFAULT_WEIGHT=0.1

export PATH="$(go env GOPATH)/bin:$PATH"

# Pebble (servidor ACME de teste, spec 015): os testes pulam com aviso quando FS_TEST_PEBBLE está vazio.
if [ -z "${FS_TEST_PEBBLE:-}" ] && command -v pebble >/dev/null 2>&1; then
	FS_TEST_PEBBLE="$(command -v pebble)"
fi
export FS_TEST_PEBBLE="${FS_TEST_PEBBLE:-}"

MODE="${1:-}"
shift || true

# ---------------------------------------------------------------------------
# Registro dos passos e resumo
# ---------------------------------------------------------------------------
STEP_NAMES=()
STEP_STATUS=()
STEP_TIMES=()
STEP_NOTES=()
FAILED=0
STOP_ON_FAIL=0
WORK="$(mktemp -d "${TMPDIR:-/tmp}/fs-verify.XXXXXX")"
# Diretório remoto dos testes linux_priv desta execução (vazio fora do passo); apagado também na saída por erro
# ou sinal (task 174).
REMOTE_WORK=""
cleanup() {
	rm -rf "$WORK"
	remote_cleanup
}
trap cleanup EXIT
trap 'exit 130' INT
trap on_term TERM

# Passo em execução (nome e início), para o resumo de uma interrupção por TERM.
CURRENT_STEP=""
CURRENT_START=0
# TERM (ex.: o `timeout` do CI): marca o passo em execução como interrompido e imprime o resumo, para o log
# mostrar onde o tempo acabou em vez de terminar sem resultado (task 253).
on_term() {
	FAILED=1
	if [ -n "$CURRENT_STEP" ]; then
		STEP_NAMES+=("$CURRENT_STEP")
		STEP_STATUS+=(fail)
		STEP_TIMES+=("$(($(now_ms) - CURRENT_START))")
		STEP_NOTES+=("interrompido por TERM")
	fi
	case "${MODE:-}" in
	quick | full)
		summary
		echo "== interrompido por TERM durante: ${CURRENT_STEP:-nenhum passo}"
		;;
	esac
	exit 143
}

now_ms() { perl -MTime::HiRes=time -e 'printf("%d\n", time()*1000)'; }

# record <nome> <ok|fail|skip> <inicio_ms> [nota]
record() {
	local end
	end=$(now_ms)
	STEP_NAMES+=("$1")
	STEP_STATUS+=("$2")
	STEP_TIMES+=("$((end - $3))")
	STEP_NOTES+=("${4:-}")
	if [ "$2" = "fail" ]; then
		FAILED=1
		if [ "$STOP_ON_FAIL" = 1 ]; then
			summary
			exit 1
		fi
	fi
}

summary() {
	local i sym secs
	echo
	echo "== verify $MODE — resumo"
	i=0
	while [ $i -lt ${#STEP_NAMES[@]} ]; do
		case "${STEP_STATUS[$i]}" in
		ok) sym="✓" ;;
		fail) sym="✗" ;;
		*) sym="pulado" ;;
		esac
		secs=$(awk "BEGIN{printf \"%.2f\", ${STEP_TIMES[$i]}/1000}")
		printf "  %-7s %-26s %7ss  %s\n" "$sym" "${STEP_NAMES[$i]}" "$secs" "${STEP_NOTES[$i]}"
		i=$((i + 1))
	done
	if [ "$FAILED" = 1 ]; then
		echo "== resultado: FALHOU"
	else
		echo "== resultado: OK"
	fi
}

# run_step <nome> <comando...>: executa e registra ok/fail.
run_step() {
	local name="$1" start
	shift
	echo
	echo "-- $name: $*"
	start=$(now_ms)
	CURRENT_STEP="$name"
	CURRENT_START=$start
	if "$@"; then
		CURRENT_STEP=""
		record "$name" ok "$start"
	else
		CURRENT_STEP=""
		record "$name" fail "$start"
	fi
}

skip_step() { record "$1" skip "$(now_ms)" "$2"; }

# ---------------------------------------------------------------------------
# Auxiliares
# ---------------------------------------------------------------------------

# Commit base do quick: merge-base de HEAD com FS_VERIFY_BASE (padrão main; cai para origin/main).
verify_base() {
	local base_ref
	base_ref="${FS_VERIFY_BASE:-main}"
	if ! git rev-parse --verify -q "$base_ref" >/dev/null; then
		base_ref="origin/main"
	fi
	git merge-base HEAD "$base_ref" 2>/dev/null || git rev-parse HEAD
}

# Arquivos alterados desde a base: commits + working tree + não rastreados.
changed_files() {
	local base
	base=$(verify_base)
	{
		git diff --name-only "$base"
		git ls-files --others --exclude-standard
	} | sort -u
}

# Pacotes Go (import path) dos diretórios informados que ainda existem.
packages_of_dirs() {
	local d
	for d in "$@"; do
		[ -d "$d" ] || continue
		ls "$d"/*.go >/dev/null 2>&1 || continue
		go list -e -f '{{if not .Error}}{{.ImportPath}}{{end}}' "./$d" 2>/dev/null
	done | sort -u
}

# Pacotes que dependem (direta ou indiretamente, inclusive pelos testes) dos pacotes dados.
reverse_deps() {
	[ $# -eq 0 ] && return 0
	local targets
	targets=" $* "
	go list -e -f '{{.ImportPath}} {{join .Deps " "}} {{join .TestImports " "}} {{join .XTestImports " "}}' ./... 2>/dev/null |
		while read -r pkg deps; do
			for d in $deps; do
				case "$targets" in
				*" $d "*)
					echo "$pkg"
					break
					;;
				esac
			done
		done | sort -u
}

pkg_to_dir() { echo "./${1#"$MODULE"/}"; }

# with_tests <pacotes...>: só os que têm *_test.go no diretório.
with_tests() {
	local p
	for p in "$@"; do
		ls "$(pkg_to_dir "$p")"/*_test.go >/dev/null 2>&1 && echo "$p"
	done
}

# ---------------------------------------------------------------------------
# Mudanças fora de .go no quick (spec 017 RF-03, task 362)
# ---------------------------------------------------------------------------
# Arquivos que não pertencem a pacote nenhum: nenhum teste por eles, salvo os gatilhos próprios (contratos,
# migrations, release-test).
NONPKG_RE='^((specs|docs|tasks|changes|tmp)/|[^/]+\.md$)'

# owner_dir <arquivo>: diretório Go mais próximo acima do arquivo (o primeiro com *.go subindo até a raiz); vazio
# se não houver nenhum.
owner_dir() {
	local d
	d=$(dirname "$1")
	while :; do
		if [ -d "$d" ] && ls "$d"/*.go >/dev/null 2>&1; then
			echo "$d"
			return 0
		fi
		[ "$d" = . ] && return 0
		d=$(dirname "$d")
	done
}

# pkgs_citing <texto> [diretório]: pacotes dos _test.go (versionados ou novos) que contêm <texto> como string
# fixa, só abaixo de [diretório] quando dado.
pkgs_citing() {
	local dirs under="${2:-.}"
	dirs=$(go_source_files | grep -E '_test\.go$' | awk -v u="$under/" 'u == "./" || index($0, u) == 1' |
		tr '\n' '\0' | xargs -0 grep -lF -- "$1" /dev/null 2>/dev/null | xargs -n1 dirname 2>/dev/null | sort -u)
	# shellcheck disable=SC2086 # lista de diretórios
	packages_of_dirs $dirs
}

# nongo_pkgs <arquivos...>: pacotes afetados por arquivos alterados que não são .go. Escreve "owner <pacote>"
# (o pacote Go mais próximo acima do arquivo: entra nos afetados antes dos dependentes, para vet/build e testes) e
# "test <pacote>" (só testes). Em testdata/, só o dono; fora, também os dependentes do dono, os pacotes cujos
# _test.go citam o caminho a partir da raiz e, para um diretório de dados sem .go abaixo do dono (ex.:
# test/golden/pcaps), os pacotes abaixo do dono que citam o nome dele.
nongo_pkgs() {
	local f owner pkg rel datadir spread=""
	: >"$WORK/nongo"
	for f in "$@"; do
		case "$f" in *.go | go.mod | go.sum | '') continue ;; esac
		echo "$f" | grep -qE "$NONPKG_RE" && continue
		owner=$(owner_dir "$f")
		[ -n "$owner" ] || continue
		pkg=$(packages_of_dirs "$owner")
		[ -n "$pkg" ] || continue
		echo "owner $pkg" >>"$WORK/nongo"
		case "/$f" in */testdata/*) continue ;; esac
		spread="$spread $pkg"
		for pkg in $(pkgs_citing "$f"); do echo "test $pkg" >>"$WORK/nongo"; done
		if [ "$(dirname "$f")" != "$owner" ]; then
			rel="${f#"$owner"/}"
			datadir="${rel%%/*}"
			for pkg in $(pkgs_citing "$datadir" "$owner"); do echo "test $pkg" >>"$WORK/nongo"; done
		fi
	done
	if [ -n "$spread" ]; then
		# shellcheck disable=SC2046,SC2086 # lista de pacotes
		reverse_deps $(echo $spread | tr ' ' '\n' | sort -u) | sed 's/^/test /' >>"$WORK/nongo"
	fi
	sort -u "$WORK/nongo"
}

# gomod_test_pkgs <base>: pacotes do módulo cujos testes rodam por uma mudança em go.mod/go.sum desde <base>. Linha
# go/toolchain alterada: ./... inteiro; senão, os que importam (direta ou indiretamente, inclusive pelos testes) um
# módulo cujo require/replace mudou no go.mod ou cuja linha mudou no go.sum.
gomod_test_pkgs() {
	local base="$1" diff mods
	diff=$( (git diff "$base" -- go.mod; git diff "$base" -- go.sum) | grep -E '^[+-]' | grep -vE '^(\+\+\+|---) ')
	if echo "$diff" | grep -qE '^[+-][[:space:]]*(go|toolchain)[[:space:]]'; then
		go list ./...
		return
	fi
	# módulo de cada linha: "require m v", "m v" dentro de um bloco, "replace m [v] => ..." e "m v h1:..." do go.sum
	mods=$(echo "$diff" | sed -E 's/^[+-][[:space:]]*//; s/^(require|replace|exclude|retract)[[:space:]]+//; s/^\(//' |
		awk '$1 ~ /\./ { print $1 }' | sort -u)
	[ -n "$mods" ] || return 0
	go list -e -test -f '{{if .ForTest}}{{.ForTest}}{{else}}{{.ImportPath}}{{end}} {{join .Deps " "}}' ./... 2>/dev/null |
		awk -v mods="$mods" '
			BEGIN { n = split(mods, m, "\n") }
			{
				pkg = $1
				sub(/\.test$/, "", pkg)
				for (i = 2; i <= NF; i++)
					for (j = 1; j <= n; j++)
						if ($i == m[j] || index($i, m[j] "/") == 1) { print pkg; next }
			}' | grep -vE '^[^ ]*_test$' | sort -u
}

# deploy_triggered <arquivos> <arquivos .go>: verdadeiro se os testes do pacote deploy devem rodar: qualquer
# arquivo de deploy/, o nats.conf, o .env.example ou um .go fora de teste com um literal "FS_..." (o
# TestEnvExampleMatchesCodeKeys lê as chaves do código).
deploy_triggered() {
	local f
	echo "$1" | grep -qE '^(deploy/|eventbus/nats/nats\.conf$|\.env\.example$)' && return 0
	for f in $2; do
		case "$f" in *_test.go) continue ;; esac
		[ -f "$f" ] && grep -qE '"FS_[A-Z0-9_]+"' "$f" && return 0
	done
	return 1
}

# Prepara os bancos-modelo SQLite e exporta as variáveis para os testes: o do store (spec 017 RF-06;
# FS_TEST_DB=local, FS_TEST_DB_TEMPLATE) e o do bot (RF-16; FS_TEST_BOT_DB=local, FS_TEST_BOT_DB_TEMPLATE), cada um
# refeito só quando o hash das próprias migrations muda. DB_RESULT: "skipped" sem nenhum, senão
# "store=<resultado> bot=<resultado>".
prepare_test_db() {
	local result store="skipped" bot="skipped"
	# Sem nenhum .sql não há modelo a manter (evita compilar a ferramenta à toa).
	if ls "$MIGRATIONS_DIR"/*.sql >/dev/null 2>&1; then
		result=$(go run ./scripts/testdb -migrations "$MIGRATIONS_DIR" -out "$TEMPLATE_DB") || return 1
		echo "testdb store: $result"
		store="$result"
		if [ "$result" != "skipped" ]; then
			export FS_TEST_DB=local
			FS_TEST_DB_TEMPLATE="$ROOT/$TEMPLATE_DB"
			export FS_TEST_DB_TEMPLATE
		fi
	fi
	if ls "$BOT_MIGRATIONS_DIR"/*.sql >/dev/null 2>&1; then
		result=$(go run ./scripts/testdb -migrations "$BOT_MIGRATIONS_DIR" -out "$BOT_TEMPLATE_DB") || return 1
		echo "testdb bot: $result"
		bot="$result"
		if [ "$result" != "skipped" ]; then
			export FS_TEST_BOT_DB=local
			FS_TEST_BOT_DB_TEMPLATE="$ROOT/$BOT_TEMPLATE_DB"
			export FS_TEST_BOT_DB_TEMPLATE
		fi
	fi
	if [ "$store" = skipped ] && [ "$bot" = skipped ]; then
		DB_RESULT="skipped"
	else
		DB_RESULT="store=$store bot=$bot"
	fi
	return 0
}

# Valida os openapi.yaml do store e do bot (Redocly) e o asyncapi.yaml (AsyncAPI CLI). Erros falham; avisos não.
contracts_check() {
	local rc=0 bin="$CONTRACTS_TOOLS_DIR/node_modules/.bin"
	if ! command -v node >/dev/null || ! command -v npm >/dev/null; then
		echo "node/npm não encontrados (instale Node.js para validar os contratos)"
		return 1
	fi
	npm_deps "$CONTRACTS_TOOLS_DIR" || return 1
	export REDOCLY_TELEMETRY=off REDOCLY_SUPPRESS_UPDATE_NOTICE=true
	"$bin/redocly" lint --format=summary "$OPENAPI_FILE" || rc=1
	"$bin/redocly" lint --format=summary "$BOT_OPENAPI_FILE" || rc=1
	# Sem telemetria do AsyncAPI CLI (preferência de privacidade)
	"$bin/asyncapi" config analytics --disable >/dev/null 2>&1 || true
	"$bin/asyncapi" validate "$ASYNCAPI_FILE" --fail-severity=error || rc=1
	return $rc
}

# npm_deps <dir>: instala as dependências de <dir> (npm ci --ignore-scripts, só o package-lock.json versionado)
# quando o package-lock.json muda; o carimbo fica em node_modules/.fs-lock-hash.
npm_deps() {
	local dir="$1" stamp want
	stamp="$dir/node_modules/.fs-lock-hash"
	want=$(git hash-object "$dir/package-lock.json") || return 1
	if [ -f "$stamp" ] && [ "$(cat "$stamp")" = "$want" ]; then
		return 0
	fi
	npm_config_update_notifier=false npm ci --prefix "$dir" --ignore-scripts --no-audit --no-fund --loglevel=error ||
		return 1
	echo "$want" >"$stamp"
}

# Valida os examples das mensagens do asyncapi contra o payload (spec 017 RF-08): o documento e depois os testes
# do próprio validador. Mensagem JSON sem exemplo só gera aviso.
asyncapi_examples_check() {
	if ! command -v node >/dev/null || ! command -v npm >/dev/null; then
		echo "node/npm não encontrados (instale Node.js para validar os examples do asyncapi)"
		return 1
	fi
	local rc=0
	npm_deps "$ASYNCAPI_EXAMPLES_DIR" || return 1
	node "$ASYNCAPI_EXAMPLES_DIR/check.mjs" "$ASYNCAPI_FILE" || rc=1
	node --test --test-reporter=dot "$ASYNCAPI_EXAMPLES_DIR/check.test.mjs" || rc=1
	return $rc
}

# Pacotes Go que leem os contratos como texto (testes de contrato): os que citam openapi.yaml ou asyncapi.yaml.
contract_reader_pkgs() {
	local dirs
	dirs=$(grep -rlE 'openapi\.yaml|asyncapi\.yaml' --include='*.go' cmd internal pkg htdocs 2>/dev/null |
		xargs -n1 dirname 2>/dev/null | sort -u)
	# shellcheck disable=SC2086
	packages_of_dirs $dirs
}

# No CI o Pebble é obrigatório: sem ele os testes de ACME pulariam em silêncio.
pebble_check() {
	if [ -z "$FS_TEST_PEBBLE" ] || [ ! -x "$FS_TEST_PEBBLE" ]; then
		echo "Pebble não encontrado (rode make tools-ci ou defina FS_TEST_PEBBLE)"
		return 1
	fi
	echo "FS_TEST_PEBBLE=$FS_TEST_PEBBLE"
}

# Arquivos .go do repositório: versionados e novos não ignorados. O que o .gitignore cobre (tmp/, bin/, dist/)
# fica de fora, como no quick (task 203).
go_source_files() {
	local f
	git ls-files --cached --others --exclude-standard -- '*.go' | while IFS= read -r f; do
		[ -f "$f" ] && echo "$f"
	done
}

# Arquivos de teste do repositório (go_source_files) que casam com o padrão ERE $1, com prefixo ./.
test_files_matching() {
	go_source_files | grep -E '_test\.go$' | tr '\n' '\0' | xargs -0 grep -lE "$1" /dev/null 2>/dev/null |
		sed 's|^|./|'
}

# Formatação de todos os .go do repositório (go_source_files), não da árvore inteira.
gofumpt_all() {
	local files
	files=$(go_source_files)
	[ -n "$files" ] || return 0
	# shellcheck disable=SC2086
	gofumpt_check $files
}

gofumpt_check() {
	local out
	out=$(gofumpt -l "$@")
	if [ -n "$out" ]; then
		echo "arquivos fora do formato (rode make fmt):"
		echo "$out"
		return 1
	fi
	return 0
}

# Arquivos de contrato cuja mudança dispara o passo "contratos" no quick.
contracts_re() {
	echo "^($OPENAPI_FILE|$BOT_OPENAPI_FILE|$ASYNCAPI_FILE|$CONTRACTS_TOOLS_DIR/package(-lock)?\.json)\$"
}

# ---------------------------------------------------------------------------
# Nível rápido
# ---------------------------------------------------------------------------
verify_quick() {
	local explicit=() files go_files dirs go_pkgs pkgs nongo nongo_tests affected rdeps test_pkgs p start existing
	if [ "${1:-}" = "--" ]; then
		shift
		explicit=("$@")
	elif [ $# -gt 0 ]; then
		echo "uso: verify.sh quick [-- <pacotes> [flags do go test]]" >&2
		exit 2
	fi

	files=$(changed_files)
	go_files=$(echo "$files" | grep -E '\.go$' | while read -r f; do [ -f "$f" ] && echo "$f"; done)
	dirs=$( (echo "$files" | grep -E '\.go$' | xargs -n1 dirname 2>/dev/null) | sort -u)
	# shellcheck disable=SC2086
	go_pkgs=$(packages_of_dirs $dirs)
	# arquivos que não são .go contam para o pacote Go mais próximo acima deles (spec 017 RF-03, task 362)
	# shellcheck disable=SC2086 # lista de arquivos (sem espaços no repositório)
	nongo=$(nongo_pkgs $files)
	nongo_tests=$(echo "$nongo" | awk '$1 == "test" { print $2 }')
	pkgs=$( (echo "$go_pkgs"; echo "$nongo" | awk '$1 == "owner" { print $2 }') | grep . | sort -u)
	migrations_changed=$(echo "$files" | grep -c "^$MIGRATIONS_DIR/" || true)
	bot_migrations_changed=$(echo "$files" | grep -c "^$BOT_MIGRATIONS_DIR/" || true)
	gomod_changed=$(echo "$files" | grep -cE '^go\.(mod|sum)$' || true)
	contracts_changed=$(echo "$files" | grep -cE "$(contracts_re)" || true)
	# examples do asyncapi: contratos, goldens referenciados (testdata) ou o próprio validador
	examples_changed=$(echo "$files" |
		grep -cE "^($OPENAPI_FILE|$ASYNCAPI_FILE|internal/[^/]+/testdata/.*|pkg/[^/]+/testdata/events/.*|$ASYNCAPI_EXAMPLES_DIR/.*)\$" ||
		true)

	echo "== verify quick"
	echo "arquivos alterados: $(echo "$files" | grep -c . || true); pacotes afetados: $(echo "$pkgs" | grep -c . || true)"

	# 1. formatação + lint só do que mudou
	if [ -n "$go_files" ]; then
		# shellcheck disable=SC2086
		run_step "format (alterados)" gofumpt_check $go_files
		lint_dirs=""
		for p in $go_pkgs; do lint_dirs="$lint_dirs $(pkg_to_dir "$p")"; done
		if [ -n "$lint_dirs" ]; then
			# shellcheck disable=SC2086
			run_step "lint (alterados)" golangci-lint run $lint_dirs
		else
			skip_step "lint (alterados)" "sem pacotes"
		fi
	else
		skip_step "format (alterados)" "nenhum .go alterado"
		skip_step "lint (alterados)" "nenhum .go alterado"
	fi

	# 2. vet + build dos afetados e dos que dependem deles
	# shellcheck disable=SC2086
	rdeps=$(reverse_deps $pkgs)
	affected=$( (echo "$pkgs"; echo "$rdeps") | grep . | sort -u)
	if [ "$gomod_changed" -gt 0 ]; then
		affected=$(go list ./...)
	fi
	if [ -n "$affected" ]; then
		# shellcheck disable=SC2086
		run_step "vet+build (afetados)" go vet $affected
	else
		skip_step "vet+build (afetados)" "nada afetado"
	fi

	# 3. banco-modelo SQLite (antes dos testes, que herdam FS_TEST_DB)
	DB_RESULT=""
	start=$(now_ms)
	if prepare_test_db; then
		if [ "$DB_RESULT" = "skipped" ]; then
			record "banco-modelo sqlite" skip "$start" "sem migrations"
		else
			record "banco-modelo sqlite" ok "$start" "$DB_RESULT"
		fi
	else
		record "banco-modelo sqlite" fail "$start"
	fi

	# 4. contratos, só se mudaram
	if [ "$contracts_changed" -gt 0 ]; then
		run_step "contratos (alterados)" contracts_check
	else
		skip_step "contratos (alterados)" "openapis/asyncapi sem mudança"
	fi
	if [ "$examples_changed" -gt 0 ]; then
		run_step "examples asyncapi" asyncapi_examples_check
	else
		skip_step "examples asyncapi" "contratos e goldens sem mudança"
	fi

	# 4b. nenhum binário compilado entre os arquivos alterados (task 070)
	existing=$(echo "$files" | while read -r f; do [ -n "$f" ] && [ -f "$f" ] && echo "$f"; done)
	if [ -n "$existing" ]; then
		# shellcheck disable=SC2086
		run_step "binários versionados (alterados)" scripts/check-binaries.sh $existing
	else
		skip_step "binários versionados (alterados)" "nenhum arquivo alterado"
	fi
	# 4c. scripts de release alterados: teste do pacote de release
	if echo "$files" | grep -qE '^(scripts/(release|release-test|lib-release|repro-check)\.sh|Makefile)$'; then
		run_step "release-test" scripts/release-test.sh
	else
		skip_step "release-test" "scripts de release sem mudança"
	fi

	# 4d. o próprio verify ou um workflow alterado: teste dele (inclui as checagens dos workflows)
	if echo "$files" | grep -qE '^(scripts/(verify(-test)?|check-binaries)\.sh|\.github/workflows/[^/]+\.yml|\.golangci\.yml|lefthook\.yml)$'; then
		run_step "verify-test" scripts/verify-test.sh
	else
		skip_step "verify-test" "verify.sh e workflows sem mudança"
	fi

	# 5. testes ligados ao que mudou (ou os explícitos)
	if [ ${#explicit[@]} -gt 0 ]; then
		run_step "testes (explícitos)" go test "${explicit[@]}"
	else
		# shellcheck disable=SC2086 # listas de pacotes
		test_pkgs=$(with_tests $pkgs $nongo_tests | tr '\n' ' ')
		# pacote deploy: qualquer arquivo dele, o nats.conf, o .env.example ou uma chave FS_* nova no código
		if ls deploy/*_test.go >/dev/null 2>&1 && deploy_triggered "$files" "$go_files"; then
			test_pkgs="$test_pkgs $MODULE/deploy"
		fi
		# go.mod/go.sum: quem importa um módulo que mudou (linha go/toolchain: ./...)
		if [ "$gomod_changed" -gt 0 ]; then
			# shellcheck disable=SC2046 # lista de pacotes
			test_pkgs="$test_pkgs $(with_tests $(gomod_test_pkgs "$(verify_base)") | tr '\n' ' ')"
		fi
		# contratos alterados: testes que leem openapi/asyncapi como texto (ex.: TestPayloadsMatchAsyncAPI)
		if [ "$contracts_changed" -gt 0 ]; then
			for p in $(contract_reader_pkgs); do
				d=$(pkg_to_dir "$p")
				ls "$d"/*_test.go >/dev/null 2>&1 && test_pkgs="$test_pkgs $p"
			done
		fi
		# migrations alteradas: testes de quem depende delas (testes de banco)
		if [ "$migrations_changed" -gt 0 ] && [ -f "$MIGRATIONS_DIR/embed.go" ]; then
			mig_pkg="$MODULE/$MIGRATIONS_DIR"
			for p in $(reverse_deps "$mig_pkg") $mig_pkg; do test_pkgs="$test_pkgs $p"; done
		fi
		if [ "$bot_migrations_changed" -gt 0 ] && [ -f "$BOT_MIGRATIONS_DIR/embed.go" ]; then
			mig_pkg="$MODULE/$BOT_MIGRATIONS_DIR"
			for p in $(reverse_deps "$mig_pkg") $mig_pkg; do test_pkgs="$test_pkgs $p"; done
		fi
		if [ -n "$(echo "$test_pkgs" | tr -d ' ')" ]; then
			# shellcheck disable=SC2086
			run_step "testes (afetados)" go test $(echo $test_pkgs | tr ' ' '\n' | sort -u)
		else
			skip_step "testes (afetados)" "nenhum teste ligado às mudanças"
		fi
	fi

	summary
	[ "$FAILED" = 0 ]
}

# ---------------------------------------------------------------------------
# Nível completo
# ---------------------------------------------------------------------------
coverage_check() {
	local out="$1" fail=0 p line lines pkg pct
	# Por pacote: os pacotes de parsers/fingerprints exigem >= 80% (só os que existem). Cada item vale para o
	# pacote e para os subpacotes com testes (pkg/fingerprint/ja4plus, pkg/fingerprint/p0f…); pacotes só de
	# apoio a testes, sem arquivos _test.go, não contam.
	for p in $COVER_STRICT_PKGS; do
		[ -d "$p" ] || continue
		lines=$(grep -E "^ok[[:space:]]+$MODULE/$p(/[^[:space:]]+)?[[:space:]]" "$out" || true)
		if [ -z "$lines" ]; then
			echo "cobertura: sem dado para $p"
			fail=1
			continue
		fi
		while read -r line; do
			pkg=$(echo "$line" | awk '{print $2}')
			pkg=${pkg#"$MODULE/"}
			pct=$(echo "$line" | sed -nE 's/.*coverage: ([0-9.]+)%.*/\1/p')
			if [ -z "$pct" ]; then
				echo "cobertura: sem dado para $pkg"
				fail=1
			elif awk "BEGIN{exit !($pct < $COVER_STRICT_MIN)}"; then
				echo "cobertura: $pkg = $pct% (< $COVER_STRICT_MIN%)"
				fail=1
			else
				echo "cobertura: $pkg = $pct%"
			fi
		done <<<"$lines"
	done
	# Total: com pacotes em lotes, só no race-check, que soma os perfis de todos os jobs.
	if [ -n "$RACE_SPLIT_PKGS" ]; then
		echo "cobertura total: no race-check (perfil deste passo + lotes de $RACE_SPLIT_PKGS)"
	else
		coverage_total "$WORK/cover.out" || fail=1
	fi
	return $fail
}

# coverage_total <perfil>...: total >= 60%, sem contar cmd/ (funções main não são testáveis por unidade). Vários
# perfis (lotes do CI) viram um só: o go tool cover soma os blocos repetidos.
coverage_total() {
	local total mode
	mode=$(head -1 "$1")
	cat "$@" | grep -v "^mode:" | grep -v "^$MODULE/cmd/" >"$WORK/cover.nocmd"
	[ -s "$WORK/cover.nocmd" ] || return 0
	(echo "$mode"; cat "$WORK/cover.nocmd") >"$WORK/cover.filtered"
	total=$(go tool cover -func="$WORK/cover.filtered" | awk '/^total:/ {gsub("%","",$3); print $3}')
	echo "cobertura total (sem cmd/): $total%"
	if [ -z "$total" ] || awk "BEGIN{exit !($total < $COVER_TOTAL_MIN)}"; then
		echo "cobertura total abaixo de $COVER_TOTAL_MIN%"
		return 1
	fi
}

full_tests() {
	# Banco isolado: sem FS_TEST_DB, cada teste cria e migra um SQLite novo.
	unset FS_TEST_DB FS_TEST_DB_TEMPLATE FS_TEST_BOT_DB FS_TEST_BOT_DB_TEMPLATE
	local pkgs rc
	pkgs=$(full_test_pkgs) || return 1
	# shellcheck disable=SC2086 # lista de pacotes
	go test -race -count=1 -covermode=atomic -coverprofile="$WORK/cover.out" $pkgs | tee "$WORK/test.out"
	rc=${PIPESTATUS[0]}
	[ "$rc" = 0 ] || return "$rc"
	if [ -n "$RACE_SPLIT_PKGS" ] && [ -n "${FS_RACE_OUT:-}" ]; then
		mkdir -p "$FS_RACE_OUT" && cp "$WORK/cover.out" "$FS_RACE_OUT/cover-main.out" || return 1
	fi
	coverage_check "$WORK/test.out"
}

# full_test_pkgs: ./... (padrão) ou ./... sem os pacotes de FS_RACE_SPLIT_PKGS, que o CI roda em lotes.
full_test_pkgs() {
	local split
	if [ -z "$RACE_SPLIT_PKGS" ]; then
		echo ./...
		return 0
	fi
	# shellcheck disable=SC2086 # padrões do go list
	split=$(go list $RACE_SPLIT_PKGS) || return 1
	if [ -z "$split" ]; then
		echo "FS_RACE_SPLIT_PKGS sem pacotes: $RACE_SPLIT_PKGS" >&2
		return 1
	fi
	go list ./... | grep -vxF "$split"
}

# ---------------------------------------------------------------------------
# Testes -race em lotes (CI, task 294; spec 017 RF-11)
# ---------------------------------------------------------------------------
# Os testes dos pacotes de FS_RACE_SPLIT_PKGS (o store: ~6 min com -race no CI) rodam em <n> jobs paralelos.
# Cada lote roda com -run os testes de nível superior que lhe cabem; o race-check confere, pelo -json de cada
# lote, que a união dos testes que rodaram é exatamente a lista do `go test -list` (nenhum fora, nenhum repetido)
# e soma a cobertura dos lotes à do resto (o mesmo total de antes).

# race_list: "<pacote> <teste>" de cada teste, exemplo e fuzz de nível superior dos pacotes em lotes (o mesmo
# binário -race dos lotes, já em cache).
race_list() {
	local pkg
	# shellcheck disable=SC2086 # padrões do go list
	for pkg in $(go list $RACE_SPLIT_PKGS); do
		# mesmo -covermode do lote: o binário compilado aqui é o que o lote roda (cache)
		if ! go test -race -covermode=atomic -list '.*' "$pkg" >"$WORK/list.out"; then
			cat "$WORK/list.out"
			return 1
		fi
		grep -E '^(Test|Example|Fuzz)' "$WORK/list.out" | sed "s|^|$pkg |"
	done
}

# race_assign <n>: lê "<pacote> <teste>" e escreve "<lote> <pacote> <teste>" (lotes 1..n). Maior peso primeiro,
# sempre no lote menos carregado (empate: o de menor número); determinístico para a mesma lista e os mesmos pesos.
race_assign() {
	local n="$1" weights=/dev/null
	[ -f "$RACE_WEIGHTS" ] && weights="$RACE_WEIGHTS"
	awk -v def="$RACE_DEFAULT_WEIGHT" -v wf="$weights" '
		BEGIN { while ((getline l < wf) > 0) if (l !~ /^#/ && split(l, a, " ") >= 2) w[a[1]] = a[2] }
		NF >= 2 { print (($2 in w) ? w[$2] : def), $1, $2 }' |
		LC_ALL=C sort -k1,1gr -k3,3 -k2,2 |
		awk -v n="$n" '{
			best = 1
			for (i = 2; i <= n; i++) if (load[i] < load[best]) best = i
			load[best] += $1
			print best, $2, $3
		}'
}

# race_shard <k> <n> <saída>: roda o lote k de n. Grava em <saída>: expected-k.txt (lista completa), ran-k.txt
# (testes de nível superior com resultado no -json), cover-k.out, test-k.json, times-k.txt e elapsed-k.txt.
race_shard() {
	local k="${1:-}" n="${2:-}" out="${3:-}" pkg names rc=0
	case "$k:$n" in *[!0-9:]* | :* | *:) k=0 ;; esac
	if [ -z "$out" ] || [ "$k" -lt 1 ] || [ "$k" -gt "$n" ]; then
		echo "uso: verify.sh race-shard <k> <n> <saída> (1 <= k <= n)" >&2
		return 2
	fi
	if [ -z "$RACE_SPLIT_PKGS" ]; then
		echo "FS_RACE_SPLIT_PKGS vazio" >&2
		return 2
	fi
	unset FS_TEST_DB FS_TEST_DB_TEMPLATE FS_TEST_BOT_DB FS_TEST_BOT_DB_TEMPLATE
	mkdir -p "$out"
	# testes de contrato do store usam o Redocly (no CI, CI=true, a ausência falha o teste); no full, o passo
	# contratos instala antes dos testes
	if command -v npm >/dev/null && [ -f "$CONTRACTS_TOOLS_DIR/package-lock.json" ]; then
		npm_deps "$CONTRACTS_TOOLS_DIR" || return 1
	fi
	race_list >"$out/expected-$k.txt" || return 1
	race_assign "$n" <"$out/expected-$k.txt" | awk -v k="$k" '$1 == k { print $2, $3 }' >"$WORK/mine.txt"
	echo "lote $k/$n: $(wc -l <"$WORK/mine.txt" | tr -d ' ') de $(wc -l <"$out/expected-$k.txt" | tr -d ' ') testes"
	: >"$out/test-$k.json"
	: >"$out/cover-$k.out"
	for pkg in $(awk '{ print $1 }' "$WORK/mine.txt" | sort -u); do
		names=$(awk -v p="$pkg" '$1 == p { print $2 }' "$WORK/mine.txt" | paste -sd '|' -)
		rm -f "$WORK/one.cover"
		go test -race -count=1 -json -covermode=atomic -coverprofile="$WORK/one.cover" -run "^($names)\$" "$pkg" \
			>>"$out/test-$k.json" || rc=1
		[ -s "$WORK/one.cover" ] && cat "$WORK/one.cover" >>"$out/cover-$k.out"
	done
	race_report "$out/test-$k.json" "$out/ran-$k.txt" "$out/times-$k.txt" "$out/elapsed-$k.txt"
	return $rc
}

# race_report <json> <ran> <times> <elapsed>: resultado de cada teste de nível superior, saída dos que falharam,
# os mais lentos (para atualizar scripts/race-weights.txt) e o tempo de cada pacote.
race_report() {
	jq -r 'select(.Test != null and (.Test | contains("/") | not) and
		(.Action == "pass" or .Action == "fail" or .Action == "skip")) | "\(.Package) \(.Test)"' "$1" |
		LC_ALL=C sort >"$2"
	jq -r 'select(.Test != null and (.Test | contains("/") | not) and (.Action == "pass" or .Action == "fail")) |
		"\(.Test) \(.Elapsed)"' "$1" | LC_ALL=C sort -k2,2gr >"$3"
	jq -rs '[.[] | select(.Action == "fail" and .Test != null) | .Test] as $f | .[] |
		select(.Action == "output" and (.Test == null or (.Test as $t | $f | index($t)))) | .Output' "$1" |
		grep -vE '^=== (RUN|PAUSE|CONT|NAME)' || true
	echo "mais lentos (s):"
	head -15 "$3" | sed 's/^/  /'
	jq -r 'select(.Test == null and (.Action == "pass" or .Action == "fail")) |
		"\(.Package) \(.Action) \(.Elapsed)s"' "$1" | tee "$4"
}

# race_union_check <n> <dir>: as n listas esperadas são iguais e a união dos ran-*.txt é exatamente a lista, sem
# repetição; imprime os testes que ficaram de fora ou sobraram.
race_union_check() {
	local n="$1" dir="$2" k fail=0
	for k in $(seq 1 "$n"); do
		if [ ! -s "$dir/expected-$k.txt" ] || [ ! -f "$dir/ran-$k.txt" ]; then
			echo "lote $k: sem expected-$k.txt ou ran-$k.txt em $dir"
			return 1
		fi
		LC_ALL=C sort "$dir/expected-$k.txt" >"$WORK/exp-$k.txt"
		if ! cmp -s "$WORK/exp-1.txt" "$WORK/exp-$k.txt"; then
			echo "lote $k: lista de testes diferente da do lote 1"
			fail=1
		fi
	done
	for k in $(seq 1 "$n"); do cat "$dir/ran-$k.txt"; done | LC_ALL=C sort >"$WORK/ran-all.txt"
	LC_ALL=C uniq -d "$WORK/ran-all.txt" | sed 's/^/em mais de um lote: /' >"$WORK/dups"
	LC_ALL=C uniq "$WORK/ran-all.txt" >"$WORK/ran-uniq.txt"
	LC_ALL=C comm -23 "$WORK/exp-1.txt" "$WORK/ran-uniq.txt" | sed 's/^/fora de todos os lotes: /' >"$WORK/missing"
	LC_ALL=C comm -13 "$WORK/exp-1.txt" "$WORK/ran-uniq.txt" | sed 's/^/fora da lista: /' >"$WORK/extra"
	cat "$WORK/dups" "$WORK/missing" "$WORK/extra"
	if [ -s "$WORK/dups" ] || [ -s "$WORK/missing" ] || [ -s "$WORK/extra" ]; then
		fail=1
	fi
	echo "lotes: $n; testes na lista: $(wc -l <"$WORK/exp-1.txt" | tr -d ' '); com resultado: $(wc -l <"$WORK/ran-uniq.txt" | tr -d ' ')"
	return $fail
}

# race_check <n> <dir>: união dos lotes e cobertura total (cover-main.out do full + cover-*.out dos lotes).
race_check() {
	local n="${1:-}" dir="${2:-}" k covers
	case "$n" in '' | *[!0-9]*) n="" ;; esac
	if [ -z "$n" ] || [ -z "$dir" ]; then
		echo "uso: verify.sh race-check <n> <diretório>" >&2
		return 2
	fi
	echo "== verify race-check"
	run_step "lotes -race: união = lista" race_union_check "$n" "$dir"
	for k in $(seq 1 "$n"); do
		[ -f "$dir/elapsed-$k.txt" ] && echo "lote $k: $(cat "$dir/elapsed-$k.txt")"
	done
	covers="$dir/cover-main.out"
	for k in $(seq 1 "$n"); do covers="$covers $dir/cover-$k.out"; done
	# shellcheck disable=SC2086 # lista de perfis
	run_step "cobertura total (full + lotes)" coverage_total $covers
	summary
	[ "$FAILED" = 0 ]
}

cpu_count() { getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 1; }

# fuzz_one <pacote> <alvo> <workers> <saída>: um alvo, 10 s (FUZZ_TIME) com <workers> processos de fuzz.
fuzz_one() {
	go test -run='^$' -fuzz="^${2}\$" -fuzztime="$FUZZ_TIME" -parallel="$3" "$1" >"$4" 2>&1
}

# Fuzz curto de todos os alvos (spec 017 RF-08: FUZZ_TIME por alvo). Os alvos rodam em lotes de FUZZ_JOBS em
# paralelo, cada um com FUZZ_WORKERS workers (CPUs / lotes): o tempo de cada alvo não muda e o passo cai de
# soma(alvos) para soma/lotes (task 253). A saída de cada alvo sai inteira, na ordem, ao fim do lote.
fuzz_all() {
	local list rc=0 file pkg name i j pid cpus jobs workers
	local targets=() pids=()
	cpus=$(cpu_count)
	jobs="${FS_FUZZ_JOBS:-$((cpus / 2))}"
	[ "$jobs" -ge 1 ] 2>/dev/null || jobs=1
	workers=$((cpus / jobs))
	[ "$workers" -ge 1 ] || workers=1
	list=$(test_files_matching '^func Fuzz[A-Z0-9_][A-Za-z0-9_]*\(')
	for file in $list; do
		pkg=$(dirname "$file")
		for name in $(sed -nE 's/^func (Fuzz[A-Za-z0-9_]*)\(.*/\1/p' "$file"); do
			targets+=("$pkg $name")
		done
	done
	echo "fuzz: ${#targets[@]} alvos, $jobs em paralelo, $workers workers cada ($FUZZ_TIME por alvo)"
	mkdir -p "$WORK/fuzz"
	i=0
	while [ "$i" -lt "${#targets[@]}" ]; do
		pids=()
		j=$i
		while [ "$j" -lt "${#targets[@]}" ] && [ "$j" -lt $((i + jobs)) ]; do
			set -- ${targets[$j]}
			fuzz_one "$1" "$2" "$workers" "$WORK/fuzz/$j.out" &
			pids+=("$!")
			j=$((j + 1))
		done
		j=$i
		for pid in "${pids[@]}"; do
			set -- ${targets[$j]}
			if wait "$pid"; then
				echo "fuzz $1 $2 ($FUZZ_TIME): ok"
			else
				echo "fuzz $1 $2 ($FUZZ_TIME): FALHOU"
				rc=1
			fi
			cat "$WORK/fuzz/$j.out"
			j=$((j + 1))
		done
		i=$j
	done
	return $rc
}

has_fuzz() { [ -n "$(test_files_matching '^func Fuzz')" ]; }

# Pacotes com testes marcados //go:build linux_priv (AF_PACKET, ethtool).
linux_priv_pkgs() {
	test_files_matching '^//go:build .*linux_priv' | xargs -n1 dirname 2>/dev/null | sort -u
}

# Apaga o diretório remoto desta execução, se houver. Só toca em /tmp/fs-verify.* criado por linux_priv_tests.
remote_cleanup() {
	[ -n "$REMOTE_WORK" ] || return 0
	ssh -p "$VPS_PORT" -o BatchMode=yes -o ConnectTimeout=10 "$VPS_SSH" "rm -rf '$REMOTE_WORK'" || true
	REMOTE_WORK=""
}

# Compila os pacotes com a tag linux_priv e os roda no servidor ($VPS_SSH) como root. Cada execução usa um diretório remoto
# próprio (mktemp -d) e apaga só ele, inclusive em erro: dois verify-full simultâneos, de worktrees diferentes,
# não se atropelam (task 174). Os testes em si toleram paralelismo (cada um abre seu AF_PACKET e um NATS embutido
# em porta aleatória; as asserções são limites inferiores), por isso não há trava.
linux_priv_tests() {
	local pkgs="$1" d name rc=0
	ssh -p "$VPS_PORT" -o BatchMode=yes -o ConnectTimeout=10 "$VPS_SSH" true || {
		echo "$VPS_LABEL inacessível por ssh ($VPS_SSH:$VPS_PORT)"
		return 1
	}
	REMOTE_WORK=$(ssh -p "$VPS_PORT" "$VPS_SSH" 'mktemp -d /tmp/fs-verify.XXXXXX') || {
		REMOTE_WORK=""
		return 1
	}
	case "$REMOTE_WORK" in
	/tmp/fs-verify.?*) ;;
	*)
		echo "diretório remoto inesperado: '$REMOTE_WORK'"
		REMOTE_WORK=""
		return 1
		;;
	esac
	echo "$VPS_LABEL: diretório $REMOTE_WORK"
	for d in $pkgs; do
		name=$(echo "${d#./}" | tr '/' '_').test
		CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go test -c -tags linux_priv -o "$WORK/$name" "$d" || {
			rc=1
			break
		}
		scp -q -P "$VPS_PORT" "$WORK/$name" "$VPS_SSH:$REMOTE_WORK/$name" || {
			rc=1
			break
		}
		echo "$VPS_LABEL: $d"
		ssh -p "$VPS_PORT" "$VPS_SSH" "cd '$REMOTE_WORK' && ./$name -test.v -test.count=1" || rc=1
	done
	remote_cleanup
	return $rc
}

# load_lock_check: falha (com o motivo) enquanto houver carga em andamento no servidor. A trava é gravada por
# test/load/*.sh; o e2e mistura tráfego, cria chaves do bot e faz forget do IP do gerador, e invalidaria a medida
# (spec 017 RF-13, task 361). FS_E2E_DURING_LOAD=1 passa por cima, de caso pensado.
LOAD_LOCK="${FS_LOAD_LOCK:-/tmp/fs-load-running}"
load_lock_check() {
	[ "${FS_E2E_DURING_LOAD:-0}" = 1 ] && return 0
	local out
	out=$(ssh -p "$VPS_PORT" -o BatchMode=yes -o ConnectTimeout=10 "$VPS_SSH" \
		"if [ -e '$LOAD_LOCK' ]; then echo \"present \$(cat '$LOAD_LOCK' 2>/dev/null)\"; else echo absent; fi") || {
		echo "$VPS_LABEL inacessível por ssh ($VPS_SSH:$VPS_PORT) ao conferir $LOAD_LOCK"
		return 1
	}
	case "$out" in
	absent) return 0 ;;
	present*)
		echo "carga em andamento em $VPS_LABEL ($LOAD_LOCK: ${out#present }); e2e recusado (FS_E2E_DURING_LOAD=1 passa por cima)"
		return 1
		;;
	*)
		echo "resposta inesperada ao conferir $LOAD_LOCK em $VPS_LABEL: $out"
		return 1
		;;
	esac
}

# e2e_tests: o passo e2e do full (matriz da spec 017), recusado durante uma carga.
e2e_tests() {
	load_lock_check || return 1
	go test -count=1 -timeout "$E2E_TIMEOUT" -tags e2e ./test/e2e/...
}

verify_full() {
	local e2e=0 pkgs
	while [ $# -gt 0 ]; do
		case "$1" in
		--e2e) e2e=1 ;;
		*)
			echo "uso: verify.sh full [--e2e]" >&2
			exit 2
			;;
		esac
		shift
	done
	STOP_ON_FAIL=1
	echo "== verify full"

	if [ "${CI:-}" = true ]; then
		run_step "pebble (CI)" pebble_check
	fi
	run_step "format" gofumpt_all
	run_step "binários versionados" scripts/check-binaries.sh
	run_step "verify-test" scripts/verify-test.sh
	run_step "lint" golangci-lint run ./...
	run_step "vet" go vet ./...
	run_step "contratos" contracts_check
	run_step "examples asyncapi" asyncapi_examples_check
	run_step "testes -race + cobertura" full_tests
	# no CI, o store sai deste passo e roda em lotes (race-shard/race-check)
	[ -z "$RACE_SPLIT_PKGS" ] || STEP_NOTES[$((${#STEP_NOTES[@]} - 1))]="sem $RACE_SPLIT_PKGS (lotes)"

	if has_fuzz; then
		run_step "fuzz curto ($FUZZ_TIME)" fuzz_all
	else
		skip_step "fuzz curto ($FUZZ_TIME)" "nenhum alvo Fuzz*"
	fi

	run_step "govulncheck" govulncheck ./...
	run_step "build linux/amd64" make -s build

	pkgs=$(linux_priv_pkgs)
	if [ "${FS_SKIP_LINUX_PRIV:-0}" = 1 ]; then
		skip_step "testes linux_priv ($VPS_LABEL)" "FS_SKIP_LINUX_PRIV=1"
	elif [ -z "$pkgs" ]; then
		skip_step "testes linux_priv ($VPS_LABEL)" "nenhum teste linux_priv"
	else
		run_step "testes linux_priv ($VPS_LABEL)" linux_priv_tests "$pkgs"
	fi

	if [ "$e2e" = 1 ]; then
		if [ -d test/e2e ] && ls test/e2e/*_test.go >/dev/null 2>&1; then
			run_step "e2e ($VPS_LABEL)" e2e_tests
		else
			skip_step "e2e ($VPS_LABEL)" "test/e2e ainda não existe"
		fi
	fi

	summary
	[ "$FAILED" = 0 ]
}

case "$MODE" in
lib) return 0 2>/dev/null || exit 0 ;; # carregado por scripts/verify-test.sh só pelas funções
quick) verify_quick "$@" ;;
full) verify_full "$@" ;;
race-shard) race_shard "$@" ;;
race-check) race_check "$@" ;;
*)
	echo "uso: verify.sh quick|full|race-shard|race-check [...]" >&2
	exit 2
	;;
esac
