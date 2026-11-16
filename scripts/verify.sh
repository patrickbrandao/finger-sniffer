#!/usr/bin/env bash
# Verificação em dois níveis (spec 017, ADR 0013).
#
#   scripts/verify.sh quick [-- <pacotes> [flags do go test]]
#   scripts/verify.sh full  [--e2e]
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
#   FS_SKIP_TRAEFIK=1    o full pula o passo "traefik" (o CI o roda num job próprio, em paralelo: task 262)
#
# Também: scripts/verify.sh traefik — só o passo do fork (spec 017 RF-14), usado pelo job "traefik" do CI.
#
# Compatível com o bash 3.2 do macOS (sem arrays associativos nem mapfile).
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 2

MODULE="github.com/patrickbrandao/finger-sniffer"
MIGRATIONS_DIR="database/sqlite/migrations"
TEMPLATE_DB="tmp/testdb/template.sqlite"
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
# Fork do traefik (ADR 0048, spec 019): módulo Go próprio, fora de todos os passos do módulo raiz; tem o passo
# "traefik" (spec 017 RF-14, task 262)
TRAEFIK_DIR="traefik"
FUZZ_TIME="${FS_FUZZ_TIME:-10s}"
VPS_SSH="${FS_VPS_SSH:-root@finger-01.tmsoft.com.br}"
VPS_PORT="${FS_VPS_PORT:-48022}"
# Rótulo do servidor nos passos e nas mensagens: o primeiro rótulo do host (finger-01)
VPS_LABEL="${VPS_SSH#*@}"
VPS_LABEL="${VPS_LABEL%%.*}"
E2E_TIMEOUT="${FS_E2E_TIMEOUT:-45m}"

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

# Arquivos alterados desde a base: commits + working tree + não rastreados.
changed_files() {
	local base_ref base
	base_ref="${FS_VERIFY_BASE:-main}"
	if ! git rev-parse --verify -q "$base_ref" >/dev/null; then
		base_ref="origin/main"
	fi
	base=$(git merge-base HEAD "$base_ref" 2>/dev/null || git rev-parse HEAD)
	{
		git diff --name-only "$base"
		git ls-files --others --exclude-standard
	} | sort -u
}

# Filtra (stdin) os caminhos do módulo raiz: tira o que está no fork do traefik (task 262).
root_only() { grep -v "^$TRAEFIK_DIR/" || true; }

# Filtra (stdin) os caminhos do fork do traefik.
traefik_only() { grep "^$TRAEFIK_DIR/" || true; }

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

# Prepara o banco-modelo SQLite e exporta as variáveis para os testes (spec 017 RF-06).
prepare_test_db() {
	local result
	# Sem nenhum .sql não há modelo a manter (evita compilar a ferramenta à toa).
	if ! ls "$MIGRATIONS_DIR"/*.sql >/dev/null 2>&1; then
		DB_RESULT="skipped"
		return 0
	fi
	result=$(go run ./scripts/testdb -migrations "$MIGRATIONS_DIR" -out "$TEMPLATE_DB") || return 1
	echo "testdb: $result"
	DB_RESULT="$result"
	if [ "$result" != "skipped" ]; then
		export FS_TEST_DB=local
		FS_TEST_DB_TEMPLATE="$ROOT/$TEMPLATE_DB"
		export FS_TEST_DB_TEMPLATE
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

# Arquivos .go do módulo raiz: versionados e novos não ignorados. O que o .gitignore cobre (tmp/, bin/, dist/)
# fica de fora, como no quick (task 203), e o fork do traefik também (task 262).
go_source_files() {
	local f
	git ls-files --cached --others --exclude-standard -- '*.go' ":(exclude)$TRAEFIK_DIR/" | while IFS= read -r f; do
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

# Pacotes do fork testados pelo passo "traefik" (relativos a traefik/): o código nosso (./pkg/fingersniffer/...)
# e os pacotes com gancho no upstream, marcados com o comentário `// finger-sniffer:` (spec 019 RF-02).
traefik_test_pkgs() {
	local own="pkg/fingersniffer"
	(
		cd "$TRAEFIK_DIR" || exit 0
		[ -d "$own" ] && echo "./$own/..."
		grep -rlE '//[[:space:]]*finger-sniffer:' --include='*.go' . 2>/dev/null |
			grep -v "^\./$own/" | xargs -n1 dirname 2>/dev/null | sort -u
	)
}

# Passo "traefik" (spec 017 RF-14): build do binário do fork e testes do código nosso e dos ganchos. Os testes
# completos do upstream não rodam aqui (ADR 0048 item 6).
traefik_check() {
	local pkgs
	pkgs=$(traefik_test_pkgs)
	echo "traefik: go build ./cmd/traefik"
	(cd "$TRAEFIK_DIR" && CGO_ENABLED=0 go build -o "$WORK/traefik.bin" ./cmd/traefik) || return 1
	if [ -z "$pkgs" ]; then
		echo "traefik: nenhum pacote nosso nem gancho // finger-sniffer: para testar"
		return 0
	fi
	echo "traefik: go test" $pkgs
	# shellcheck disable=SC2086
	(cd "$TRAEFIK_DIR" && go test -count=1 $pkgs)
}

# traefik_plan <quick|full> [arquivos alterados]: "run" ou o motivo de pular o passo "traefik".
traefik_plan() {
	if [ "$1" = quick ] && [ -z "$(echo "${2:-}" | traefik_only)" ]; then
		echo "traefik sem mudança"
	elif [ ! -f "$TRAEFIK_DIR/go.mod" ]; then
		echo "sem $TRAEFIK_DIR/go.mod (fork ainda não importado, task 263)"
	elif [ "$1" = full ] && [ "${FS_SKIP_TRAEFIK:-0}" = 1 ]; then
		echo "FS_SKIP_TRAEFIK=1"
	else
		echo run
	fi
}

# traefik_step <quick|full> [arquivos alterados]: roda ou pula o passo "traefik".
traefik_step() {
	local plan
	plan=$(traefik_plan "$@")
	if [ "$plan" = run ]; then
		run_step "traefik" traefik_check
	else
		case "$plan" in
		sem*) echo "aviso: passo traefik pulado: $plan" ;;
		esac
		skip_step "traefik" "$plan"
	fi
}

# Arquivos de contrato cuja mudança dispara o passo "contratos" no quick.
contracts_re() {
	echo "^($OPENAPI_FILE|$BOT_OPENAPI_FILE|$ASYNCAPI_FILE|$CONTRACTS_TOOLS_DIR/package(-lock)?\.json)\$"
}

# ---------------------------------------------------------------------------
# Nível rápido
# ---------------------------------------------------------------------------
verify_quick() {
	local explicit=() all_files files go_files dirs pkgs affected rdeps test_pkgs p start existing
	if [ "${1:-}" = "--" ]; then
		shift
		explicit=("$@")
	elif [ $# -gt 0 ]; then
		echo "uso: verify.sh quick [-- <pacotes> [flags do go test]]" >&2
		exit 2
	fi

	all_files=$(changed_files)
	# Tudo abaixo é do módulo raiz; o fork do traefik só entra no passo "traefik" (task 262).
	files=$(echo "$all_files" | root_only)
	go_files=$(echo "$files" | grep -E '\.go$' | while read -r f; do [ -f "$f" ] && echo "$f"; done)
	dirs=$( (echo "$files" | grep -E '\.go$' | xargs -n1 dirname 2>/dev/null) | sort -u)
	# shellcheck disable=SC2086
	pkgs=$(packages_of_dirs $dirs)
	migrations_changed=$(echo "$files" | grep -c "^$MIGRATIONS_DIR/" || true)
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
		for p in $pkgs; do lint_dirs="$lint_dirs $(pkg_to_dir "$p")"; done
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

	# 4e. fork do traefik: só quando traefik/** muda
	traefik_step quick "$all_files"

	# 5. testes ligados ao que mudou (ou os explícitos)
	if [ ${#explicit[@]} -gt 0 ]; then
		run_step "testes (explícitos)" go test "${explicit[@]}"
	else
		test_pkgs=""
		for p in $pkgs; do
			d=$(pkg_to_dir "$p")
			ls "$d"/*_test.go >/dev/null 2>&1 && test_pkgs="$test_pkgs $p"
		done
		# scripts de deploy alterados: testes deles (pacote deploy)
		if echo "$files" | grep -qE '^(deploy/.*\.sh|\.env\.example)$' && ls deploy/*_test.go >/dev/null 2>&1; then
			test_pkgs="$test_pkgs $MODULE/deploy"
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
	local out="$1" fail=0 p line lines pkg pct total
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
	# Total: >= 60%, sem contar cmd/ (funções main não são testáveis por unidade).
	grep -v "^mode:" "$WORK/cover.out" | grep -v "^$MODULE/cmd/" >"$WORK/cover.nocmd"
	if [ -s "$WORK/cover.nocmd" ]; then
		(head -1 "$WORK/cover.out"; cat "$WORK/cover.nocmd") >"$WORK/cover.filtered"
		total=$(go tool cover -func="$WORK/cover.filtered" | awk '/^total:/ {gsub("%","",$3); print $3}')
		echo "cobertura total (sem cmd/): $total%"
		if awk "BEGIN{exit !($total < $COVER_TOTAL_MIN)}"; then
			echo "cobertura total abaixo de $COVER_TOTAL_MIN%"
			fail=1
		fi
	fi
	return $fail
}

full_tests() {
	# Banco isolado: sem FS_TEST_DB, cada teste cria e migra um SQLite novo.
	unset FS_TEST_DB FS_TEST_DB_TEMPLATE
	go test -race -count=1 -covermode=atomic -coverprofile="$WORK/cover.out" ./... | tee "$WORK/test.out"
	local rc=${PIPESTATUS[0]}
	[ "$rc" = 0 ] || return "$rc"
	coverage_check "$WORK/test.out"
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

	if has_fuzz; then
		run_step "fuzz curto ($FUZZ_TIME)" fuzz_all
	else
		skip_step "fuzz curto ($FUZZ_TIME)" "nenhum alvo Fuzz*"
	fi

	run_step "govulncheck" govulncheck ./...
	run_step "build linux/amd64" make -s build
	traefik_step full

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
			run_step "e2e ($VPS_LABEL)" go test -count=1 -timeout "$E2E_TIMEOUT" -tags e2e ./test/e2e/...
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
traefik)
	# Só o passo do fork (job "traefik" do CI); sem traefik/go.mod, pula com aviso.
	STOP_ON_FAIL=1
	traefik_step full
	summary
	[ "$FAILED" = 0 ]
	;;
*)
	echo "uso: verify.sh quick|full|traefik [...]" >&2
	exit 2
	;;
esac
