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
#   FS_SKIP_LINUX_PRIV=1 pula os testes privilegiados na vps602 (usado no CI)
#   FS_VPS_SSH           destino ssh (padrão root@vps602.tmsoft.com.br)
#   FS_VPS_PORT          porta ssh (padrão 48022)
#   FS_TEST_PEBBLE       binário do Pebble para os testes de ACME (padrão: o do PATH, instalado por make tools);
#                        exportado para os testes; no CI (CI=true) a ausência dele falha o verify-full
#
# Compatível com o bash 3.2 do macOS (sem arrays associativos nem mapfile).
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 2

MODULE="github.com/patrickbrandao/finger-sniffer"
MIGRATIONS_DIR="database/sqlite/migrations"
TEMPLATE_DB="tmp/testdb/template.sqlite"
COVER_STRICT_PKGS="pkg/detect pkg/probe pkg/tlsparse pkg/h1 pkg/h2passive pkg/quicparse pkg/fingerprint"
COVER_STRICT_MIN=80
COVER_TOTAL_MIN=60
OPENAPI_FILE="cmd/finger-sniffer-store/openapi.yaml"
ASYNCAPI_FILE="eventbus/nats/asyncapi.yaml"
# Validadores dos contratos (Node, via npx; versões fixadas)
REDOCLY_CLI="@redocly/cli@2.76.0"
ASYNCAPI_CLI="@asyncapi/cli@6.3.0"
FUZZ_TIME="${FS_FUZZ_TIME:-10s}"
VPS_SSH="${FS_VPS_SSH:-root@vps602.tmsoft.com.br}"
VPS_PORT="${FS_VPS_PORT:-48022}"

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
trap 'rm -rf "$WORK"' EXIT

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
	if "$@"; then
		record "$name" ok "$start"
	else
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

# Valida openapi.yaml (Redocly) e asyncapi.yaml (AsyncAPI CLI). Erros falham; avisos não.
contracts_check() {
	local rc=0
	command -v npx >/dev/null || {
		echo "npx não encontrado (instale Node.js para validar os contratos)"
		return 1
	}
	export REDOCLY_TELEMETRY=off REDOCLY_SUPPRESS_UPDATE_NOTICE=true
	npx -y "$REDOCLY_CLI" lint --format=summary "$OPENAPI_FILE" || rc=1
	# Sem telemetria do AsyncAPI CLI (preferência de privacidade)
	npx -y "$ASYNCAPI_CLI" config analytics --disable >/dev/null 2>&1 || true
	npx -y "$ASYNCAPI_CLI" validate "$ASYNCAPI_FILE" --fail-severity=error || rc=1
	return $rc
}

# No CI o Pebble é obrigatório: sem ele os testes de ACME pulariam em silêncio.
pebble_check() {
	if [ -z "$FS_TEST_PEBBLE" ] || [ ! -x "$FS_TEST_PEBBLE" ]; then
		echo "Pebble não encontrado (rode make tools-ci ou defina FS_TEST_PEBBLE)"
		return 1
	fi
	echo "FS_TEST_PEBBLE=$FS_TEST_PEBBLE"
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

# ---------------------------------------------------------------------------
# Nível rápido
# ---------------------------------------------------------------------------
verify_quick() {
	local explicit=() files go_files dirs pkgs affected rdeps test_pkgs p start
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
	pkgs=$(packages_of_dirs $dirs)
	migrations_changed=$(echo "$files" | grep -c "^$MIGRATIONS_DIR/" || true)
	gomod_changed=$(echo "$files" | grep -cE '^go\.(mod|sum)$' || true)
	contracts_changed=$(echo "$files" | grep -cE "^($OPENAPI_FILE|$ASYNCAPI_FILE)\$" || true)

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
		skip_step "contratos (alterados)" "openapi/asyncapi sem mudança"
	fi

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

fuzz_all() {
	local list rc=0 file pkg name
	list=$(grep -rlE '^func Fuzz[A-Z0-9_][A-Za-z0-9_]*\(' --include='*_test.go' . 2>/dev/null)
	for file in $list; do
		pkg=$(dirname "$file")
		for name in $(sed -nE 's/^func (Fuzz[A-Za-z0-9_]*)\(.*/\1/p' "$file"); do
			echo "fuzz $pkg $name ($FUZZ_TIME)"
			go test -run='^$' -fuzz="^${name}\$" -fuzztime="$FUZZ_TIME" "$pkg" || rc=1
		done
	done
	return $rc
}

has_fuzz() { grep -rqE '^func Fuzz' --include='*_test.go' . 2>/dev/null; }

# Pacotes com testes marcados //go:build linux_priv (AF_PACKET, ethtool).
linux_priv_pkgs() {
	grep -rlE '^//go:build .*linux_priv' --include='*_test.go' . 2>/dev/null | xargs -n1 dirname 2>/dev/null | sort -u
}

linux_priv_tests() {
	local pkgs="$1" d name rc=0
	ssh -p "$VPS_PORT" -o BatchMode=yes -o ConnectTimeout=10 "$VPS_SSH" true || {
		echo "vps602 inacessível por ssh ($VPS_SSH:$VPS_PORT)"
		return 1
	}
	ssh -p "$VPS_PORT" "$VPS_SSH" 'mkdir -p /tmp/fs-verify' || return 1
	for d in $pkgs; do
		name=$(echo "${d#./}" | tr '/' '_').test
		CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go test -c -tags linux_priv -o "$WORK/$name" "$d" || return 1
		scp -q -P "$VPS_PORT" "$WORK/$name" "$VPS_SSH:/tmp/fs-verify/$name" || return 1
		echo "vps602: $d"
		ssh -p "$VPS_PORT" "$VPS_SSH" "cd /tmp/fs-verify && ./$name -test.v -test.count=1" || rc=1
	done
	ssh -p "$VPS_PORT" "$VPS_SSH" 'rm -rf /tmp/fs-verify' || true
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
	run_step "format" gofumpt_check .
	run_step "lint" golangci-lint run ./...
	run_step "vet" go vet ./...
	run_step "contratos" contracts_check
	run_step "testes -race + cobertura" full_tests

	if has_fuzz; then
		run_step "fuzz curto ($FUZZ_TIME)" fuzz_all
	else
		skip_step "fuzz curto ($FUZZ_TIME)" "nenhum alvo Fuzz*"
	fi

	run_step "govulncheck" govulncheck ./...
	run_step "build linux/amd64" make -s build

	pkgs=$(linux_priv_pkgs)
	if [ "${FS_SKIP_LINUX_PRIV:-0}" = 1 ]; then
		skip_step "testes linux_priv (vps602)" "FS_SKIP_LINUX_PRIV=1"
	elif [ -z "$pkgs" ]; then
		skip_step "testes linux_priv (vps602)" "nenhum teste linux_priv"
	else
		run_step "testes linux_priv (vps602)" linux_priv_tests "$pkgs"
	fi

	if [ "$e2e" = 1 ]; then
		if [ -d test/e2e ] && ls test/e2e/*_test.go >/dev/null 2>&1; then
			run_step "e2e (vps602)" go test -count=1 -tags e2e ./test/e2e/...
		else
			skip_step "e2e (vps602)" "test/e2e ainda não existe"
		fi
	fi

	summary
	[ "$FAILED" = 0 ]
}

case "$MODE" in
quick) verify_quick "$@" ;;
full) verify_full "$@" ;;
*)
	echo "uso: verify.sh quick|full [...]" >&2
	exit 2
	;;
esac
