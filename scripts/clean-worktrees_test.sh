#!/usr/bin/env bash
# Teste do scripts/clean-worktrees.sh (task 374), sem rede: um repositório temporário com
#   - worktree limpo cuja branch tem PR mergeado (sai com --apply);
#   - worktree com alteração pendente e branch mergeada (fica);
#   - worktree limpo com branch sem PR mergeado (fica);
#   - worktree com HEAD destacado já na main (sai) e outro fora da main (fica);
#   - branch task/* mergeada sem worktree (sai) e sem PR mergeado (fica).
# O gh é trocado por um stub que devolve a lista de branches mergeadas.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$ROOT/scripts/clean-worktrees.sh"
T="$(mktemp -d "${TMPDIR:-/tmp}/fs-clean-wt-test.XXXXXX")"
trap 'rm -rf "$T"' EXIT

fail=0
check() {
	if eval "$2"; then echo "ok   $1"; else
		echo "FAIL $1"
		fail=1
	fi
}

# stub do gh: imprime as branches mergeadas do arquivo
mkdir -p "$T/bin"
cat >"$T/bin/gh" <<'EOF'
#!/usr/bin/env bash
cat "$FAKE_MERGED"
EOF
chmod +x "$T/bin/gh"
export PATH="$T/bin:$PATH" FAKE_MERGED="$T/merged"
printf '%s\n' task/001-merged task/002-dirty task/005-branch-only >"$FAKE_MERGED"

R="$T/repo"
g() { git -C "$R" -c user.name=t -c user.email=t@t -c commit.gpgsign=false "$@"; }
git init -q -b main "$R"
g commit -q --allow-empty -m base
for b in task/001-merged task/002-dirty task/003-no-pr task/005-branch-only task/006-no-pr; do
	g branch "$b"
done
g worktree add -q "$T/wt1" task/001-merged
g worktree add -q "$T/wt2" task/002-dirty
g worktree add -q "$T/wt3" task/003-no-pr
g worktree add -q --detach "$T/wt4" main
g worktree add -q --detach "$T/wt5" main
echo x >"$T/wt2/novo.txt"
# HEAD destacado com commit fora da main
git -C "$T/wt5" -c user.name=t -c user.email=t@t -c commit.gpgsign=false commit -q --allow-empty -m fora

out=$(cd "$R" && FS_CLEAN_MAIN=main bash "$SCRIPT" 2>&1)
check "dry-run sai com 0" "[ \$? = 0 ]"
check "dry-run não remove worktree" "[ -d '$T/wt1' ] && [ -d '$T/wt4' ]"
check "dry-run não apaga branch" "g rev-parse -q --verify task/005-branch-only >/dev/null"
check "dry-run diz que nada mudou" "echo \"\$out\" | grep -q 'nada foi alterado'"
check "dry-run lista o mergeado" "echo \"\$out\" | grep -q 'wt1.*task/001-merged'"

# shellcheck disable=SC2034 # lida dentro do eval de check
out=$(cd "$R" && FS_CLEAN_MAIN=main bash "$SCRIPT" --apply 2>&1)
check "apply sai com 0" "[ \$? = 0 ]"
check "worktree limpo mergeado removido" "[ ! -e '$T/wt1' ]"
check "worktree destacado na main removido" "[ ! -e '$T/wt4' ]"
check "worktree com alteração mantido" "[ -f '$T/wt2/novo.txt' ]"
check "worktree sem PR mergeado mantido" "[ -d '$T/wt3' ]"
check "worktree destacado fora da main mantido" "[ -d '$T/wt5' ]"
check "branch mergeada sem worktree apagada" "! g rev-parse -q --verify task/005-branch-only >/dev/null"
check "branch do worktree removido apagada" "! g rev-parse -q --verify task/001-merged >/dev/null"
check "branch em uso por worktree mantido fica" "g rev-parse -q --verify task/002-dirty >/dev/null"
check "branch sem PR mergeado fica" "g rev-parse -q --verify task/006-no-pr >/dev/null"
check "motivo da alteração pendente listado" "echo \"\$out\" | grep -q 'wt2.*alteração pendente'"
check "registros podados" "[ \$(g worktree list | wc -l) = 4 ]"

check "opção inválida recusada" "! bash '$SCRIPT' --bogus >/dev/null 2>&1"
printf '#!/usr/bin/env bash\nexit 1\n' >"$T/bin/gh"
check "gh falhando aborta sem alterar" "! (cd '$R' && bash '$SCRIPT' --apply >/dev/null 2>&1) && [ -d '$T/wt3' ]"

[ "$fail" = 0 ] && echo "== clean-worktrees-test: OK" || echo "== clean-worktrees-test: FALHOU"
exit "$fail"
