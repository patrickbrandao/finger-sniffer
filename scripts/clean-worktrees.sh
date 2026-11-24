#!/usr/bin/env bash
# Limpeza dos worktrees e branches de tarefas já mergeadas (task 374, specs/002 "Fluxo das tarefas").
#
#   make clean-worktrees                 # só lista (padrão, igual a --dry-run)
#   make clean-worktrees ARGS=--apply    # remove o que a lista marcou para remover
#
# Como o merge é squash, `git branch --merged main` não reconhece as branches das tarefas; "mergeada" aqui é ter PR
# mergeado no GitHub (`gh pr list --state merged`) com a branch como head.
#
# Remove (só com --apply):
#   - worktree ligado (qualquer um, menos o principal e o de onde o script roda) sem alteração pendente
#     (`status --porcelain` vazio), não travado, cuja branch tem PR mergeado ou cujo HEAD destacado já está na main;
#     depois `git worktree prune` (também limpa os registros de worktrees cujo diretório sumiu);
#   - branch local `task/*` com PR mergeado que não esteja em uso por um worktree mantido (`git branch -D`).
# Nunca toca worktree com alteração pendente, travado ou com branch sem PR mergeado, nem branch sem PR mergeado:
# esses saem numa lista à parte. Branches remotas não são tocadas (o GitHub já as apaga no merge).
#
# Variáveis: FS_CLEAN_MAIN (ref da main para o HEAD destacado; padrão origin/main, ou main se não houver remoto),
# FS_CLEAN_PR_LIMIT (quantos PRs mergeados consultar; padrão 5000).
set -euo pipefail

apply=0
case "${1:-}" in
"" | --dry-run) ;;
--apply) apply=1 ;;
*)
	echo "uso: clean-worktrees.sh [--dry-run|--apply]" >&2
	exit 2
	;;
esac

top="$(git rev-parse --show-toplevel)"
cd "$top"
# o worktree principal é o primeiro da lista; o atual é o de onde o script roda
main_wt="$(git worktree list --porcelain | sed -n '1s/^worktree //p')"
main_ref="${FS_CLEAN_MAIN:-}"
if [ -z "$main_ref" ]; then
	if git rev-parse -q --verify origin/main >/dev/null; then main_ref=origin/main; else main_ref=main; fi
fi

tmp="$(mktemp -d "${TMPDIR:-/tmp}/fs-clean-wt.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

# branches com PR mergeado (uma consulta só; falha do gh aborta, para não decidir sem saber)
if ! gh pr list --state merged --limit "${FS_CLEAN_PR_LIMIT:-5000}" --json headRefName --jq '.[].headRefName' \
	>"$tmp/merged"; then
	echo "clean-worktrees: gh pr list falhou; nada foi alterado" >&2
	exit 1
fi
is_merged() { grep -qxF -- "$1" "$tmp/merged"; }

: >"$tmp/rm-wt"
: >"$tmp/keep-wt"
: >"$tmp/keep-branches" # branches em uso por worktree mantido

# percorre os worktrees ligados (registros separados por linha vazia no --porcelain)
check_wt() {
	local path="$1" branch="$2" head="$3" locked="$4" prunable="$5" why=""
	[ -n "$path" ] || return 0
	[ "$path" != "$main_wt" ] || return 0
	if [ "$path" = "$top" ]; then
		why="worktree atual"
	elif [ "$prunable" = 1 ]; then
		echo "$path	(diretório sumiu; sai no git worktree prune)" >>"$tmp/rm-wt"
		return 0
	elif [ "$locked" = 1 ]; then
		why="travado (git worktree lock)"
	elif [ -n "$(git -C "$path" status --porcelain 2>/dev/null || echo '?')" ]; then
		why="alteração pendente"
	elif [ -n "$branch" ]; then
		is_merged "$branch" || why="branch $branch sem PR mergeado"
	elif ! git merge-base --is-ancestor "$head" "$main_ref" 2>/dev/null; then
		why="HEAD destacado fora da $main_ref"
	fi
	if [ -n "$why" ]; then
		echo "$path	$why" >>"$tmp/keep-wt"
		[ -z "$branch" ] || echo "$branch" >>"$tmp/keep-branches"
	else
		echo "$path	${branch:-HEAD destacado $head}" >>"$tmp/rm-wt"
	fi
}

path="" branch="" head="" locked=0 prunable=0
while IFS= read -r line || [ -n "$path" ]; do
	case "$line" in
	"worktree "*) path="${line#worktree }" ;;
	"HEAD "*) head="${line#HEAD }" ;;
	"branch refs/heads/"*) branch="${line#branch refs/heads/}" ;;
	locked*) locked=1 ;;
	prunable*) prunable=1 ;;
	"")
		check_wt "$path" "$branch" "$head" "$locked" "$prunable"
		path="" branch="" head="" locked=0 prunable=0
		;;
	esac
done < <(git worktree list --porcelain)

# branches locais task/*: mergeadas e fora de worktree mantido saem; as outras ficam listadas
: >"$tmp/rm-br"
: >"$tmp/keep-br"
git for-each-ref --format='%(refname:short)' 'refs/heads/task/' | while IFS= read -r b; do
	if ! is_merged "$b"; then
		echo "$b" >>"$tmp/keep-br"
	elif grep -qxF -- "$b" "$tmp/keep-branches"; then
		echo "$b	(em uso por worktree mantido)" >>"$tmp/keep-br"
	else
		echo "$b" >>"$tmp/rm-br"
	fi
done

show() {
	local title="$1" file="$2"
	echo "== $title: $(wc -l <"$file" | tr -d ' ')"
	sed 's/^/  /' "$file"
}
if [ "$apply" = 1 ]; then verb="removendo"; else verb="a remover (--apply remove)"; fi
show "worktrees $verb" "$tmp/rm-wt"
show "worktrees mantidos" "$tmp/keep-wt"
show "branches task/* $verb" "$tmp/rm-br"
show "branches task/* mantidas" "$tmp/keep-br"

if [ "$apply" = 0 ]; then
	echo "== só listagem; nada foi alterado"
	exit 0
fi

cut -f1 "$tmp/rm-wt" | while IFS= read -r p; do
	[ -d "$p" ] || continue
	# sem --force: o git recusa se algo mudou desde a conferência
	git worktree remove "$p" || echo "clean-worktrees: não removido: $p" >&2
done
git worktree prune
cut -f1 "$tmp/rm-br" | while IFS= read -r b; do
	git branch -D -- "$b" >/dev/null || echo "clean-worktrees: branch não apagada: $b" >&2
done
echo "== feito"
