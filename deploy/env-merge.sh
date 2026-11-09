#!/usr/bin/env bash
# Acrescenta ao env do servidor as chaves novas do .env.example, sem sobrescrever as existentes (spec 016, task 035).
#
#   deploy/env-merge.sh <.env.example> <finger-sniffer.env>
#
# - chave ausente no servidor: acrescentada no fim, com os comentários que a precedem no .env.example;
# - chave presente com valor diferente do padrão novo: só um aviso (o valor do servidor é mantido);
# - idempotente: uma segunda execução não acrescenta nada.
# Compatível com o bash 3.2 do macOS (o teste roda no Mac e no CI).
set -euo pipefail

if [ $# -ne 2 ]; then
	echo "uso: env-merge.sh <.env.example> <finger-sniffer.env>" >&2
	exit 2
fi
example="$1"
target="$2"
[ -f "$example" ] || {
	echo "env-merge: $example não existe" >&2
	exit 2
}
[ -f "$target" ] || {
	echo "env-merge: $target não existe" >&2
	exit 2
}

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT

added=0
pending=""
while IFS= read -r line || [ -n "$line" ]; do
	case "$line" in
	"#"*)
		pending="${pending}${line}"$'\n'
		continue
		;;
	"")
		pending=""
		continue
		;;
	esac
	key=${line%%=*}
	if [ "$key" = "$line" ] || ! [[ "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
		pending=""
		continue
	fi
	new=${line#*=}
	# a última ocorrência vale (como no EnvironmentFile do systemd)
	cur_line=$(grep -E "^${key}=" "$target" | tail -n 1 || true)
	if [ -z "$cur_line" ]; then
		printf '%s%s\n' "$pending" "$line" >>"$tmp"
		added=$((added + 1))
		echo "[env] acrescentada $key=$new"
	else
		cur=${cur_line#*=}
		if [ "$cur" != "$new" ]; then
			echo "[env] aviso: $key=$cur no servidor difere do padrão do .env.example ($new); mantido o do servidor"
		fi
	fi
	pending=""
done <"$example"

if [ "$added" -gt 0 ]; then
	# o append preserva dono e modo do arquivo
	{
		printf '\n# --- acrescentado pelo deploy (chaves novas do .env.example) ---\n'
		cat "$tmp"
	} >>"$target"
	echo "[env] $added chave(s) nova(s) em $target"
fi
