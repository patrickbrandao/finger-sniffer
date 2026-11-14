- infra: `format`, fuzz e a lista de pacotes `linux_priv` do `verify-full` leem só os `.go` versionados ou novos não
  ignorados; `tmp/` fora do Git não quebra mais o `verify-full` no checkout principal (task 203).
