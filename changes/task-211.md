- htdocs: o "Run probe" trata o 503 do `?wait` (teto de 64 esperas): espera o `Retry-After` (1 s se ausente ou
  ilegível, no máximo 5 s) e repete até o prazo do `wait`; outros códigos seguem como erro (task 211).
