- verify-quick: arquivos que não são `.go` (testdata, `//go:embed`, `htdocs/`, units e dados de `deploy/`, `nats.conf`)
  contam para o pacote Go mais próximo acima; `go.mod`/`go.sum` testam quem importa o módulo trocado (linha
  `go`/`toolchain`: `./...`); chave `FS_*` nova no código roda o pacote `deploy` (spec 017 RF-03, task 362).
