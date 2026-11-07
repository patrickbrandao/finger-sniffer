# 0005 — SQLite com BLOBs, goose e limites de memória

Status: provisória (revisar se o spike da task 006 mostrar I/O, vacuum ou latência do SQLite fora das metas da
spec 000, ou se o store passar de 384 MiB)
Data: 2026-11-07

## Contexto
Retenção curta (10 min / 2 GiB), sem banco permanente, consultas por probe/IP/porta/tempo, pcaps de até 16 MiB.

## Decisão
- SQLite via `modernc.org/sqlite` (Go puro, mantém `CGO_ENABLED=0`), modo WAL.
- Pcaps e bytes crus **dentro do SQLite como BLOB**; expurgo em lotes + `PRAGMA incremental_vacuum`.
- Migrations goose v3 embutidas (`go:embed`) em `database/sqlite/migrations/`, up/down, aplicadas no start do store.
- Teto de disco `FS_STORE_MAX_BYTES` = 2 GiB.
- `MemoryMax` das units: store 384M, nats 128M, demais 96M.

## Alternativas consideradas
- Índice em RAM + arquivos em disco (recomendado) — rejeitado pelo usuário.
- Arquivos em disco com SQLite só para metadados (recomendado) — rejeitado pelo usuário.
- mattn/go-sqlite3 (cgo); executor de migrations próprio; recriar o banco a cada start.

## Consequências
- Um único arquivo para operar; consultas SQL simples.
- Escrita e vacuum constantes em 1 vCPU são o principal risco de desempenho.
