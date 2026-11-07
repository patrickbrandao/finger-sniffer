# 0013 — Verificação em dois níveis, qualidade e CI/CD

Status: aceita
Data: 2026-11-07

## Contexto
Agentes precisam de retorno rápido a cada tarefa e de garantia completa antes de PR e release. Parte dos testes
(AF_PACKET, ethtool) só roda em Linux com privilégio.

## Decisão
- `scripts/verify.sh` → `make verify-quick` (padrão; só o que mudou desde o merge-base com `main`) e
  `make verify-full` (tudo, `-race`, govulncheck, fuzz curto, build, testes `linux_priv` na vps602; `--e2e`).
  Detalhes na spec 017.
- SQLite de testes: banco-modelo migrado, refeito só quando o hash das migrations muda; copiado por teste.
- Testes: unidade (golden pcaps), integração (NATS embutido), contrato (openapi/asyncapi), e2e (matriz).
  Cobertura ≥ 80% nos pacotes de parsers/fingerprints, ≥ 60% no total.
- Qualidade: golangci-lint v2 (govet, staticcheck, errcheck, gosec, revive), gofumpt/goimports, lefthook pre-commit.
- CI GitHub Actions: `verify-full` sem e2e e sem `linux_priv` em todo PR e na `main`.
- Deploy: `make deploy` a partir do Mac, sem aprovação; e2e roda local contra a vps602.

## Alternativas consideradas
- Um nível só; unidade + e2e sem meta; só go vet + gofmt; Actions fazendo deploy.

## Consequências
- Agentes informam o nível rodado e o resultado em cada entrega.
