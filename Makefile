# finger-sniffer — alvos de desenvolvimento (specs/016, specs/017)

MODULE   := github.com/patrickbrandao/finger-sniffer
SERVICES := capture web raw dns store
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.0.0-dev)
COMMIT   ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
# Build reproduzível (task 070): sem build ID, sem carimbo de VCS e sem caminhos locais (-trimpath);
# a versão e o commit entram só pelo -X. Mesmo commit + mesma toolchain = mesmo SHA-256.
LDFLAGS  := -s -w -buildid= -X $(MODULE)/internal/version.Version=$(VERSION) -X $(MODULE)/internal/version.Commit=$(COMMIT)
GOBUILD_FLAGS := -trimpath -buildvcs=false -mod=readonly
# Toolchain exata fixada no go.mod (diretiva toolchain); usada por release e pelo teste de reprodutibilidade
GO_TOOLCHAIN := $(shell sed -n 's/^toolchain //p' go.mod)
BIN      := bin
ARGS     ?=
SVC      ?=

# Versões fixadas das ferramentas de desenvolvimento
GOLANGCI_LINT_VERSION := v2.15.0
GOFUMPT_VERSION       := v0.12.0
GOIMPORTS_VERSION     := v0.52.0
GOOSE_VERSION         := v3.29.0
LEFTHOOK_VERSION      := v2.2.2
GOVULNCHECK_VERSION   := v1.9.0
# Servidor ACME de teste (spec 015; usado pelos testes da task 027 via FS_TEST_PEBBLE)
PEBBLE_VERSION        := v2.10.1

.PHONY: all tools tools-ci build test fmt lint verify-quick verify-full deploy release repro-check clean

all: build

tools:
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	go install mvdan.cc/gofumpt@$(GOFUMPT_VERSION)
	go install golang.org/x/tools/cmd/goimports@$(GOIMPORTS_VERSION)
	go install github.com/pressly/goose/v3/cmd/goose@$(GOOSE_VERSION)
	go install github.com/evilmartians/lefthook/v2@$(LEFTHOOK_VERSION)
	go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
	go install github.com/letsencrypt/pebble/v2/cmd/pebble@$(PEBBLE_VERSION)

# Só o que o verify-full precisa (usado no CI), inclusive o Pebble
tools-ci:
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	go install mvdan.cc/gofumpt@$(GOFUMPT_VERSION)
	go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
	go install github.com/letsencrypt/pebble/v2/cmd/pebble@$(PEBBLE_VERSION)

# Binários estáticos linux/amd64 para a vps602 (ADR 0009)
build:
	@mkdir -p $(BIN)
	@for s in $(SERVICES); do \
		echo "build finger-sniffer-$$s"; \
		CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(GOBUILD_FLAGS) -ldflags '$(LDFLAGS)' \
			-o $(BIN)/finger-sniffer-$$s ./cmd/finger-sniffer-$$s || exit 1; \
	done

test:
	go test ./...

fmt:
	gofumpt -w .
	goimports -local $(MODULE) -w .

lint:
	golangci-lint run ./...

verify-quick:
	@test -x scripts/verify.sh || { echo "scripts/verify.sh não implementado (task 002)"; exit 1; }
	scripts/verify.sh quick $(ARGS)

verify-full:
	@test -x scripts/verify.sh || { echo "scripts/verify.sh não implementado (task 002)"; exit 1; }
	scripts/verify.sh full $(ARGS)

deploy:
	@test -x deploy/deploy.sh || { echo "deploy/deploy.sh não implementado (task 003)"; exit 1; }
	SVC=$(SVC) deploy/deploy.sh

# Pacote de release em dist/ (task 070). Não cria tag nem publica: isso é do architect (checklist em
# .github/release-checklist.md). FS_RELEASE_SKIP_CHECKS=1 pula árvore limpa/main/verify-full (teste local).
release:
	@test -n "$(filter v%,$(VERSION))" || { echo "uso: make release VERSION=vX.Y.Z"; exit 2; }
	GOTOOLCHAIN=$(GO_TOOLCHAIN) scripts/release.sh $(VERSION)

# Dois builds (um em outro diretório) têm de dar o mesmo SHA-256 (task 070; rodado no CI)
repro-check:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) scripts/repro-check.sh

clean:
	rm -rf $(BIN) dist
