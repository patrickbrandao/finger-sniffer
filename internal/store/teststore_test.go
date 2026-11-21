package store

import (
	"context"
	"testing"

	"github.com/patrickbrandao/finger-sniffer/pkg/service"
)

// testSpaceSize e testSpaceFree são o espaço folgado dos testes que sobem um Store real: 4 GiB com 3 livres (75%),
// longe do expurgo por espaço (spaceLowPct) e do "db space <n>% free" no health.
const (
	testSpaceSize = 4 << 30
	testSpaceFree = 3 << 30
)

// newTestStore sobe um Store real para os testes. Sem Config.SpaceReader, o espaço do banco seria o statfs do
// t.TempDir(), no disco de quem roda: com menos de 10% livre o laço de retenção apaga as conexões no meio do teste
// (task 410). Por isso fixa um espaço folgado; o teste que mede o espaço de propósito passa o seu SpaceReader.
func newTestStore(ctx context.Context, t *testing.T, svc *service.Service, cfg Config) *Store {
	t.Helper()
	st, err := New(ctx, svc, withTestSpace(cfg), []byte("openapi: 3.1.0\n"))
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// withTestSpace liga o espaço folgado quando o teste não escolheu outro.
func withTestSpace(cfg Config) Config {
	if cfg.SpaceReader == nil {
		cfg.SpaceReader = newFakeSpace(testSpaceSize, testSpaceFree)
	}
	return cfg
}

// TestWithTestSpace: o helper liga o espaço folgado quando falta e respeita o SpaceReader escolhido pelo teste.
func TestWithTestSpace(t *testing.T) {
	size, free, err := withTestSpace(Config{}).SpaceReader.Space()
	if err != nil || size != testSpaceSize || free != testSpaceFree {
		t.Fatalf("default space = %d/%d (%v), want %d/%d", size, free, err, int64(testSpaceSize), int64(testSpaceFree))
	}
	own := newFakeSpace(100<<20, 5<<20)
	if got := withTestSpace(Config{SpaceReader: own}).SpaceReader; got != own {
		t.Fatalf("own SpaceReader replaced by %T", got)
	}
}
