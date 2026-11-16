package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestEmbeddedOpenAPI: o binário serve o contrato do próprio diretório (GET /bot/v1/openapi.yaml).
func TestEmbeddedOpenAPI(t *testing.T) {
	disk, err := os.ReadFile("openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(disk, openapiYAML) || !bytes.HasPrefix(openapiYAML, []byte("openapi: 3.1.0")) {
		t.Fatal("openapi embutido diverge do arquivo")
	}
}

// TestRunCLIExitCodes: 0 no sucesso, 2 no uso errado, 1 em erro de operação.
func TestRunCLIExitCodes(t *testing.T) {
	t.Setenv("FS_BOT_DB", filepath.Join(t.TempDir(), "bot.db"))
	if c := runCLI([]string{"key", "list"}); c != 0 {
		t.Errorf("key list: %d", c)
	}
	if c := runCLI([]string{"key", "bogus"}); c != 2 {
		t.Errorf("uso errado: %d", c)
	}
	if c := runCLI([]string{"key", "revoke", "nope"}); c != 1 {
		t.Errorf("chave inexistente: %d", c)
	}
}
