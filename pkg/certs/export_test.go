package certs

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWritePair(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "certs")
	crt, key := genPair(t, "x", []string{"x.example"}, time.Now().Add(time.Hour))
	if err := WritePair(dir, SlotHTTP01, crt, key); err != nil {
		t.Fatal(err)
	}
	// Reescrita por cima também é atômica e não deixa temporários.
	if err := WritePair(dir, SlotHTTP01, crt, key); err != nil {
		t.Fatal(err)
	}
	files, _ := os.ReadDir(dir)
	if len(files) != 2 {
		t.Fatalf("arquivos: %v", files)
	}
	for _, f := range []struct {
		name string
		data []byte
		mode os.FileMode
	}{{"http01.crt", crt, 0o644}, {"http01.key", key, 0o600}} {
		p := filepath.Join(dir, f.name)
		got, err := os.ReadFile(p)
		if err != nil || !bytes.Equal(got, f.data) {
			t.Fatalf("%s: %v", f.name, err)
		}
		fi, _ := os.Stat(p)
		if fi.Mode().Perm() != f.mode {
			t.Errorf("%s: modo %v, quer %v", f.name, fi.Mode().Perm(), f.mode)
		}
	}
	di, _ := os.Stat(dir)
	if di.Mode().Perm() != 0o700 {
		t.Errorf("diretório: modo %v", di.Mode().Perm())
	}
}

func TestWritePairErrors(t *testing.T) {
	for _, name := range []string{"", "../x", "a/b"} {
		if err := WritePair(t.TempDir(), name, nil, nil); err == nil {
			t.Errorf("nome %q aceito", name)
		}
	}
	// Diretório impossível (um arquivo no caminho).
	f := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WritePair(filepath.Join(f, "sub"), SlotDNS01, nil, nil); err == nil {
		t.Error("diretório inválido aceito")
	}
}
