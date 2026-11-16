//go:build load

package main

import (
	"os"
	"regexp"
	"testing"
	"time"
)

// TestRunDefaultsOfficialProfile: sem flags, o "run" gera o perfil oficial do RNF-01 (ADR 0042: 200
// simultâneas, 50 novas/s) e o relatório usa a meta QUIC de 500 ms (ADR 0026), a mesma do run.sh (task 250).
func TestRunDefaultsOfficialProfile(t *testing.T) {
	var c config
	fs, _ := runFlags(&c)
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	if c.Rate != 50 || c.MaxActive != 200 {
		t.Fatalf("padrão %d/s, %d simultâneas; o oficial é 50/s e 200", c.Rate, c.MaxActive)
	}
	if defaultQUICTarget != 500*time.Millisecond {
		t.Fatalf("meta QUIC %v", defaultQUICTarget)
	}
	sh, err := os.ReadFile("../../run.sh")
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`QUIC_TARGET="\$\{QUIC_TARGET:-500ms\}"`).Match(sh) {
		t.Fatal("run.sh: QUIC_TARGET padrão diferente de 500ms")
	}
}
