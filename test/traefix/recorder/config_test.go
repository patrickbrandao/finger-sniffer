package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestTraefixTestConfig confere os arquivos do ambiente de teste (task 406): nenhuma chave versionada, os
// marcadores que o up.sh troca, o perfil da spec 019 RF-03 em fstest e o marcador da ADR 0074 no forwardAuth.
func TestTraefixTestConfig(t *testing.T) {
	read := func(p string) string {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	static, dynamic := read("../static.yml"), read("../dynamic.yml")
	key := regexp.MustCompile(`fsk_[A-Za-z0-9]`)
	for name, s := range map[string]string{"static.yml": static, "dynamic.yml": dynamic, "up.sh": read("../up.sh")} {
		if key.MatchString(s) {
			t.Errorf("%s tem algo com cara de chave do bot (fsk_…): nenhuma chave é versionada", name)
		}
	}
	for _, m := range []string{
		"Bearer __FS_BLOCK_KEY__", "Bearer __FS_REVOKED_KEY__", "denyRequiresResponseHeader: X-Traefix-Deny",
		"address: http://10.249.255.254:9003/bot/v1/auth", "timeout: 200ms", "maxIdleConnsPerHost: -1",
	} {
		if !strings.Contains(dynamic, m) {
			t.Errorf("dynamic.yml sem %q", m)
		}
	}
	if strings.Count(dynamic, "denyRequiresResponseHeader: X-Traefix-Deny") != 3 {
		t.Error("dynamic.yml: os três forwardAuth precisam do marcador X-Traefix-Deny (ADR 0074)")
	}
	// perfil da spec 019 RF-03 na entrada fstest (até a próxima entrada)
	_, rest, ok := strings.Cut(static, "\n  fstest:\n")
	if !ok {
		t.Fatal("static.yml sem a entrada fstest")
	}
	fstest, _, _ := strings.Cut(rest, "\n  fsnoraw:")
	for _, m := range []string{
		`address: ":18443"`, "http3: {}", "tcp: true", "headerDetail: full", "rawBytes: true",
		"url: http://127.0.0.1:18090/bot/v1/ingest/traefik",
	} {
		if !strings.Contains(fstest, m) {
			t.Errorf("fstest sem %q (spec 019 RF-03)", m)
		}
	}
	for _, m := range []string{"http3HeaderOrder", "headerPrefix", "allowSensitiveFields", "proxyProtocol"} {
		if strings.Contains(fstest, m) {
			t.Errorf("fstest com %q, fora do perfil da spec 019 RF-03", m)
		}
	}
	for _, ep := range []string{"fsnoraw:", "fsh3o:", "fsplain:", "fsmetrics:", `"127.0.0.1:18082"`} {
		if !strings.Contains(static, ep) {
			t.Errorf("static.yml sem %s", ep)
		}
	}
}
