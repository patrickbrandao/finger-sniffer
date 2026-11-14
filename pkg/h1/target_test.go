package h1

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

// TestLimitTarget: corte do alvo em bytes, recuando até fronteira de runa; alvo curto fica intacto e sem
// marca; alvo que não é UTF-8 é cortado no teto exato (task 160).
func TestLimitTarget(t *testing.T) {
	cases := []struct {
		target string
		max    int
		want   string
		cut    bool
	}{
		{"/abc", 10, "/abc", false},
		{"/abc", 4, "/abc", false},
		{"/abcdef", 4, "/abc", true},
		{"/ação", 3, "/a", true}, // ç tem 2 bytes: não parte a runa
		{"/a€b", 4, "/a", true},  // € tem 3 bytes
		{"/\x80\x80\x80\x80\x80", 3, "/\x80\x80", true},
		{"/x", 0, "/x", false},
	}
	for _, c := range cases {
		r := &Request{RequestLine: RequestLine{Target: c.target}}
		r.LimitTarget(c.max)
		if r.RequestLine.Target != c.want || r.RequestLine.TargetTruncated != c.cut {
			t.Errorf("%q/%d: %q truncated=%v", c.target, c.max, r.RequestLine.Target, r.RequestLine.TargetTruncated)
		}
	}
	r := &Request{RequestLine: RequestLine{Target: "/" + strings.Repeat("é", 1000)}}
	r.LimitTarget(100)
	if !utf8.ValidString(r.RequestLine.Target) || len(r.RequestLine.Target) > 100 {
		t.Fatalf("UTF-8 %q", r.RequestLine.Target)
	}
	b, _ := json.Marshal(RequestLine{Target: "/"})
	if strings.Contains(string(b), "target_truncated") {
		t.Fatalf("marca sem corte: %s", b)
	}
}
