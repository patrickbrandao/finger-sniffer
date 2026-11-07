package probe

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestValid(t *testing.T) {
	for s, want := range map[string]bool{
		"abcdefgh": true, "t1a2b3c4": true, "0123456789abcdefghij0123456789ab": true,
		"abcdefg": false, "0123456789abcdefghij0123456789abc": false, "ABCDEFGH": false,
		"abcd-efgh": false, "abcd_efgh": false, "": false, "abcdéfgh": false,
	} {
		if Valid(s) != want {
			t.Errorf("Valid(%q) = %v, want %v", s, !want, want)
		}
	}
}

func TestHost(t *testing.T) {
	e := NewExtractor()
	tests := []struct {
		host     string
		ok       bool
		id, zone string
		controls []string
		unknown  []string
	}{
		{"t1a2b3c4.dns-monitor.tmsoft.com.br", true, "t1a2b3c4", "dns-monitor.tmsoft.com.br", nil, nil},
		{"T1A2b3C4.DNS-Monitor.tmsoft.com.br.", true, "t1a2b3c4", "dns-monitor.tmsoft.com.br", nil, nil},
		{"t1a2b3c4.dns-monitor.tmsoft.com.br:443", true, "t1a2b3c4", "dns-monitor.tmsoft.com.br", nil, nil},
		{"t1a2b3c4.v4.noh3.dns-monitor.tmsoft.com.br", true, "t1a2b3c4", "dns-monitor.tmsoft.com.br", []string{"v4", "noh3"}, nil},
		{"t1a2b3c4.foo.nx.dns-monitor.tmsoft.com.br", true, "t1a2b3c4", "dns-monitor.tmsoft.com.br", []string{"nx"}, []string{"foo"}},
		{"abcdefgh.vps602.tmsoft.com.br", true, "abcdefgh", "vps602.tmsoft.com.br", nil, nil},
		{"dns-monitor.tmsoft.com.br", true, "", "dns-monitor.tmsoft.com.br", nil, nil},
		{"_acme-challenge.dns-monitor.tmsoft.com.br", true, "", "dns-monitor.tmsoft.com.br", nil, []string{"_acme-challenge"}},
		{"short.dns-monitor.tmsoft.com.br", true, "", "dns-monitor.tmsoft.com.br", nil, []string{"short"}},
		{"nodata.dns-monitor.tmsoft.com.br", true, "", "dns-monitor.tmsoft.com.br", []string{"nodata"}, nil},
		{"t1a2b3c4.example.com", false, "", "", nil, nil},
		{"xdns-monitor.tmsoft.com.br", false, "", "", nil, nil},
		{"172.233.24.85", false, "", "", nil, nil},
		{"[2600:3c0d::1]:443", false, "", "", nil, nil},
		{"", false, "", "", nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			info, ok := e.Host(tt.host)
			if ok != tt.ok || info.ID != tt.id || info.Zone != tt.zone ||
				!slices.Equal(info.Controls, tt.controls) || !slices.Equal(info.Unknown, tt.unknown) {
				t.Fatalf("Host(%q) = %+v, %v", tt.host, info, ok)
			}
		})
	}
}

func TestHostInfoHas(t *testing.T) {
	info, _ := NewExtractor().Host("t1a2b3c4.v6.dns-monitor.tmsoft.com.br")
	if !info.Has(ControlV6) || info.Has(ControlV4) {
		t.Fatalf("Has: %+v", info)
	}
}

func TestNewExtractorCustomZones(t *testing.T) {
	e := NewExtractor(" ", "Example.COM.", "")
	if info, ok := e.Host("abcdefgh.example.com"); !ok || info.ID != "abcdefgh" {
		t.Fatalf("custom zone: %+v %v", info, ok)
	}
	if _, ok := e.Host("abcdefgh.dns-monitor.tmsoft.com.br"); ok {
		t.Fatal("default zone must not apply when zones are given")
	}
}

func TestFromTarget(t *testing.T) {
	tests := []struct {
		target string
		id     string
		ok     bool
	}{
		{"/p/t1a2b3c4/", "t1a2b3c4", true},
		{"/p/t1a2b3c4", "t1a2b3c4", true},
		{"/p/t1a2b3c4/r?status=204", "t1a2b3c4", true},
		{"/p/t1a2b3c4?x=1", "t1a2b3c4", true},
		{"/p/t1a2b3c4#frag", "t1a2b3c4", true},
		{"http://host.example/p/t1a2b3c4/ws", "t1a2b3c4", true},
		{"https://h:8443/p/abcdefgh/", "abcdefgh", true},
		{"/p/T1A2B3C4/", "", false},
		{"/p/short/", "", false},
		{"/q/t1a2b3c4/", "", false},
		{"/", "", false},
		{"*", "", false},
		{"host:443", "", false},
		{"http://[::1", "", false},
	}
	for _, tt := range tests {
		id, ok := FromTarget(tt.target)
		if id != tt.id || ok != tt.ok {
			t.Errorf("FromTarget(%q) = %q, %v; want %q, %v", tt.target, id, ok, tt.id, tt.ok)
		}
	}
}

func TestParseLine(t *testing.T) {
	ok := []struct {
		in   string
		want Line
	}{
		{"PROBE abcdefgh\r\n", Line{ID: "abcdefgh", Terminator: "crlf"}},
		{"PROBE abcdefgh\n", Line{ID: "abcdefgh", Terminator: "lf"}},
		{"PROBE abcdefgh mode=echo\r\n", Line{ID: "abcdefgh", Mode: "echo", Terminator: "crlf"}},
		{"PROBE abcdefgh mode=source n=1000\r\n", Line{ID: "abcdefgh", Mode: "source", N: 1000, Terminator: "crlf"}},
		{"PROBE abcdefgh n=5 mode=sink\r\n", Line{ID: "abcdefgh", Mode: "sink", N: 5, Terminator: "crlf"}},
		{"PROBE abcdefgh mode=banner\r\n", Line{ID: "abcdefgh", Mode: "banner", Terminator: "crlf"}},
	}
	for _, tt := range ok {
		got, err := ParseLine([]byte(tt.in))
		if err != nil || got != tt.want {
			t.Errorf("ParseLine(%q) = %+v, %v; want %+v", tt.in, got, err, tt.want)
		}
	}

	bad := []struct {
		in  string
		err error
	}{
		{"GET / HTTP/1.1\r\n", ErrNotProbeLine},
		{"PROBE abcdefgh", ErrIncomplete},
		{"PROBE " + strings.Repeat("a", MaxLineLen) + "\r\n", ErrTooLong},
		{"PROBE ABCDEFGH\r\n", nil},
		{"PROBE abcdefgh mode=loop\r\n", nil},
		{"PROBE abcdefgh n=0\r\n", nil},
		{"PROBE abcdefgh n=x\r\n", nil},
		{"PROBE abcdefgh foo=1\r\n", nil},
		{"PROBE abcdefgh echo\r\n", nil},
		{"PROBE abcdefgh  mode=echo\r\n", nil},
	}
	for _, tt := range bad {
		_, err := ParseLine([]byte(tt.in))
		if err == nil {
			t.Errorf("ParseLine(%q): expected error", tt.in)
			continue
		}
		if tt.err != nil && !errors.Is(err, tt.err) {
			t.Errorf("ParseLine(%q) = %v, want %v", tt.in, err, tt.err)
		}
	}
}

// FuzzHost: nunca há pânico e todo ID devolvido é válido e pertence a uma zona reconhecida.
func FuzzHost(f *testing.F) {
	for _, s := range []string{"t1a2b3c4.dns-monitor.tmsoft.com.br", "a.b.v4.vps602.tmsoft.com.br:80", "[::1]:53", "..", ""} {
		f.Add(s)
	}
	e := NewExtractor()
	f.Fuzz(func(t *testing.T, host string) {
		info, ok := e.Host(host)
		if !ok {
			if info.ID != "" {
				t.Fatalf("id without zone: %+v", info)
			}
			return
		}
		if info.ID != "" && !Valid(info.ID) {
			t.Fatalf("invalid id %q from %q", info.ID, host)
		}
		if !slices.Contains(DefaultZones, info.Zone) {
			t.Fatalf("unknown zone %q", info.Zone)
		}
	})
}

// FuzzFromTarget: todo ID devolvido é válido e aparece literalmente no alvo.
func FuzzFromTarget(f *testing.F) {
	for _, s := range []string{"/p/abcdefgh/", "http://x/p/abcdefgh", "/p/", "%zz"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, target string) {
		id, ok := FromTarget(target)
		if ok && (!Valid(id) || !strings.Contains(target, id)) {
			t.Fatalf("FromTarget(%q) = %q", target, id)
		}
	})
}

// FuzzParseLine: nunca há pânico; sucesso implica ID válido e modo conhecido.
func FuzzParseLine(f *testing.F) {
	for _, s := range []string{"PROBE abcdefgh\r\n", "PROBE abcdefgh mode=source n=10\n", "PROBE \n"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		l, err := ParseLine(b)
		if err != nil {
			return
		}
		if !Valid(l.ID) || l.N < 0 {
			t.Fatalf("bad result %+v for %q", l, b)
		}
		switch l.Mode {
		case "", ModeEcho, ModeBanner, ModeSink, ModeSource:
		default:
			t.Fatalf("bad mode %q", l.Mode)
		}
	})
}
