package raw

import (
	"strings"
	"testing"
	"time"
)

func TestParsePortsDefault(t *testing.T) {
	// O padrão da spec 006 RF-01: portas, modos e banners.
	ports, err := ParsePorts(DefaultPorts)
	if err != nil {
		t.Fatal(err)
	}
	want := map[int]struct {
		mode   string
		tls    bool
		banner string
	}{
		7:   {"echo", false, GenericBanner},
		21:  {"banner", false, "220 finger-sniffer FTP ready\r\n"},
		22:  {"banner", false, "SSH-2.0-finger-sniffer\r\n"},
		25:  {"banner", false, "220 finger-sniffer ESMTP ready\r\n"},
		110: {"banner", false, "+OK finger-sniffer POP3 ready\r\n"},
		143: {"banner", false, "* OK finger-sniffer IMAP ready\r\n"},
		587: {"banner", false, "220 finger-sniffer ESMTP ready\r\n"},
		993: {"banner", true, "* OK finger-sniffer IMAP ready\r\n"},
	}
	if len(ports) != len(want) {
		t.Fatalf("got %d ports, want %d", len(ports), len(want))
	}
	for _, p := range ports {
		w, ok := want[p.Port]
		if !ok {
			t.Fatalf("unexpected port %d", p.Port)
		}
		if p.Mode != w.mode || p.TLS != w.tls || p.Banner != w.banner {
			t.Errorf("port %d = %+v, want %+v", p.Port, p, w)
		}
	}
	if ports[7].Name() != "tls-banner" || ports[0].Name() != "echo" {
		t.Errorf("Name: %q %q", ports[7].Name(), ports[0].Name())
	}
}

func TestParsePortsModes(t *testing.T) {
	ports, err := ParsePorts(" 1000:sink , 1001:source,1002:tls-echo,1003:tls-sink,1004:tls-source,0:echo,0:echo,")
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, len(ports))
	for i, p := range ports {
		got[i] = p.Name()
	}
	if s := strings.Join(got, ","); s != "sink,source,tls-echo,tls-sink,tls-source,echo,echo" {
		t.Errorf("modes = %s", s)
	}
}

func TestParsePortsErrors(t *testing.T) {
	for _, in := range []string{"", ",", "7", "x:echo", "70000:echo", "-1:echo", "7:bogus", "7:tls-bogus", "7:echo,7:sink"} {
		if _, err := ParsePorts(in); err == nil {
			t.Errorf("ParsePorts(%q) = nil error", in)
		}
	}
}

func TestLoadConfig(t *testing.T) {
	t.Setenv("FS_LISTEN_IPV4", "192.0.2.10")
	t.Setenv("FS_LISTEN_IPV6", "")
	t.Setenv("FS_RAW_PORTS", "")
	t.Setenv("FS_IDLE_DEFAULT", "")
	t.Setenv("FS_RAW_STREAM_MAX_BYTES", "")
	c, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if len(c.ListenIPs) != 1 || c.ListenIPs[0].String() != "192.0.2.10" {
		t.Errorf("ListenIPs = %v", c.ListenIPs)
	}
	if len(c.Ports) != 8 || c.Idle != DefaultIdle || c.StreamMax != DefaultStreamMax || c.SourceBytes != DefaultSourceBytes {
		t.Errorf("defaults = %+v", c)
	}

	t.Setenv("FS_RAW_PORTS", "7007:echo")
	t.Setenv("FS_IDLE_DEFAULT", "3s")
	t.Setenv("FS_RAW_STREAM_MAX_BYTES", "1024")
	c, err = LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Ports) != 1 || c.Idle != 3*time.Second || c.StreamMax != 1024 {
		t.Errorf("env = %+v", c)
	}

	for k, v := range map[string]string{
		"FS_RAW_PORTS": "bad", "FS_IDLE_DEFAULT": "-1s", "FS_RAW_STREAM_MAX_BYTES": "0",
	} {
		t.Run(k, func(t *testing.T) {
			t.Setenv(k, v)
			if _, err := LoadConfig(); err == nil {
				t.Errorf("%s=%s: nil error", k, v)
			}
		})
	}
	t.Setenv("FS_IDLE_DEFAULT", "x")
	if _, err := LoadConfig(); err == nil {
		t.Error("bad duration: nil error")
	}
	t.Setenv("FS_IDLE_DEFAULT", "")
	t.Setenv("FS_RAW_STREAM_MAX_BYTES", "x")
	if _, err := LoadConfig(); err == nil {
		t.Error("bad int: nil error")
	}
}

func TestLoadConfigListenIPs(t *testing.T) {
	// ADR 0001: o raw escuta só nos IPs públicos, nunca em todos os endereços.
	t.Setenv("FS_RAW_PORTS", "")
	t.Setenv("FS_IDLE_DEFAULT", "")
	t.Setenv("FS_RAW_STREAM_MAX_BYTES", "")
	t.Setenv("FS_LISTEN_IPV4", " 192.0.2.10 ")
	t.Setenv("FS_LISTEN_IPV6", "2001:db8::10")
	c, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if len(c.ListenIPs) != 2 || c.ListenIPs[0].String() != "192.0.2.10" || c.ListenIPs[1].String() != "2001:db8::10" {
		t.Errorf("ListenIPs = %v", c.ListenIPs)
	}
	t.Setenv("FS_LISTEN_IPV4", "")
	if c, err = LoadConfig(); err != nil || len(c.ListenIPs) != 1 || !c.ListenIPs[0].Is6() {
		t.Errorf("v6 only: %v %v", c.ListenIPs, err)
	}
	for _, tc := range []struct{ v4, v6 string }{
		{"", ""}, {"0.0.0.0", ""}, {"", "::"}, {"2001:db8::1", ""}, {"", "192.0.2.1"}, {"x", ""}, {"", "fe80::1%eth0"},
	} {
		t.Setenv("FS_LISTEN_IPV4", tc.v4)
		t.Setenv("FS_LISTEN_IPV6", tc.v6)
		if _, err := LoadConfig(); err == nil {
			t.Errorf("v4=%q v6=%q: nil error", tc.v4, tc.v6)
		}
	}
}
