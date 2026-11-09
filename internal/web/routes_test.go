package web

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/patrickbrandao/finger-sniffer/pkg/h1"
)

func TestClassify(t *testing.T) {
	cases := map[string]routeKind{
		"/p/" + testProbe + "/":           routeMirror,
		"/p/" + testProbe + "/r":          routeControl,
		"/r":                              routeControl,
		"/p/" + testProbe:                 routeStatic,
		"/p/ABCDEFGH/":                    routeStatic,
		"/p/" + testProbe + "/x":          routeStatic,
		"/.well-known/acme-challenge/tok": routeACME,
		"/index.html":                     routeStatic,
		"/":                               routeStatic,
	}
	for path, want := range cases {
		if got := classify(path); got != want {
			t.Errorf("classify(%q) = %d, want %d", path, got, want)
		}
	}
}

func TestTarget(t *testing.T) {
	cases := []struct {
		rl          h1.RequestLine
		path, query string
		ok          bool
	}{
		{h1.RequestLine{Target: "/a?b=1#f", Form: h1.FormOrigin}, "/a", "b=1", true},
		{h1.RequestLine{Target: "http://h:80/p/x/?q", Form: h1.FormAbsolute}, "/p/x/", "q", true},
		{h1.RequestLine{Target: "http://h", Form: h1.FormAbsolute}, "/", "", true},
		{h1.RequestLine{Target: "http://h?x=1", Form: h1.FormAbsolute}, "/", "x=1", true},
		{h1.RequestLine{Target: "*", Form: h1.FormAsterisk}, "", "", false},
		{h1.RequestLine{Target: "h:443", Form: h1.FormAuthority}, "", "", false},
	}
	for _, c := range cases {
		p, q, ok := target(c.rl)
		if p != c.path || q != c.query || ok != c.ok {
			t.Errorf("target(%q) = %q %q %v", c.rl.Target, p, q, ok)
		}
	}
}

func TestResolve(t *testing.T) {
	cases := map[string]string{
		"/":              "index.html",
		"/index.html":    "index.html",
		"/sub/":          "sub/index.html",
		"/a%20b.txt":     "a b.txt",
		"/x//y.css":      "x/y.css",
		"/../etc/passwd": "",
		"/%2e%2e/secret": "",
		"/.git/config":   "",
		"/a/../b":        "",
		"/a\\b":          "",
		"/a%00.html":     "",
		"relative":       "",
		"/bad%zzescape":  "",
		"/sub/.env":      "",
	}
	for in, want := range cases {
		got, ok := resolve(in)
		if (want == "") == ok || got != want {
			t.Errorf("resolve(%q) = %q %v, want %q", in, got, ok, want)
		}
	}
}

// TestStatic: htdocs servido com Content-Type pela extensão, index.html em diretório, sem listagem, sem
// extensões fora da lista, sem escapar da pasta.
func TestStatic(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	writeFile(t, h.htdocs, "index.html", "<h1>root</h1>")
	writeFile(t, h.htdocs, "sub/index.html", "<h1>sub</h1>")
	writeFile(t, h.htdocs, "app.mjs", "export {}")
	writeFile(t, h.htdocs, "robots.txt", "User-agent: *")
	writeFile(t, h.htdocs, "nolist/a.txt", "a")
	writeFile(t, h.htdocs, "bin.exe", "MZ")
	writeFile(t, h.htdocs, ".hidden.html", "secret")
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("outside"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(h.htdocs, "link.txt")); err != nil {
		t.Fatal(err)
	}

	c := dial(t, h.addr80)
	cl := newClient(t, c)
	cases := []struct {
		method, path string
		status       int
		ctype, body  string
	}{
		{"GET", "/index.html", 200, "text/html; charset=utf-8", "<h1>root</h1>"},
		{"GET", "/", 200, "text/html; charset=utf-8", "<h1>root</h1>"},
		{"GET", "/sub/", 200, "text/html; charset=utf-8", "<h1>sub</h1>"},
		{"GET", "/sub", 200, "text/html; charset=utf-8", "<h1>sub</h1>"},
		{"GET", "/app.mjs", 200, "text/javascript; charset=utf-8", "export {}"},
		{"GET", "/robots.txt", 200, "text/plain; charset=utf-8", "User-agent: *"},
		{"GET", "/nolist/", 404, "", ""},
		{"GET", "/bin.exe", 404, "", ""},
		{"GET", "/.hidden.html", 404, "", ""},
		{"GET", "/../../etc/passwd", 404, "", ""},
		{"GET", "/%2e%2e/%2e%2e/etc/passwd", 404, "", ""},
		{"GET", "/link.txt", 404, "", ""},
		{"GET", "/missing.html", 404, "", ""},
		{"POST", "/index.html", 405, "", ""},
		{"GET", "/.well-known/acme-challenge/token", 404, "", ""},
	}
	for _, k := range cases {
		cl.send(k.method + " " + k.path + " HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")
		resp, body := cl.response(k.method)
		if resp.StatusCode != k.status {
			t.Errorf("%s %s: status %d", k.method, k.path, resp.StatusCode)
			continue
		}
		if k.ctype != "" && (resp.Header.Get("Content-Type") != k.ctype || body != k.body) {
			t.Errorf("%s: %q %q", k.path, resp.Header.Get("Content-Type"), body)
		}
	}
}

// TestACMEHook: o gancho do HTTP-01 responde o token conhecido (task 027 liga o ACME de verdade).
func TestACMEHook(t *testing.T) {
	h := newHarness(t, harnessOpts{deps: func(d *Deps) {
		d.ACME = func(tok string) ([]byte, bool) {
			if tok == "good" {
				return []byte("good.key-auth"), true
			}
			return nil, false
		}
	}})
	c := dial(t, h.addr80)
	cl := newClient(t, c)
	cl.send(get("/.well-known/acme-challenge/good", "vps602.tmsoft.com.br"))
	if resp, body := cl.response("GET"); resp.StatusCode != 200 || body != "good.key-auth" {
		t.Fatalf("acme %d %q", resp.StatusCode, body)
	}
	cl.send(get("/.well-known/acme-challenge/bad", "vps602.tmsoft.com.br"))
	if resp, _ := cl.response("GET"); resp.StatusCode != 404 {
		t.Fatalf("acme bad %d", resp.StatusCode)
	}
}
