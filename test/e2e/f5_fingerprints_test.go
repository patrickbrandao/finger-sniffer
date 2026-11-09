//go:build e2e

package e2e

// Conferência consolidada da F5 (task 067, item 2 de sucesso da spec 000): as impressões de curl, Go, Chrome e
// Firefox no registro do espelho conferidas campo a campo com as ferramentas de referência aplicadas ao mesmo
// pcap, o devolvido por GET /api/v1/connections/{id}/pcap:
//   - TCP (h2 e h1): JA3 e JA3 MD5 (tshark), JA3N (tshark ja3_full com as extensões ordenadas), JA4 e JA4_r
//     (ja4 da FoxIO e tshark), JA4_o (ja4 -O), JA4T (ja4), p0f (p0f -r), Akamai h2 (tshark com o keylog do
//     cliente, técnica do fingerproxy no ref.py do golden da task 036) e JA4H (ja4 com o keylog);
//   - QUIC (h3): JA4 q, JA4_r q e JA4_o q (ja4 e tshark).
// O tshark e o ja4 rodam na vps602 (as mesmas versões dos golden). Os navegadores rodam headless com o sandbox
// ligado. A tabela consolidada vai para testdata/fingerprints-f5.md com FS_E2E_UPDATE=1 (sempre sai no log).
//
// Divergências da ferramenta aceitas, com o valor do ja4 como referência:
//   - tshark 4.4 mantém o GREASE dos algoritmos de assinatura no JA4_r (Chrome) e erra a parte c do JA4
//     (task 036);
//   - ja4 0.18.6 não emite JA4H quando o curl com OpenSSL manda prefácio, SETTINGS, WINDOW_UPDATE e HEADERS no
//     mesmo registro TLS (task 036).

import (
	"context"
	"crypto/md5" //nolint:gosec // JA3 é MD5 por definição
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------- registro

// f5TLS são as impressões do ClientHello no registro (TLSInfo do openapi).
type f5TLS struct {
	JA3     string `json:"ja3"`
	JA3MD5  string `json:"ja3_md5"`
	JA3N    string `json:"ja3n"`
	JA3NMD5 string `json:"ja3n_md5"`
	JA4     string `json:"ja4"`
	JA4R    string `json:"ja4_r"`
	JA4O    string `json:"ja4_o"`
}

// f5Conn é o registro completo da conexão, só com o que esta conferência usa.
type f5Conn struct {
	ConnID string   `json:"conn_id"`
	Proto  string   `json:"proto"`
	L4     string   `json:"l4"`
	Dst    endpoint `json:"dst"`
	Ended  *string  `json:"ended"`
	TCP    *struct {
		JA4T *string `json:"ja4t"`
		P0F  *string `json:"p0f"`
	} `json:"tcp"`
	TLS  *f5TLS `json:"tls"`
	HTTP []struct {
		JA4H *string `json:"ja4h"`
	} `json:"http"`
	HTTP2 *struct {
		Akamai  string `json:"akamai"`
		Streams []struct {
			JA4H *string `json:"ja4h"`
		} `json:"streams"`
	} `json:"http2"`
	HTTP3 *struct {
		ClientHello *f5TLS `json:"client_hello"`
		Requests    []struct {
			JA4H *string `json:"ja4h"`
		} `json:"requests"`
	} `json:"http3"`
}

// ---------------------------------------------------------------- referência

// f5Ref é o que tshark, ja4 e p0f dizem sobre o pcap de uma conexão.
type f5Ref struct {
	// tshark (primeiro ClientHello do pcap)
	TsharkJA3Full, TsharkJA3, TsharkJA4, TsharkJA4R string
	// ja4 da FoxIO (-r e -r -O)
	ToolJA4, ToolJA4R, ToolJA4O, ToolJA4T string
	ToolJA4H                              []string
	// p0f -r (assinatura crua do SYN)
	P0F string
	// Akamai montado com os campos h2 do tshark (ref.py da task 036)
	Akamai *string
}

// ja4Line é uma linha de ja4 -j (um fluxo).
type ja4Line struct {
	Transport string `json:"transport"`
	JA4       string `json:"ja4"`
	JA4R      string `json:"ja4_r"`
	JA4O      string `json:"ja4_o"`
	JA4T      string `json:"ja4t"`
	HTTP      []struct {
		JA4H string `json:"ja4h"`
	} `json:"http"`
}

const ja4Bin = "/root/ja4-rust/target/release/ja4"

// f5Analyze manda o pcap da conexão e o keylog do cliente para a vps602 e roda tshark, ja4 (-r e -r -O), p0f -r
// e, em TCP, o ref.py do golden TLS (Akamai). Uma saída por seção, separadas por marcadores.
func f5Analyze(t *testing.T, connID string, port int, quic bool, keylog []byte) f5Ref {
	t.Helper()
	pcap := pcapOf(t, connID)
	dir := "/tmp/fs-e2e-f5/" + connID
	t.Cleanup(func() { remote(t, "rm -rf "+dir+"; rmdir /tmp/fs-e2e-f5 2>/dev/null; true") })
	remoteIn(t, "mkdir -p "+dir+" && cat > "+dir+"/c.pcap", pcap)
	remoteIn(t, "cat > "+dir+"/c.keys", keylog)
	script := "cd " + dir + " && " +
		"{ " + ja4Bin + " -j -r --keylog-file c.keys c.pcap 2>/dev/null | grep '^{' > c.ja4.jsonl || true; } && " +
		"{ " + ja4Bin + " -j -r -O --keylog-file c.keys c.pcap 2>/dev/null | grep '^{' > o.jsonl || true; } && " +
		"echo '=====ja4' && cat c.ja4.jsonl && echo '=====ja4o' && cat o.jsonl && echo '=====tshark' && " +
		"tshark -r c.pcap -o tls.keylog_file:c.keys -Y 'tls.handshake.type == 1' -T fields -E separator=/t " +
		"-e tls.handshake.ja3_full -e tls.handshake.ja3 -e tls.handshake.ja4 -e tls.handshake.ja4_r 2>/dev/null | head -1"
	if !quic {
		py, err := refPy()
		if err != nil {
			t.Fatal(err)
		}
		py = []byte(strings.Replace(string(py), `SERVER_PORT = "7702"`, fmt.Sprintf(`SERVER_PORT = "%d"`, port), 1))
		remoteIn(t, "cat > "+dir+"/ref.py", py)
		script += " && echo '=====p0f' && { rm -f p.log; p0f -r c.pcap -o p.log >/dev/null 2>&1; " +
			"grep ' mod=syn|' p.log | head -1 || true; } && echo '=====ref' && " +
			"tshark -r c.pcap -o tls.keylog_file:c.keys -T json --no-duplicate-keys -J 'tcp tls http2 http' " +
			"-Y 'tls.handshake.type == 1 || http2 || http' > c.tshark.json 2>/dev/null && python3 ref.py c >/dev/null && cat c.ref.json"
	}
	out := remote(t, script)
	sec := map[string]string{}
	for part := range strings.SplitSeq(out, "=====") {
		name, body, _ := strings.Cut(part, "\n")
		sec[strings.TrimSpace(name)] = strings.TrimSpace(body)
	}
	var ref f5Ref
	for _, l := range firstJA4(t, sec["ja4"], quic) {
		ref.ToolJA4, ref.ToolJA4R, ref.ToolJA4T = l.JA4, l.JA4R, l.JA4T
		for _, h := range l.HTTP {
			if h.JA4H != "" {
				ref.ToolJA4H = append(ref.ToolJA4H, h.JA4H)
			}
		}
	}
	for _, l := range firstJA4(t, sec["ja4o"], quic) {
		ref.ToolJA4O = l.JA4O
	}
	if f := strings.Split(sec["tshark"], "\t"); len(f) == 4 {
		ref.TsharkJA3Full, ref.TsharkJA3, ref.TsharkJA4, ref.TsharkJA4R = f[0], f[1], f[2], f[3]
	} else {
		t.Errorf("%s: saída do tshark inesperada: %q", connID, sec["tshark"])
	}
	if !quic {
		for kv := range strings.SplitSeq(sec["p0f"], "|") {
			if v, ok := strings.CutPrefix(kv, "raw_sig="); ok {
				ref.P0F = v
			}
		}
		var r struct {
			Akamai *string `json:"akamai"`
		}
		if err := json.Unmarshal([]byte(sec["ref"]), &r); err != nil {
			t.Fatalf("%s: ref.json: %v\n%.1500s", connID, err, sec["ref"])
		}
		ref.Akamai = r.Akamai
	}
	return ref
}

// firstJA4 devolve o primeiro fluxo do ja4 com ClientHello (TCP: prefixo t; QUIC: q).
func firstJA4(t *testing.T, jsonl string, quic bool) []ja4Line {
	t.Helper()
	want := "t"
	if quic {
		want = "q"
	}
	for l := range strings.Lines(jsonl) {
		var j ja4Line
		if err := json.Unmarshal([]byte(l), &j); err != nil {
			t.Errorf("ja4: %v: %q", err, l)
			continue
		}
		if strings.HasPrefix(j.JA4, want) || strings.HasPrefix(j.JA4O, want) {
			return []ja4Line{j}
		}
	}
	return nil
}

// ja3n deriva o JA3N (spec 008 RF-03: extensões em ordem numérica) do ja3_full do tshark.
func ja3n(full string) (string, string) {
	f := strings.Split(full, ",")
	if len(f) != 5 {
		return "", ""
	}
	if f[2] != "" {
		ext := strings.Split(f[2], "-")
		sort.Slice(ext, func(i, j int) bool {
			a, _ := strconv.Atoi(ext[i])
			b, _ := strconv.Atoi(ext[j])
			return a < b
		})
		f[2] = strings.Join(ext, "-")
	}
	s := strings.Join(f, ",")
	sum := md5.Sum([]byte(s)) //nolint:gosec // JA3 é MD5 por definição
	return s, hex.EncodeToString(sum[:])
}

// sigAlgGREASE diz se o JA4_r tem GREASE (0x?a?a) nos algoritmos de assinatura (a terceira seção).
var greaseSig = regexp.MustCompile(`^[0-9a-f]a[0-9a-f]a$`)

func sigAlgGREASE(ja4r string) bool {
	p := strings.Split(ja4r, "_")
	if len(p) < 4 {
		return false
	}
	for v := range strings.SplitSeq(p[3], ",") {
		if greaseSig.MatchString(v) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- tabela

// f5Row é uma linha da tabela consolidada.
type f5Row struct {
	order  int
	client string
	fp     string
	rec    string
	foxio  string // "—" quando a ferramenta não calcula a impressão
	tshark string
	result string
	bad    bool
}

type f5Table struct {
	mu   sync.Mutex
	rows []f5Row
	conn map[string]int // conexões conferidas por cliente
}

func (tb *f5Table) add(r f5Row) {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	tb.rows = append(tb.rows, r)
}

const dash = "—"

// cmp monta o resultado de uma linha: o registro tem de ser igual a cada referência presente (≠ "—").
func cmp(rec, foxio, tshark string) (string, bool) {
	if rec == "" {
		return "DIVERGE: ausente no registro", true
	}
	var bad []string
	if foxio != dash && rec != foxio {
		bad = append(bad, "ja4")
	}
	if tshark != dash && rec != tshark {
		bad = append(bad, "tshark")
	}
	if len(bad) > 0 {
		return "DIVERGE (" + strings.Join(bad, ", ") + ")", true
	}
	return "igual", false
}

func code(s string) string {
	if s == "" || s == dash {
		return dash
	}
	return "`" + strings.ReplaceAll(s, "|", `\|`) + "`"
}

// ---------------------------------------------------------------- clientes

// f5Client é um cliente da conferência: run faz uma sondagem a url gravando as chaves TLS em keylog.
type f5Client struct {
	order int
	name  string
	quic  bool
	h2    bool
	keys  bool
	needs string
	run   func(ctx context.Context, url, keylog string) error
}

// chromeArgsRun roda o Chrome headless (sandbox ligado) com --dump-dom e o keylog.
func chromeArgsRun(extra ...string) func(ctx context.Context, url, keylog string) error {
	return func(ctx context.Context, url, keylog string) error {
		dir, err := os.MkdirTemp("", "fs-e2e-chrome-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(dir) //nolint:errcheck // perfil descartável
		args := append([]string{
			"--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
			"--user-data-dir=" + dir, "--ssl-key-log-file=" + keylog,
		}, extra...)
		out, err := exec.CommandContext(ctx, chromeBin, append(args, "--dump-dom", url)...).Output() //nolint:gosec // navegador local
		if err != nil {
			return err
		}
		if !strings.Contains(string(out), "conn_id: ") {
			return fmt.Errorf("chrome: página sem conn_id: %.300s", out)
		}
		return nil
	}
}

// chromeH3Run força QUIC para o host do probe (--origin-to-force-quic-on não mexe no sandbox nem na
// verificação do certificado).
func chromeH3Run(ctx context.Context, url, keylog string) error {
	host := strings.TrimPrefix(url, "https://")
	host, _, _ = strings.Cut(host, "/")
	return chromeArgsRun("--origin-to-force-quic-on="+host+":443")(ctx, url, keylog)
}

// firefoxPrefsRun roda o Firefox headless (sandbox ligado) com --screenshot num perfil descartável com as
// preferências dadas e SSLKEYLOGFILE. A rede roda no processo pai mesmo quando os processos de conteúdo não
// sobem (task 036).
func firefoxPrefsRun(prefs func(host string) []string) func(ctx context.Context, url, keylog string) error {
	return func(ctx context.Context, url, keylog string) error {
		dir, err := os.MkdirTemp("", "fs-e2e-firefox-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(dir) //nolint:errcheck // perfil descartável
		host := strings.TrimPrefix(url, "https://")
		host, _, _ = strings.Cut(host, "/")
		js := []string{`user_pref("network.dns.disableIPv6", true);`}
		for _, p := range prefs(host) {
			js = append(js, "user_pref("+p+");")
		}
		if err := os.WriteFile(filepath.Join(dir, "user.js"), []byte(strings.Join(js, "\n")+"\n"), 0o600); err != nil {
			return err
		}
		shot := filepath.Join(dir, "s.png")
		cmd := exec.CommandContext(ctx, firefoxBin, "--headless", "--no-remote", "--profile", dir, "--screenshot", shot, url) //nolint:gosec // navegador local
		cmd.Env = append(os.Environ(), "SSLKEYLOGFILE="+keylog)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("%w: %.500s", err, out)
		}
		return nil
	}
}

func ffTCP(h2 bool) func(string) []string {
	return func(string) []string {
		p := []string{`"network.http.http3.enable", false`}
		if !h2 {
			p = append(p, `"network.http.http2.enabled", false`)
		}
		return p
	}
}

func ffH3(host string) []string {
	return []string{
		`"network.http.http3.enable", true`,
		`"network.http.http3.alt-svc-mapping-for-testing", "` + host + `;h3=:443"`,
	}
}

func f5Clients() []f5Client {
	cs := []f5Client{
		{order: 10, name: "curl-openssl h2", h2: true, keys: true, needs: curlOpenSSL, run: curlRun(curlOpenSSL, "--http2")},
		{order: 11, name: "curl-openssl h1", keys: true, needs: curlOpenSSL, run: curlRun(curlOpenSSL, "--http1.1")},
		{order: 12, name: "curl-libressl h2", h2: true, needs: curlLibreSSL, run: curlRun(curlLibreSSL, "--http2")},
		{order: 20, name: "go h2", h2: true, keys: true, run: goRun(true)},
		{order: 21, name: "go h1", keys: true, run: goRun(false)},
		{order: 30, name: "chrome h2", h2: true, keys: true, needs: chromeBin, run: chromeArgsRun("--disable-quic")},
		{order: 31, name: "chrome h1", keys: true, needs: chromeBin, run: chromeArgsRun("--disable-quic", "--disable-http2")},
		{order: 40, name: "firefox h2", h2: true, keys: true, needs: firefoxBin, run: firefoxPrefsRun(ffTCP(true))},
		{order: 41, name: "firefox h1", keys: true, needs: firefoxBin, run: firefoxPrefsRun(ffTCP(false))},
		{order: 60, name: "quic-go h3", quic: true, keys: true, run: goH3Run},
		{order: 70, name: "chrome h3", quic: true, keys: true, needs: chromeBin, run: chromeH3Run},
		{order: 80, name: "firefox h3", quic: true, keys: true, needs: firefoxBin, run: firefoxPrefsRun(ffH3)},
	}
	if c := curlHTTP3(); c != "" {
		cs = append(cs, f5Client{order: 50, name: "curl h3", quic: true, keys: true, run: curlH3Run(c)})
	}
	return cs
}

// ---------------------------------------------------------------- teste

// TestF5Fingerprints: impressões do registro × ja4 da FoxIO × tshark (e p0f -r) sobre o pcap de cada conexão.
func TestF5Fingerprints(t *testing.T) {
	tb := &f5Table{conn: map[string]int{}}
	t.Cleanup(func() { writeF5Table(t, tb) })
	for _, cl := range f5Clients() {
		t.Run(strings.ReplaceAll(cl.name, " ", "-"), func(t *testing.T) {
			t.Parallel()
			if cl.needs != "" {
				if _, err := os.Stat(cl.needs); err != nil {
					t.Skipf("%s não está instalado nesta máquina", cl.needs)
				}
			}
			id := newID(t)
			url := "https://" + probeHost(id) + "/p/" + id + "/"
			keylog := filepath.Join(t.TempDir(), "keys")
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			if err := cl.run(ctx, url, keylog); err != nil {
				t.Fatalf("%s: %v", cl.name, err)
			}
			keys, _ := os.ReadFile(keylog) //nolint:gosec // temporário do teste
			if cl.keys && len(keys) == 0 {
				t.Fatalf("%s não gravou o keylog", cl.name)
			}
			if cl.quic {
				c := waitF5QUIC(t, id)
				checkF5QUIC(t, tb, cl, c, f5Analyze(t, c.ConnID, 443, true, keys))
				return
			}
			p := waitProbe(t, id, func(p *probeResp) bool {
				for _, c := range p.conns(443) {
					if c.TLS != nil && len(c.HTTP)+h2Streams(c) > 0 {
						return true
					}
				}
				return false
			})
			main := true // a primeira conexão com dados de aplicação vai para a tabela; as demais só conferidas
			for _, pc := range p.conns(443) {
				if pc.TLS == nil {
					continue
				}
				var c f5Conn
				addLive("connection-example.json", get(t, "/connections/"+pc.ConnID, &c))
				withData := len(c.HTTP) > 0 || (c.HTTP2 != nil && len(c.HTTP2.Streams) > 0)
				checkF5TCP(t, tb, cl, c, f5Analyze(t, c.ConnID, 443, false, keys), main && withData)
				if withData {
					main = false
				}
			}
		})
	}
}

// waitF5QUIC espera a conexão quic/h3 do probe com o ClientHello e uma requisição. Não exige o fim: o Firefox
// só fecha por ociosidade; o pcap do Initial já está completo.
func waitF5QUIC(t *testing.T, id string) f5Conn {
	t.Helper()
	var seen []string
	for deadline := time.Now().Add(45 * time.Second); time.Now().Before(deadline); time.Sleep(500 * time.Millisecond) {
		p := probeNow(t, id)
		seen = seen[:0]
		for _, x := range p.Connections {
			seen = append(seen, fmt.Sprintf("%s:%d/%s", x.Proto, x.Dst.Port, x.L4))
		}
		for _, x := range p.Connections {
			if x.Proto == "quic/h3" && x.HTTP3 != nil && x.HTTP3.ClientHello != nil && len(x.HTTP3.Requests) > 0 {
				time.Sleep(1500 * time.Millisecond) // pacotes em voo chegam ao pcap
				var c f5Conn
				addLive("connection-example.json", get(t, "/connections/"+x.ConnID, &c))
				return c
			}
		}
	}
	t.Fatalf("probe %s: nenhuma conexão quic/h3 com ClientHello e requisição em 45 s (conexões: %v)", id, seen)
	return f5Conn{}
}

// checkF5TCP confere uma conexão TLS sobre TCP; table diz se ela entra na tabela (a principal do cliente).
func checkF5TCP(t *testing.T, tb *f5Table, cl f5Client, c f5Conn, ref f5Ref, table bool) {
	t.Helper()
	var rows []f5Row
	row := func(fp, rec, foxio, tshark string) *f5Row {
		res, bad := cmp(rec, foxio, tshark)
		rows = append(rows, f5Row{order: cl.order, client: cl.name, fp: fp, rec: rec, foxio: foxio, tshark: tshark, result: res, bad: bad})
		return &rows[len(rows)-1]
	}
	tl := c.TLS
	n, nmd5 := ja3n(ref.TsharkJA3Full)
	row("JA3", tl.JA3, dash, ref.TsharkJA3Full)
	row("JA3 MD5", tl.JA3MD5, dash, ref.TsharkJA3)
	row("JA3N", tl.JA3N, dash, n).result += " (tshark: ja3_full com extensões ordenadas)"
	row("JA3N MD5", tl.JA3NMD5, dash, nmd5)
	tsharkTolerant(row("JA4", tl.JA4, ref.ToolJA4, ref.TsharkJA4), tl.JA4R, ref.TsharkJA4R)
	tsharkTolerant(row("JA4_r", tl.JA4R, ref.ToolJA4R, ref.TsharkJA4R), tl.JA4R, ref.TsharkJA4R)
	row("JA4_o", tl.JA4O, ref.ToolJA4O, dash)
	var ja4t, p0f string
	if c.TCP != nil {
		ja4t, p0f = deref(c.TCP.JA4T), deref(c.TCP.P0F)
	}
	row("JA4T", ja4t, ref.ToolJA4T, dash)
	r := row("p0f", p0f, dash, dash)
	if !r.bad && p0f != ref.P0F {
		r.result, r.bad = "DIVERGE (p0f -r: `"+ref.P0F+"`)", true
	} else if !r.bad {
		r.result = "igual ao `p0f -r`"
	}
	if cl.h2 && c.HTTP2 != nil && len(c.HTTP2.Streams) > 0 {
		if !cl.keys {
			rows = append(rows, f5Row{
				order: cl.order, client: cl.name, fp: "Akamai", rec: c.HTTP2.Akamai, foxio: dash, tshark: dash,
				result: "sem referência: cliente sem SSLKEYLOGFILE",
			})
		} else {
			row("Akamai", c.HTTP2.Akamai, dash, deref(ref.Akamai))
		}
		var recH []string
		for _, s := range c.HTTP2.Streams {
			recH = append(recH, deref(s.JA4H))
		}
		ja4hRow(&rows, cl, "JA4H (h2)", recH, ref.ToolJA4H)
	}
	if !cl.h2 && len(c.HTTP) > 0 {
		var recH []string
		for _, h := range c.HTTP {
			recH = append(recH, deref(h.JA4H))
		}
		ja4hRow(&rows, cl, "JA4H (h1)", recH, ref.ToolJA4H)
	}
	for _, r := range rows {
		if r.bad {
			t.Errorf("%s %s %s: registro %s, ja4 %s, tshark %s: %s", cl.name, c.ConnID, r.fp, r.rec, r.foxio, r.tshark, r.result)
		}
	}
	t.Logf("%s %s: %d impressões conferidas (ja4=%s ja4t=%s)", cl.name, c.ConnID, len(rows), tl.JA4, ja4t)
	tb.mu.Lock()
	tb.conn[cl.name]++
	tb.mu.Unlock()
	if table {
		for _, r := range rows {
			tb.add(r)
		}
	}
}

// tsharkTolerant aceita a divergência conhecida do tshark 4.4 (GREASE nos algoritmos de assinatura): o
// registro bate com o ja4, e o JA4_r do tshark só difere do registro pelo GREASE nessa seção.
func tsharkTolerant(r *f5Row, recJA4R, tsharkJA4R string) {
	if !r.bad || r.rec != r.foxio || !sigAlgGREASE(tsharkJA4R) {
		return
	}
	strip := func(s string) string {
		p := strings.Split(s, "_")
		if len(p) < 4 {
			return s
		}
		var sig []string
		for v := range strings.SplitSeq(p[3], ",") {
			if !greaseSig.MatchString(v) {
				sig = append(sig, v)
			}
		}
		p[3] = strings.Join(sig, ",")
		return strings.Join(p, "_")
	}
	if strip(tsharkJA4R) == recJA4R {
		r.result, r.bad = "igual ao ja4; tshark diverge: mantém GREASE nos algoritmos de assinatura (limitação do tshark 4.4, task 036)", false
	}
}

// ja4hRow confere o JA4H de cada requisição da conexão com os do ja4, na ordem.
func ja4hRow(rows *[]f5Row, cl f5Client, fp string, rec, tool []string) {
	r := f5Row{order: cl.order, client: cl.name, fp: fp, rec: strings.Join(rec, " "), foxio: strings.Join(tool, " "), tshark: dash}
	switch {
	case !cl.keys:
		r.foxio, r.result = dash, "sem referência: cliente sem SSLKEYLOGFILE"
	case len(tool) == 0 && cl.name == "curl-openssl h2":
		// task 036: prefácio, SETTINGS, WINDOW_UPDATE e HEADERS no mesmo registro TLS; o ja4 não acha o HEADERS
		r.foxio, r.result = dash, "ja4 não emite (limitação do ja4 0.18.6 com prefácio e HEADERS no mesmo registro TLS, task 036)"
	case slices.Equal(rec, tool[:min(len(tool), len(rec))]) && len(tool) >= len(rec):
		r.result = "igual"
		if len(rec) > 1 {
			r.result = fmt.Sprintf("igual (%d requisições)", len(rec))
		}
	default:
		r.result, r.bad = "DIVERGE (ja4)", true
	}
	*rows = append(*rows, r)
}

// checkF5QUIC confere o JA4 q (e JA4_r/JA4_o) do ClientHello do Initial.
func checkF5QUIC(t *testing.T, tb *f5Table, cl f5Client, c f5Conn, ref f5Ref) {
	t.Helper()
	if c.Proto != "quic/h3" || c.HTTP3 == nil || c.HTTP3.ClientHello == nil {
		t.Fatalf("%s: proto=%s sem http3.client_hello", c.ConnID, c.Proto)
	}
	ch := c.HTTP3.ClientHello
	var rows []f5Row
	row := func(fp, rec, foxio, tshark string) *f5Row {
		res, bad := cmp(rec, foxio, tshark)
		rows = append(rows, f5Row{order: cl.order, client: cl.name, fp: fp, rec: rec, foxio: foxio, tshark: tshark, result: res, bad: bad})
		return &rows[len(rows)-1]
	}
	tsharkTolerant(row("JA4 q", ch.JA4, ref.ToolJA4, ref.TsharkJA4), ch.JA4R, ref.TsharkJA4R)
	tsharkTolerant(row("JA4_r q", ch.JA4R, ref.ToolJA4R, ref.TsharkJA4R), ch.JA4R, ref.TsharkJA4R)
	row("JA4_o q", ch.JA4O, ref.ToolJA4O, dash)
	if !strings.HasPrefix(ch.JA4, "q") {
		t.Errorf("%s: JA4 sem prefixo q: %s", c.ConnID, ch.JA4)
	}
	if len(c.HTTP3.Requests) > 0 {
		// o ja4 não decifra o h3: o JA4H h3 fica registrado sem referência externa
		rows = append(rows, f5Row{
			order: cl.order, client: cl.name, fp: "JA4H (h3)", rec: deref(c.HTTP3.Requests[0].JA4H),
			foxio: dash, tshark: dash, result: "sem referência: ja4 0.18.6 e tshark 4.4 não calculam JA4H em h3",
		})
	}
	for _, r := range rows {
		if r.bad {
			t.Errorf("%s %s %s: registro %s, ja4 %s, tshark %s: %s", cl.name, c.ConnID, r.fp, r.rec, r.foxio, r.tshark, r.result)
		}
	}
	t.Logf("%s %s: JA4 %s", cl.name, c.ConnID, ch.JA4)
	tb.mu.Lock()
	tb.conn[cl.name]++
	tb.mu.Unlock()
	for _, r := range rows {
		tb.add(r)
	}
}

// ---------------------------------------------------------------- relatório

func cmdLine(name string, args ...string) string {
	out, err := exec.Command(name, args...).CombinedOutput() //nolint:gosec // ferramentas locais
	if err != nil {
		return dash
	}
	l, _, _ := strings.Cut(strings.TrimSpace(string(out)), "\n")
	return strings.TrimSpace(l)
}

// writeF5Table monta a tabela consolidada; com FS_E2E_UPDATE=1 grava em testdata/fingerprints-f5.md.
func writeF5Table(t *testing.T, tb *f5Table) {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	if len(tb.rows) == 0 {
		return
	}
	sort.SliceStable(tb.rows, func(i, j int) bool { return tb.rows[i].order < tb.rows[j].order })
	var health struct {
		Services map[string]struct {
			Commit string `json:"commit"`
		} `json:"services"`
	}
	get(t, "/health", &health)
	commits := map[string]bool{}
	for _, s := range health.Services {
		commits[s.Commit] = true
	}
	var cs []string
	for c := range commits {
		cs = append(cs, c)
	}
	sort.Strings(cs)
	h3curl := "sem curl HTTP/3"
	if c := curlHTTP3(); c != "" {
		h3curl = "HTTP/3 pelo " + c
	}
	tools := remote(t, "tshark --version 2>/dev/null | head -1; "+ja4Bin+" -V; dpkg -s p0f | sed -n 's/^Version: /p0f /p'")

	var b strings.Builder
	b.WriteString("# Conferência FoxIO/tshark consolidada (task 067)\n\n")
	b.WriteString("Gerado por `TestF5Fingerprints` (`test/e2e/f5_fingerprints_test.go`) com `FS_E2E_UPDATE=1`. Cada impressão\n")
	b.WriteString("do registro (`GET /api/v1/connections/{id}`) é comparada com o `ja4` da FoxIO e o `tshark` aplicados ao **mesmo\n")
	b.WriteString("pcap**, o de `GET /api/v1/connections/{id}/pcap`, com o keylog do próprio cliente. `—` = a ferramenta não\n")
	b.WriteString("calcula essa impressão. JA4T e p0f vêm do SYN; o p0f é conferido com `p0f -r` sobre o mesmo pcap.\n\n")
	fmt.Fprintf(&b, "- Data: %s; serviços na vps602 no commit %s.\n", time.Now().UTC().Format("2006-01-02 15:04Z"), strings.Join(cs, ", "))
	fmt.Fprintf(&b, "- Ferramentas na vps602: %s.\n", strings.ReplaceAll(strings.ReplaceAll(tools, ".\n", "\n"), "\n", "; "))
	fmt.Fprintf(&b, "- Clientes (macOS %s): %s; %s; %s; Go %s (net/http e quic-go); %s; %s.\n",
		cmdLine("sw_vers", "-productVersion"), cmdLine(curlOpenSSL, "-V"), cmdLine(curlLibreSSL, "-V"),
		h3curl,
		strings.TrimPrefix(runtime.Version(), "go"), cmdLine(chromeBin, "--version"), cmdLine(firefoxBin, "--version"))
	b.WriteString("- Chrome e Firefox headless com o sandbox ligado. h3: Chrome com `--origin-to-force-quic-on=<host>:443`,\n")
	b.WriteString("  Firefox com `network.http.http3.alt-svc-mapping-for-testing` no perfil descartável; TCP: QUIC desligado.\n")
	b.WriteString("- `curl-libressl` (curl do macOS) não grava SSLKEYLOGFILE: Akamai e JA4H sem referência; os demais campos\n")
	b.WriteString("  conferidos. A tabela mostra a primeira conexão com dados de cada cliente; as demais (preconnect do Chrome)\n")
	b.WriteString("  foram conferidas do mesmo jeito.\n\n")

	// resumo: cliente × impressão
	cols := []string{"JA3", "JA3N", "JA4", "JA4_r", "JA4_o", "JA4T", "p0f", "Akamai", "JA4H", "JA4 q"}
	colOf := func(fp string) string {
		fp = strings.TrimSuffix(fp, " MD5")
		switch {
		case strings.HasPrefix(fp, "JA4H"):
			return "JA4H"
		case strings.HasSuffix(fp, " q"):
			return "JA4 q"
		}
		return fp
	}
	summary := map[string]map[string]string{}
	var order []string
	for _, r := range tb.rows {
		m := summary[r.client]
		if m == nil {
			m = map[string]string{}
			summary[r.client] = m
			order = append(order, r.client)
		}
		cell := "igual"
		switch {
		case r.bad:
			cell = "**DIVERGE**"
		case strings.HasPrefix(r.result, "sem referência"):
			cell = "sem ref."
		case strings.Contains(r.result, "diverge") || strings.Contains(r.result, "limitação"):
			cell = "igual¹"
		}
		col := colOf(r.fp)
		if prev := m[col]; prev == "**DIVERGE**" || prev == "igual¹" && cell == "igual" {
			continue
		}
		m[col] = cell
	}
	b.WriteString("## Resumo\n\n| Cliente | " + strings.Join(cols, " | ") + " |\n|" + strings.Repeat(" --- |", len(cols)+1) + "\n")
	for _, c := range order {
		cells := make([]string, len(cols))
		for i, col := range cols {
			cells[i] = summary[c][col]
			if cells[i] == "" {
				cells[i] = dash
			}
		}
		fmt.Fprintf(&b, "| %s | %s |\n", c, strings.Join(cells, " | "))
	}
	b.WriteString("\n¹ igual à referência válida, com divergência conhecida de uma das ferramentas (detalhe abaixo).\n" +
		"JA3N: o tshark não calcula; a referência é o `ja3_full` do tshark com as extensões em ordem numérica.\n" +
		"JA4H h3: sem referência externa (nem o `ja4` nem o `tshark` calculam); os campos QPACK são conferidos com o\n" +
		"tshark no caso 12 (`f4_h3_test.go`).\n\n## Detalhe\n\n")

	clients := map[string]bool{}
	bad := 0
	b.WriteString("| Cliente | Impressão | Registro | FoxIO `ja4` | tshark | Resultado |\n| --- | --- | --- | --- | --- | --- |\n")
	for _, r := range tb.rows {
		clients[r.client] = true
		if r.bad {
			bad++
		}
		foxio, tshark := code(r.foxio), code(r.tshark)
		if r.foxio == r.rec && r.foxio != "" && r.foxio != dash {
			foxio = "= registro"
		}
		if r.tshark == r.rec && r.tshark != "" && r.tshark != dash {
			tshark = "= registro"
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s |\n", r.client, r.fp, code(r.rec), foxio, tshark, r.result)
	}
	var names []string
	for n := range clients {
		names = append(names, fmt.Sprintf("%s (%d conexões)", n, tb.conn[n]))
	}
	sort.Strings(names)
	fmt.Fprintf(&b, "\nConexões conferidas: %s. Linhas com divergência não justificada: %d.\n", strings.Join(names, ", "), bad)

	t.Logf("tabela consolidada:\n%s", b.String())
	if os.Getenv("FS_E2E_UPDATE") != "1" {
		return
	}
	_, file, _, _ := runtime.Caller(0)
	out := filepath.Join(filepath.Dir(file), "testdata", "fingerprints-f5.md")
	if err := os.MkdirAll(filepath.Dir(out), 0o750); err != nil {
		t.Error(err)
		return
	}
	if err := os.WriteFile(out, []byte(b.String()), 0o600); err != nil {
		t.Error(err)
	}
}
