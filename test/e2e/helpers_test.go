//go:build e2e

package e2e

// Funções comuns dos testes da F3 e da F4 (tasks 039 e 060): probe ID novo, long-poll do probe, tipos do registro, socket TCP
// cru, conferências na vps602 (tshark e ja4 da FoxIO) e a validação de contrato de todas as respostas reais no
// fim da suíte (TestMain).

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const zone = "dns-monitor.tmsoft.com.br"

// vpsHost é o nome da vps602 (certificado da 9000 e das portas web).
var vpsHost = env("FS_E2E_HOST", "vps602.tmsoft.com.br")

// TestMain roda a suíte e, se ela passou, valida contra o openapi.yaml todas as respostas reais guardadas
// pelos testes da F3 (live). O TestF2ExitCriterion continua validando as dele por conta própria.
func TestMain(m *testing.M) {
	code := m.Run()
	if code == 0 {
		if err := validateLive(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			code = 1
		}
	}
	os.Exit(code)
}

// ---------------------------------------------------------------- probe

// newID devolve um probe ID novo ([a-z0-9]{16}, começa por "f3" para achar nos logs).
func newID(t *testing.T) string {
	t.Helper()
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 14)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return "f3" + string(b)
}

func probeHost(id string) string { return id + "." + zone }

type tlsInfo struct {
	ClientHelloB64      string `json:"client_hello_b64"`
	ClientHelloRecords  int    `json:"client_hello_records"`
	ClientHelloSegments int    `json:"client_hello_segments"`
	SNI                 *string
	ALPN                []string `json:"alpn"`
	JA3                 string   `json:"ja3"`
	JA3MD5              string   `json:"ja3_md5"`
	JA4                 string   `json:"ja4"`
	JA4R                string   `json:"ja4_r"`
	Negotiated          *struct {
		Version string  `json:"version"`
		ALPN    *string `json:"alpn"`
	} `json:"negotiated"`
	HandshakeMs *float64 `json:"handshake_ms"`
}

type h1Request struct {
	Index       int    `json:"index"`
	RawHeadB64  string `json:"raw_head_b64"`
	RequestLine struct {
		Method     string `json:"method"`
		Target     string `json:"target"`
		Form       string `json:"form"`
		Version    string `json:"version"`
		Terminator string `json:"terminator"`
	} `json:"request_line"`
	Fields     [][4]string `json:"fields"`
	FieldCount int         `json:"field_count"`
	HeadSize   int         `json:"head_size"`
	Duplicates []string    `json:"duplicates"`
	Body       struct {
		Framing string  `json:"framing"`
		Size    int     `json:"size"`
		SHA256  *string `json:"sha256"`
		RawB64  *string `json:"raw_b64"`
		Chunks  []struct {
			Size        int     `json:"size"`
			SizeLiteral string  `json:"size_literal"`
			Ext         *string `json:"ext"`
		} `json:"chunks"`
		Trailers [][4]string `json:"trailers"`
	} `json:"body"`
	ExpectContinue *struct {
		Waited bool     `json:"waited"`
		WaitMs *float64 `json:"wait_ms"`
	} `json:"expect_continue"`
	Pipelined            bool     `json:"pipelined"`
	Upgrade              *string  `json:"upgrade"`
	TFirstByteMs         *float64 `json:"t_first_byte_ms"`
	TSincePrevResponseMs *float64 `json:"t_since_prev_response_ms"`
	JA4H                 *string  `json:"ja4h"`
	Status               int      `json:"status"`
	ResponseSentB64      string   `json:"response_sent_b64"`
	ResponseSentSize     int      `json:"response_sent_size"`
	Controls             *struct {
		Params  map[string]string `json:"params"`
		Clamped []string          `json:"clamped"`
		Invalid []string          `json:"invalid"`
	} `json:"controls"`
	ProxySignals []struct {
		Kind string `json:"kind"`
	} `json:"proxy_signals"`
}

type h2Info struct {
	Mode         string     `json:"mode"`
	PrefaceOK    bool       `json:"preface_ok"`
	Settings     [][2]int64 `json:"settings"`
	WindowUpdate *int64     `json:"window_update"`
	Akamai       string     `json:"akamai"`
	Streams      []struct {
		StreamID    int      `json:"stream_id"`
		PseudoOrder []string `json:"pseudo_order"`
		Fields      []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
			Repr  string `json:"repr"`
		} `json:"fields"`
		JA4H   *string `json:"ja4h"`
		Status int     `json:"status"`
	} `json:"streams"`
	Frames []struct {
		Dir      string `json:"dir"`
		Type     string `json:"type"`
		StreamID int    `json:"stream_id"`
	} `json:"frames"`
}

type wsInfo struct {
	Over       string  `json:"over"`
	Path       string  `json:"path"`
	Extensions *string `json:"extensions"`
	Frames     []struct {
		Dir        string  `json:"dir"`
		Opcode     int     `json:"opcode"`
		Fin        bool    `json:"fin"`
		Rsv        int     `json:"rsv"`
		Masked     bool    `json:"masked"`
		MaskKeyHex *string `json:"mask_key_hex"`
		Length     int     `json:"length"`
	} `json:"frames"`
	Close *struct {
		By     string  `json:"by"`
		Code   *int    `json:"code"`
		Reason *string `json:"reason"`
	} `json:"close"`
}

type rawInfo struct {
	Mode      string       `json:"mode"`
	TLS       bool         `json:"tls"`
	Banner    *string      `json:"banner"`
	ProbeLine *string      `json:"probe_line"`
	ReadsIn   [][2]float64 `json:"reads_in"`
	WritesOut [][2]float64 `json:"writes_out"`
	HalfClose *struct {
		ServerSentAfterClientFin bool `json:"server_sent_after_client_fin"`
		Bytes                    int  `json:"bytes"`
	} `json:"half_close"`
}

// record é o registro completo de uma conexão (só os campos conferidos aqui; o contrato inteiro é validado
// pelo Redocly).
type record struct {
	ConnID   string   `json:"conn_id"`
	ProbeID  *string  `json:"probe_id"`
	Proto    string   `json:"proto"`
	L4       string   `json:"l4"`
	Src      endpoint `json:"src"`
	Dst      endpoint `json:"dst"`
	Started  string   `json:"started"`
	Ended    *string  `json:"ended"`
	Requests int      `json:"requests"`
	Times    map[string]*string
	Close    struct {
		By        string `json:"by"`
		How       string `json:"how"`
		HalfClose bool   `json:"half_close"`
	} `json:"close"`
	TLS       *tlsInfo    `json:"tls"`
	HTTP      []h1Request `json:"http"`
	HTTP2     *h2Info     `json:"http2"`
	HTTP3     *h3Info     `json:"http3"`
	WebSocket *wsInfo     `json:"websocket"`
	Raw       *rawInfo    `json:"raw"`
}

type dnsQuery struct {
	ProbeID  *string  `json:"probe_id"`
	Resolver endpoint `json:"resolver"`
	Proto    string   `json:"proto"`
	Qname    string   `json:"qname"`
	Qtype    string   `json:"qtype"`
	Flags    struct {
		RD bool `json:"rd"`
	} `json:"flags"`
	EDNS *struct {
		UDPSize int `json:"udp_size"`
		ECS     *struct {
			Family       int    `json:"family"`
			SourcePrefix int    `json:"source_prefix"`
			Address      string `json:"address"`
		} `json:"ecs"`
	} `json:"edns"`
	Response struct {
		Rcode   string `json:"rcode"`
		Answers []struct {
			Name string `json:"name"`
			Type string `json:"type"`
			TTL  int    `json:"ttl"`
			Data string `json:"data"`
		} `json:"answers"`
	} `json:"response"`
}

type probeResp struct {
	ProbeID     string     `json:"probe_id"`
	AllClosed   bool       `json:"all_closed"`
	Connections []record   `json:"connections"`
	DNS         []dnsQuery `json:"dns"`
}

// conns devolve as conexões do probe com a porta de destino dada (0 = todas), na ordem de início.
func (p *probeResp) conns(port int) []record {
	var out []record
	for _, c := range p.Connections {
		if port == 0 || c.Dst.Port == port {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Started < out[j].Started })
	return out
}

// waitProbe faz o long-poll de /probes/{id}?wait=10s até ready aceitar a resposta e todas as conexões
// terem terminado (prazo de 60 s), e guarda a resposta para a validação de contrato.
func waitProbe(t *testing.T, id string, ready func(*probeResp) bool) *probeResp {
	t.Helper()
	p, b := waitProbeRaw(t, id, ready)
	addLive("probe-example.json", b)
	return p
}

// waitProbeRaw é o waitProbe sem guardar a resposta para o contrato. O long-poll responde na hora quando o
// probe ainda não tem conexões (o registro só aparece até 500 ms depois do fim), por isso o laço.
func waitProbeRaw(t *testing.T, id string, ready func(*probeResp) bool) (*probeResp, []byte) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	var last []byte
	for time.Now().Before(deadline) {
		resp, err := http.Get(api + "/probes/" + id + "?wait=10s") //nolint:gosec // URL do teste
		if err != nil {
			t.Fatalf("GET probe %s: %v", id, err)
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusOK:
			var p probeResp
			if err := json.Unmarshal(b, &p); err != nil {
				t.Fatalf("probe %s: %v", id, err)
			}
			last = b
			if p.AllClosed && ready(&p) {
				return &p, b
			}
		case http.StatusNotFound:
		default:
			t.Fatalf("GET probe %s: %d %s", id, resp.StatusCode, b)
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("probe %s não ficou pronto em 60 s; última resposta:\n%s", id, last)
	return nil, nil
}

// atLeast é o ready de waitProbe para "n conexões terminadas na porta".
func atLeast(n, port int) func(*probeResp) bool {
	return func(p *probeResp) bool { return len(p.conns(port)) >= n }
}

// connRecord busca o registro completo da conexão (também entra na validação de contrato).
func connRecord(t *testing.T, connID string) record {
	t.Helper()
	var r record
	addLive("connection-example.json", get(t, "/connections/"+connID, &r))
	return r
}

// rawStream baixa /connections/{id}/raw?dir=in|out.
func rawStream(t *testing.T, connID, dir string) []byte {
	t.Helper()
	resp, err := http.Get(api + "/connections/" + connID + "/raw?dir=" + dir) //nolint:gosec // URL do teste
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck // leitura
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("raw %s %s: %d %s", connID, dir, resp.StatusCode, b)
	}
	return b
}

func b64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64 %q: %v", s, err)
	}
	return b
}

func ptr[T any](p *T) any {
	if p == nil {
		return "<nil>"
	}
	return *p
}

// ---------------------------------------------------------------- TCP cru

// rawConn é um socket TCP para o espelho, com leitura com prazo.
type rawConn struct {
	*net.TCPConn
	br *bufio.Reader
}

func dialTCP(t *testing.T, port int) *rawConn {
	t.Helper()
	c, err := net.DialTimeout("tcp4", fmt.Sprintf("%s:%d", vps4, port), 5*time.Second)
	if err != nil {
		t.Fatalf("dial %d: %v", port, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	tc := c.(*net.TCPConn)
	return &rawConn{TCPConn: tc, br: bufio.NewReader(tc)}
}

func (c *rawConn) send(t *testing.T, s string) {
	t.Helper()
	if _, err := io.WriteString(c, s); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// readN lê exatamente n bytes (prazo de 10 s).
func (c *rawConn) readN(t *testing.T, n int) []byte {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	b := make([]byte, n)
	if _, err := io.ReadFull(c.br, b); err != nil {
		t.Fatalf("read %d bytes: %v (lido %q)", n, err, b)
	}
	return b
}

// readAll lê até o servidor fechar (prazo d) e devolve os bytes e o erro de leitura final.
func (c *rawConn) readAll(d time.Duration) ([]byte, error) {
	_ = c.SetReadDeadline(time.Now().Add(d))
	b, err := io.ReadAll(c.br)
	return b, err
}

// response é uma resposta HTTP/1 lida do socket cru, com o cabeçalho literal.
type response struct {
	Head   string // linha de status e campos, até o CRLF CRLF inclusive
	Status int
	Header http.Header
	Body   []byte
}

// readResponse lê uma resposta (cabeçalho + corpo por Content-Length ou chunked; 1xx sem corpo).
func (c *rawConn) readResponse(t *testing.T) response {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(15 * time.Second))
	var head strings.Builder
	for {
		line, err := c.br.ReadString('\n')
		head.WriteString(line)
		if err != nil {
			t.Fatalf("lendo cabeçalho: %v (lido %q)", err, head.String())
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	r := response{Head: head.String(), Header: http.Header{}}
	lines := strings.Split(strings.TrimRight(r.Head, "\r\n"), "\r\n")
	parts := strings.SplitN(lines[0], " ", 3)
	if len(parts) < 2 {
		t.Fatalf("linha de status inválida: %q", lines[0])
	}
	r.Status, _ = strconv.Atoi(parts[1])
	for _, l := range lines[1:] {
		k, v, _ := strings.Cut(l, ":")
		r.Header.Add(k, strings.TrimSpace(v))
	}
	if r.Status < 200 || r.Status == 204 || r.Status == 304 {
		return r
	}
	switch {
	case r.Header.Get("Content-Length") != "":
		n, _ := strconv.Atoi(r.Header.Get("Content-Length"))
		r.Body = c.readN(t, n)
	case strings.EqualFold(r.Header.Get("Transfer-Encoding"), "chunked"):
		var body bytes.Buffer
		for {
			line, err := c.br.ReadString('\n')
			if err != nil {
				t.Fatalf("chunked: %v", err)
			}
			n, err := strconv.ParseInt(strings.TrimSpace(strings.SplitN(line, ";", 2)[0]), 16, 64)
			if err != nil {
				t.Fatalf("tamanho de chunk %q: %v", line, err)
			}
			if n == 0 {
				for { // trailers até a linha vazia
					l, err := c.br.ReadString('\n')
					if err != nil || l == "\r\n" {
						break
					}
					r.Head += l
				}
				break
			}
			body.Write(c.readN(t, int(n)))
			c.readN(t, 2)
		}
		r.Body = body.Bytes()
	}
	return r
}

// ---------------------------------------------------------------- vps602

// remoteIn roda um comando na vps602 com stdin.
func remoteIn(t *testing.T, cmd string, stdin []byte) string {
	t.Helper()
	c := exec.Command("ssh", "-4", "-p", vpsPort, "-o", "BatchMode=yes", vpsSSH, cmd)
	c.Stdin = bytes.NewReader(stdin)
	out, err := c.CombinedOutput()
	if err != nil {
		t.Fatalf("ssh %q: %v\n%s", cmd, err, out)
	}
	return strings.TrimSpace(string(out))
}

// pcapOf baixa o pcap da conexão pela API.
func pcapOf(t *testing.T, connID string) []byte {
	t.Helper()
	resp, err := http.Get(api + "/connections/" + connID + "/pcap") //nolint:gosec // URL do teste
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck // leitura
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || len(b) < 24 {
		t.Fatalf("pcap %s: %d (%d bytes)", connID, resp.StatusCode, len(b))
	}
	return b
}

// toolRef é o que as ferramentas de referência (tshark 4.4 e ja4 da FoxIO na vps602, ref.py do golden da
// task 036) dizem sobre o pcap de uma conexão.
type toolRef struct {
	ClientHellos []struct {
		JA3     string   `json:"ja3"`
		JA4     string   `json:"ja4"`
		JA4Tool string   `json:"ja4_tool"`
		JA4R    string   `json:"ja4_r_tool"`
		SNI     string   `json:"sni"`
		ALPN    []string `json:"alpn"`
	} `json:"client_hellos"`
	Akamai *string `json:"akamai"`
	JA4H   *string `json:"ja4h"`
	// ClientBytes é o fluxo TCP do cliente remontado pelo tshark (sem retransmissões).
	ClientBytes []byte `json:"-"`
}

var refPy = sync.OnceValues(func() ([]byte, error) {
	_, file, _, _ := runtime.Caller(0)
	return os.ReadFile(filepath.Join(filepath.Dir(file), "..", "golden", "tls", "ref.py")) //nolint:gosec // repositório
})

// analyzePcap manda o pcap (e o keylog do cliente, se houver) para a vps602 e roda tshark, ja4 e ref.py
// sobre ele, como no golden da task 036. serverPort é a porta do espelho na conexão.
func analyzePcap(t *testing.T, connID string, serverPort int, keylog []byte) toolRef {
	t.Helper()
	pcap := pcapOf(t, connID)
	py, err := refPy()
	if err != nil {
		t.Fatal(err)
	}
	// o ref.py do golden usa a porta 7702 do servidor temporário; aqui é a porta do espelho
	py = bytes.Replace(py, []byte(`SERVER_PORT = "7702"`), []byte(fmt.Sprintf(`SERVER_PORT = "%d"`, serverPort)), 1)
	dir := "/tmp/fs-e2e-f3/" + connID
	t.Cleanup(func() { remote(t, "rm -rf "+dir+"; rmdir /tmp/fs-e2e-f3 2>/dev/null; true") })
	remoteIn(t, "mkdir -p "+dir+" && cat > "+dir+"/c.pcap", pcap)
	remoteIn(t, "cat > "+dir+"/c.keys", keylog)
	remoteIn(t, "cat > "+dir+"/ref.py", py)
	out := remote(t, fmt.Sprintf("cd %s && "+
		"tshark -r c.pcap -o tls.keylog_file:c.keys -T json --no-duplicate-keys -J 'tcp tls http2 http' "+
		"-Y 'tls.handshake.type == 1 || http2 || http' > c.tshark.json 2>/dev/null && "+
		"{ /root/ja4-rust/target/release/ja4 -j -r --keylog-file c.keys c.pcap 2>/dev/null | grep '^{' > c.ja4.jsonl || true; } && "+
		"python3 ref.py c >/dev/null && cat c.ref.json && echo '=====' && "+
		"tshark -r c.pcap -Y 'tcp.dstport == %d && tcp.len > 0' -T fields -e tcp.seq -e tcp.payload 2>/dev/null", dir, serverPort))
	js, segs, ok := strings.Cut(out, "=====")
	if !ok {
		t.Fatalf("saída inesperada das ferramentas:\n%s", out)
	}
	var ref toolRef
	if err := json.Unmarshal([]byte(js), &ref); err != nil {
		t.Fatalf("ref.json: %v\n%s", err, js)
	}
	ref.ClientBytes = reassemble(t, segs)
	return ref
}

// reassemble junta os segmentos "seq<TAB>payload_hex" do tshark pela sequência relativa, descartando
// retransmissões.
func reassemble(t *testing.T, lines string) []byte {
	t.Helper()
	var buf []byte
	for l := range strings.Lines(strings.TrimSpace(lines)) {
		seqS, hexS, _ := strings.Cut(strings.TrimSpace(l), "\t")
		hexS = strings.ReplaceAll(hexS, ":", "")
		seq, err := strconv.Atoi(seqS)
		if err != nil {
			t.Fatalf("seq %q: %v", seqS, err)
		}
		data := make([]byte, len(hexS)/2)
		for i := range data {
			v, err := strconv.ParseUint(hexS[2*i:2*i+2], 16, 8)
			if err != nil {
				t.Fatalf("payload: %v", err)
			}
			data[i] = byte(v)
		}
		off := seq - 1 // tcp.seq é relativo: o primeiro byte de dados é 1
		if off+len(data) <= len(buf) {
			continue // retransmissão
		}
		if off > len(buf) {
			t.Fatalf("buraco no fluxo do cliente em %d (tenho %d)", off, len(buf))
		}
		buf = append(buf, data[len(buf)-off:]...)
	}
	return buf
}

// ---------------------------------------------------------------- contrato

var (
	liveMu sync.Mutex
	live   = map[string][][]byte{}
)

// addLive guarda uma resposta real para validar contra o exemplo de mesmo nome do openapi.yaml.
func addLive(example string, b []byte) {
	liveMu.Lock()
	defer liveMu.Unlock()
	live[example] = append(live[example], append([]byte(nil), b...))
}

// validateLive copia o openapi.yaml e os exemplos para um diretório temporário, acrescenta cada resposta real
// como mais um exemplo da mesma rota (ao lado do exemplo do repositório) e roda o Redocly do verify, cuja
// regra no-invalid-media-type-examples (erro) valida cada exemplo contra o schema.
func validateLive() error {
	liveMu.Lock()
	defer liveMu.Unlock()
	if len(live) == 0 {
		return nil
	}
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(file), "..", "..")
	dir, err := os.MkdirTemp("", "fs-e2e-contract-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir) //nolint:errcheck // temporário
	if err := os.MkdirAll(filepath.Join(dir, "testdata"), 0o750); err != nil {
		return err
	}
	spec, err := os.ReadFile(filepath.Join(root, "cmd/finger-sniffer-store/openapi.yaml")) //nolint:gosec // repositório
	if err != nil {
		return err
	}
	redocly, err := os.ReadFile(filepath.Join(root, "redocly.yaml")) //nolint:gosec // repositório
	if err != nil {
		return err
	}
	golden, _ := filepath.Glob(filepath.Join(root, "cmd/finger-sniffer-store/testdata/*.json"))
	for _, g := range golden {
		b, _ := os.ReadFile(g) //nolint:gosec // repositório
		if err := os.WriteFile(filepath.Join(dir, "testdata", filepath.Base(g)), b, 0o600); err != nil {
			return err
		}
	}
	text := string(spec)
	total := 0
	names := make([]string, 0, len(live))
	for name := range live {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		ref := `{ $ref: "./testdata/` + name + `" }`
		i := strings.Index(text, ref)
		if i < 0 {
			return fmt.Errorf("contrato: exemplo %s não está no openapi.yaml", name)
		}
		lineStart := strings.LastIndex(text[:i], "\n") + 1
		lineEnd := i + len(ref)
		indent := text[lineStart : lineStart+len(text[lineStart:])-len(strings.TrimLeft(text[lineStart:], " "))]
		var extra strings.Builder
		for k, b := range live[name] {
			f := fmt.Sprintf("live-%s-%03d.json", strings.TrimSuffix(name, ".json"), k)
			ex, _ := json.Marshal(map[string]any{"summary": "resposta real do e2e", "value": json.RawMessage(b)})
			if err := os.WriteFile(filepath.Join(dir, "testdata", f), ex, 0o600); err != nil {
				return err
			}
			fmt.Fprintf(&extra, "\n%slive%03d: { $ref: \"./testdata/%s\" }", indent, k, f)
			total++
		}
		text = text[:lineEnd] + extra.String() + text[lineEnd:]
	}
	if err := os.WriteFile(filepath.Join(dir, "openapi.yaml"), []byte(text), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "redocly.yaml"), redocly, 0o600); err != nil {
		return err
	}
	cmd := exec.Command("npx", "-y", "@redocly/cli@2.76.0", "lint", "openapi.yaml")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "REDOCLY_TELEMETRY=off", "REDOCLY_SUPPRESS_UPDATE_NOTICE=true")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("contrato: respostas reais do e2e não validam contra o openapi.yaml: %v\n%s", err, out)
	}
	fmt.Printf("contrato: %d respostas reais do e2e validadas contra o openapi.yaml (%s)\n", total, strings.Join(names, ", "))
	return nil
}
