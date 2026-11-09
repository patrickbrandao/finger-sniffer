package tlsgolden_test

// Conferência dos golden de TLS e h2 da task 036. O teste não usa código do projeto: ele garante que os
// arquivos gerados por collect.sh são coerentes entre si antes de servirem de gabarito para pkg/tlsparse,
// pkg/fingerprint e pkg/h2passive. Confere:
//   - todo caso tem ClientHello com JA3 e JA4 do tshark e JA4 do ja4 da FoxIO; as partes a e b do JA4 batem
//     entre as duas ferramentas, e a parte c só diverge quando o tshark contou um GREASE nos algoritmos de
//     assinatura (defeito do tshark 4.4, registrado no README);
//   - os bytes h2 decifrados do cliente (pkg/h2passive/testdata/clients) começam pelo prefácio e têm a mesma
//     sequência de frames (tipo, stream, tamanho) e os mesmos SETTINGS e WINDOW_UPDATE que o tshark dissecou;
//   - o Akamai montado a partir do tshark bate com o de tls.peet.ws para o mesmo cliente, e o JA4 também.

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const (
	pcapsDir   = "pcaps"
	clientsDir = "../../../pkg/h2passive/testdata/clients"
	preface    = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
)

type clientHello struct {
	TCPStream int      `json:"tcp_stream"`
	JA3       string   `json:"ja3"`
	JA4       string   `json:"ja4"`
	JA4R      string   `json:"ja4_r"`
	JA4Tool   string   `json:"ja4_tool"`
	JA4RTool  string   `json:"ja4_r_tool"`
	SNI       string   `json:"sni"`
	ALPN      []string `json:"alpn"`
}

type h2Frame struct {
	Type      int        `json:"type"`
	Flags     string     `json:"flags"`
	Stream    int        `json:"stream"`
	Length    int        `json:"length"`
	Settings  [][2]int64 `json:"settings"`
	Increment int64      `json:"increment"`
}

type h2Conn struct {
	TCPStream int       `json:"tcp_stream"`
	Akamai    string    `json:"akamai"`
	Frames    []h2Frame `json:"frames"`
}

type ref struct {
	Case           string        `json:"case"`
	ClientHellos   []clientHello `json:"client_hellos"`
	HTTP2          []h2Conn      `json:"http2"`
	Akamai         *string       `json:"akamai"`
	JA3            string        `json:"ja3"`
	JA4            string        `json:"ja4"`
	JA4H           *string       `json:"ja4h"`
	ClientH2Stream int           `json:"client_h2_tcp_stream"`
	ClientH2Bytes  int           `json:"client_h2_bytes"`
}

func loadJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

func refs(t *testing.T) map[string]ref {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(pcapsDir, "*.ref.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("nenhum *.ref.json em pcaps/")
	}
	out := map[string]ref{}
	for _, f := range files {
		var r ref
		loadJSON(t, f, &r)
		out[r.Case] = r
	}
	return out
}

// os casos que a coleta precisa produzir (spec 017 RF-12: curl, Go, Chrome e Firefox, em h2 e h1)
var wantCases = []string{
	"curl-libressl-h2", "curl-libressl-h1", "curl-openssl-h2", "curl-openssl-h1",
	"go-h2", "go-h1", "chrome-h2", "chrome-h1", "firefox-h2", "firefox-h1",
}

func TestCasesComplete(t *testing.T) {
	rs := refs(t)
	for _, c := range wantCases {
		r, ok := rs[c]
		if !ok {
			t.Errorf("%s: caso ausente", c)
			continue
		}
		for _, ext := range []string{".pcap", ".keys", ".tshark.json", ".ja4.jsonl"} {
			if st, err := os.Stat(filepath.Join(pcapsDir, c+ext)); err != nil || st.Size() == 0 {
				t.Errorf("%s%s: ausente ou vazio", c, ext)
			}
		}
		h2 := strings.HasSuffix(c, "-h2")
		if h2 && r.Akamai == nil {
			t.Errorf("%s: sem Akamai", c)
		}
		if !h2 && r.Akamai != nil {
			t.Errorf("%s: Akamai em caso h1", c)
		}
		// o ja4 0.18.6 não emite JA4H quando o HEADERS vem no mesmo registro TLS do prefácio (README)
		if r.JA4H == nil && c != "curl-openssl-h2" {
			t.Errorf("%s: sem JA4H do ja4", c)
		}
	}
}

func hasGREASESigAlg(ja4r string) bool {
	parts := strings.Split(ja4r, "_")
	if len(parts) < 4 {
		return false
	}
	for _, v := range strings.Split(parts[3], ",") {
		if len(v) == 4 && v[0] == v[2] && v[1] == 'a' && v[3] == 'a' {
			return true
		}
	}
	return false
}

func TestClientHelloTsharkVsJA4(t *testing.T) {
	for name, r := range refs(t) {
		if len(r.ClientHellos) == 0 {
			t.Errorf("%s: sem ClientHello", name)
			continue
		}
		if r.JA4 == "" || r.JA3 == "" {
			t.Errorf("%s: JA3/JA4 de referência vazios", name)
		}
		for _, ch := range r.ClientHellos {
			if ch.JA3 == "" || ch.JA4 == "" || ch.JA4Tool == "" {
				t.Errorf("%s stream %d: JA3/JA4 ausente (tshark %q/%q, ja4 %q)", name, ch.TCPStream, ch.JA3,
					ch.JA4, ch.JA4Tool)
				continue
			}
			if ch.SNI != "vps602.tmsoft.com.br" {
				t.Errorf("%s stream %d: SNI %q", name, ch.TCPStream, ch.SNI)
			}
			ts, tool := strings.Split(ch.JA4, "_"), strings.Split(ch.JA4Tool, "_")
			if ts[0] != tool[0] || ts[1] != tool[1] {
				t.Errorf("%s stream %d: JA4 a/b diferem: tshark %s, ja4 %s", name, ch.TCPStream, ch.JA4, ch.JA4Tool)
			}
			if ts[2] != tool[2] && !hasGREASESigAlg(ch.JA4R) {
				t.Errorf("%s stream %d: JA4 c difere sem GREASE: tshark %s, ja4 %s", name, ch.TCPStream, ch.JA4,
					ch.JA4Tool)
			}
		}
	}
}

// frames lê a sequência de frames h2 dos bytes do cliente (depois do prefácio).
func frames(t *testing.T, b []byte) []h2Frame {
	t.Helper()
	var out []h2Frame
	for len(b) >= 9 {
		n := int(b[0])<<16 | int(b[1])<<8 | int(b[2])
		if len(b) < 9+n {
			t.Fatalf("frame truncado: %d bytes de %d", len(b)-9, n)
		}
		f := h2Frame{
			Type:   int(b[3]),
			Flags:  "0x" + strconv.FormatInt(int64(b[4])|0x100, 16)[1:],
			Stream: int(binary.BigEndian.Uint32(b[5:9]) & 0x7fffffff),
			Length: n,
		}
		p := b[9 : 9+n]
		switch f.Type {
		case 4:
			f.Settings = [][2]int64{}
			for i := 0; i+6 <= len(p); i += 6 {
				f.Settings = append(f.Settings, [2]int64{
					int64(binary.BigEndian.Uint16(p[i:])), int64(binary.BigEndian.Uint32(p[i+2:])),
				})
			}
		case 8:
			f.Increment = int64(binary.BigEndian.Uint32(p) & 0x7fffffff)
		}
		out = append(out, f)
		b = b[9+n:]
	}
	if len(b) != 0 {
		t.Fatalf("%d bytes sobrando no fim", len(b))
	}
	return out
}

func TestClientH2BytesMatchTshark(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(clientsDir, "*.client.h2"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 5 {
		t.Fatalf("%d arquivos .client.h2 em %s, esperados 5 (um por cliente h2)", len(files), clientsDir)
	}
	for _, f := range files {
		name := strings.TrimSuffix(filepath.Base(f), ".client.h2")
		t.Run(name, func(t *testing.T) {
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.HasPrefix(b, []byte(preface)) {
				t.Fatal("sem prefácio h2")
			}
			var exp ref
			loadJSON(t, filepath.Join(clientsDir, name+".expected.json"), &exp)
			if exp.ClientH2Bytes != len(b) {
				t.Fatalf("tamanho %d, esperado %d", len(b), exp.ClientH2Bytes)
			}
			var conn *h2Conn
			for i := range exp.HTTP2 {
				if exp.HTTP2[i].TCPStream == exp.ClientH2Stream {
					conn = &exp.HTTP2[i]
				}
			}
			if conn == nil || exp.Akamai == nil || conn.Akamai != *exp.Akamai {
				t.Fatal("conexão principal ou Akamai ausente no expected.json")
			}
			got := frames(t, b[len(preface):])
			if len(got) != len(conn.Frames) {
				t.Fatalf("%d frames nos bytes, %d no tshark", len(got), len(conn.Frames))
			}
			for i, g := range got {
				w := conn.Frames[i]
				if g.Type != w.Type || g.Stream != w.Stream || g.Length != w.Length || g.Flags != w.Flags {
					t.Errorf("frame %d: bytes %+v, tshark %+v", i, g, w)
				}
				if g.Type == 4 && !equalSettings(g.Settings, w.Settings) {
					t.Errorf("frame %d: SETTINGS %v, tshark %v", i, g.Settings, w.Settings)
				}
				if g.Type == 8 && g.Increment != w.Increment {
					t.Errorf("frame %d: WINDOW_UPDATE %d, tshark %d", i, g.Increment, w.Increment)
				}
			}
			// a primeira parte do Akamai (SETTINGS) sai direto dos bytes
			s := []string{}
			for _, kv := range got[0].Settings {
				s = append(s, strconv.FormatInt(kv[0], 10)+":"+strconv.FormatInt(kv[1], 10))
			}
			if a := strings.Split(*exp.Akamai, "|")[0]; a != strings.Join(s, ";") {
				t.Errorf("Akamai S %q, bytes %q", a, strings.Join(s, ";"))
			}
		})
	}
}

func equalSettings(a, b [][2]int64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

type peet struct {
	TLS struct {
		JA3Hash string `json:"ja3_hash"`
		JA4     string `json:"ja4"`
	} `json:"tls"`
	HTTP2 struct {
		Akamai string `json:"akamai_fingerprint"`
	} `json:"http2"`
}

func TestAkamaiMatchesPeet(t *testing.T) {
	rs := refs(t)
	// o Firefox headless não entrega o corpo da página (processos de conteúdo não sobem no ambiente da coleta),
	// então não há resposta do tls.peet.ws para ele; ver README
	for _, c := range []string{"chrome", "curl-libressl", "curl-openssl", "go"} {
		t.Run(c, func(t *testing.T) {
			var p peet
			loadJSON(t, filepath.Join(pcapsDir, c+".peet.json"), &p)
			r := rs[c+"-h2"]
			if r.Akamai == nil || *r.Akamai != p.HTTP2.Akamai {
				t.Errorf("Akamai: tshark %v, tls.peet.ws %q", r.Akamai, p.HTTP2.Akamai)
			}
			// o tls.peet.ws escreve a contagem de extensões sem zero à esquerda ("t13d497h2" no curl do macOS):
			// compara-se só b e c, além do a quando ele tem o tamanho certo
			ours, theirs := strings.Split(r.JA4, "_"), strings.Split(p.TLS.JA4, "_")
			if len(theirs) != 3 || ours[1] != theirs[1] || ours[2] != theirs[2] ||
				(len(theirs[0]) == 10 && ours[0] != theirs[0]) {
				t.Errorf("JA4: ja4 %s, tls.peet.ws %s", r.JA4, p.TLS.JA4)
			}
			// o Chrome embaralha a ordem das extensões a cada conexão: JA3 não é estável
			if c != "chrome" && r.JA3 != p.TLS.JA3Hash {
				t.Errorf("JA3: tshark %s, tls.peet.ws %s", r.JA3, p.TLS.JA3Hash)
			}
		})
	}
}
