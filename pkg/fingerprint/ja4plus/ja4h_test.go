package ja4plus

import (
	"bytes"
	"encoding/json"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/patrickbrandao/finger-sniffer/pkg/h2passive"
)

type ja4hGolden struct {
	JA4H   string `json:"ja4h"`
	JA4HR  string `json:"ja4h_r"`
	JA4HO  string `json:"ja4h_o"`
	JA4HRO string `json:"ja4h_ro"`
}

func loadJA4HGolden(t *testing.T) map[string][]ja4hGolden {
	t.Helper()
	b, err := os.ReadFile("testdata/ja4h.golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var g map[string][]ja4hGolden
	if err := json.Unmarshal(b, &g); err != nil {
		t.Fatal(err)
	}
	return g
}

func check(t *testing.T, name string, got JA4HResult, want ja4hGolden) {
	t.Helper()
	if got.JA4H != want.JA4H || got.JA4HR != want.JA4HR || got.JA4HO != want.JA4HO || got.JA4HRO != want.JA4HRO {
		t.Errorf("%s:\n got %+v\nwant %+v", name, got, want)
	}
}

// clientPayload junta o payload TCP do cliente (porta de destino dst) de um pcapng.
func clientPayload(t *testing.T, path string, dst layers.TCPPort) []byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close() //nolint:errcheck // só leitura
	r, err := pcapgo.NewNgReader(f, pcapgo.DefaultNgReaderOptions)
	if err != nil {
		t.Fatal(err)
	}
	var out []byte
	for {
		data, _, err := r.ReadPacketData()
		if err != nil {
			break
		}
		p := gopacket.NewPacket(data, r.LinkType(), gopacket.Default)
		if tcp, ok := p.Layer(layers.LayerTypeTCP).(*layers.TCP); ok && tcp.DstPort == dst {
			out = append(out, tcp.Payload...)
		}
	}
	return out
}

// TestJA4HFoxIOHTTP1 confere o JA4H contra o `ja4` oficial no http1-with-cookies.pcapng da FoxIO.
func TestJA4HFoxIOHTTP1(t *testing.T) {
	want := loadJA4HGolden(t)["http1-with-cookies.pcapng"]
	raw := clientPayload(t, "testdata/http1-with-cookies.pcapng", 8000)
	head, _, ok := bytes.Cut(raw, []byte("\r\n\r\n"))
	if !ok || len(want) != 1 {
		t.Fatalf("requisição não encontrada (%d bytes, %d gabaritos)", len(raw), len(want))
	}
	lines := strings.Split(string(head), "\r\n")
	reqLine := strings.Fields(lines[0])
	in := JA4HInput{Method: reqLine[0], Version: reqLine[2]}
	for _, l := range lines[1:] {
		name, value, _ := strings.Cut(l, ":")
		in.Fields = append(in.Fields, JA4HField{Name: name, Value: strings.TrimLeft(value, " \t")})
	}
	check(t, "http1", JA4H(in), want[0])
}

// TestJA4HFoxIOHTTP2 confere o JA4H dos 15 streams do http2-with-cookies.pcapng da FoxIO contra o `ja4`
// oficial, lendo o sentido do cliente (decifrado pelo tshark) com o parser passivo h2.
func TestJA4HFoxIOHTTP2(t *testing.T) {
	want := loadJA4HGolden(t)["http2-with-cookies.pcapng"]
	raw, err := os.ReadFile("../../h2passive/testdata/chrome-foxio-in.bin")
	if err != nil {
		t.Fatal(err)
	}
	info := h2passive.Parse(raw, h2passive.Options{})
	if len(info.Streams) != len(want) {
		t.Fatalf("%d streams, ja4 %d", len(info.Streams), len(want))
	}
	for i, st := range info.Streams {
		check(t, "stream "+strconv.Itoa(int(st.StreamID)), JA4H(fromHTTP2(st.Fields[:st.HeadFields])), want[i])
	}
}

// fromHTTP2 monta a entrada do JA4H a partir dos campos de um stream h2.
func fromHTTP2(fields []h2passive.HPACKField) JA4HInput {
	in := JA4HInput{Version: "HTTP/2"}
	for _, f := range fields {
		if f.Name == ":method" {
			in.Method = f.Value
		}
		in.Fields = append(in.Fields, JA4HField{Name: f.Name, Value: f.Value})
	}
	return in
}

// TestJA4HUpstreamVectors são os casos dos testes da própria ferramenta (rust/ja4/src/http.rs).
func TestJA4HUpstreamVectors(t *testing.T) {
	cookie := "FastAB=0=6859,1=8174,2=4183,3=3319,4=3917,5=2557,6=4259,7=6070,8=0804,9=6453,10=1942,11=4435," +
		"12=4143,13=9445,14=6957,15=8682,16=1885,17=1825,18=3760,19=0929; sato=1; countryCode=US; stateCode=VA; " +
		"geoData=purcellville|VA|20132|US|NA|-400|broadband|39.160|-77.700|511; usprivacy=1---; umto=1; " +
		"_dd_s=logs=1&id=b5c2d770-eaba-4847-8202-390c4552ff9a&created=1686159462724&expire=1686160422726"
	h1 := JA4HInput{Method: "GET", Version: "HTTP/1.1", Fields: []JA4HField{
		{"Host", "www.cnn.com"},
		{"Cookie", cookie},
		{"Sec-Ch-Ua", ""},
		{"Sec-Ch-Ua-Mobile", "?0"},
		{"User-Agent", "Mozilla/5.0"},
		{"Sec-Ch-Ua-Platform", `""`},
		{"Accept", "*/*"},
		{"Sec-Fetch-Site", "same-origin"},
		{"Sec-Fetch-Mode", "cors"},
		{"Sec-Fetch-Dest", "empty"},
		{"Sec-Fetch-Mode", "cors"},
		{"Sec-Fetch-Dest", "empty"},
		{"Referer", "https://www.cnn.com/"},
		{"Accept-Encoding", "gzip, deflate"},
		{"Accept-Language", "en-US,en;q=0.9"},
	}}
	r := JA4H(h1)
	if r.JA4H != "ge11cr13enus_88d2d584d47f_0f2659b474bf_161698816dab" ||
		r.JA4HO != "ge11cr13enus_88d2d584d47f_457935509480_ff4b0b83634b" {
		t.Fatalf("h1: %+v", r)
	}

	h2 := JA4HInput{Method: "GET", Version: "HTTP/2"}
	for _, n := range []string{
		":method", ":scheme", ":authority", ":path", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
		"upgrade-insecure-requests", "user-agent", "accept", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user",
		"sec-fetch-dest", "accept-encoding", "accept-language",
	} {
		v := ""
		if n == "accept-language" {
			v = "en-US,en;q=0.9"
		}
		h2.Fields = append(h2.Fields, JA4HField{n, v})
	}
	r = JA4H(h2)
	if r.JA4H != "ge20nn12enus_60f823d07c94_000000000000_000000000000" ||
		r.JA4HR != "ge20nn12enus_sec-ch-ua,sec-ch-ua-mobile,sec-ch-ua-platform,upgrade-insecure-requests,"+
			"user-agent,accept,sec-fetch-site,sec-fetch-mode,sec-fetch-user,sec-fetch-dest,accept-encoding,accept-language__" {
		t.Fatalf("h2: %+v", r)
	}
}

func TestJA4HDetails(t *testing.T) {
	// ordenação dos cookies como o Rust: nome, sem valor antes de com valor, valor
	in := JA4HInput{Method: "POST", Version: "HTTP/2", Fields: []JA4HField{
		{"cookie", "pardot=tee"}, {"cookie", "a=y=z"}, {"cookie", "a=x"}, {"cookie", "no-value"}, {"cookie", "a"},
	}}
	r := JA4H(in)
	if !strings.HasSuffix(r.JA4HR, "_a,a,a,no-value,pardot_a,a=x,a=y=z,no-value,pardot=tee") ||
		!strings.HasPrefix(r.JA4HR, "po20cn000000__") {
		t.Fatalf("raw = %q", r.JA4HR)
	}
	if !strings.HasSuffix(r.JA4HRO, "_pardot,a,a,no-value,a_pardot=tee,a=y=z,a=x,no-value,a") {
		t.Fatalf("raw original = %q", r.JA4HRO)
	}
	// h1: só o primeiro Cookie conta; nomes sem caixa; 99 campos no máximo
	h1 := JA4HInput{Method: "connect", Version: "HTTP/1.0", Fields: []JA4HField{
		{"COOKIE", "b=2; a=1"},
		{"cookie", "z=9"},
		{"REFERER", "x"},
		{"accept-language", " da, en-gb;q=0.8"},
		{"Accept-Language", "fr"},
	}}
	for range 120 {
		h1.Fields = append(h1.Fields, JA4HField{"X", "y"})
	}
	r = JA4H(h1)
	if !strings.HasPrefix(r.JA4HR, "co10cr99da00_") || !strings.HasSuffix(r.JA4HR, "_a,b_a=1,b=2") {
		t.Fatalf("h1 = %q", r.JA4HR)
	}
	for _, tc := range []struct{ method, version, lang, want string }{
		{"PATCH", "HTTP/3", "en;q=0.5", "pa30nn01en;q"},
		{"X", "HTTP/9", "", "x000nn010000"},
		{"", "HTTP/2.0", "pt-BR", "0020nn01ptbr"},
		{"DELETE", "HTTP/3.0", "ÉÉ-ÉÉÉ", "de30nn01éééé"},
	} {
		r := JA4H(JA4HInput{Method: tc.method, Version: tc.version, Fields: []JA4HField{{"Accept-Language", tc.lang}}})
		if a, _, _ := strings.Cut(r.JA4H, "_"); a != tc.want {
			t.Errorf("%+v: %q", tc, a)
		}
	}
	if hash12("551d0f,551d25,551d11") != "aae71e8db6d7" {
		t.Fatal("hash12")
	}
}

// FuzzJA4H: entradas arbitrárias não podem causar pânico e o fingerprint termina sempre nos três hashes (o
// primeiro bloco pode conter `_` vindo do Accept-Language, como na ferramenta oficial).
func FuzzJA4H(f *testing.F) {
	f.Add("GET", "HTTP/1.1", "Cookie", "a=1; b", "en-US,en")
	f.Add("", "HTTP/2", "cookie", "=", "")
	f.Fuzz(func(t *testing.T, method, version, name, value, lang string) {
		r := JA4H(JA4HInput{Method: method, Version: version, Fields: []JA4HField{
			{name, value}, {"Accept-Language", lang}, {"cookie", value},
		}})
		if !ja4hTail.MatchString(r.JA4H) || !ja4hTail.MatchString(r.JA4HO) {
			t.Fatalf("formato: %q", r.JA4H)
		}
	})
}

var ja4hTail = regexp.MustCompile(`_[0-9a-f]{12}_[0-9a-f]{12}_[0-9a-f]{12}$`)
