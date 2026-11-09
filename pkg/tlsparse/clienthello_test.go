package tlsparse

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

// tsharkLayers são os campos extraídos pelo tshark 4.4 (testdata/regen.sh) de um ClientHello.
type tsharkLayers map[string][]string

func loadTshark(t *testing.T, name string) tsharkLayers {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name+".tshark.json"))
	if err != nil {
		t.Fatal(err)
	}
	var pkts []struct {
		Source struct {
			Layers tsharkLayers `json:"layers"`
		} `json:"_source"`
	}
	if err := json.Unmarshal(b, &pkts); err != nil {
		t.Fatal(err)
	}
	if len(pkts) != 1 {
		t.Fatalf("%s: %d pacotes com ClientHello no gabarito, esperado 1", name, len(pkts))
	}
	return pkts[0].Source.Layers
}

func samples(t *testing.T) []string {
	t.Helper()
	m, err := filepath.Glob("testdata/*.bin")
	if err != nil {
		t.Fatal(err)
	}
	if len(m) < 10 {
		t.Fatalf("só %d amostras em testdata", len(m))
	}
	var out []string
	for _, p := range m {
		out = append(out, strings.TrimSuffix(filepath.Base(p), ".bin"))
	}
	return out
}

func readSample(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name+".bin"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func hex16(v []uint16) []string {
	out := []string{}
	for _, x := range v {
		out = append(out, fmt.Sprintf("0x%04x", x))
	}
	return out
}

func dec[T uint8 | uint16 | int](v []T) []string {
	out := []string{}
	for _, x := range v {
		out = append(out, strconv.Itoa(int(x)))
	}
	return out
}

// tsharkString imita a exibição do tshark para bytes que não são UTF-8 válido: cada byte inválido vira
// U+FFFD.
func tsharkString(s string) string {
	var b strings.Builder
	for len(s) > 0 {
		r, n := utf8.DecodeRuneInString(s)
		if r == utf8.RuneError && n == 1 {
			b.WriteRune(utf8.RuneError)
		} else {
			b.WriteString(s[:n])
		}
		s = s[n:]
	}
	return b.String()
}

func strs(v []string) []string {
	out := []string{}
	for _, s := range v {
		out = append(out, tsharkString(s))
	}
	return out
}

func orEmpty(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

// TestParseMatchesTshark confere cada campo da spec 008 RF-02 contra o tshark 4.4 sobre os mesmos bytes.
func TestParseMatchesTshark(t *testing.T) {
	for _, name := range samples(t) {
		t.Run(name, func(t *testing.T) {
			raw := readSample(t, name)
			ch, err := Parse(raw)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if len(ch.ExtensionErrors) > 0 {
				t.Fatalf("erros de extensão: %v", ch.ExtensionErrors)
			}
			ts := loadTshark(t, name)
			check := func(field string, got []string) {
				t.Helper()
				want := orEmpty(ts[field])
				if !slices.Equal(got, want) {
					t.Errorf("%s:\n got %v\nwant %v", field, got, want)
				}
			}
			// o tshark repete a versão de cada registro; todos os registros das amostras têm a mesma
			rv := slices.Repeat([]string{fmt.Sprintf("0x%04x", ch.RecordVersion)}, ch.Records)
			check("tls.record.version", rv)
			check("tls.handshake.version", []string{fmt.Sprintf("0x%04x", ch.HandshakeVersion)})
			check("tls.handshake.random", []string{hex.EncodeToString(ch.Random)})
			check("tls.handshake.session_id_length", []string{strconv.Itoa(len(ch.SessionID))})
			check("tls.handshake.ciphersuite", hex16(ch.CipherSuites))
			check("tls.handshake.comp_method", dec(ch.CompressionMethods))
			var types, lens []string
			var sigs []uint16
			for _, e := range ch.Extensions {
				types = append(types, strconv.Itoa(int(e.Type)))
				lens = append(lens, strconv.Itoa(len(e.Data)))
				// o tshark usa o mesmo campo para os três vetores de algoritmos, na ordem das extensões
				switch e.Type {
				case ExtSignatureAlgorithms:
					sigs = append(sigs, ch.SignatureAlgorithms...)
				case ExtSignatureAlgsCert:
					sigs = append(sigs, ch.SignatureAlgorithmsCert...)
				case ExtDelegatedCredentials:
					sigs = append(sigs, ch.DelegatedCredentials...)
				}
			}
			check("tls.handshake.extension.type", orEmpty(types))
			check("tls.handshake.extension.len", orEmpty(lens))
			var sni []string
			if ch.HasSNI {
				sni = []string{ch.SNI}
			}
			check("tls.handshake.extensions_server_name", orEmpty(sni))
			check("tls.handshake.extensions_alpn_str", strs(ch.ALPN))
			check("tls.handshake.extensions_supported_group", hex16(ch.SupportedGroups))
			check("tls.handshake.extensions_ec_point_format", dec(ch.ECPointFormats))
			check("tls.handshake.sig_hash_alg", hex16(sigs))
			check("tls.handshake.extensions.supported_version", hex16(ch.SupportedVersions))
			var ksg, ksl []int
			for _, k := range ch.KeyShares {
				ksg = append(ksg, int(k.Group))
				ksl = append(ksl, k.Length)
			}
			check("tls.handshake.extensions_key_share_group", dec(ksg))
			check("tls.handshake.extensions_key_share_key_exchange_length", dec(ksl))
			check("tls.extension.psk_ke_mode", dec(ch.PSKModes))
			check("tls.compress_certificate.algorithm", dec(ch.CompressCertificate))
			var rsl []string
			if ch.RecordSizeLimit >= 0 {
				rsl = []string{strconv.Itoa(ch.RecordSizeLimit)}
			}
			check("tls.record_size_limit", orEmpty(rsl))
			// o tshark 4.4 só decodifica o ALPS no codepoint antigo (17513)
			var alpsOld []string
			for _, e := range ch.Extensions {
				if e.Type == ExtALPSOld {
					r := reader{buf: e.Data}
					v, _ := protocolList(&r)
					alpsOld = append(alpsOld, v...)
				}
			}
			check("tls.handshake.extensions_alps_alpn_str", strs(alpsOld))

			// presença das extensões com flag
			if ch.PaddingLen >= 0 != ch.HasExtension(ExtPadding) ||
				ch.StatusRequest != ch.HasExtension(ExtStatusRequest) ||
				ch.SessionTicket != ch.HasExtension(ExtSessionTicket) ||
				ch.EncryptedClientHello != ch.HasExtension(ExtEncryptedClientHello) ||
				ch.PreSharedKey != ch.HasExtension(ExtPreSharedKey) ||
				ch.EarlyData != ch.HasExtension(ExtEarlyData) {
				t.Error("flag de presença diverge da lista de extensões")
			}
			if !strings.HasSuffix(name, "2records") && ch.Records != 1 {
				t.Errorf("Records = %d, esperado 1", ch.Records)
			}
		})
	}
}

func TestTwoRecords(t *testing.T) {
	two, err := Parse(readSample(t, "chrome-2records"))
	if err != nil {
		t.Fatal(err)
	}
	one, err := Parse(readSample(t, "chrome"))
	if err != nil {
		t.Fatal(err)
	}
	if two.Records != 2 || one.Records != 1 {
		t.Fatalf("Records = %d e %d, esperado 2 e 1", two.Records, one.Records)
	}
	if !slices.Equal(two.Raw, one.Raw) {
		t.Fatal("mensagem remontada de 2 registros difere da de 1 registro")
	}
	if in := NewInfo(two, readSample(t, "chrome-2records"), 0); in.ClientHelloRecords != 2 {
		t.Fatalf("client_hello_records = %d", in.ClientHelloRecords)
	}
}

// splitRecords reparte a mensagem do primeiro registro em registros de no máximo size bytes.
func splitRecords(rec []byte, size int) []byte {
	msg := rec[RecordHeaderLen:]
	var out []byte
	for len(msg) > 0 {
		n := min(size, len(msg))
		out = append(out, rec[0], rec[1], rec[2], byte(n>>8), byte(n))
		out = append(out, msg[:n]...)
		msg = msg[n:]
	}
	return out
}

func TestManyTinyRecords(t *testing.T) {
	rec := readSample(t, "firefox")
	data := splitRecords(rec, 1) // até o cabeçalho de handshake chega byte a byte
	ch, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if ch.Records != len(rec)-RecordHeaderLen || ch.SNI != "localhost" {
		t.Fatalf("Records=%d SNI=%q", ch.Records, ch.SNI)
	}
}

func TestReassembleExtraBytes(t *testing.T) {
	rec := readSample(t, "go")
	// registro seguinte (ChangeCipherSpec) no mesmo buffer: não entra na captura
	data := append(append([]byte{}, rec...), 0x14, 0x03, 0x03, 0x00, 0x01, 0x01)
	r, err := Reassemble(data)
	if err != nil {
		t.Fatal(err)
	}
	if r.Consumed != len(rec) || r.Records != 1 {
		t.Fatalf("Consumed=%d Records=%d", r.Consumed, r.Records)
	}
	// mensagem e mais bytes de handshake no mesmo registro: a mensagem para no tamanho declarado
	msg := rec[RecordHeaderLen:]
	body := append(append([]byte{}, msg...), 0x0f, 0, 0, 0)
	data = append([]byte{0x16, 0x03, 0x01, byte(len(body) >> 8), byte(len(body))}, body...)
	r, err = Reassemble(data)
	if err != nil || len(r.Message) != len(msg) {
		t.Fatalf("err=%v len=%d", err, len(r.Message))
	}
}

func TestTruncated(t *testing.T) {
	rec := readSample(t, "chrome")
	full, err := Parse(rec)
	if err != nil {
		t.Fatal(err)
	}
	for _, cut := range []int{0, 3, 5, 8, 9, 40, 43, 76, 77, 120, 300, 1000, len(rec) - 1} {
		ch, err := Parse(rec[:cut])
		if !errors.Is(err, ErrIncomplete) {
			t.Fatalf("corte %d: err = %v, esperado ErrIncomplete", cut, err)
		}
		if ch == nil {
			t.Fatalf("corte %d: ClientHello nil", cut)
		}
		// o que veio é prefixo do completo
		if len(ch.Extensions) > len(full.Extensions) || len(ch.CipherSuites) > len(full.CipherSuites) {
			t.Fatalf("corte %d: mais campos que o completo", cut)
		}
		for i, e := range ch.Extensions {
			if e.Type != full.Extensions[i].Type || !slices.Equal(e.Data, full.Extensions[i].Data) {
				t.Fatalf("corte %d: extensão %d diverge", cut, i)
			}
		}
	}
	// corte no meio das extensões preserva as que chegaram inteiras
	ch, _ := Parse(rec[:1000])
	if len(ch.Extensions) == 0 || len(ch.CipherSuites) != len(full.CipherSuites) {
		t.Fatalf("corte 1000: %d extensões, %d cifras", len(ch.Extensions), len(ch.CipherSuites))
	}
}

func TestGREASE(t *testing.T) {
	rec := readSample(t, "chrome")
	ch, err := Parse(rec)
	if err != nil {
		t.Fatal(err)
	}
	in := NewInfo(ch, rec, 0)
	if !in.CipherSuites[0].GREASE || in.CipherSuites[0].Name != "GREASE" {
		t.Fatalf("primeira cifra do Chrome deveria ser GREASE: %+v", in.CipherSuites[0])
	}
	if in.CipherSuites[1].GREASE || in.CipherSuites[1].Name != "TLS_AES_128_GCM_SHA256" {
		t.Fatalf("segunda cifra: %+v", in.CipherSuites[1])
	}
	if !in.Extensions[0].GREASE || !in.Extensions[len(in.Extensions)-1].GREASE {
		t.Fatal("primeira e última extensões do Chrome são GREASE")
	}
	if !in.SupportedGroups[0].GREASE || !in.SupportedVersions[0].GREASE || !in.KeyShare[0].Group.GREASE {
		t.Fatal("GREASE não marcado em groups/versions/key_share")
	}
	if in.SupportedGroups[1].Name != "X25519MLKEM768" {
		t.Fatalf("grupo: %+v", in.SupportedGroups[1])
	}
}

func TestInfoJSON(t *testing.T) {
	rec := readSample(t, "openssl3-tls10")
	ch, err := Parse(rec)
	if err != nil {
		t.Fatal(err)
	}
	in := NewInfo(ch, rec, 0)
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	// listas nunca nulas; opcionais anuláveis presentes como null
	for _, k := range []string{
		"cipher_suites", "compression_methods", "extensions", "alpn", "supported_groups", "ec_point_formats",
		"signature_algorithms", "supported_versions", "key_share", "psk_key_exchange_modes",
		"compress_certificate", "alps", "delegated_credentials", "alerts",
	} {
		if _, ok := m[k].([]any); !ok {
			t.Errorf("%s = %#v, esperado lista", k, m[k])
		}
	}
	for _, k := range []string{"negotiated", "handshake_ms", "padding_len", "record_size_limit"} {
		if v, ok := m[k]; !ok || v != nil {
			t.Errorf("%s = %#v, esperado null", k, v)
		}
	}
	if _, ok := m["ja4"]; ok {
		t.Error("ja4 vazio não deveria sair")
	}
	if m["sni"] != "example.com" || m["client_hello_records"] != 1.0 || m["handshake_version"] != 769.0 {
		t.Errorf("sni=%v records=%v version=%v", m["sni"], m["client_hello_records"], m["handshake_version"])
	}
	if m["client_hello_b64"] == "" || m["client_hello_truncated"] != nil {
		t.Error("client_hello_b64 deveria vir inteiro e sem truncated")
	}

	// SNI ausente vira null; padding e record_size_limit presentes viram números
	rec = readSample(t, "firefox")
	ch, _ = Parse(rec)
	in = NewInfo(ch, rec, 100)
	if !in.ClientHelloTruncated || len(in.ClientHelloB64) != 100 {
		t.Fatalf("inline: truncated=%v len=%d", in.ClientHelloTruncated, len(in.ClientHelloB64))
	}
	if in.RecordSizeLimit == nil || *in.RecordSizeLimit != 16385 {
		t.Fatalf("record_size_limit = %v", in.RecordSizeLimit)
	}
	if len(in.DelegatedCredentials) == 0 || in.DelegatedCredentials[0].Name != "ecdsa_secp256r1_sha256" {
		t.Fatalf("delegated_credentials = %+v", in.DelegatedCredentials)
	}
	if !in.EncryptedClientHello || in.Extensions[0].Name != "server_name" {
		t.Fatal("ECH ou nome da extensão")
	}

	ch, _ = Parse(readSample(t, "chrome"))
	in = NewInfo(ch, nil, 0)
	if in.PaddingLen != nil || len(in.ALPS) != 1 || in.ALPS[0] != "h2" || in.ClientHelloB64 == nil {
		t.Fatalf("chrome: padding=%v alps=%v", in.PaddingLen, in.ALPS)
	}
	ch, _ = Parse(readSample(t, "foxio-non-ascii-alpn"))
	in = NewInfo(ch, nil, 0)
	if in.PaddingLen == nil || !slices.Equal(ch.ALPSCodepoints, []uint16{ExtALPSOld}) {
		t.Fatalf("padding=%v alps=%v", in.PaddingLen, ch.ALPSCodepoints)
	}
	a := NewAlert("in", 2, 40)
	if a.Name != "handshake_failure" {
		t.Fatalf("alerta: %+v", a)
	}
}

func TestNoSNI(t *testing.T) {
	ch, err := ParseMessage(buildHello(nil))
	if err != nil {
		t.Fatal(err)
	}
	in := NewInfo(ch, nil, 0)
	if in.SNI != nil || ch.HasSNI || len(ch.Extensions) != 0 {
		t.Fatal("ClientHello sem extensões")
	}
}

// buildHello monta uma mensagem ClientHello mínima com as extensões dadas (já codificadas).
func buildHello(exts []byte) []byte {
	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)                // session id
	body = append(body, 0, 2, 0x13, 0x01) // cipher suites
	body = append(body, 1, 0)             // compressão
	if exts != nil {
		body = append(body, byte(len(exts)>>8), byte(len(exts)))
		body = append(body, exts...)
	}
	n := len(body)
	return append([]byte{1, byte(n >> 16), byte(n >> 8), byte(n)}, body...)
}

func ext(typ uint16, data ...byte) []byte {
	return append([]byte{byte(typ >> 8), byte(typ), byte(len(data) >> 8), byte(len(data))}, data...)
}

func TestMalformedExtensions(t *testing.T) {
	cases := map[string][]byte{
		"sni":            ext(ExtServerName, 0, 5, 0, 0, 9, 'a'),
		"sni-trailing":   ext(ExtServerName, 0, 0, 1),
		"sni-entry":      ext(ExtServerName, 0, 1, 0),
		"sni-name":       ext(ExtServerName, 0, 2, 0, 0),
		"groups-odd":     ext(ExtSupportedGroups, 0, 1, 0),
		"groups":         ext(ExtSupportedGroups, 0),
		"points":         ext(ExtECPointFormats, 3, 0),
		"points-trail":   ext(ExtECPointFormats, 1, 0, 0),
		"sigalgs":        ext(ExtSignatureAlgorithms, 0, 4, 4),
		"sigalgs-cert":   ext(ExtSignatureAlgsCert, 0, 4, 4),
		"alpn":           ext(ExtALPN, 0, 3, 5, 'h', '2'),
		"alpn-list":      ext(ExtALPN, 0),
		"cc":             ext(ExtCompressCertificate, 5, 0),
		"cc-odd":         ext(ExtCompressCertificate, 1, 2),
		"rsl":            ext(ExtRecordSizeLimit, 1),
		"dc":             ext(ExtDelegatedCredentials, 0, 3, 4, 3, 1),
		"psk":            ext(ExtPreSharedKey, 0, 9),
		"psk-id":         ext(ExtPreSharedKey, 0, 3, 0, 1, 'x'),
		"psk-age":        ext(ExtPreSharedKey, 0, 5, 0, 1, 'x', 0, 0),
		"psk-binders":    ext(ExtPreSharedKey, 0, 7, 0, 1, 'x', 0, 0, 0, 0),
		"versions":       ext(ExtSupportedVersions, 4, 3, 4),
		"versions-odd":   ext(ExtSupportedVersions, 1, 3),
		"psk-modes":      ext(ExtPSKKeyExchangeModes, 2, 1),
		"keyshare":       ext(ExtKeyShare, 0, 9),
		"keyshare-group": ext(ExtKeyShare, 0, 1, 0),
		"keyshare-key":   ext(ExtKeyShare, 0, 4, 0, 0x1d, 0, 9),
		"alps":           ext(ExtALPS, 0, 3, 2, 'h'),
	}
	for name, e := range cases {
		t.Run(name, func(t *testing.T) {
			// a extensão ruim no meio de duas boas: as boas continuam decodificadas
			exts := append(ext(ExtStatusRequest, 1, 0, 0, 0, 0), e...)
			exts = append(exts, ext(ExtEarlyData)...)
			ch, err := ParseMessage(buildHello(exts))
			if err != nil {
				t.Fatalf("erro de extensão virou erro do ClientHello: %v", err)
			}
			if len(ch.ExtensionErrors) != 1 || len(ch.Extensions) != 3 || !ch.StatusRequest || !ch.EarlyData {
				t.Fatalf("errors=%v exts=%d", ch.ExtensionErrors, len(ch.Extensions))
			}
			var pe *ParseError
			if !errors.As(ch.ExtensionErrors[0], &pe) || pe.Offset == 0 || pe.Error() == "" {
				t.Fatalf("ParseError: %v", ch.ExtensionErrors[0])
			}
		})
	}
}

func TestValidExtensions(t *testing.T) {
	exts := ext(ExtPreSharedKey, 0, 7, 0, 1, 'x', 0, 0, 0, 1, 0, 3, 2, 0xaa, 0xbb)
	exts = append(exts, ext(ExtSessionTicket, 1, 2, 3)...)
	exts = append(exts, ext(ExtServerName, 0, 8, 1, 0, 1, 'z', 0, 0, 1, 'h')...)
	ch, err := ParseMessage(buildHello(exts))
	if err != nil || len(ch.ExtensionErrors) > 0 {
		t.Fatal(err, ch.ExtensionErrors)
	}
	if !ch.PreSharedKey || ch.PSKIdentities != 1 || ch.SessionTicketLen != 3 || ch.SNI != "h" {
		t.Fatalf("%+v", ch)
	}
}

func TestMalformedHello(t *testing.T) {
	good := buildHello(ext(ExtEarlyData))
	cases := map[string][]byte{
		"empty":       {},
		"header":      {1, 0, 0},
		"version":     {1, 0, 0, 1, 3},
		"random":      append([]byte{1, 0, 0, 10, 3, 3}, make([]byte, 8)...),
		"session-id":  good[:4+2+32+1][:4+2+32],
		"ciphers":     good[:4+2+32+1+1],
		"compression": good[:4+2+32+1+4],
		"ext-type":    append(buildHello([]byte{0}), 0),
		"ext-len":     buildHello([]byte{0, 0x2a, 0}),
		"ext-data":    buildHello([]byte{0, 0x2a, 0, 5, 1}),
	}
	for name, msg := range cases {
		msg = slices.Clone(msg)
		t.Run(name, func(t *testing.T) {
			// cabeçalho declara o tamanho do que veio, para isolar o campo ruim
			if len(msg) >= 4 && name != "header" && name != "version" {
				n := len(msg) - 4
				msg[1], msg[2], msg[3] = byte(n>>16), byte(n>>8), byte(n)
			}
			ch, err := ParseMessage(msg)
			if err == nil || ch == nil {
				t.Fatalf("err=%v", err)
			}
		})
	}
	if _, err := ParseMessage([]byte{2, 0, 0, 0}); !errors.Is(err, ErrNotClientHello) {
		t.Fatal(err)
	}
	// corpo maior que o declarado: o excesso é ignorado
	long := append(append([]byte{}, good...), 0xff, 0xff)
	if _, err := ParseMessage(long); err != nil {
		t.Fatal(err)
	}
	// corpo menor que o declarado depois da compressão (sem extensões)
	short := buildHello(nil)
	short[3] += 5
	if _, err := ParseMessage(short); err == nil {
		t.Fatal("corpo cortado sem erro")
	}
	short = buildHello(ext(ExtEarlyData))
	short[3] += 5
	if _, err := ParseMessage(short); err == nil {
		t.Fatal("corpo cortado sem erro")
	}
}

func TestReassembleErrors(t *testing.T) {
	rec := readSample(t, "go")
	cases := []struct {
		name string
		data []byte
		want error
	}{
		{"alert", []byte{0x15, 0x03, 0x03, 0, 2, 2, 40}, ErrNotHandshake},
		{"http", []byte("GET / HTTP/1.1\r\n"), ErrNotHandshake},
		{"sslv2-version", []byte{0x16, 0x02, 0x00, 0, 4, 1, 0, 0, 0}, ErrNotHandshake},
		{"server-hello", []byte{0x16, 0x03, 0x03, 0, 4, 2, 0, 0, 0}, ErrNotClientHello},
		{"too-large", []byte{0x16, 0x03, 0x01, 0, 4, 1, 0x01, 0, 1}, ErrTooLarge},
		{"short", rec[:3], ErrIncomplete},
	}
	for _, c := range cases {
		if _, err := Reassemble(c.data); !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, esperado %v", c.name, err, c.want)
		}
	}
	// registro de outro tipo no meio da mensagem
	msg := rec[RecordHeaderLen:]
	data := append([]byte{0x16, 0x03, 0x01, 0, 10}, msg[:10]...)
	data = append(data, 0x17, 0x03, 0x03, 0, 1, 0)
	if _, err := Reassemble(data); err == nil || errors.Is(err, ErrIncomplete) {
		t.Fatalf("err = %v", err)
	}
	if _, err := Parse(data); err == nil {
		t.Fatal("Parse sem erro")
	}
}
