package bot

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// Lotes reais do traefix (task 273; spec 019 RF-12 e critério 2): gravados do container de teste no finger-01
// (tmsoftbrasil/traefix:latest, fork-point-218-g9f480d2e7) com clientes do teste (curl e Chrome no Mac do gerador),
// sem dados pessoais: o IP de origem do gerador foi trocado por um endereço de documentação (198.51.100.73 e
// 2001:db8:4400::5db6), no `src.ip` e no SYN cru, com as somas de verificação refeitas. O resto é o que o traefix
// mandou. Detalhes e a configuração em docs/dev/traefix-finger-01.md.

// realBatch é um lote real e o que o ingest tem de contar dele.
type realBatch struct {
	file     string
	connID   string
	accepted int
	proto    string // h1 | h2 | h3 | "" (conexão sem requisição)
	raw      bool   // rawBytes: true na entrada
}

var realBatches = []realBatch{
	{"h1-curl-v4.json", "01M7QBVHWC8YXNE7D0NV1KP9P7", 2, "h1", true},
	{"h2-curl-v4.json", "01M7QBJJG7Z53XKFPTPWQCVARH", 2, "h2", true},
	{"h2-chrome-v6.json", "01M7QBW4J9B5C4NB89NKHDB960", 2, "h2", true},
	{"h2-curl-v4-noraw.json", "01M7QCP7VCJZQB1EMWNKWVC4F0", 2, "h2", false},
	{"h3-curl-v4.json", "01M7QBT8JQDT8PW821WZFFEVWH", 2, "h3", true},
	{"h3-curl-v4-headerorder.json", "01M7QCP7XH744SSJ7QEGETARE6", 2, "h3", true},
	{"conn-only-chrome-v6.json", "01M7QBW4J9WRSDSTP9508JCTWM", 1, "", true},
	// task 313 (fork-point-223-g59c901c7b, headerDetail: full): timing em TCP e h3 e udp em h3. Os lotes de uma
	// conexão foram juntados num só (o registro de conexão do relay sai antes do de requisição), com os registros sem
	// mudança. Nos de relay (SOCKS5 por ssh -D até o finger-01), a origem era o IP público do próprio host, trocada
	// por 2001:db8:4400::86 e 203.0.113.86; o SYN veio do loopback com a soma TCP parcial e saiu com a soma refeita.
	{"h2-curl-v4-timing.json", "01M7TP8W4CAYFJEE8F9SSZHMVZ", 2, "h2", true},
	{"h2-curl-relay-v6.json", "01M7TPAMXBAC3TWH9RHMQBD8CC", 2, "h2", true},
	{"h2-curl-relay-v4.json", "01M7TPB2DHANTR2H12949RFE51", 2, "h2", true},
	{"h2-chrome-relay-v6.json", "01M7TPDYGT6TZTMFYE8MER1185", 2, "h2", true},
	{"h3-curl-v4-udp.json", "01M7TPH36A9SZGGNBPXEGVK7XP", 2, "h3", true},
	{"h3-chrome-v4-udp.json", "01M7TPHKDRNBJCZ558RYBZQ9RF", 3, "h3", true},
}

// timingCase é o que o veredito de um lote real da task 313 tem de mostrar dos tempos e do TTL.
type timingCase struct {
	file        string
	relay       bool  // relay_rtt_gap esperado
	tcpRTT      int64 // tcp_rtt_us do registro (0 = ausente, h3)
	gap         int64 // rtt_gap_us do registro
	ttlInitial  int   // TTL inicial esperado (do SYN em TCP, de udp.ttl em h3)
	relayDetail string
}

var timingCases = []timingCase{
	{"h2-curl-v4-timing.json", false, 9718, 1089, 64, ""},
	{"h2-curl-relay-v6.json", true, 28, 34438, 64, "rtt gap 34.4 ms, tcp rtt 0.0 ms, first byte after 227.0 ms"},
	// o host do finger-01 tem net.ipv4.ip_default_ttl=128 (sysctl do host): o SYN IPv4 do relay local sai com 128
	{"h2-curl-relay-v4.json", true, 20, 36072, 128, "rtt gap 36.1 ms, tcp rtt 0.0 ms, first byte after 14.1 ms"},
	{"h2-chrome-relay-v6.json", true, 23, 39906, 64, "rtt gap 39.9 ms, tcp rtt 0.0 ms, first byte after 11.2 ms"},
	{"h3-curl-v4-udp.json", false, 0, 0, 64, ""},
	{"h3-chrome-v4-udp.json", false, 0, 0, 64, ""},
}

// TestTraefixRealTiming: critérios da task 313 pelos lotes reais da fork-point-223 — os tempos do registro chegam ao
// Fingerprints do veredito, o relay (SOCKS5) sai com relay_rtt_gap e o direto não, h3 tem o TTL inicial de udp.ttl e
// nenhum tempo de TCP; a rodada sintética com a origem do relay trocada por loopback não aplica o sinal (ADR 0065
// item 3: com origem local o par da conexão TCP é um proxy local).
func TestTraefixRealTiming(t *testing.T) {
	for _, c := range timingCases {
		t.Run(c.file, func(t *testing.T) {
			b := realSample(t, c.file)
			sentAt, conn := realRecords(t, b)
			f := newFixture(t)
			f.clock.Advance(sentAt.Sub(f.clock.Now()))
			if code, got := f.postIngest(string(b)); code != 202 || got["rejected"] != 0 {
				t.Fatalf("ingest: %d %v", code, got)
			}
			v := f.verdictOf(str(conn, "connId"))
			ids := signalIDList(v.Signals)
			fp := v.Fingerprints
			if slices.Contains(ids, "relay_rtt_gap") != c.relay {
				t.Fatalf("relay_rtt_gap %v, quer %v: %v %+v", !c.relay, c.relay, ids, fp)
			}
			for _, s := range v.Signals {
				if s.ID == "relay_rtt_gap" && (s.Detail != c.relayDetail || s.Weight != 15) {
					t.Errorf("sinal: %+v", s)
				}
			}
			if fp.TTLInitial == nil || *fp.TTLInitial != c.ttlInitial {
				t.Errorf("ttl_initial %v, quer %d", fp.TTLInitial, c.ttlInitial)
			}
			if c.tcpRTT == 0 {
				if fp.TCPRTTMicros != nil || fp.RTTGapMicros != nil || !v.View.H3 || deref(fp.TimingSource) != timingUser {
					t.Errorf("h3: tempos de TCP %+v view %+v", fp, v.View)
				}
				return
			}
			if val(fp.TCPRTTMicros) != c.tcpRTT || val(fp.RTTGapMicros) != c.gap || fp.TLSRTTMicros == nil ||
				fp.EstToFirstMicros == nil || deref(fp.TimingSource) != timingKernel || !v.View.TCP {
				t.Errorf("tempos: %+v view %+v", fp, v.View)
			}
			if !c.relay {
				return
			}
			// rodada sintética: o mesmo lote com a origem em loopback descarta a visão TCP e o sinal
			src := str(conn, "src", "ip")
			lo := strings.Replace(string(b), `"ip": "`+src+`"`, `"ip": "127.0.0.1"`, 1)
			lo = strings.ReplaceAll(lo, str(conn, "connId"), "01M7TPAMXBAC3TWH9RHMQBD8ZZ")
			if code, got := f.postIngest(lo); code != 202 || got["rejected"] != 0 {
				t.Fatalf("ingest em loopback: %d %v", code, got)
			}
			vl := f.verdictOf("01M7TPAMXBAC3TWH9RHMQBD8ZZ")
			if slices.Contains(signalIDList(vl.Signals), "relay_rtt_gap") || vl.View.TCP || val(vl.Fingerprints.RTTGapMicros) != c.gap {
				t.Errorf("origem loopback: %v view %+v fp %+v", signalIDList(vl.Signals), vl.View, vl.Fingerprints)
			}
		})
	}
}

func realSample(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "ingest", "real", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// realRecords devolve o lote e o registro de conexão dele (o primeiro).
func realRecords(t *testing.T, b []byte) (sentAt time.Time, conn map[string]any) {
	t.Helper()
	var batch struct {
		SentAt  time.Time        `json:"sentAt"`
		Records []map[string]any `json:"records"`
	}
	if err := json.Unmarshal(b, &batch); err != nil {
		t.Fatal(err)
	}
	for _, r := range batch.Records {
		if r["type"] == "connection" {
			return batch.SentAt, r
		}
	}
	t.Fatal("lote real sem registro de conexão")
	return time.Time{}, nil
}

func str(m map[string]any, path ...string) string {
	var cur any = m
	for _, p := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur = mm[p]
	}
	s, _ := cur.(string)
	return s
}

// TestTraefixRealBatches: os lotes reais entram com rejected 0, sem parse_error, sem divergência entre as
// fingerprints prontas do traefix e as calculadas pelo bot (exceto ja4o, sem golden; ADR 0063 item 4), e a visão
// de cada um é a que o traefix mandou.
func TestTraefixRealBatches(t *testing.T) {
	for _, s := range realBatches {
		t.Run(s.file, func(t *testing.T) {
			b := realSample(t, s.file)
			sentAt, conn := realRecords(t, b)
			connID := str(conn, "connId")
			if s.connID != "" && connID != s.connID {
				t.Fatalf("connId %s, quer %s", connID, s.connID)
			}
			f := newFixture(t)
			f.clock.Advance(sentAt.Sub(f.clock.Now()))
			c, got := f.postIngest(string(b))
			if c != 202 || got["accepted"] != s.accepted || got["rejected"] != 0 {
				t.Fatalf("ingest: %d %v", c, got)
			}
			for _, part := range []string{PartClientHello, PartH2Prefix} {
				if n := f.metrics.Get(metricIngestParseErrors + `{part="` + part + `"}`); n != 0 {
					t.Errorf("parse_errors{%s} = %v", part, n)
				}
			}
			for _, k := range mismatchKinds {
				n := f.metrics.Get(mismatchMetric(k))
				switch {
				case n != 0 && k == mismatchJA4O:
					t.Logf("AVISO: divergência ja4o = %v (sem golden de JA4_o)", n)
				case n != 0:
					t.Errorf("divergência %s = %v", k, n)
				}
			}
			fc, ok := f.srv.Index().Fork(connID, f.clock.Now())
			if !ok || !fc.HasConnRecord || !fc.HasSrc {
				t.Fatalf("conexão fora do índice: %+v", fc)
			}
			if fc.TLS == nil || fc.TLS.ParseError || fc.TLS.JA4 != str(conn, "tls", "ja4") || fc.TLS.JA3MD5 != str(conn, "tls", "ja3") ||
				fc.TLS.Ready == s.raw {
				t.Errorf("tls: %+v, traefix ja4 %s ja3 %s", fc.TLS, str(conn, "tls", "ja4"), str(conn, "tls", "ja3"))
			}
			if s.proto == "h2" && (fc.H2 == nil || fc.H2.Akamai != str(conn, "http2", "akamai")) {
				t.Errorf("h2: %+v, traefix %s", fc.H2, str(conn, "http2", "akamai"))
			}
			switch s.proto {
			case "h3":
				// sem udp (fork-point-218) não há visão de transporte; com udp (fork-point-223) só o TTL, marcada UDP
				udp, hasUDP := conn["udp"].(map[string]any)
				switch {
				case !strings.HasPrefix(fc.TLS.JA4, "q"):
					t.Errorf("h3: ja4 %s", fc.TLS.JA4)
				case !hasUDP && fc.TCP != nil:
					t.Errorf("h3 sem udp com visão de transporte: %+v", fc.TCP)
				case hasUDP && (fc.TCP == nil || !fc.TCP.UDP || fc.TCP.JA4T != "" || float64(fc.TCP.TTL) != udp["ttl"]):
					t.Errorf("h3: visão UDP %+v, udp do traefix %v", fc.TCP, udp)
				}
			default:
				if fc.TCP == nil || fc.TCP.JA4T != str(conn, "tcp", "ja4t") {
					t.Errorf("tcp: %+v, traefix %s", fc.TCP, str(conn, "tcp", "ja4t"))
				}
			}
			if s.proto == "" && len(fc.Requests) != 0 {
				t.Errorf("conexão sem requisição com %d requisições", len(fc.Requests))
			}
			if s.proto != "" && len(fc.Requests) != s.accepted-1 {
				t.Errorf("requisições: %d", len(fc.Requests))
			}
		})
	}
}

// ja4tOneDigitScale acha o tcp.ja4t com a escala de janela de 1 dígito (macOS 6, Linux 7), que o padrão do
// esquema publicado pelo traefix ainda recusa (pedido PT-11 da spec 019).
var ja4tOneDigitScale = regexp.MustCompile(`("ja4t": "[0-9]+_[0-9-]+_[0-9]+_[0-9]")`)

// TestTraefixRealBatchesContract: os lotes reais validam contra o TraefixFingerprintBatch do openapi e contra a
// cópia do esquema do traefix. Para a cópia, enquanto o PT-11 não for entregue, o tcp.ja4t de escala com 1 dígito
// sai do lote (o resto do registro é conferido); o openapi valida o lote inteiro.
func TestTraefixRealBatchesContract(t *testing.T) {
	if testing.Short() {
		t.Skip("contrato via Redocly pulado com -short")
	}
	var vals, forCopy [][]byte
	for _, s := range realBatches {
		b := realSample(t, s.file)
		vals = append(vals, b)
		forCopy = append(forCopy, ja4tOneDigitScale.ReplaceAll(b, []byte(`"ja4tRemovedForPT11": "x"`)))
	}
	for _, ref := range []string{refTraefixBatch, refTraefixIngestBody} {
		if out, err := lintContractWith(t, ref, true, nil, vals...); err != nil {
			t.Fatalf("lotes reais não validam contra %s: %v\n%s", ref, err, out)
		}
	}
	if out, err := lintTraefixCopy(t, forCopy...); err != nil {
		t.Fatalf("lotes reais não validam contra a cópia do esquema do traefix: %v\n%s", err, out)
	}
	// o desvio do PT-11 continua lá: se a cópia passar a aceitar o lote inteiro, o PT-11 foi entregue e o
	// contorno acima sai
	if out, err := lintTraefixCopy(t, vals...); err == nil {
		t.Logf("AVISO: a cópia do esquema já aceita o tcp.ja4t de 1 dígito (PT-11 entregue?): retire o contorno\n%s", out)
	}
}
