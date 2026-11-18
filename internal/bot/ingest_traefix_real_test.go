package bot

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
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
				if fc.TCP != nil || !strings.HasPrefix(fc.TLS.JA4, "q") {
					t.Errorf("h3: tcp %+v ja4 %s", fc.TCP, fc.TLS.JA4)
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
