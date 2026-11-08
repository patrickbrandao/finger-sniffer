package store

import (
	"bufio"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/patrickbrandao/finger-sniffer/pkg/fingerprint/p0f"
)

// Golden pcaps da task 013 (test/golden/pcaps): cada pcap passa pelo ingest e o registro de cada conexão é
// comparado com as saídas de referência geradas na vps602 sobre o mesmo arquivo — tshark (RTT do handshake,
// retransmissões, segmentos, keepalives), ja4 da FoxIO (JA4T) e p0f -r (assinatura e SO).

const goldenDir = "../../test/golden/pcaps"

// tsharkPkt é um pacote do tshark -T json -e ... (cada campo vem como lista de strings).
type tsharkPkt struct {
	Source struct {
		Layers map[string][]string `json:"layers"`
	} `json:"_source"`
}

func (p tsharkPkt) get(k string) string {
	if v := p.Source.Layers[k]; len(v) > 0 {
		return v[0]
	}
	return ""
}

func (p tsharkPkt) has(k string) bool { _, ok := p.Source.Layers[k]; return ok }

func (p tsharkPkt) srcAddr() string {
	if a := p.get("ip.src"); a != "" {
		return a
	}
	return p.get("ipv6.src")
}

// goldenFlow é o que o tshark diz de uma conexão.
type goldenFlow struct {
	cliPort             int
	rttMs               float64
	hasRTT              bool
	segsIn, segsOut     int
	retxIn, retxOut     int
	keepalives          int
	ja4t, p0fSig, p0fOS string
}

func loadGolden(t *testing.T, name string) map[int]*goldenFlow {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(goldenDir, name+".tshark.json")) //nolint:gosec // testdata
	if err != nil {
		t.Fatal(err)
	}
	var pkts []tsharkPkt
	if err := json.Unmarshal(b, &pkts); err != nil {
		t.Fatal(err)
	}
	type st struct {
		client string
		synAck bool
		f      *goldenFlow
	}
	streams := map[string]*st{}
	flows := map[int]*goldenFlow{}
	for _, p := range pkts {
		s := streams[p.get("tcp.stream")]
		flags, _ := strconv.ParseUint(strings.TrimPrefix(p.get("tcp.flags"), "0x"), 16, 16)
		src, sport := p.srcAddr(), p.get("tcp.srcport")
		if s == nil {
			if flags&0x12 != 0x02 {
				continue // fluxo sem SYN no pcap
			}
			port, _ := strconv.Atoi(sport)
			s = &st{client: src + "/" + sport, f: &goldenFlow{cliPort: port}}
			streams[p.get("tcp.stream")] = s
			flows[port] = s.f
		}
		fromCli := src+"/"+sport == s.client
		f := s.f
		retx := p.has("tcp.analysis.retransmission")
		if fromCli {
			f.segsIn++
			if retx {
				f.retxIn++
			}
			if p.has("tcp.analysis.keep_alive") {
				f.keepalives++
			}
			if s.synAck && !f.hasRTT && flags == 0x10 {
				if v := p.get("tcp.analysis.ack_rtt"); v != "" {
					x, _ := strconv.ParseFloat(v, 64)
					f.rttMs, f.hasRTT = x*1000, true
				}
			}
		} else {
			f.segsOut++
			if retx {
				f.retxOut++
			}
			if flags&0x12 == 0x12 {
				s.synAck = true
			}
		}
	}
	// JA4T (ja4 -j, um objeto por fluxo)
	if fh, err := os.Open(filepath.Join(goldenDir, name+".ja4.jsonl")); err == nil {
		sc := bufio.NewScanner(fh)
		for sc.Scan() {
			var j struct {
				SrcPort int    `json:"src_port"`
				JA4T    string `json:"ja4t"`
			}
			if json.Unmarshal(sc.Bytes(), &j) == nil {
				if f := flows[j.SrcPort]; f != nil && f.ja4t == "" {
					f.ja4t = j.JA4T
				}
			}
		}
		_ = fh.Close()
	}
	// p0f -r (só as observações syn: cli=<ip>/<porta>)
	if raw, err := os.ReadFile(filepath.Join(goldenDir, name+".p0f.txt")); err == nil { //nolint:gosec // testdata
		for _, line := range strings.Split(string(raw), "\n") {
			if !strings.Contains(line, " mod=syn|") {
				continue
			}
			kv := map[string]string{}
			for _, part := range strings.Split(line[strings.Index(line, "mod="):], "|") {
				k, v, _ := strings.Cut(part, "=")
				kv[k] = v
			}
			cli := kv["cli"]
			port, _ := strconv.Atoi(cli[strings.LastIndexByte(cli, '/')+1:])
			if f := flows[port]; f != nil && f.p0fSig == "" {
				f.p0fSig, f.p0fOS = kv["raw_sig"], kv["os"]
			}
		}
	}
	return flows
}

func TestGoldenPcaps(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(goldenDir, "*.pcap"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 8 {
		t.Fatalf("só %d golden pcaps em %s (task 013 pede >= 8)", len(files), goldenDir)
	}
	conns := 0
	for _, file := range files {
		name := strings.TrimSuffix(filepath.Base(file), ".pcap")
		t.Run(name, func(t *testing.T) {
			want := loadGolden(t, name)
			in, db := newTestIngestor(t, func(c *IngestConfig) { c.P0F = goldenP0F(t) })
			run(t, in, 0, pcapBatch(t, file))
			if err := in.Finalize(t.Context(), in.flows.due(math.MaxInt64)); err != nil {
				t.Fatal(err)
			}
			rows, err := db.Query("SELECT record_json FROM connections")
			if err != nil {
				t.Fatal(err)
			}
			got := map[int]connectionJSON{}
			for rows.Next() {
				var s string
				var r connectionJSON
				if err := rows.Scan(&s); err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal([]byte(s), &r); err != nil {
					t.Fatal(err)
				}
				got[r.Src.Port] = r
			}
			_ = rows.Close()
			for port, w := range want {
				if !w.hasRTT {
					continue // sem handshake completo: vira pacote avulso
				}
				r, ok := got[port]
				if !ok {
					t.Errorf("porta %d: conexão não registrada", port)
					continue
				}
				conns++
				tc := r.TCP
				if tc.RTTHandshakeMs == nil || math.Abs(*tc.RTTHandshakeMs-w.rttMs) >= 0.1 {
					t.Errorf("porta %d: rtt = %v, tshark = %.6f", port, tc.RTTHandshakeMs, w.rttMs)
				}
				if w.ja4t != "" && (tc.JA4T == nil || *tc.JA4T != w.ja4t) {
					t.Errorf("porta %d: ja4t = %v, ja4 = %s", port, deref(tc.JA4T), w.ja4t)
				}
				if w.p0fSig != "" && (tc.P0F == nil || *tc.P0F != w.p0fSig) {
					t.Errorf("porta %d: p0f = %v, p0f -r = %s", port, deref(tc.P0F), w.p0fSig)
				}
				if w.p0fOS != "" && len(in.flows.p0f.TCPRecords(true)) > 0 {
					guess := "???"
					if tc.OSGuess != nil {
						guess = *tc.OSGuess
					}
					if guess != w.p0fOS {
						t.Errorf("porta %d: os = %s, p0f -r = %s", port, guess, w.p0fOS)
					}
				}
				if r.Totals.In.Segments != w.segsIn || r.Totals.Out.Segments != w.segsOut {
					t.Errorf("porta %d: segmentos = %d/%d, tshark = %d/%d", port, r.Totals.In.Segments, r.Totals.Out.Segments, w.segsIn, w.segsOut)
				}
				if r.Totals.In.Retransmits != w.retxIn || r.Totals.Out.Retransmits != w.retxOut {
					t.Errorf("porta %d: retransmissões = %d/%d, tshark = %d/%d", port, r.Totals.In.Retransmits, r.Totals.Out.Retransmits, w.retxIn, w.retxOut)
				}
				if len(tc.KeepaliveProbes) != w.keepalives {
					t.Errorf("porta %d: keepalives = %d, tshark = %d", port, len(tc.KeepaliveProbes), w.keepalives)
				}
			}
		})
	}
	t.Logf("%d conexões conferidas contra tshark, ja4 e p0f -r", conns)
}

// goldenP0F carrega o p0f.fp real (FS_P0F_DB ou o do deploy) para conferir o palpite de SO; sem ele o teste
// confere só a assinatura crua (o p0f.fp é LGPL e não vai para o repositório).
func goldenP0F(t *testing.T) *p0f.DB {
	t.Helper()
	path := os.Getenv("FS_P0F_DB")
	if path == "" {
		path = "/finger-sniffer/etc/p0f.fp"
	}
	db, err := p0f.LoadDB(path)
	if err != nil {
		return nil
	}
	return db
}

func deref(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}
