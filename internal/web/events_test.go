package web

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/h1"
)

var update = flag.Bool("update", false, "regrava os exemplos em testdata/events")

// TestStreamDir: pedaços de até 64 KiB com offsets contínuos e, passado o teto, um pedaço vazio truncated.
func TestStreamDir(t *testing.T) {
	var got []event.StreamBytes
	s := streamDir{dir: "in", max: 150 << 10, emit: func(b event.StreamBytes) { got = append(got, b) }}
	s.add(bytes.Repeat([]byte("a"), 70<<10))
	s.add(bytes.Repeat([]byte("b"), 10))
	s.flush()
	s.add(bytes.Repeat([]byte("c"), 100<<10)) // passa do teto
	s.add([]byte("ignored"))
	s.flush()
	var off int64
	for i, b := range got[:len(got)-1] {
		if b.Offset != off || len(b.Data) > event.StreamChunkBytes || b.Truncated {
			t.Fatalf("chunk %d offset %d len %d", i, b.Offset, len(b.Data))
		}
		off += int64(len(b.Data))
	}
	last := got[len(got)-1]
	if off != 150<<10 || !last.Truncated || len(last.Data) != 0 || last.Offset != 150<<10 {
		t.Fatalf("total %d last %+v", off, last)
	}
	if s.total != 70<<10+10+100<<10+7 {
		t.Fatalf("total %d", s.total)
	}
}

// TestFitHTTP1: listas enormes são cortadas até o evento caber em 900 KiB.
func TestFitHTTP1(t *testing.T) {
	srv := NewServer(testConfig(t.TempDir()), Deps{})
	req := &h1.Request{RawHead: bytes.Repeat([]byte("x"), 1<<20), Fields: []h1.Field{}, Duplicates: []string{}}
	for i := range 60000 {
		req.Fields = append(req.Fields, h1.Field{"Via", ": ", strings.Repeat("v", 10) + string(rune('a'+i%26)), "crlf"})
		req.ProxySignals = append(req.ProxySignals, h1.ProxySignal{Kind: "via", Detail: ptr(strings.Repeat("d", 200))})
	}
	req.FieldCount = len(req.Fields)
	data := srv.fitHTTP1(time.Now(), &event.Flow{L4: "tcp"}, "", req)
	if len(data) > event.MaxEventBytes || !req.FieldsTruncated || !req.RawHeadTruncated || req.FieldCount != 60000 {
		t.Fatalf("size %d truncated %v", len(data), req.FieldsTruncated)
	}
}

// ------------------------------------------------------------------ contrato

func readDoc(t *testing.T, rel string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", rel))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// block devolve o trecho de um esquema com indent de 4 espaços (até o próximo irmão).
func block(t *testing.T, doc, name string) string {
	t.Helper()
	i := strings.Index(doc, "\n    "+name+":\n")
	if i < 0 {
		t.Fatalf("%s not found", name)
	}
	b := doc[i+1:]
	if m := regexp.MustCompile(`\n    [A-Za-z]`).FindStringIndex(b[1:]); m != nil {
		b = b[:m[0]+1]
	}
	return b
}

func keysOf(v any, set map[string]bool) {
	switch x := v.(type) {
	case map[string]any:
		for k, vv := range x {
			set[k] = true
			keysOf(vv, set)
		}
	case []any:
		for _, vv := range x {
			keysOf(vv, set)
		}
	}
}

// contractBlocks são os esquemas (openapi/asyncapi) de cada subject, com os que eles referenciam.
func contractBlocks(t *testing.T) map[string]string {
	openapi := readDoc(t, "cmd/finger-sniffer-store/openapi.yaml")
	async := readDoc(t, "eventbus/nats/asyncapi.yaml")
	join := func(doc string, names ...string) string {
		var b strings.Builder
		for _, n := range names {
			b.WriteString(block(t, doc, n))
		}
		return b.String()
	}
	return map[string]string{
		event.SubjectWebHTTP1Request:    join(openapi, "HTTP1Request", "ProxySignal", "Controls"),
		event.SubjectWebTLSClientHello:  join(openapi, "TLSInfo", "TLSExtension", "CodeName"),
		event.SubjectWebRawSession:      join(openapi, "RawInfo"),
		event.SubjectWebTLSHandshake:    join(async, "TLSHandshakePayload"),
		event.SubjectWebStreamBytes:     join(async, "StreamBytesPayload"),
		event.SubjectWebHTTP2Connection: join(openapi, "HTTP2Info", "H2Frame"),
		event.SubjectWebHTTP2Stream:     join(openapi, "HTTP2Stream", "HPACKField", "Controls"),
		event.SubjectWebWebSocketFrame:  join(async, "WebSocketFramePayload"),
		"envelope":                      join(async, "Envelope", "Flow"),
	}
}

// checkContract confere que toda chave serializada existe no esquema do subject.
func checkContract(t *testing.T, blocks map[string]string, e decoded) {
	t.Helper()
	if e.Size > event.MaxEventBytes {
		t.Errorf("%s: %d bytes > 900 KiB", e.Subject, e.Size)
	}
	var env map[string]any
	data, _ := json.Marshal(e.Env)
	_ = json.Unmarshal(data, &env)
	for k := range env {
		if k != "payload" && !regexp.MustCompile(`\n\s+`+k+`:`).MatchString(blocks["envelope"]) {
			t.Errorf("envelope key %q not in contract", k)
		}
	}
	set := map[string]bool{}
	keysOf(e.Payload, set)
	b, ok := blocks[e.Subject]
	if !ok {
		t.Fatalf("no contract for %s", e.Subject)
	}
	for k := range set {
		if !regexp.MustCompile(`\n\s+` + regexp.QuoteMeta(k) + `:`).MatchString(b) {
			t.Errorf("%s: key %q not in contract", e.Subject, k)
		}
	}
}

// shape descreve as chaves de um valor JSON (para comparar com os exemplos sem depender de valores).
func shape(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, vv := range x {
			out[k] = shape(vv)
		}
		return out
	case []any:
		if len(x) == 0 {
			return []any{}
		}
		return []any{shape(x[0])}
	default:
		return nil
	}
}

// TestEventsContractAndGolden gera tráfego de todos os tipos, confere cada evento com o contrato (asyncapi
// 0.2.0 e openapi) e com os exemplos de testdata/events/ (gerados por este teste com -update, para a task 040).
func TestEventsContractAndGolden(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	writeFile(t, h.htdocs, "index.html", "<p>x</p>")
	c := dialTLS(t, h.addr443, testSNI)
	cl := newClient(t, c)
	cl.send("POST /p/" + testProbe + "/ HTTP/1.1\r\nHost: " + testSNI + "\r\nVia: 1.1 p\r\nExpect: 100-continue\r\n" +
		"Transfer-Encoding: chunked\r\n\r\n")
	_, _ = cl.br.ReadString('\n')
	_, _ = cl.br.ReadString('\n')
	cl.send("3;e=1\r\nabc\r\n0\r\nX-T: 1\r\n\r\n")
	cl.response("POST")
	port := srcPort(c)
	h.events.wait(t, event.SubjectWebHTTP1Request, port, 1)

	raw := dial(t, h.addr80)
	_, _ = raw.Write([]byte("PROBE " + testProbe + "\r\nbytes"))
	_ = raw.Close()
	h.events.wait(t, event.SubjectWebRawSession, srcPort(raw), 1)

	blocks := contractBlocks(t)
	examples := map[string]decoded{}
	for _, subj := range []string{
		event.SubjectWebTLSClientHello, event.SubjectWebTLSHandshake,
		event.SubjectWebHTTP1Request, event.SubjectWebStreamBytes, event.SubjectWebRawSession,
	} {
		evs := h.events.find(t, subj, 0)
		if len(evs) == 0 {
			t.Fatalf("no %s", subj)
		}
		for _, e := range evs {
			checkContract(t, blocks, e)
		}
		examples[subj] = evs[0]
	}

	for subj, e := range examples {
		checkGolden(t, subj, e)
	}
}

// checkGolden compara a forma do evento com o exemplo em testdata/events/ (ou o regrava com -update).
func checkGolden(t *testing.T, subj string, e decoded) {
	t.Helper()
	dir := filepath.Join("testdata", "events")
	file := filepath.Join(dir, strings.TrimPrefix(subj, "fs.v1.web.")+".json")
	var full map[string]any
	_ = json.Unmarshal(mustJSON(t, e.Env), &full)
	full["payload"] = e.Payload
	if *update {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		out, _ := json.MarshalIndent(full, "", "  ")
		if err := os.WriteFile(file, append(out, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("%v (rode go test -run %s -update)", err, t.Name())
	}
	var golden map[string]any
	if err := json.Unmarshal(data, &golden); err != nil {
		t.Fatal(err)
	}
	g, f := mustJSON(t, shape(golden)), mustJSON(t, shape(full))
	if !bytes.Equal(g, f) {
		t.Errorf("%s: shape changed (rode -update)\n golden %s\n now    %s", subj, g, f)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
