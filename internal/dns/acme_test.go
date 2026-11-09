package dns

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

// startNATS sobe um nats-server embutido e devolve uma conexão a ele.
func startNATS(t *testing.T) *nats.Conn {
	t.Helper()
	ns, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: server.RANDOM_PORT, NoLog: true, NoSigs: true})
	if err != nil {
		t.Fatal(err)
	}
	go ns.Start()
	t.Cleanup(ns.Shutdown)
	if !ns.ReadyForConnections(5 * time.Second) {
		t.Fatal("nats not ready")
	}
	nc, err := nats.Connect(ns.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	return nc
}

// acmeCall faz o request/reply como o web fará e decodifica a resposta.
func acmeCall(t *testing.T, nc *nats.Conn, subject, name, value string) ACMEReply {
	t.Helper()
	data, _ := json.Marshal(ACMERequest{Name: name, Value: value})
	m, err := nc.Request(subject, data, 2*time.Second)
	if err != nil {
		t.Fatalf("%s: %v", subject, err)
	}
	var r ACMEReply
	if err := json.Unmarshal(m.Data, &r); err != nil {
		t.Fatalf("reply %q: %v", m.Data, err)
	}
	return r
}

func TestACMERequestReply(t *testing.T) {
	nc := startNATS(t)
	z, clk := newTestZone()
	var logged atomic.Int32
	subs, err := SubscribeACME(nc, z, func(string, ...any) { logged.Add(1) })
	if err != nil || len(subs) != 2 {
		t.Fatal(err)
	}
	const name = "_acme-challenge.dns-monitor.tmsoft.com.br."
	for _, v := range []string{"tokenA", "tokenB", "tokenA"} {
		if r := acmeCall(t, nc, SubjectACMESet, name, v); !r.OK || r.Error != nil {
			t.Fatalf("set %s: %+v", v, r)
		}
	}
	if got := z.ACMEValues(name); !slices.Equal(got, []string{"tokenA", "tokenB"}) {
		t.Fatalf("valores %v", got)
	}
	if r := acmeCall(t, nc, SubjectACMEClear, name, "tokenA"); !r.OK {
		t.Fatalf("clear: %+v", r)
	}
	if got := z.ACMEValues(name); !slices.Equal(got, []string{"tokenB"}) {
		t.Fatalf("após clear %v", got)
	}
	clk.advance(ACMEValueTTL)
	if got := z.ACMEValues(name); len(got) != 0 {
		t.Fatalf("após expirar %v", got)
	}

	// Nome fora da zona → ok:false com erro.
	r := acmeCall(t, nc, SubjectACMESet, "_acme-challenge.example.com.", "x")
	if r.OK || r.Error == nil || *r.Error == "" {
		t.Fatalf("fora da zona: %+v", r)
	}
	// JSON inválido → ok:false.
	m, err := nc.Request(SubjectACMESet, []byte("{"), 2*time.Second)
	if err != nil || !strings.Contains(string(m.Data), `"ok":false`) {
		t.Fatalf("json inválido: %v %s", err, m.Data)
	}
	if logged.Load() == 0 {
		t.Fatal("sem log")
	}
	// Publicação sem reply não derruba nada.
	if err := nc.Publish(SubjectACMESet, []byte(`{"name":"x","value":"y"}`)); err != nil {
		t.Fatal(err)
	}
	_ = nc.Flush()
}

func TestHandleACMEUnknownSubject(t *testing.T) {
	z, _ := newTestZone()
	out := z.HandleACME("fs.v1.dns.acme.other", []byte(`{"name":"a","value":"b"}`))
	if !strings.Contains(string(out), `"ok":false`) {
		t.Fatal(string(out))
	}
	// Resposta de sucesso: error é null (o contrato aceita string ou null).
	out = z.HandleACME(SubjectACMESet, []byte(`{"name":"_acme-challenge.dns-monitor.tmsoft.com.br","value":"b"}`))
	if string(out) != `{"ok":true,"error":null}` {
		t.Fatal(string(out))
	}
}

// contractBlock devolve o trecho do asyncapi.yaml de uma mensagem (até a próxima mensagem do mesmo nível).
func contractBlock(t *testing.T, doc, name string) string {
	t.Helper()
	i := strings.Index(doc, "\n    "+name+":\n")
	if i < 0 {
		t.Fatalf("%s not in asyncapi", name)
	}
	block := doc[i+1:]
	next := regexp.MustCompile(`\n    [A-Za-z]+:\n`).FindStringIndex(block[1:])
	if next != nil {
		block = block[:next[0]+1]
	}
	return block
}

// TestACMEMatchesAsyncAPI confere que ACMERequest/ACMEReply têm exatamente os campos do contrato.
func TestACMEMatchesAsyncAPI(t *testing.T) {
	raw, err := os.ReadFile("../../eventbus/nats/asyncapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	for _, subj := range []string{SubjectACMESet, SubjectACMEClear} {
		if !strings.Contains(doc, "address: "+subj+"\n") {
			t.Errorf("subject %s not in contract", subj)
		}
	}
	cases := []struct {
		msg      string
		value    any
		required string
		props    []string
	}{
		{"ACMERequest", ACMERequest{}, "name, value", []string{"name", "value"}},
		{"ACMEReply", ACMEReply{}, "ok", []string{"ok", "error"}},
	}
	propRe := regexp.MustCompile(`\n          ([a-z_]+): \{`)
	for _, c := range cases {
		block := contractBlock(t, doc, c.msg)
		req := regexp.MustCompile(`required: \[([^\]]*)\]`).FindStringSubmatch(block)
		if req == nil || req[1] != c.required {
			t.Errorf("%s required = %v", c.msg, req)
		}
		var props []string
		for _, m := range propRe.FindAllStringSubmatch(block, -1) {
			props = append(props, m[1])
		}
		if !slices.Equal(props, c.props) {
			t.Errorf("%s properties in contract = %v, want %v", c.msg, props, c.props)
		}
		data, _ := json.Marshal(c.value)
		var fields map[string]any
		_ = json.Unmarshal(data, &fields)
		if len(fields) != len(c.props) {
			t.Errorf("%s struct JSON fields = %v", c.msg, fields)
		}
		for _, p := range c.props {
			if _, ok := fields[p]; !ok {
				t.Errorf("%s: %s not in struct JSON", c.msg, p)
			}
		}
	}
}

// TestACMEReplyGolden gera as respostas do request/reply do DNS-01 pelo HandleACME real e as compara com os
// exemplos em testdata/events (referenciados pelo asyncapi). Regrava com -update.
func TestACMEReplyGolden(t *testing.T) {
	z, _ := newTestZone()
	cases := []struct {
		file    string
		subject string
		req     ACMERequest
		ok      bool
	}{
		{"dns.acme.reply.ok.json", SubjectACMESet, ACMERequest{Name: "_acme-challenge.dns-monitor.tmsoft.com.br.", Value: "tokenA"}, true},
		{"dns.acme.reply.error.json", SubjectACMESet, ACMERequest{Name: "_acme-challenge.example.com.", Value: "tokenA"}, false},
	}
	for _, c := range cases {
		data, _ := json.Marshal(c.req)
		out := z.HandleACME(c.subject, data)
		var r ACMEReply
		if err := json.Unmarshal(out, &r); err != nil {
			t.Fatalf("%s: %v", c.file, err)
		}
		if r.OK != c.ok || (r.Error == nil) != c.ok {
			t.Fatalf("%s: resposta %s", c.file, out)
		}
		var buf bytes.Buffer
		if err := json.Indent(&buf, out, "", "  "); err != nil {
			t.Fatal(err)
		}
		buf.WriteByte('\n')
		file := filepath.Join("testdata", "events", c.file)
		if *update {
			if err := os.WriteFile(file, buf.Bytes(), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		want, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("%v (rode com -update)", err)
		}
		if !bytes.Equal(buf.Bytes(), want) {
			t.Errorf("%s diverge do golden; rode go test ./internal/dns -run TestACMEReplyGolden -update\n%s", c.file, buf.Bytes())
		}
		checkACMEReplySchema(t, c.file, want)
	}
}

// checkACMEReplySchema valida o golden contra o schema ACMEReply do asyncapi (ok boolean obrigatório,
// error string ou null, nada além disso). A AsyncAPI CLI não valida exemplos vindos de traits.
func checkACMEReplySchema(t *testing.T, file string, data []byte) {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("%s: %v", file, err)
	}
	if _, ok := m["ok"].(bool); !ok {
		t.Errorf("%s: ok ausente ou não boolean", file)
	}
	for k, v := range m {
		switch k {
		case "ok":
		case "error":
			if _, isStr := v.(string); v != nil && !isStr {
				t.Errorf("%s: error não é string nem null", file)
			}
		default:
			t.Errorf("%s: chave %q fora do schema ACMEReply", file, k)
		}
	}
}

// TestACMEReplyGoldenInAsyncAPI confere que o asyncapi referencia os dois golden nos exemplos de ACMEReply.
func TestACMEReplyGoldenInAsyncAPI(t *testing.T) {
	raw, err := os.ReadFile("../../eventbus/nats/asyncapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	i := strings.Index(doc, "\n    ACMEReplyExamples:\n")
	if i < 0 {
		t.Fatal("ACMEReplyExamples not in asyncapi")
	}
	block := doc[i+1:]
	if j := regexp.MustCompile(`\n    [A-Za-z]+:\n`).FindStringIndex(block[1:]); j != nil {
		block = block[:j[0]+1]
	}
	if strings.Contains(block, "(à mão)") {
		t.Error("ACMEReplyExamples ainda tem exemplo à mão")
	}
	for _, f := range []string{"dns.acme.reply.ok.json", "dns.acme.reply.error.json"} {
		if !strings.Contains(block, "\n            $ref: \"../../internal/dns/testdata/events/"+f+"\"\n") {
			t.Errorf("asyncapi não referencia %s", f)
		}
	}
}
