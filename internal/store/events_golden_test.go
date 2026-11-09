package store

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// connIDRequestGolden é o pedido que service.RequestConnID publica (golden do pkg/service, task 045).
const connIDRequestGolden = "../../pkg/service/testdata/events/store.conn_id.request.json"

// TestConnIDReplyGolden: a resposta do store a uma conexão ainda desconhecida (reserved: true) tem a forma do
// exemplo em testdata/events/store.conn_id.reply.json, referenciado pelo asyncapi. -update o regrava.
func TestConnIDReplyGolden(t *testing.T) {
	req, err := os.ReadFile(connIDRequestGolden)
	if err != nil {
		t.Fatal(err)
	}
	in, _ := newTestIngestor(t, nil)
	data, err := replyConnID(in.flows, req, base)
	if err != nil {
		t.Fatal(err)
	}
	var rep event.ConnIDReply
	if err := json.Unmarshal(data, &rep); err != nil || !rep.Reserved || !ValidConnID(rep.ConnID) {
		t.Fatalf("%s %v", data, err)
	}
	// Requisição inválida não tem resposta.
	if _, err := replyConnID(in.flows, []byte(`{"flow":{"l4":"sctp"}}`), base); err == nil {
		t.Fatal("expected error")
	}
	checkEventGolden(t, filepath.Join("testdata", "events", "store.conn_id.reply.json"), data)
}

// checkEventGolden compara a forma (chaves e aninhamento) de data com o golden, ou o regrava com -update.
func checkEventGolden(t *testing.T, file string, data []byte) {
	t.Helper()
	var got any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if *update {
		out, _ := json.MarshalIndent(got, "", "  ")
		if err := os.WriteFile(file, append(out, '\n'), 0o644); err != nil { //nolint:gosec // testdata versionado
			t.Fatal(err)
		}
		return
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("%v (rode go test -run %s -update)", err, t.Name())
	}
	var golden any
	if err := json.Unmarshal(raw, &golden); err != nil {
		t.Fatal(err)
	}
	g, _ := json.Marshal(jsonShape(golden))
	f, _ := json.Marshal(jsonShape(got))
	if !bytes.Equal(g, f) {
		t.Errorf("%s: shape changed (rode -update)\n golden %s\n now    %s", file, g, f)
	}
}

// jsonShape troca cada valor escalar por null e cada lista pelo seu primeiro item: sobra só a forma.
func jsonShape(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, vv := range x {
			out[k] = jsonShape(vv)
		}
		return out
	case []any:
		if len(x) == 0 {
			return []any{}
		}
		return []any{jsonShape(x[0])}
	default:
		return nil
	}
}
