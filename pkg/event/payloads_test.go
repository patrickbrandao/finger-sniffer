package event

import (
	"encoding/json"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func asyncAPI(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("../../eventbus/nats/asyncapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// openAPI lê o openapi.yaml, onde ficam os schemas de payload que o asyncapi referencia (ex. HTTP3Info).
func openAPI(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("../../cmd/finger-sniffer-store/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// schemaBlock devolve o trecho de um esquema/mensagem com o indent de 4 espaços (até o próximo irmão).
func schemaBlock(t *testing.T, doc, name string) string {
	t.Helper()
	i := strings.Index(doc, "\n    "+name+":\n")
	if i < 0 {
		t.Fatalf("%s not found in asyncapi", name)
	}
	block := doc[i+1:]
	if m := regexp.MustCompile(`\n    [A-Za-z]`).FindStringIndex(block); m != nil {
		block = block[:m[0]]
	}
	return block
}

// jsonKeys junta todas as chaves (em qualquer nível) de um valor serializado.
func jsonKeys(t *testing.T, v any) []string {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var tree any
	_ = json.Unmarshal(data, &tree)
	set := map[string]bool{}
	var walk func(any)
	walk = func(n any) {
		switch x := n.(type) {
		case map[string]any:
			for k, v := range x {
				set[k] = true
				walk(v)
			}
		case []any:
			for _, v := range x {
				walk(v)
			}
		}
	}
	walk(tree)
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestPayloadsMatchAsyncAPI: toda chave serializada existe no esquema do contrato, e toda propriedade do
// contrato aparece na serialização de um valor completo (teste de contrato, nos dois sentidos).
func TestPayloadsMatchAsyncAPI(t *testing.T) {
	async, openapi := asyncAPI(t), openAPI(t)
	s, n, f, u, yes := "x", 1, 1.5, uint64(7), true
	cases := []struct {
		schema string
		value  any
	}{
		{"StreamBytesPayload", StreamBytes{Dir: DirectionIn, Offset: 1, Data: []byte("a"), Truncated: true}},
		{"ConnIDRequestPayload", ConnIDRequest{Flow: Flow{L4: "tcp"}, Ts: "t"}},
		{"ConnIDReplyPayload", ConnIDReply{ConnID: "x", Reserved: true}},
		{"WebSocketFramePayload", WebSocketFrame{
			MaskKeyHex: &s,
			Upgrade:    &WebSocketUpgrade{Over: "h2", Extensions: &s, Subprotocol: &s},
			Close:      &WebSocketClose{By: "client", Code: &n, Reason: &s},
		}},
		{"TLSHandshakePayload", TLSHandshake{
			Negotiated: &TLSNegotiated{ALPN: &s}, HandshakeMs: &f, Alerts: []TLSAlert{{Dir: DirectionOut}},
		}},
		{"ACMERequest", ACMERequest{Name: "n", Value: "v"}},
		{"ACMEReply", ACMEReply{OK: false, Error: &s}},
		// Payloads h3 (ADR 0019): os schemas estão no openapi, referenciados pelas mensagens do asyncapi.
		{"HTTP3Info", HTTP3Info{
			InitialFrames: []string{"CRYPTO"}, TransportParams: []TransportParam{{ID: 1, Name: "max_idle_timeout", ValueHex: "00"}},
			ClientHello: json.RawMessage(`{}`), H3Settings: [][2]uint64{{1, 0}}, H3ControlStreamSeen: true,
			Close: &HTTP3Close{By: "client", How: QUICCloseConnection, ErrorCode: &u, Reason: &s}, Requests: []HTTP3Request{},
		}},
		{"HTTP3Request", HTTP3Request{PseudoOrder: []string{":method"}, Fields: []QPACKField{}, JA4H: &s, Controls: json.RawMessage(`{}`)}},
		{"QPACKField", QPACKField{Repr: "indexed", Static: &yes, Index: &n, NeverIndexed: &yes, HuffmanName: &yes, HuffmanValue: &yes}},
	}
	propRe := regexp.MustCompile(`(?m)^\s+([a-z_0-9]+):`)
	nonProps := map[string]bool{
		"type": true, "description": true, "required": true, "properties": true, "items": true, "enum": true,
		"pattern": true, "contentEncoding": true, "payload": true, "name": true, "traits": true, "const": true,
		"additionalProperties": true,
	}
	for _, c := range cases {
		t.Run(c.schema, func(t *testing.T) {
			doc := async
			if strings.HasPrefix(c.schema, "HTTP3") || c.schema == "QPACKField" {
				doc = openapi // schemas de payload do openapi, referenciados pelo asyncapi
			}
			block := schemaBlock(t, doc, c.schema)
			keys := jsonKeys(t, c.value)
			for _, k := range keys {
				if k == "flow" || k == "l4" || strings.HasPrefix(k, "src_") || strings.HasPrefix(k, "dst_") {
					continue // Flow tem teste próprio (envelope)
				}
				if !regexp.MustCompile(`\n\s+` + k + `:`).MatchString(block) {
					t.Errorf("json key %q not in contract", k)
				}
			}
			got := map[string]bool{}
			for _, k := range keys {
				got[k] = true
			}
			for _, m := range propRe.FindAllStringSubmatch(block, -1) {
				name := m[1]
				// "name" e "error"/"value" são propriedades de verdade nas mensagens ACME.
				if nonProps[name] && (c.schema != "ACMERequest" || name != "name") {
					continue
				}
				if !got[name] {
					t.Errorf("contract property %q missing in struct JSON", name)
				}
			}
		})
	}
}

// matchSubject aplica as regras de curinga do NATS (* = um token, > = um ou mais tokens no fim).
func matchSubject(pattern, subject string) bool {
	p, s := strings.Split(pattern, "."), strings.Split(subject, ".")
	for i, tok := range p {
		if tok == ">" {
			return len(s) > i
		}
		if i >= len(s) || (tok != "*" && tok != s[i]) {
			return false
		}
	}
	return len(p) == len(s)
}

func inStream(subject string) bool {
	for _, p := range StreamSubjects {
		if matchSubject(p, subject) {
			return true
		}
	}
	return false
}

// TestSubjectsMatchAsyncAPI: os subjects do contrato são exatamente as constantes; o stream pega todos os
// eventos e nenhum request/reply (ADR 0017).
func TestSubjectsMatchAsyncAPI(t *testing.T) {
	var contract []string
	for _, m := range regexp.MustCompile(`address: (fs\.v1\.[a-z0-9_.]+)`).FindAllStringSubmatch(asyncAPI(t), -1) {
		contract = append(contract, m[1])
	}
	ours := append(append([]string{}, EventSubjects...), RequestSubjects...)
	sort.Strings(contract)
	sort.Strings(ours)
	if strings.Join(contract, ",") != strings.Join(ours, ",") {
		t.Fatalf("contract subjects\n%v\nconstants\n%v", contract, ours)
	}
	for _, s := range EventSubjects {
		if !inStream(s) {
			t.Errorf("event subject %s not captured by the stream", s)
		}
	}
	for _, s := range RequestSubjects {
		if inStream(s) {
			t.Errorf("request subject %s must stay out of the stream", s)
		}
	}
	if !matchSubject("fs.v1.web.>", "fs.v1.web.tls.handshake") || matchSubject("fs.v1.web.>", "fs.v1.web") {
		t.Fatal("matchSubject")
	}
}

// TestTransportParamJSON: o transport parameter vai como `[id, nome, valor_hex]` e volta igual.
func TestTransportParamJSON(t *testing.T) {
	data, _ := json.Marshal(HTTP3Info{TransportParams: []TransportParam{{ID: 0x0a0a, Name: "GREASE", ValueHex: "beef"}}})
	if !strings.Contains(string(data), `"transport_params":[[2570,"GREASE","beef"]]`) {
		t.Fatalf("%s", data)
	}
	var back HTTP3Info
	if err := json.Unmarshal(data, &back); err != nil || back.TransportParams[0] != (TransportParam{ID: 2570, Name: "GREASE", ValueHex: "beef"}) {
		t.Fatalf("%+v %v", back, err)
	}
	for _, bad := range []string{`[1,"x"]`, `{}`, `["a","x","y"]`, `[1,2,"y"]`, `[1,"x",3]`} {
		var p TransportParam
		if err := json.Unmarshal([]byte(bad), &p); err == nil {
			t.Errorf("%s: expected error", bad)
		}
	}
}

func TestStreamBytesBase64(t *testing.T) {
	data, _ := json.Marshal(StreamBytes{Dir: DirectionOut, Offset: 65536, Data: []byte("hi")})
	if string(data) != `{"dir":"out","offset":65536,"data_b64":"aGk="}` {
		t.Fatalf("%s", data)
	}
	var back StreamBytes
	if err := json.Unmarshal(data, &back); err != nil || string(back.Data) != "hi" {
		t.Fatalf("%+v %v", back, err)
	}
	if DefaultEventInlineMax != 131072 || MaxEventBytes != 921600 || StreamChunkBytes != 65536 || DefaultRawStreamMaxBytes != 16777216 {
		t.Fatal("limits differ from ADR 0018")
	}
}
