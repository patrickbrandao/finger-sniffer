package event

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestNewDecodeRoundTrip(t *testing.T) {
	ts := time.Date(2026, 11, 7, 12, 0, 0, 123, time.UTC)
	flow := &Flow{L4: "tcp", SrcIP: "192.0.2.1", SrcPort: 41234, DstIP: "172.233.24.85", DstPort: 443}
	e, err := New(ServiceWeb, "1.2.3", ts, flow, Heartbeat{Status: StatusOK, Commit: "abc", StartedAt: FormatTime(ts)})
	if err != nil {
		t.Fatal(err)
	}
	if e.Ts != "2026-11-07T12:00:00.000000123Z" {
		t.Fatalf("ts = %q", e.Ts)
	}
	data, _ := json.Marshal(e)
	got, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if got.Service != ServiceWeb || got.Flow.DstPort != 443 || got.SchemaVersion != 1 {
		t.Fatalf("%+v", got)
	}
	when, err := got.Time()
	if err != nil || !when.Equal(ts) {
		t.Fatalf("Time() = %v %v", when, err)
	}
	var hb Heartbeat
	if err := json.Unmarshal(got.Payload, &hb); err != nil || hb.Status != StatusOK {
		t.Fatalf("payload %+v %v", hb, err)
	}
}

func TestNewBadPayload(t *testing.T) {
	if _, err := New(ServiceWeb, "v", time.Now(), nil, make(chan int)); err == nil {
		t.Fatal("expected error")
	}
}

func TestDecodeErrors(t *testing.T) {
	cases := map[string]error{
		`{`: nil,
		`{"schema_version":2,"service":"web","service_version":"v","ts":"x"}`: ErrSchemaVersion,
		`{"schema_version":1,"service_version":"v","ts":"x"}`:                 ErrMissingField,
		`{"schema_version":1,"service":"web","ts":"x"}`:                       ErrMissingField,
		`{"schema_version":1,"service":"web","service_version":"v"}`:          ErrMissingField,
	}
	for in, want := range cases {
		_, err := Decode([]byte(in))
		if err == nil || (want != nil && !errors.Is(err, want)) {
			t.Errorf("Decode(%s) = %v, want %v", in, err, want)
		}
	}
	// Campo desconhecido é ignorado (compatibilidade aditiva).
	if _, err := Decode([]byte(`{"schema_version":1,"service":"web","service_version":"v","ts":"t","new":1}`)); err != nil {
		t.Fatal(err)
	}
}

// TestEnvelopeMatchesAsyncAPI confere que os campos obrigatórios do Envelope no asyncapi.yaml são exatamente
// os que o Decode exige, e que todas as propriedades do contrato existem na struct (teste de contrato).
func TestEnvelopeMatchesAsyncAPI(t *testing.T) {
	raw, err := os.ReadFile("../../eventbus/nats/asyncapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	i := strings.Index(doc, "\n    Envelope:\n")
	if i < 0 {
		t.Fatal("Envelope schema not found")
	}
	block := doc[i:]
	if j := strings.Index(block[1:], "\n    StreamBytesPayload:"); j > 0 {
		block = block[:j]
	}
	req := regexp.MustCompile(`required: \[([^\]]*)\]`).FindStringSubmatch(block)
	if req == nil || req[1] != "schema_version, service, service_version, ts" {
		t.Fatalf("required in contract = %v", req)
	}
	data, _ := json.Marshal(Envelope{Flow: &Flow{}, ProbeID: new(string), Payload: json.RawMessage(`{}`)})
	var fields map[string]any
	_ = json.Unmarshal(data, &fields)
	for _, name := range []string{"schema_version", "service", "service_version", "ts", "flow", "probe_id"} {
		if !strings.Contains(block, "\n        "+name+":") {
			t.Errorf("%s not in contract", name)
		}
		if _, ok := fields[name]; !ok {
			t.Errorf("%s not in struct JSON", name)
		}
	}
}

func TestFSPBRoundTrip(t *testing.T) {
	in := []Packet{
		{TsNs: 1, Dir: DirIn, WireLen: 60, Frame: []byte{1, 2, 3}},
		{TsNs: 1 << 62, Dir: DirOut, Flags: FlagTruncated | FlagOffloadSuspect, WireLen: 9000, Frame: bytes.Repeat([]byte{7}, 1514)},
		{TsNs: 3},
	}
	var buf []byte
	for _, p := range in {
		buf = AppendPacket(buf, p)
	}
	var out []Packet
	n, err := DecodePackets(buf, func(p Packet) error { out = append(out, p); return nil })
	if err != nil || n != len(in) {
		t.Fatalf("n=%d err=%v", n, err)
	}
	for i := range in {
		a, b := in[i], out[i]
		if a.TsNs != b.TsNs || a.Dir != b.Dir || a.Flags != b.Flags || a.WireLen != b.WireLen || !bytes.Equal(a.Frame, b.Frame) {
			t.Fatalf("%d: %+v != %+v", i, a, b)
		}
	}
}

func TestFSPBErrors(t *testing.T) {
	buf := AppendPacket(nil, Packet{TsNs: 1, Frame: []byte{1, 2, 3}})
	for _, cut := range []int{5, FSPBHeaderLen + 1} {
		if _, err := DecodePackets(buf[:cut], func(Packet) error { return nil }); !errors.Is(err, ErrShortBatch) {
			t.Fatalf("cut %d: %v", cut, err)
		}
	}
	boom := errors.New("boom")
	if _, err := DecodePackets(buf, func(Packet) error { return boom }); !errors.Is(err, boom) {
		t.Fatalf("callback error: %v", err)
	}
}

func FuzzDecodePackets(f *testing.F) {
	f.Add(AppendPacket(nil, Packet{TsNs: 1, Frame: []byte{1}}))
	f.Fuzz(func(t *testing.T, b []byte) {
		total := 0
		_, _ = DecodePackets(b, func(p Packet) error {
			total += FSPBHeaderLen + len(p.Frame)
			return nil
		})
		if total > len(b) {
			t.Fatalf("decoded %d bytes from %d", total, len(b))
		}
	})
}

func FuzzDecode(f *testing.F) {
	f.Add([]byte(`{"schema_version":1,"service":"web","service_version":"v","ts":"t"}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		e, err := Decode(b)
		if err == nil && (e.SchemaVersion != 1 || e.Service == "" || e.Ts == "") {
			t.Fatalf("accepted invalid envelope %+v", e)
		}
	})
}
