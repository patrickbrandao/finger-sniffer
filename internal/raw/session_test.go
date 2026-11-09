package raw

import (
	"bytes"
	"encoding/json"
	"flag"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/patrickbrandao/finger-sniffer/internal/version"
	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/probe"
)

var update = flag.Bool("update", false, "regrava os arquivos golden de testdata/")

// fakePub guarda as mensagens publicadas.
type fakePub struct {
	mu   sync.Mutex
	msgs []*nats.Msg
}

func (f *fakePub) Publish(m *nats.Msg) {
	f.mu.Lock()
	f.msgs = append(f.msgs, m)
	f.mu.Unlock()
}

func (f *fakePub) all() []*nats.Msg {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*nats.Msg(nil), f.msgs...)
}

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func testSession(mode string) (*session, *fakePub) {
	pub := &fakePub{}
	cfg := &Config{Idle: time.Second, SourceBytes: DefaultSourceBytes, StreamMax: DefaultStreamMax}
	em := &emitter{pub: pub, log: quietLog(), flow: &event.Flow{L4: "tcp"}}
	return newSession(nil, cfg, PortSpec{Port: 7, Mode: mode, Banner: GenericBanner}, time.Now(), em), pub
}

func TestFeedProbeLine(t *testing.T) {
	cases := []struct {
		name   string
		chunks []string
		// out é o que vai ao modo depois de cada pedaço.
		out      []string
		probeID  string
		mode     string
		sourceN  int64
		lineDone bool
	}{
		{"not probe", []string{"hello"}, []string{"hello"}, "", "echo", DefaultSourceBytes, true},
		{"prefix then diverges", []string{"PRO", "XY"}, []string{"", "PROXY"}, "", "echo", DefaultSourceBytes, true},
		{"split line", []string{"PROBE abcd", "efgh mode=sink n=5\r\nrest"}, []string{"", "rest"}, "abcdefgh", "sink", 5, true},
		{"lf line", []string{"PROBE abcdefgh\n"}, []string{""}, "abcdefgh", "echo", DefaultSourceBytes, true},
		{"invalid probe", []string{"PROBE x\r\n"}, []string{"PROBE x\r\n"}, "", "echo", DefaultSourceBytes, true},
		{"pending", []string{"PROBE abcdefgh"}, []string{""}, "", "echo", DefaultSourceBytes, false},
		{"too long", []string{"PROBE " + string(bytes.Repeat([]byte("a"), probe.MaxLineLen))}, []string{"PROBE " + string(bytes.Repeat([]byte("a"), probe.MaxLineLen))}, "", "echo", DefaultSourceBytes, true},
		{"after line", []string{"hi\n", "PROBE abcdefgh\n"}, []string{"hi\n", "PROBE abcdefgh\n"}, "", "echo", DefaultSourceBytes, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, _ := testSession(probe.ModeEcho)
			for i, ch := range c.chunks {
				if got := string(s.feed([]byte(ch))); got != c.out[i] {
					t.Errorf("chunk %d: got %q, want %q", i, got, c.out[i])
				}
			}
			if s.probeID != c.probeID || s.mode != c.mode || s.sourceN != c.sourceN || s.lineDone != c.lineDone {
				t.Errorf("state id=%q mode=%q n=%d done=%v", s.probeID, s.mode, s.sourceN, s.lineDone)
			}
			if c.probeID != "" && (s.info.ProbeLine == nil || len(*s.info.ProbeLine) == 0) {
				t.Error("probe_line not recorded")
			}
		})
	}
}

func TestStreamChunksAndTruncation(t *testing.T) {
	// Pedaços de até 64 KiB; passado o teto, um pedaço vazio com truncated e nada mais.
	pub := &fakePub{}
	em := &emitter{pub: pub, log: quietLog()}
	st := stream{dir: event.DirectionIn, max: 2*event.StreamChunkBytes + 10}
	now := time.Now()
	st.write(em, now, "", bytes.Repeat([]byte{'x'}, event.StreamChunkBytes+5))
	st.write(em, now, "", bytes.Repeat([]byte{'y'}, event.StreamChunkBytes+5)) // exatamente o teto
	st.write(em, now, "", []byte("z"))
	st.write(em, now, "", []byte("w"))
	type chunk struct {
		off   int64
		n     int
		trunc bool
	}
	var got []chunk
	for _, m := range pub.all() {
		var env struct {
			Payload event.StreamBytes `json:"payload"`
		}
		if err := json.Unmarshal(m.Data, &env); err != nil {
			t.Fatal(err)
		}
		got = append(got, chunk{env.Payload.Offset, len(env.Payload.Data), env.Payload.Truncated})
	}
	want := []chunk{{0, event.StreamChunkBytes, false}, {event.StreamChunkBytes, 5, false}, {event.StreamChunkBytes + 5, event.StreamChunkBytes, false}, {2*event.StreamChunkBytes + 5, 5, false}, {2*event.StreamChunkBytes + 10, 0, true}}
	if len(got) != len(want) {
		t.Fatalf("chunks = %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("chunk %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestAppendTimedCap(t *testing.T) {
	var l []TimedLength
	for range maxTimed + 10 {
		l = appendTimed(l, 1.5, 3)
	}
	if len(l) != maxTimed {
		t.Fatalf("len = %d", len(l))
	}
}

// TestGoldenEvents confere a forma JSON dos eventos publicados contra testdata/ (chaves do asyncapi e do
// schema RawInfo).
func TestGoldenEvents(t *testing.T) {
	oldVersion := version.Version
	version.Version = "0.0.0-test"
	t.Cleanup(func() { version.Version = oldVersion })

	pub := &fakePub{}
	flow := &event.Flow{L4: "tcp", SrcIP: "203.0.113.7", SrcPort: 51000, DstIP: "198.51.100.1", DstPort: 21}
	em := &emitter{pub: pub, log: quietLog(), flow: flow}
	ts := time.Date(2026, 11, 8, 12, 0, 0, 123456789, time.UTC)
	banner := "220 finger-sniffer FTP ready\r\n"
	line := "PROBE abcdefgh mode=source n=1000\r\n"
	st := stream{dir: event.DirectionIn, max: DefaultStreamMax}
	st.write(em, ts, "abcdefgh", []byte(line))
	em.publish(event.SubjectRawSession, ts, "abcdefgh", Info{
		Mode: "source", Banner: &banner, ProbeLine: &line,
		ReadsIn:   []TimedLength{{12.345678, float64(len(line))}},
		WritesOut: []TimedLength{{0.051234, float64(len(banner))}, {12.4, 1000}},
	})
	em.publish(event.SubjectRawSession, ts, "", Info{
		Mode: "echo", ReadsIn: []TimedLength{{1, 5}}, WritesOut: []TimedLength{{1.1, 5}, {2.2, 17}},
		HalfClose: &HalfClose{ServerSentAfterClientFIN: true, Bytes: 17},
	})
	msgs := pub.all()
	names := []string{"raw_read.golden.json", "raw_session_probe.golden.json", "raw_session_halfclose.golden.json"}
	subjects := []string{event.SubjectRawRead, event.SubjectRawSession, event.SubjectRawSession}
	if len(msgs) != len(names) {
		t.Fatalf("got %d msgs", len(msgs))
	}
	for i, m := range msgs {
		if m.Subject != subjects[i] {
			t.Errorf("msg %d subject %q", i, m.Subject)
		}
		var buf bytes.Buffer
		if err := json.Indent(&buf, m.Data, "", "  "); err != nil {
			t.Fatal(err)
		}
		buf.WriteByte('\n')
		path := filepath.Join("testdata", names[i])
		if *update {
			if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(buf.Bytes(), want) {
			t.Errorf("%s differs:\n%s", path, buf.String())
		}
		if _, err := event.Decode(m.Data); err != nil {
			t.Errorf("%s: %v", path, err)
		}
	}
}
