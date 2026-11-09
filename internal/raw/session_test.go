package raw

import (
	"bytes"
	"encoding/json"
	"flag"
	"io"
	"log/slog"
	"net"
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
	cut := false
	for range maxTimed {
		l = appendTimed(l, &cut, 1.5, 3)
	}
	// Exatamente maxTimed itens cabem sem corte.
	if len(l) != maxTimed || cut {
		t.Fatalf("len = %d cut = %v", len(l), cut)
	}
	for range 10 {
		l = appendTimed(l, &cut, 1.5, 3)
	}
	if len(l) != maxTimed || !cut {
		t.Fatalf("len = %d cut = %v", len(l), cut)
	}
}

// discardConn é um net.Conn que aceita e descarta toda escrita.
type discardConn struct{ net.Conn }

func (discardConn) Write(b []byte) (int, error)      { return len(b), nil }
func (discardConn) SetWriteDeadline(time.Time) error { return nil }
func (discardConn) Close() error                     { return nil }

// TestSessionTimedTruncated confere reads_in_truncated e writes_out_truncated no fs.v1.raw.session (spec 006
// RF-06): cada flag liga só no sentido que passou de maxTimed, e os bytes seguem completos em fs.v1.raw.read.
func TestSessionTimedTruncated(t *testing.T) {
	cases := []struct {
		name            string
		reads, writes   int
		wantIn, wantOut bool
	}{
		{"none", maxTimed, maxTimed, false, false},
		{"reads", maxTimed + 1, 3, true, false},
		{"writes", 2, maxTimed + 5, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pub := &fakePub{}
			em := &emitter{pub: pub, log: quietLog(), flow: &event.Flow{L4: "tcp"}}
			cfg := &Config{Idle: time.Second, StreamMax: DefaultStreamMax}
			s := newSession(discardConn{}, cfg, PortSpec{Mode: "source"}, time.Now(), em)
			for range tc.reads {
				s.recordRead([]byte("r"))
			}
			// Escritas pequenas, como um source que manda um byte por vez.
			for range tc.writes {
				if err := s.write([]byte("w")); err != nil {
					t.Fatal(err)
				}
			}
			s.finish()
			var info Info
			var inBytes, outBytes int
			for _, m := range pub.all() {
				env, err := event.Decode(m.Data)
				if err != nil {
					t.Fatal(err)
				}
				switch m.Subject {
				case event.SubjectRawSession:
					if err := json.Unmarshal(env.Payload, &info); err != nil {
						t.Fatal(err)
					}
					var raw map[string]json.RawMessage
					if err := json.Unmarshal(env.Payload, &raw); err != nil {
						t.Fatal(err)
					}
					// As flags são sempre serializadas, mesmo false.
					for _, k := range []string{"reads_in_truncated", "writes_out_truncated"} {
						if _, ok := raw[k]; !ok {
							t.Errorf("missing %s", k)
						}
					}
				case event.SubjectRawRead:
					var sb event.StreamBytes
					if err := json.Unmarshal(env.Payload, &sb); err != nil {
						t.Fatal(err)
					}
					if sb.Dir == event.DirectionIn {
						inBytes += len(sb.Data)
					} else {
						outBytes += len(sb.Data)
					}
				}
			}
			if info.ReadsInTruncated != tc.wantIn || info.WritesOutTruncated != tc.wantOut {
				t.Errorf("truncated in=%v out=%v, want %v %v", info.ReadsInTruncated, info.WritesOutTruncated, tc.wantIn, tc.wantOut)
			}
			if len(info.ReadsIn) != min(tc.reads, maxTimed) || len(info.WritesOut) != min(tc.writes, maxTimed) {
				t.Errorf("reads_in=%d writes_out=%d", len(info.ReadsIn), len(info.WritesOut))
			}
			if inBytes != tc.reads || outBytes != tc.writes {
				t.Errorf("stream bytes in=%d out=%d, want %d %d", inBytes, outBytes, tc.reads, tc.writes)
			}
		})
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
