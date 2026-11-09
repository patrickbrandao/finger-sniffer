package store

import (
	"bytes"
	"context"
	"testing"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

func chunk(t *testing.T, ms int, dir string, off int64, data []byte, truncated bool) fakeMsg {
	return appMsg(t, event.SubjectWebStreamBytes, "tcp", client, mirror, ms, "", event.StreamBytes{Dir: dir, Offset: off, Data: data, Truncated: truncated})
}

func TestStreamsRawByOffset(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	run(t, in, 100, batch(client, mirror, protoTCP, fullTCP[:5]),
		chunk(t, 25, event.DirectionIn, 3, []byte("def"), false),
		chunk(t, 25, event.DirectionIn, 0, []byte("abc"), false),
		chunk(t, 35, event.DirectionOut, 0, []byte("HTTP/1.1 200 OK\r\n"), false))
	id, _ := onlyConn(t, db)
	q := NewQueries(db, in.flows.live, 65535)
	got, err := q.Raw(context.Background(), id, "in")
	if err != nil || string(got) != "abcdef" {
		t.Fatalf("in %q %v", got, err)
	}
	if got, _ := q.Raw(context.Background(), id, "out"); string(got) != "HTTP/1.1 200 OK\r\n" {
		t.Fatalf("out %q", got)
	}
	if count(t, db, "SELECT count(*) FROM app_events") != 0 {
		t.Fatal("stream chunks do not go to app_events")
	}
	if r := recordOf(t, in, id); r.RawTruncated != nil {
		t.Fatal("not truncated")
	}
}

func TestStreamsCapAndTruncated(t *testing.T) {
	in, db := newTestIngestor(t, func(c *IngestConfig) { c.RawStreamMax = 10 })
	run(t, in, 100, batch(client, mirror, protoTCP, fullTCP[:5]),
		chunk(t, 25, event.DirectionIn, 0, bytes.Repeat([]byte("a"), 8), false),
		chunk(t, 26, event.DirectionIn, 8, bytes.Repeat([]byte("b"), 8), false), // passa do teto: cortado
		chunk(t, 36, event.DirectionOut, 0, []byte("x"), false),
		chunk(t, 37, event.DirectionOut, 1, nil, true)) // produtor avisa que cortou
	id, _ := onlyConn(t, db)
	got, _ := NewQueries(db, in.flows.live, 65535).Raw(context.Background(), id, "in")
	if string(got) != "aaaaaaaabb" {
		t.Fatalf("%q", got)
	}
	r := recordOf(t, in, id)
	if r.RawTruncated == nil || !r.RawTruncated.In || !r.RawTruncated.Out {
		t.Fatalf("%+v", r.RawTruncated)
	}
	// Depois de fechada, o registro refeito de app_events mantém a marca.
	run(t, in, 5000, batch(client, mirror, protoTCP, fullTCP[5:]))
	processAt(t, in, 6000, appMsg(t, event.SubjectRawSession, "tcp", client, mirror, 1000, "", map[string]any{}))
	if _, r := onlyConn(t, db); r.RawTruncated == nil || !r.RawTruncated.In || !r.RawTruncated.Out {
		t.Fatalf("after rebuild %+v", r.RawTruncated)
	}
}

func TestStreamsDegradedNotStored(t *testing.T) {
	in, db := newTestIngestor(t, func(c *IngestConfig) { c.MaxOpen = 0 })
	run(t, in, 100, batch(client, mirror, protoTCP, fullTCP[:5]), chunk(t, 25, event.DirectionIn, 0, []byte("abc"), false))
	if count(t, db, "SELECT count(*) FROM raw_streams") != 0 {
		t.Fatal("degraded mode must not store raw bytes")
	}
}
