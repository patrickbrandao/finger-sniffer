package service

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

type fakeRequester struct {
	reply    []byte
	err      error
	subject  string
	req      event.ConnIDRequest
	deadline time.Duration
}

func (f *fakeRequester) RequestWithContext(ctx context.Context, subj string, data []byte) (*nats.Msg, error) {
	f.subject = subj
	_ = json.Unmarshal(data, &f.req)
	if d, ok := ctx.Deadline(); ok {
		f.deadline = time.Until(d)
	}
	if f.err != nil {
		return nil, f.err
	}
	return &nats.Msg{Data: f.reply}, nil
}

func TestRequestConnID(t *testing.T) {
	ts := time.Date(2026, 11, 8, 1, 2, 3, 4, time.UTC)
	flow := event.Flow{L4: "tcp", SrcIP: "192.0.2.1", SrcPort: 40000, DstIP: "172.233.24.85", DstPort: 80}
	f := &fakeRequester{reply: []byte(`{"conn_id":"01JC0X3K8V2T7Q9N4M6P1R5S8W","reserved":true}`)}
	rep, err := RequestConnID(context.Background(), f, flow, ts)
	if err != nil || rep.ConnID != "01JC0X3K8V2T7Q9N4M6P1R5S8W" || !rep.Reserved {
		t.Fatalf("%+v %v", rep, err)
	}
	if f.subject != event.SubjectStoreConnID || f.req.Flow != flow || f.req.Ts != "2026-11-08T01:02:03.000000004Z" {
		t.Fatalf("request %s %+v", f.subject, f.req)
	}
	if f.deadline <= 0 || f.deadline > ConnIDTimeout {
		t.Fatalf("default deadline %v", f.deadline)
	}

	// Prazo do chamador prevalece.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := RequestConnID(ctx, f, flow, ts); err != nil || f.deadline <= ConnIDTimeout {
		t.Fatalf("caller deadline %v %v", f.deadline, err)
	}

	for _, bad := range []string{`{`, `{"conn_id":"short"}`} {
		f.reply = []byte(bad)
		if _, err := RequestConnID(context.Background(), f, flow, ts); !errors.Is(err, ErrConnIDReply) {
			t.Fatalf("%s: %v", bad, err)
		}
	}
	f.err = nats.ErrTimeout
	if _, err := RequestConnID(context.Background(), f, flow, ts); !errors.Is(err, nats.ErrTimeout) {
		t.Fatal(err)
	}
}
