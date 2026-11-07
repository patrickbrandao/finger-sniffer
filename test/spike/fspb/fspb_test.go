package fspb

import (
	"bytes"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	in := []Record{
		{TsNs: 1, Dir: DirIn, WireLen: 60, Frame: []byte{1, 2, 3}},
		{TsNs: 1 << 62, Dir: DirOut, Flags: FlagTruncated, WireLen: 1514, Frame: bytes.Repeat([]byte{9}, 1514)},
		{TsNs: 3, Frame: nil},
	}
	var buf []byte
	for _, r := range in {
		buf = Append(buf, r)
	}
	var out []Record
	n, err := Decode(buf, func(r Record) error { out = append(out, r); return nil })
	if err != nil || n != len(in) {
		t.Fatalf("decode n=%d err=%v", n, err)
	}
	for i := range in {
		a, b := in[i], out[i]
		if a.TsNs != b.TsNs || a.Dir != b.Dir || a.Flags != b.Flags || a.WireLen != b.WireLen || !bytes.Equal(a.Frame, b.Frame) {
			t.Fatalf("record %d: %+v != %+v", i, a, b)
		}
	}
}

func TestShort(t *testing.T) {
	buf := Append(nil, Record{TsNs: 1, Frame: []byte{1, 2, 3}})
	for _, cut := range []int{5, HeaderLen + 1} {
		if _, err := Decode(buf[:cut], func(Record) error { return nil }); err != ErrShort {
			t.Fatalf("cut %d: err=%v", cut, err)
		}
	}
}

func FuzzDecode(f *testing.F) {
	f.Add(Append(nil, Record{TsNs: 1, Frame: []byte{1}}))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = Decode(b, func(Record) error { return nil })
	})
}
