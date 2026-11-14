package event

import (
	"errors"
	"testing"
)

// TestCheckPacketHeaders: só fspb1 com schema 1 passa; ausência ou outro valor é rejeitado (ADR 0034 item 10).
func TestCheckPacketHeaders(t *testing.T) {
	cases := []struct {
		format, version string
		ok              bool
	}{
		{FSPBFormat, "1", true},
		{"fspb2", "1", false},
		{FSPBFormat, "2", false},
		{"", "", false},
		{FSPBFormat, "", false},
	}
	for _, c := range cases {
		h := map[string]string{HeaderFormat: c.format, HeaderSchemaVersion: c.version}
		err := CheckPacketHeaders(func(k string) string { return h[k] })
		if (err == nil) != c.ok || (err != nil && !errors.Is(err, ErrPacketHeaders)) {
			t.Errorf("%q/%q: err %v", c.format, c.version, err)
		}
	}
}

// TestDecodePacketsCount: devolve quantos registros leu e ErrShortBatch no lote truncado.
func TestDecodePacketsCount(t *testing.T) {
	var buf []byte
	for range 3 {
		buf = AppendPacket(buf, Packet{TsNs: 1, Frame: []byte{1, 2, 3}})
	}
	n, err := DecodePackets(buf, func(Packet) error { return nil })
	if n != 3 || err != nil {
		t.Fatalf("n %d err %v", n, err)
	}
	if _, err := DecodePackets(buf[:len(buf)-1], func(Packet) error { return nil }); !errors.Is(err, ErrShortBatch) {
		t.Fatalf("short: %v", err)
	}
}
