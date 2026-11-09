package tlsparse

import (
	"bytes"
	"reflect"
	"testing"
)

// rec monta um registro TLS 1.2 com o tipo e o conteúdo dados.
func rec(typ byte, body ...byte) []byte {
	return append([]byte{typ, 0x03, 0x03, byte(len(body) >> 8), byte(len(body))}, body...)
}

// feedChunks alimenta o leitor em pedaços de n bytes e junta os alertas devolvidos.
func feedChunks(r *AlertReader, b []byte, n int) []RecordAlert {
	var out []RecordAlert
	for len(b) > 0 {
		k := min(n, len(b))
		out = append(out, r.Feed(b[:k])...)
		b = b[k:]
	}
	return out
}

func TestAlertReader(t *testing.T) {
	hello := rec(RecordTypeHandshake, 0x01, 0x00, 0x00, 0x02, 0x03, 0x03)
	cases := []struct {
		name string
		in   []byte
		want []RecordAlert
	}{
		{
			"unknown_ca after hello", cat(hello, rec(RecordTypeAlert, 2, 48)),
			[]RecordAlert{{Level: 2, Description: 48, Offset: int64(len(hello))}},
		},
		{
			"two alerts in one record", rec(RecordTypeAlert, 1, 0, 2, 40),
			[]RecordAlert{{Level: 1, Description: 0}, {Level: 2, Description: 40}},
		},
		{
			"alert split across records", cat(rec(RecordTypeAlert, 2), rec(RecordTypeAlert, 70)),
			[]RecordAlert{{Level: 2, Description: 70}},
		},
		{
			"split interrupted by another record", cat(rec(RecordTypeAlert, 2), hello, rec(RecordTypeAlert, 2, 10)),
			[]RecordAlert{{Level: 2, Description: 10, Offset: int64(5 + 1 + len(hello))}},
		},
		{
			"encrypted alert after CCS ignored", cat(rec(RecordTypeChangeCipherSpec, 1), rec(RecordTypeAlert, bytes.Repeat([]byte{0xaa}, 26)...)),
			nil,
		},
		{
			"plain 2-byte alert after CCS kept", cat(rec(RecordTypeChangeCipherSpec, 1), rec(RecordTypeAlert, 2, 48)),
			[]RecordAlert{{Level: 2, Description: 48, Offset: 6}},
		},
		{"application data not read", cat(rec(RecordTypeApplicationData, 0x15, 0x03, 0x03, 0x00, 0x02, 2, 48)), nil},
		{
			"empty record", cat(rec(RecordTypeAlert), rec(RecordTypeAlert, 2, 50)),
			[]RecordAlert{{Level: 2, Description: 50, Offset: 5}},
		},
		{"not TLS stops", cat([]byte("GET / HTTP/1.1\r\n"), rec(RecordTypeAlert, 2, 48)), nil},
	}
	for _, c := range cases {
		for _, chunk := range []int{1, 3, 7, 1 << 16} {
			r := NewAlertReader()
			got := feedChunks(r, c.in, chunk)
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("%s (chunk %d): got %+v want %+v", c.name, chunk, got, c.want)
			}
			if all := r.Alerts(); len(all) != len(c.want) {
				t.Errorf("%s: Alerts() %+v", c.name, all)
			}
		}
	}
}

func TestAlertReaderCap(t *testing.T) {
	r := NewAlertReader()
	r.Feed(rec(RecordTypeAlert, bytes.Repeat([]byte{1, 0}, MaxAlerts+3)...))
	if len(r.Alerts()) != MaxAlerts || r.Dropped() != 3 {
		t.Fatalf("alerts %d dropped %d", len(r.Alerts()), r.Dropped())
	}
	if NewAlertReader().SawChangeCipherSpec() {
		t.Fatal("ccs")
	}
	bad := NewAlertReader()
	bad.Feed([]byte{0x16, 0x03, 0x01, 0xff, 0xff})
	if !bad.Stopped() {
		t.Fatal("oversized record should stop")
	}
}

func cat(parts ...[]byte) []byte {
	var b []byte
	for _, p := range parts {
		b = append(b, p...)
	}
	return b
}

// FuzzAlertReader: nenhuma entrada causa pânico; a leitura em pedaços dá os mesmos alertas que de uma vez.
func FuzzAlertReader(f *testing.F) {
	f.Add(cat(rec(RecordTypeHandshake, 1, 0, 0, 0), rec(RecordTypeAlert, 2, 48)))
	f.Add(cat(rec(RecordTypeAlert, 2), rec(RecordTypeAlert, 70)))
	f.Add(cat(rec(RecordTypeChangeCipherSpec, 1), rec(RecordTypeAlert, 1, 2, 3)))
	f.Fuzz(func(t *testing.T, data []byte) {
		whole := NewAlertReader()
		a := whole.Feed(data)
		parts := NewAlertReader()
		b := feedChunks(parts, data, 3)
		if !reflect.DeepEqual(a, b) || len(a) > MaxAlerts {
			t.Fatalf("whole %+v chunked %+v", a, b)
		}
	})
}
