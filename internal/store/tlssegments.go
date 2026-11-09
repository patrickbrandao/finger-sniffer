package store

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"

	"github.com/patrickbrandao/finger-sniffer/pkg/iana"
)

// clientHelloLen soma os registros TLS de handshake (5 bytes de cabeçalho + corpo) que levam o ClientHello, a
// partir dos bytes crus do evento. records limita a contagem (client_hello_records); 0 = todos os de handshake.
func clientHelloLen(raw []byte, records int) int {
	total, n := 0, 0
	for off := 0; off+5 <= len(raw); {
		if raw[off] != 22 { // handshake
			break
		}
		l := int(binary.BigEndian.Uint16(raw[off+3 : off+5]))
		total += 5 + l
		off += 5 + l
		n++
		if records > 0 && n >= records {
			break
		}
	}
	return total
}

// clientHelloSegments conta quantos segmentos TCP do cliente, a partir do primeiro com dados, cobrem os bytes
// do ClientHello (spec 004: calculado pelo store). 0 quando não há pacotes ou bytes crus.
func clientHelloSegments(ch map[string]any, tcp *tcpJSON) int {
	if tcp == nil || len(tcp.SegmentsIn) == 0 {
		return 0
	}
	b64, _ := ch["client_hello_b64"].(string)
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) == 0 {
		return 0
	}
	records := 0
	switch v := ch["client_hello_records"].(type) {
	case json.Number:
		if n, err := v.Int64(); err == nil {
			records = int(n)
		}
	case float64:
		records = int(v)
	}
	need := clientHelloLen(raw, records)
	if need == 0 {
		need = len(raw)
	}
	got, segs := 0, 0
	for _, s := range tcp.SegmentsIn {
		l := int(s[1])
		if l <= 0 {
			continue
		}
		got += l
		segs++
		if got >= need {
			break
		}
	}
	return segs
}

// alertName dá o nome IANA do alerta TLS (registro "TLS Alerts", via pkg/iana); "unknown" fora do registro.
func alertName(code int) string {
	if code < 0 || code > 255 {
		return "unknown"
	}
	if n := iana.Alert(uint8(code)); n != "" {
		return n
	}
	return "unknown"
}
