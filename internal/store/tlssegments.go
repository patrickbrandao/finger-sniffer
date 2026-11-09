package store

import (
	"encoding/base64"
	"encoding/binary"
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
	if v, ok := ch["client_hello_records"].(float64); ok {
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

// alertName dá o nome do alerta TLS (RFC 8446 seção 6 e registro da IANA).
func alertName(code int) string {
	if n, ok := tlsAlertNames[code]; ok {
		return n
	}
	return "unknown"
}

var tlsAlertNames = map[int]string{
	0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac", 21: "decryption_failed", 22: "record_overflow",
	30: "decompression_failure", 40: "handshake_failure", 41: "no_certificate", 42: "bad_certificate",
	43: "unsupported_certificate", 44: "certificate_revoked", 45: "certificate_expired", 46: "certificate_unknown",
	47: "illegal_parameter", 48: "unknown_ca", 49: "access_denied", 50: "decode_error", 51: "decrypt_error",
	52: "too_many_cids_requested", 60: "export_restriction", 70: "protocol_version", 71: "insufficient_security",
	80: "internal_error", 86: "inappropriate_fallback", 90: "user_canceled", 100: "no_renegotiation",
	109: "missing_extension", 110: "unsupported_extension", 111: "certificate_unobtainable", 112: "unrecognized_name",
	113: "bad_certificate_status_response", 114: "bad_certificate_hash_value", 115: "unknown_psk_identity",
	116: "certificate_required", 120: "no_application_protocol", 121: "ech_required",
}
