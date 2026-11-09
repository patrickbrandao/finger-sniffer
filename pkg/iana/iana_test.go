package iana

import "testing"

func TestIsGREASE(t *testing.T) {
	n := 0
	for v := 0; v <= 0xffff; v++ {
		if IsGREASE(uint16(v)) {
			n++
			if v&0x0f0f != 0x0a0a || v>>8 != v&0xff {
				t.Fatalf("0x%04x não é GREASE", v)
			}
		}
	}
	if n != 16 {
		t.Fatalf("%d valores GREASE, esperado 16", n)
	}
	want8 := map[uint8]bool{0x0b: true, 0x2a: true, 0x49: true, 0x68: true, 0x87: true, 0xa6: true, 0xc5: true, 0xe4: true}
	for v := 0; v <= 0xff; v++ {
		if IsGREASE8(uint8(v)) != want8[uint8(v)] {
			t.Fatalf("IsGREASE8(0x%02x)", v)
		}
	}
}

func TestNames(t *testing.T) {
	cases := []struct {
		got, want string
	}{
		{CipherSuite(0x1301), "TLS_AES_128_GCM_SHA256"},
		{CipherSuite(0xc02b), "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"},
		{CipherSuite(0x00ff), "TLS_EMPTY_RENEGOTIATION_INFO_SCSV"},
		{CipherSuite(0x5600), "TLS_FALLBACK_SCSV"},
		{CipherSuite(0xdada), GREASEName},
		{CipherSuite(0xfefe), ""},
		{Extension(0x0000), "server_name"},
		{Extension(0x000a), "supported_groups"},
		{Extension(0x0023), "session_ticket"},
		{Extension(0xfe0d), "encrypted_client_hello"},
		{Extension(0x44cd), "application_settings"},
		{Extension(0x4469), "application_settings_old"},
		{Extension(0x3374), "next_protocol_negotiation"},
		{Extension(0x2a2a), GREASEName},
		{Extension(0xca34), ""},
		{Group(0x001d), "x25519"},
		{Group(0x11ec), "X25519MLKEM768"},
		{Group(0x0a0a), GREASEName},
		{SignatureScheme(0x0403), "ecdsa_secp256r1_sha256"},
		{SignatureScheme(0x0804), "rsa_pss_rsae_sha256"},
		{SignatureScheme(0x0303), "ecdsa_sha224"},
		{SignatureScheme(0x0402), "dsa_sha256"},
		{SignatureScheme(0x0101), "rsa_md5"},
		{SignatureScheme(0x2a2a), GREASEName},
		{SignatureScheme(0xff77), ""},
		{Version(0x0304), "TLS 1.3"},
		{Version(0x0301), "TLS 1.0"},
		{Version(0x0300), "SSL 3.0"},
		{Version(0x7f17), "TLS 1.3 draft 23"},
		{Version(0x1a1a), GREASEName},
		{Version(0x0305), ""},
		{CertCompression(2), "brotli"},
		{CertCompression(0x7a7a), GREASEName},
		{Alert(40), "handshake_failure"},
		{Alert(0), "close_notify"},
		{Alert(255), ""},
		{AlertLevel(2), "fatal"},
		{AlertLevel(1), "warning"},
		{HandshakeType(1), "client_hello"},
		{ECPointFormat(0), "uncompressed"},
		{PSKMode(1), "psk_dhe_ke"},
		{PSKMode(0x2a), GREASEName},
	}
	for i, c := range cases {
		if c.got != c.want {
			t.Errorf("caso %d: %q, esperado %q", i, c.got, c.want)
		}
	}
}

func TestTablesClean(t *testing.T) {
	// nenhuma faixa não atribuída ou reservada vazou para as tabelas geradas
	all := []map[uint16]string{cipherSuites, extensions, supportedGroups, signatureSchemes, certCompressionAlgorithms}
	for _, m := range all {
		if len(m) == 0 {
			t.Fatal("tabela vazia")
		}
		for k, v := range m {
			if v == "" || v == "Unassigned" || v == "Reserved" {
				t.Fatalf("0x%04x: %q", k, v)
			}
		}
	}
	if len(cipherSuites) < 300 {
		t.Fatalf("só %d cipher suites", len(cipherSuites))
	}
}
