// Package iana traz nomes legíveis dos códigos de TLS (cipher suites, extensões, grupos, algoritmos de
// assinatura, versões, alertas, formatos de ponto, modos PSK e algoritmos de compress_certificate).
//
// As tabelas de tables.go são geradas por gentables.go a partir dos registros IANA, sem depender de utls
// nem de crypto/tls; aqui ficam só as regras (GREASE, versões, composição dos pares hash/assinatura do
// TLS 1.2) e os códigos que circulam na prática sem registro na IANA (ALPS, NPN, Channel ID…).
//
// Toda função devolve "" para código desconhecido; GREASE (RFC 8701) devolve "GREASE".
package iana

import "fmt"

// GREASEName é o nome devolvido para valores GREASE.
const GREASEName = "GREASE"

// IsGREASE informa se v é um valor GREASE de 16 bits (RFC 8701): 0x?a?a com os dois bytes iguais.
func IsGREASE(v uint16) bool {
	return v>>8 == v&0xff && v&0x0f == 0x0a
}

// IsGREASE8 informa se v é um valor GREASE de 8 bits (RFC 8701 §2, psk_key_exchange_modes): 0x0b + n×0x1f.
func IsGREASE8(v uint8) bool {
	return v%0x1f == 0x0b
}

// extensões vistas em clientes reais e ausentes do registro IANA
var extraExtensions = map[uint16]string{
	0x3374: "next_protocol_negotiation",
	0x4469: "application_settings_old", // ALPS, codepoint antigo do Chrome (17513)
	0x44cd: "application_settings",     // ALPS, codepoint novo do Chrome (17613)
	0x754f: "channel_id_old",
	0x7550: "channel_id",
	0xffce: "encrypted_server_name",
}

// versões do protocolo; não há registro IANA para elas
var versions = map[uint16]string{
	0x0002: "SSL 2.0",
	0x0300: "SSL 3.0",
	0x0301: "TLS 1.0",
	0x0302: "TLS 1.1",
	0x0303: "TLS 1.2",
	0x0304: "TLS 1.3",
	0xfeff: "DTLS 1.0",
	0xfefd: "DTLS 1.2",
	0xfefc: "DTLS 1.3",
}

// níveis de alerta (RFC 8446 §6)
var alertLevels = map[uint8]string{1: "warning", 2: "fatal"}

func lookup16(m map[uint16]string, v uint16) string {
	if IsGREASE(v) {
		return GREASEName
	}
	return m[v]
}

// CipherSuite devolve o nome IANA da cipher suite.
func CipherSuite(v uint16) string { return lookup16(cipherSuites, v) }

// Extension devolve o nome da extensão TLS.
func Extension(v uint16) string {
	if n := lookup16(extensions, v); n != "" {
		return n
	}
	return extraExtensions[v]
}

// Group devolve o nome do grupo (supported_groups, key_share).
func Group(v uint16) string { return lookup16(supportedGroups, v) }

// SignatureScheme devolve o nome do algoritmo de assinatura. Códigos sem registro no SignatureScheme são
// lidos como o par hash/assinatura do TLS 1.2 (RFC 5246 §7.4.1.4.1), por exemplo 0x0303 → "ecdsa_sha224".
func SignatureScheme(v uint16) string {
	if n := lookup16(signatureSchemes, v); n != "" {
		return n
	}
	h, s := legacyHashes[uint8(v>>8)], legacySignatures[uint8(v&0xff)]
	if h == "" || s == "" {
		return ""
	}
	return s + "_" + h
}

// Version devolve o nome da versão do protocolo ("TLS 1.3"); rascunhos do TLS 1.3 (0x7fNN) viram
// "TLS 1.3 draft NN".
func Version(v uint16) string {
	if IsGREASE(v) {
		return GREASEName
	}
	if n, ok := versions[v]; ok {
		return n
	}
	if v>>8 == 0x7f {
		return fmt.Sprintf("TLS 1.3 draft %d", v&0xff)
	}
	return ""
}

// CertCompression devolve o nome do algoritmo de compress_certificate (RFC 8879).
func CertCompression(v uint16) string { return lookup16(certCompressionAlgorithms, v) }

// Alert devolve o nome da descrição do alerta.
func Alert(v uint8) string { return alerts[v] }

// AlertLevel devolve o nome do nível do alerta.
func AlertLevel(v uint8) string { return alertLevels[v] }

// HandshakeType devolve o nome do tipo de mensagem de handshake.
func HandshakeType(v uint8) string { return handshakeTypes[v] }

// ECPointFormat devolve o nome do formato de ponto.
func ECPointFormat(v uint8) string { return ecPointFormats[v] }

// PSKMode devolve o nome do modo de troca de chave PSK.
func PSKMode(v uint8) string {
	if IsGREASE8(v) {
		return GREASEName
	}
	return pskKeyExchangeModes[v]
}
