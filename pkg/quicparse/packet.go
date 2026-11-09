package quicparse

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// Versões QUIC conhecidas.
const (
	// Version1 é o QUIC v1 (RFC 9000).
	Version1 uint32 = 0x00000001
	// Version2 é o QUIC v2 (RFC 9369).
	Version2 uint32 = 0x6b3343cf
)

// Tipos de pacote de cabeçalho longo, já traduzidos da codificação da versão (v2 troca os bits).
const (
	PacketInitial   = "initial"
	Packet0RTT      = "0rtt"
	PacketHandshake = "handshake"
	PacketRetry     = "retry"
	// PacketVersionNegotiation é o pacote com versão 0.
	PacketVersionNegotiation = "version_negotiation"
	// PacketUnknown é um cabeçalho longo de versão desconhecida: só o que é invariante (RFC 8999) vale.
	PacketUnknown = "unknown"
	// PacketShort é um pacote de cabeçalho curto (1-RTT); ocupa o resto do datagrama.
	PacketShort = "short"
)

// Erros do Initial.
var (
	ErrNotLongHeader  = errors.New("quicparse: não é cabeçalho longo")
	ErrHeader         = errors.New("quicparse: cabeçalho longo inválido")
	ErrUnknownVersion = errors.New("quicparse: versão QUIC desconhecida")
	ErrDecrypt        = errors.New("quicparse: falha ao decifrar o Initial")
)

// versionParams são as constantes que mudam entre v1 e v2 para as chaves Initial.
type versionParams struct {
	salt                    []byte
	keyLabel, ivLabel, hpLb string
	initialType             byte // os 2 bits de tipo que significam Initial
}

var (
	// RFC 9001 seção 5.2
	saltV1 = []byte{
		0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
		0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
	}
	// RFC 9369 seção 3.3.1
	saltV2 = []byte{
		0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
		0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
	}
)

func paramsFor(v uint32) (versionParams, bool) {
	switch v {
	case Version1:
		return versionParams{saltV1, "quic key", "quic iv", "quic hp", 0}, true
	case Version2:
		return versionParams{saltV2, "quicv2 key", "quicv2 iv", "quicv2 hp", 1}, true
	}
	return versionParams{}, false
}

// KnownVersion informa se a versão tem chaves Initial conhecidas (v1 e v2).
func KnownVersion(v uint32) bool {
	_, ok := paramsFor(v)
	return ok
}

// packetType traduz os 2 bits de tipo do cabeçalho longo.
func packetType(version uint32, bits byte) string {
	if version == 0 {
		return PacketVersionNegotiation
	}
	p, ok := paramsFor(version)
	if !ok {
		return PacketUnknown
	}
	// v1: 0 Initial, 1 0-RTT, 2 Handshake, 3 Retry; v2: 1 Initial, 2 0-RTT, 3 Handshake, 0 Retry
	switch (bits - p.initialType) & 3 {
	case 0:
		return PacketInitial
	case 1:
		return Packet0RTT
	case 2:
		return PacketHandshake
	}
	return PacketRetry
}

// LongHeader é o cabeçalho longo como chegou, antes da remoção da proteção.
type LongHeader struct {
	// First é o primeiro byte, ainda protegido.
	First   byte
	Version uint32
	// Type é o tipo traduzido (PacketInitial…).
	Type string
	DCID []byte
	SCID []byte
	// Token só existe no Initial.
	Token []byte
	// Length é o campo Length (número do pacote + payload); só em Initial, 0-RTT e Handshake.
	Length uint64
	// PNOffset é onde começa o número do pacote (fim do cabeçalho até Length).
	PNOffset int
	// Size é o tamanho total do pacote no datagrama (cabeçalho + Length), ou o resto do datagrama nos
	// tipos sem Length.
	Size int
}

// ParseLongHeader lê o cabeçalho longo do início de b. Para versão desconhecida só lê o invariante
// (versão, DCID e SCID) e Size vai até o fim de b.
func ParseLongHeader(b []byte) (*LongHeader, error) {
	if len(b) == 0 || b[0]&0x80 == 0 {
		return nil, ErrNotLongHeader
	}
	r := reader{buf: b}
	h := &LongHeader{First: r.byte()}
	vb := r.bytes(4)
	if r.bad {
		return nil, fmt.Errorf("%w: versão: %w", ErrHeader, errShort)
	}
	h.Version = binary.BigEndian.Uint32(vb)
	h.Type = packetType(h.Version, (h.First>>4)&3)
	h.DCID = r.bytes(uint64(r.byte()))
	h.SCID = r.bytes(uint64(r.byte()))
	if r.bad {
		return nil, fmt.Errorf("%w: connection IDs: %w", ErrHeader, errShort)
	}
	switch h.Type {
	case PacketVersionNegotiation, PacketUnknown, PacketRetry:
		h.Size = len(b)
		return h, nil
	}
	if len(h.DCID) > 20 || len(h.SCID) > 20 {
		return nil, fmt.Errorf("%w: connection ID acima de 20 bytes", ErrHeader)
	}
	if h.Type == PacketInitial {
		h.Token = r.bytes(r.varint())
	}
	h.Length = r.varint()
	if r.bad {
		return nil, fmt.Errorf("%w: token/length: %w", ErrHeader, errShort)
	}
	h.PNOffset = r.off
	if h.Length > uint64(len(b)-r.off) { //nolint:gosec // off <= len(b)
		return h, fmt.Errorf("%w: Length %d passa do datagrama (%d)", ErrHeader, h.Length, len(b)-r.off)
	}
	h.Size = r.off + int(h.Length) //nolint:gosec // Length <= len(b)
	return h, nil
}

// InitialKeys são as chaves Initial de um sentido (RFC 9001 seção 5.2).
type InitialKeys struct {
	aead cipher.AEAD
	iv   []byte
	hp   cipher.Block
}

// expandLabel é o HKDF-Expand-Label do TLS 1.3 com contexto vazio.
//
//nolint:gosec // n e o rótulo cabem em um byte (constantes do pacote)
func expandLabel(secret []byte, label string, n int) []byte {
	full := "tls13 " + label
	info := make([]byte, 0, 4+len(full))
	info = append(info, byte(n>>8), byte(n), byte(len(full)))
	info = append(info, full...)
	info = append(info, 0)
	out, err := hkdf.Expand(sha256.New, secret, string(info), n)
	if err != nil {
		// só falha com n acima de 255*32, impossível aqui
		panic(err)
	}
	return out
}

// NewInitialKeys deriva as chaves Initial do cliente (server=false) ou do servidor para a versão e o
// DCID do primeiro Initial do cliente.
func NewInitialKeys(version uint32, dcid []byte, server bool) (*InitialKeys, error) {
	p, ok := paramsFor(version)
	if !ok {
		return nil, ErrUnknownVersion
	}
	initial, err := hkdf.Extract(sha256.New, dcid, p.salt)
	if err != nil {
		return nil, err
	}
	label := "client in"
	if server {
		label = "server in"
	}
	secret := expandLabel(initial, label, 32)
	key := expandLabel(secret, p.keyLabel, 16)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	hp, err := aes.NewCipher(expandLabel(secret, p.hpLb, 16))
	if err != nil {
		return nil, err
	}
	return &InitialKeys{aead: aead, iv: expandLabel(secret, p.ivLabel, 12), hp: hp}, nil
}

// Opened é um pacote protegido já aberto.
type Opened struct {
	// Header é o cabeçalho sem a proteção (primeiro byte e número do pacote em claro), até o número do
	// pacote inclusive: é o AAD do AEAD.
	Header []byte
	// PacketNumber é o número completo, reconstruído a partir do maior já visto.
	PacketNumber uint64
	PNLen        int
	// Payload são os frames em claro.
	Payload []byte
}

// Open remove a proteção do cabeçalho e decifra o pacote pkt (exatamente um pacote, do primeiro byte até
// o fim do Length) cujo cabeçalho h foi lido por ParseLongHeader. largest é o maior número de pacote já
// decifrado nesse espaço (-1 se nenhum). pkt não é alterado.
//
//nolint:gosec // índices limitados pelo tamanho do pacote e pnLen <= 4
func (k *InitialKeys) Open(pkt []byte, h *LongHeader, largest int64) (*Opened, error) {
	pn := h.PNOffset
	if pn+4+16 > len(pkt) || h.Size > len(pkt) {
		return nil, fmt.Errorf("%w: pacote curto demais para a amostra", ErrDecrypt)
	}
	var mask [16]byte
	k.hp.Encrypt(mask[:], pkt[pn+4:pn+4+16])
	first := pkt[0] ^ (mask[0] & 0x0f)
	pnLen := int(first&0x03) + 1
	if pn+pnLen > h.Size {
		return nil, fmt.Errorf("%w: número do pacote passa do Length", ErrDecrypt)
	}
	hdr := make([]byte, pn+pnLen)
	copy(hdr, pkt[:pn+pnLen])
	hdr[0] = first
	var trunc uint64
	for i := range pnLen {
		hdr[pn+i] ^= mask[1+i]
		trunc = trunc<<8 | uint64(hdr[pn+i])
	}
	full := DecodePacketNumber(largest, trunc, pnLen*8)
	nonce := make([]byte, len(k.iv))
	copy(nonce, k.iv)
	for i := range 8 {
		nonce[len(nonce)-1-i] ^= byte(full >> (8 * i))
	}
	ct := pkt[pn+pnLen : h.Size]
	if len(ct) < k.aead.Overhead() {
		return nil, fmt.Errorf("%w: payload menor que a etiqueta", ErrDecrypt)
	}
	plain, err := k.aead.Open(nil, nonce, ct, hdr)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDecrypt, err)
	}
	return &Opened{Header: hdr, PacketNumber: full, PNLen: pnLen, Payload: plain}, nil
}

// Seal faz o caminho inverso de Open: monta um Initial protegido com o cabeçalho hdr (do primeiro byte,
// em claro, até o número do pacote inclusive, com Length já correto para o payload + 16) e os frames
// em payload. Usado nos testes e por quem precisa gerar Initials sintéticos.
//
//nolint:gosec // idem Open
func (k *InitialKeys) Seal(hdr []byte, pnOffset int, pn uint64, payload []byte) []byte {
	pnLen := int(hdr[0]&0x03) + 1
	nonce := make([]byte, len(k.iv))
	copy(nonce, k.iv)
	for i := range 8 {
		nonce[len(nonce)-1-i] ^= byte(pn >> (8 * i))
	}
	out := append([]byte(nil), hdr...)
	out = k.aead.Seal(out, nonce, payload, hdr)
	if pnOffset+4+16 > len(out) {
		return out
	}
	var mask [16]byte
	k.hp.Encrypt(mask[:], out[pnOffset+4:pnOffset+4+16])
	out[0] ^= mask[0] & 0x0f
	for i := range pnLen {
		out[pnOffset+i] ^= mask[1+i]
	}
	return out
}

// DecodePacketNumber reconstrói o número do pacote completo (RFC 9000 apêndice A.3).
func DecodePacketNumber(largest int64, truncated uint64, bits int) uint64 {
	expected := uint64(largest + 1) //nolint:gosec // largest >= -1
	win := uint64(1) << bits
	half := win / 2
	mask := win - 1
	candidate := (expected &^ mask) | truncated
	switch {
	case candidate+half <= expected && candidate < (1<<62)-win:
		return candidate + win
	case candidate > expected+half && candidate >= win:
		return candidate - win
	}
	return candidate
}
