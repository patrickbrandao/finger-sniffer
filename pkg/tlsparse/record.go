package tlsparse

import (
	"errors"
	"fmt"
)

// Constantes do registro TLS (RFC 8446 §5.1).
const (
	// RecordHeaderLen é o tamanho do cabeçalho do registro: tipo, versão e tamanho.
	RecordHeaderLen = 5
	// RecordTypeHandshake é o tipo de conteúdo dos registros de handshake.
	RecordTypeHandshake = 0x16
	// RecordTypeAlert é o tipo de conteúdo dos registros de alerta.
	RecordTypeAlert = 0x15
	// HandshakeTypeClientHello é o tipo da mensagem ClientHello.
	HandshakeTypeClientHello = 0x01
	// handshakeHeaderLen: tipo (1) e tamanho (3).
	handshakeHeaderLen = 4
	// MaxClientHelloLen limita o tamanho da mensagem ClientHello aceita na remontagem (os maiores vistos na
	// prática, com ECH e chaves pós-quânticas, ficam abaixo de 4 KiB).
	MaxClientHelloLen = 64 << 10
)

// Erros da remontagem.
var (
	// ErrIncomplete: os bytes acabaram antes do fim do ClientHello; mais dados podem completá-lo.
	ErrIncomplete = errors.New("tlsparse: client hello incomplete")
	// ErrNotHandshake: o primeiro registro não é de handshake TLS.
	ErrNotHandshake = errors.New("tlsparse: not a TLS handshake record")
	// ErrNotClientHello: a primeira mensagem de handshake não é ClientHello.
	ErrNotClientHello = errors.New("tlsparse: first handshake message is not a ClientHello")
	// ErrTooLarge: ClientHello acima de MaxClientHelloLen.
	ErrTooLarge = errors.New("tlsparse: client hello too large")
)

// Reassembly é o resultado da remontagem do ClientHello a partir dos registros TLS.
type Reassembly struct {
	// RecordVersion é a versão do primeiro registro.
	RecordVersion uint16
	// Records é quantos registros TLS carregaram o ClientHello (client_hello_records).
	Records int
	// Consumed é quantos bytes de entrada os registros usados ocupam (cabeçalhos incluídos).
	Consumed int
	// Message é a mensagem de handshake remontada: tipo, tamanho de 3 bytes e corpo.
	Message []byte
}

// Reassemble junta os fragmentos de handshake de um ou mais registros até completar o ClientHello.
//
// Em caso de erro devolve o que já foi juntado. ErrIncomplete indica que faltam bytes (a mensagem ou um
// registro estão cortados); os demais erros são definitivos.
func Reassemble(data []byte) (Reassembly, error) {
	var r Reassembly
	var msg []byte
	need := -1 // tamanho total da mensagem quando o cabeçalho de handshake chegar
	off := 0
	for {
		if need >= 0 && len(msg) >= need {
			r.Message = msg[:need]
			return r, nil
		}
		if len(data)-off < RecordHeaderLen {
			r.Message = msg
			return r, ErrIncomplete
		}
		typ := data[off]
		ver := uint16(data[off+1])<<8 | uint16(data[off+2])
		n := int(data[off+3])<<8 | int(data[off+4])
		if r.Records == 0 && (typ != RecordTypeHandshake || data[off+1] != 0x03) {
			return r, ErrNotHandshake
		}
		if typ != RecordTypeHandshake {
			r.Message = msg
			return r, fmt.Errorf("tlsparse: record %d has type 0x%02x before the end of the client hello",
				r.Records+1, typ)
		}
		if r.Records == 0 {
			r.RecordVersion = ver
		}
		body := data[off+RecordHeaderLen:]
		incomplete := false
		if len(body) < n {
			incomplete = true
		} else {
			body = body[:n]
		}
		r.Records++
		msg = append(msg, body...)
		if !incomplete {
			off += RecordHeaderLen + n
			r.Consumed = off
		} else {
			r.Consumed = len(data)
		}
		if need < 0 && len(msg) >= handshakeHeaderLen {
			if msg[0] != HandshakeTypeClientHello {
				r.Message = msg
				return r, ErrNotClientHello
			}
			l := int(msg[1])<<16 | int(msg[2])<<8 | int(msg[3])
			if l > MaxClientHelloLen {
				r.Message = msg
				return r, ErrTooLarge
			}
			need = handshakeHeaderLen + l
		}
		if incomplete {
			// o registro está cortado: mesmo que a mensagem já esteja inteira, faltam bytes do registro
			r.Message = msg
			if need >= 0 && len(msg) > need {
				r.Message = msg[:need]
			}
			return r, ErrIncomplete
		}
	}
}
