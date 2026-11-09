package tlsparse

import "errors"

// Tipos de extensão decodificados.
const (
	ExtServerName           uint16 = 0x0000
	ExtStatusRequest        uint16 = 0x0005
	ExtSupportedGroups      uint16 = 0x000a
	ExtECPointFormats       uint16 = 0x000b
	ExtSignatureAlgorithms  uint16 = 0x000d
	ExtALPN                 uint16 = 0x0010
	ExtPadding              uint16 = 0x0015
	ExtCompressCertificate  uint16 = 0x001b
	ExtRecordSizeLimit      uint16 = 0x001c
	ExtDelegatedCredentials uint16 = 0x0022
	ExtSessionTicket        uint16 = 0x0023
	ExtPreSharedKey         uint16 = 0x0029
	ExtEarlyData            uint16 = 0x002a
	ExtSupportedVersions    uint16 = 0x002b
	ExtPSKKeyExchangeModes  uint16 = 0x002d
	ExtSignatureAlgsCert    uint16 = 0x0032
	ExtKeyShare             uint16 = 0x0033
	ExtALPSOld              uint16 = 0x4469 // 17513
	ExtALPS                 uint16 = 0x44cd // 17613
	ExtEncryptedClientHello uint16 = 0xfe0d
)

var (
	errMalformed = errors.New("malformed extension data")
	errTrailing  = errors.New("trailing bytes after extension data")
)

// decodeExtension preenche os campos decodificados de uma extensão conhecida. Desconhecidas ficam só com
// os dados crus. A presença é registrada antes da decodificação, para valer mesmo com dados malformados.
func (ch *ClientHello) decodeExtension(typ uint16, data []byte) error {
	r := reader{buf: data}
	switch typ {
	case ExtServerName:
		ch.HasSNI = true
		return ch.decodeSNI(r)
	case ExtStatusRequest:
		ch.StatusRequest = true
		return nil
	case ExtSupportedGroups:
		v, err := u16vec(&r)
		ch.SupportedGroups = v
		return err
	case ExtECPointFormats:
		v, ok := r.vec8()
		if !ok {
			return errMalformed
		}
		ch.ECPointFormats = append([]uint8{}, v...)
		return trailing(&r)
	case ExtSignatureAlgorithms:
		v, err := u16vec(&r)
		ch.SignatureAlgorithms = v
		return err
	case ExtSignatureAlgsCert:
		v, err := u16vec(&r)
		ch.SignatureAlgorithmsCert = v
		return err
	case ExtALPN:
		v, err := protocolList(&r)
		ch.ALPN = v
		return err
	case ExtPadding:
		ch.PaddingLen = len(data)
		return nil
	case ExtCompressCertificate:
		v, ok := r.vec8()
		if !ok {
			return errMalformed
		}
		ch.CompressCertificate = u16list(v)
		if len(v)%2 != 0 {
			return errMalformed
		}
		return trailing(&r)
	case ExtRecordSizeLimit:
		v, ok := r.u16()
		if !ok {
			return errMalformed
		}
		ch.RecordSizeLimit = int(v)
		return trailing(&r)
	case ExtDelegatedCredentials:
		ch.HasDelegatedCredentials = true
		v, err := u16vec(&r)
		ch.DelegatedCredentials = v
		return err
	case ExtSessionTicket:
		ch.SessionTicket = true
		ch.SessionTicketLen = len(data)
		return nil
	case ExtPreSharedKey:
		ch.PreSharedKey = true
		return ch.decodePSK(r)
	case ExtEarlyData:
		ch.EarlyData = true
		return nil
	case ExtSupportedVersions:
		v, ok := r.vec8()
		if !ok {
			return errMalformed
		}
		ch.SupportedVersions = u16list(v)
		if len(v)%2 != 0 {
			return errMalformed
		}
		return trailing(&r)
	case ExtPSKKeyExchangeModes:
		v, ok := r.vec8()
		if !ok {
			return errMalformed
		}
		ch.PSKModes = append([]uint8{}, v...)
		return trailing(&r)
	case ExtKeyShare:
		return ch.decodeKeyShare(r)
	case ExtALPSOld, ExtALPS:
		ch.ALPSCodepoints = append(ch.ALPSCodepoints, typ)
		v, err := protocolList(&r)
		ch.ALPS = append(ch.ALPS, v...)
		return err
	case ExtEncryptedClientHello:
		ch.EncryptedClientHello = true
		return nil
	}
	return nil
}

// decodeSNI lê a ServerNameList (RFC 6066 §3) e guarda o primeiro host_name.
func (ch *ClientHello) decodeSNI(r reader) error {
	list, ok := r.vec16()
	if !ok {
		return errMalformed
	}
	l := reader{buf: list}
	for !l.empty() {
		typ, ok := l.u8()
		if !ok {
			return errMalformed
		}
		name, ok := l.vec16()
		if !ok {
			return errMalformed
		}
		if typ == 0 && ch.SNI == "" {
			ch.SNI = string(name)
		}
	}
	return trailing(&r)
}

// decodeKeyShare lê o KeyShareClientHello (RFC 8446 §4.2.8): grupos e tamanhos das chaves.
func (ch *ClientHello) decodeKeyShare(r reader) error {
	list, ok := r.vec16()
	if !ok {
		return errMalformed
	}
	l := reader{buf: list}
	for !l.empty() {
		g, ok := l.u16()
		if !ok {
			return errMalformed
		}
		k, ok := l.vec16()
		if !ok {
			return errMalformed
		}
		ch.KeyShares = append(ch.KeyShares, KeyShare{Group: g, Length: len(k)})
	}
	return trailing(&r)
}

// decodePSK conta as identidades do OfferedPsks (RFC 8446 §4.2.11).
func (ch *ClientHello) decodePSK(r reader) error {
	ids, ok := r.vec16()
	if !ok {
		return errMalformed
	}
	l := reader{buf: ids}
	for !l.empty() {
		if _, ok := l.vec16(); !ok {
			return errMalformed
		}
		if _, ok := l.u32(); !ok {
			return errMalformed
		}
		ch.PSKIdentities++
	}
	if _, ok := r.vec16(); !ok { // binders
		return errMalformed
	}
	return trailing(&r)
}

// u16vec lê um vetor de uint16 com tamanho de 2 bytes.
func u16vec(r *reader) ([]uint16, error) {
	v, ok := r.vec16()
	if !ok {
		return nil, errMalformed
	}
	out := u16list(v)
	if len(v)%2 != 0 {
		return out, errMalformed
	}
	return out, trailing(r)
}

// protocolList lê uma ProtocolNameList (ALPN, RFC 7301 §3.1; ALPS usa o mesmo formato).
func protocolList(r *reader) ([]string, error) {
	list, ok := r.vec16()
	if !ok {
		return nil, errMalformed
	}
	var out []string
	l := reader{buf: list}
	for !l.empty() {
		p, ok := l.vec8()
		if !ok {
			return out, errMalformed
		}
		out = append(out, string(p))
	}
	return out, trailing(r)
}

func trailing(r *reader) error {
	if !r.empty() {
		return errTrailing
	}
	return nil
}
