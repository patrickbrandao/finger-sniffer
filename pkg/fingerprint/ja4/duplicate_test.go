package ja4

import (
	"encoding/binary"
	"testing"

	"github.com/patrickbrandao/finger-sniffer/pkg/tlsparse"
)

// TestDuplicateExtensionsFirstOccurrence: ClientHello da prova da task 386 (ALPN h2 e depois x1,
// supported_versions 0304 e depois 0303, signature_algorithms 0403 e depois 0804, supported_groups repetido).
// Pela regra da primeira ocorrência de pkg/tlsparse o JA4 dá a versão 13 e o ALPN h2, como o ja4 da FoxIO
// (primeiro ALPN, maior das supported_versions); a lista de extensões mantém as repetições.
func TestDuplicateExtensionsFirstOccurrence(t *testing.T) {
	rawExt := func(typ uint16, data ...byte) []byte {
		b := binary.BigEndian.AppendUint16(nil, typ)
		b = binary.BigEndian.AppendUint16(b, uint16(len(data)))
		return append(b, data...)
	}
	var exts []byte
	exts = append(exts, rawExt(0x0010, 0, 3, 2, 'h', '2')...)
	exts = append(exts, rawExt(0x002b, 2, 0x03, 0x04)...)
	exts = append(exts, rawExt(0x000d, 0, 2, 0x04, 0x03)...)
	exts = append(exts, rawExt(0x000a, 0, 2, 0x00, 0x1d)...)
	exts = append(exts, rawExt(0x0010, 0, 3, 2, 'x', '1')...)
	exts = append(exts, rawExt(0x002b, 2, 0x03, 0x03)...)
	exts = append(exts, rawExt(0x000d, 0, 2, 0x08, 0x04)...)
	exts = append(exts, rawExt(0x000a, 0, 2, 0x00, 0x17)...)
	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0, 0, 2, 0x13, 0x01, 1, 0)
	body = binary.BigEndian.AppendUint16(body, uint16(len(exts)))
	body = append(body, exts...)
	msg := append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	ch, err := tlsparse.ParseMessage(msg)
	if err != nil {
		t.Fatal(err)
	}
	if len(ch.ExtensionErrors) != 4 {
		t.Fatalf("ExtensionErrors=%v", ch.ExtensionErrors)
	}
	f := Compute(ch, TCP)
	const want = "t13i0108h2_1301_000a,000a,000d,000d,002b,002b_0403"
	if f.JA4R != want {
		t.Fatalf("JA4_r %q, want %q", f.JA4R, want)
	}
}
