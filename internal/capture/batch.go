package capture

import (
	"strconv"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/patrickbrandao/finger-sniffer/internal/version"
	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// BatchMaxBytes é o teto do corpo de um lote: abaixo do max_payload de 1 MB do NATS (eventbus/nats/nats.conf)
// com folga para os cabeçalhos, e igual ao limite de 900 KiB dos eventos (spec 001). Um frame sozinho nunca passa
// disso: o filtro BPF corta em maxSnap (256 KiB).
const BatchMaxBytes = 900 << 10

// Batcher junta pacotes num lote FSPB v1 até maxCount pacotes, maxBytes de corpo ou maxWait desde o primeiro
// (spec 003 RF-04, ADR 0015).
type Batcher struct {
	maxCount int
	maxBytes int
	maxWait  time.Duration
	iface    string

	buf   []byte
	count int
	first time.Time
}

// NewBatcher cria um lote vazio.
func NewBatcher(maxCount int, maxWait time.Duration, iface string) *Batcher {
	return &Batcher{maxCount: maxCount, maxBytes: BatchMaxBytes, maxWait: maxWait, iface: iface, buf: make([]byte, 0, 256<<10)}
}

// Fits informa se o pacote cabe no lote atual sem passar de maxBytes. Lote vazio aceita qualquer pacote.
func (b *Batcher) Fits(p event.Packet) bool {
	return b.count == 0 || len(b.buf)+event.FSPBHeaderLen+len(p.Frame) <= b.maxBytes
}

// Add acrescenta um pacote (o frame é copiado) e informa se o lote ficou cheio (por contagem ou por bytes). Quem
// chama confere Fits antes e publica o lote atual quando o pacote não cabe.
func (b *Batcher) Add(p event.Packet, now time.Time) bool {
	if b.count == 0 {
		b.first = now
	}
	b.buf = event.AppendPacket(b.buf, p)
	b.count++
	return b.count >= b.maxCount || len(b.buf)+event.FSPBHeaderLen+1500 > b.maxBytes
}

// Due informa se há lote parcial com a espera esgotada.
func (b *Batcher) Due(now time.Time) bool {
	return b.count > 0 && now.Sub(b.first) >= b.maxWait
}

// Len devolve quantos pacotes há no lote.
func (b *Batcher) Len() int { return b.count }

// Take devolve a mensagem NATS do lote e o esvazia (nil se vazio).
func (b *Batcher) Take() *nats.Msg {
	if b.count == 0 {
		return nil
	}
	msg := nats.NewMsg(event.SubjectCapturePacket)
	msg.Header.Set(event.HeaderSchemaVersion, strconv.Itoa(event.SchemaVersion))
	msg.Header.Set(event.HeaderService, event.ServiceCapture)
	msg.Header.Set(event.HeaderServiceVersion, version.Version)
	msg.Header.Set(event.HeaderFormat, event.FSPBFormat)
	msg.Header.Set(event.HeaderCount, strconv.Itoa(b.count))
	msg.Header.Set(event.HeaderIface, b.iface)
	msg.Data = append([]byte(nil), b.buf...)
	b.buf, b.count = b.buf[:0], 0
	return msg
}
