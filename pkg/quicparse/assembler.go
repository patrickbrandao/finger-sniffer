package quicparse

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/patrickbrandao/finger-sniffer/pkg/fingerprint/ja3"
	"github.com/patrickbrandao/finger-sniffer/pkg/fingerprint/ja4"
	"github.com/patrickbrandao/finger-sniffer/pkg/tlsparse"
)

// DefaultMaxDatagrams é o teto de datagramas guardados por 5-tupla até o ClientHello completar (spec 011).
const DefaultMaxDatagrams = 8

// Erros do Assembler.
var (
	// ErrIncomplete: o teto de datagramas chegou antes de o ClientHello completar.
	ErrIncomplete = errors.New("quicparse: ClientHello incompleto no teto de datagramas")
	// ErrNotInitial: o primeiro pacote do primeiro datagrama não é um Initial.
	ErrNotInitial = errors.New("quicparse: o primeiro pacote não é Initial")
)

// Options configura o Assembler.
type Options struct {
	// MaxDatagrams é o teto de datagramas analisados (<= 0 usa DefaultMaxDatagrams).
	MaxDatagrams int
	// InlineMax é o FS_EVENT_INLINE_MAX para client_hello_b64 (<= 0 usa o padrão do tlsparse).
	InlineMax int
}

// Assembler recebe, em ordem, os datagramas que o cliente mandou numa 5-tupla e remonta o ClientHello
// dos Initials (vários pacotes e datagramas, CRYPTO fora de ordem e duplicado). Não é seguro para uso
// concorrente; não guarda referência aos datagramas recebidos.
type Assembler struct {
	opts    Options
	seen    int
	done    bool
	err     error
	started bool
	keys    *InitialKeys
	version uint32
	dcid    []byte
	largest int64
	initDgs int
	crypto  CryptoStream
	info    Info
	ch      *tlsparse.ClientHello
	frames  int
}

// NewAssembler cria um Assembler.
func NewAssembler(opts Options) *Assembler {
	if opts.MaxDatagrams <= 0 {
		opts.MaxDatagrams = DefaultMaxDatagrams
	}
	return &Assembler{opts: opts, largest: -1, info: Info{
		InitialFrames:   []string{},
		TransportParams: []TransportParam{},
		H3Settings:      [][2]uint64{},
		Requests:        []HTTP3Request{},
	}}
}

// Add analisa mais um datagrama do cliente e informa se a análise terminou (ClientHello completo, versão
// desconhecida, erro definitivo ou teto de datagramas). Depois de terminada, Add não faz nada.
func (a *Assembler) Add(d []byte) bool {
	if a.done {
		return true
	}
	a.seen++
	first := !a.started
	pkts, hasInitial := a.packets(d)
	if first {
		a.info.InitialDatagramSize = len(d)
		a.info.PaddedTo1200 = len(d) >= 1200
		a.info.CoalescedPackets = pkts
	}
	if a.done {
		return true
	}
	if hasInitial {
		a.initDgs++
	}
	if msg, ok := a.crypto.HandshakeMessage(); ok {
		a.finish(msg)
		return true
	}
	if err := a.crypto.Err(); err != nil {
		a.stop(err)
		return true
	}
	if a.seen >= a.opts.MaxDatagrams {
		a.stop(ErrIncomplete)
	}
	return a.done
}

// packets percorre os pacotes coalescidos do datagrama; devolve quantos achou e se algum Initial da
// conexão foi decifrado.
func (a *Assembler) packets(d []byte) (n int, initial bool) {
	for off := 0; off < len(d); {
		b := d[off:]
		if b[0]&0x80 == 0 {
			if b[0]&0x40 != 0 {
				n++ // cabeçalho curto: ocupa o resto do datagrama
			}
			if !a.started {
				a.stop(ErrNotLongHeader)
			}
			return n, initial
		}
		h, err := ParseLongHeader(b)
		if err != nil {
			if !a.started {
				a.stop(err)
			}
			return n, initial
		}
		n++
		if !a.started {
			if !a.start(h) {
				return n, initial
			}
		}
		if h.Type == PacketInitial && h.Version == a.version {
			if a.initial(b[:h.Size], h) {
				initial = true
			}
		}
		off += h.Size
	}
	return n, initial
}

// start registra o cabeçalho do primeiro pacote e deriva as chaves; false encerra a análise.
func (a *Assembler) start(h *LongHeader) bool {
	a.started = true
	a.version = h.Version
	a.dcid = append([]byte(nil), h.DCID...)
	a.info.Version = fmt.Sprintf("%08x", h.Version)
	a.info.DCIDHex = hex.EncodeToString(h.DCID)
	a.info.SCIDHex = hex.EncodeToString(h.SCID)
	a.info.TokenLen = len(h.Token)
	a.info.TokenHex = hex.EncodeToString(h.Token)
	a.info.InitialLength = int(h.Length) //nolint:gosec // limitado pelo datagrama
	a.info.InitialPacketNumber = -1
	if !KnownVersion(h.Version) {
		// versão desconhecida: só o cabeçalho; o quic-go responde Version Negotiation
		a.stop(ErrUnknownVersion)
		return false
	}
	if h.Type != PacketInitial {
		a.stop(ErrNotInitial)
		return false
	}
	k, err := NewInitialKeys(h.Version, h.DCID, false)
	if err != nil {
		a.stop(err)
		return false
	}
	a.keys = k
	return true
}

// initial decifra um Initial e consome os frames.
func (a *Assembler) initial(pkt []byte, h *LongHeader) bool {
	o, err := a.keys.Open(pkt, h, a.largest)
	if err != nil {
		if a.err == nil {
			a.err = err
		}
		return false
	}
	if int64(o.PacketNumber) > a.largest { //nolint:gosec // número de pacote < 2^62
		a.largest = int64(o.PacketNumber) //nolint:gosec // idem
	}
	if a.info.InitialPacketNumber < 0 {
		a.info.InitialPacketNumber = int64(o.PacketNumber) //nolint:gosec // idem
	}
	frames, ferr := ParseFrames(o.Payload)
	for _, f := range frames {
		a.frames++
		if len(a.info.InitialFrames) < MaxInitialFrames {
			a.info.InitialFrames = append(a.info.InitialFrames, f.Name())
		} else {
			a.info.InitialFramesTruncated = true
		}
		if f.Type == FrameCrypto {
			a.crypto.Add(f.Offset, f.Data)
		}
	}
	if ferr != nil && a.err == nil {
		a.err = ferr
	}
	return true
}

func (a *Assembler) stop(err error) {
	a.done = true
	if err != nil {
		a.err = err
	}
}

// finish analisa o ClientHello completo e calcula os fingerprints.
func (a *Assembler) finish(msg []byte) {
	a.done = true
	a.info.ClientHelloDatagrams = a.initDgs
	ch, err := tlsparse.ParseMessage(msg)
	a.ch = ch
	a.info.ClientHello = tlsparse.NewInfo(ch, msg, a.opts.InlineMax)
	ja3.Fill(a.info.ClientHello, ch)
	ja4.Fill(a.info.ClientHello, ch, ja4.QUIC)
	for _, e := range ch.Extensions {
		if e.Type == ExtQUICTransportParams || e.Type == ExtQUICTransportParamsDraft {
			tp, _, tperr := ParseTransportParams(e.Data)
			a.info.TransportParams = tp
			if err == nil {
				err = tperr
			}
			break
		}
	}
	if err != nil {
		a.err = err
	} else if errors.Is(a.err, ErrDecrypt) || errors.Is(a.err, ErrFrame) {
		// o ClientHello completou apesar de um pacote ilegível (retransmissão estragada, por exemplo)
		a.err = nil
	}
}

// Done informa se a análise terminou.
func (a *Assembler) Done() bool { return a.done }

// Complete informa se o ClientHello foi remontado inteiro.
func (a *Assembler) Complete() bool { return a.ch != nil }

// Err devolve o motivo do fim sem ClientHello (ou o erro de análise do ClientHello); nil quando tudo
// correu bem.
func (a *Assembler) Err() error { return a.err }

// Datagrams é quantos datagramas o Assembler analisou.
func (a *Assembler) Datagrams() int { return a.seen }

// Version é a versão QUIC do primeiro pacote (0 antes do primeiro datagrama válido).
func (a *Assembler) Version() uint32 { return a.version }

// DCID é o Destination Connection ID do primeiro Initial (o das chaves Initial).
func (a *Assembler) DCID() []byte { return a.dcid }

// ClientHello devolve o ClientHello analisado (nil se não completou).
func (a *Assembler) ClientHello() *tlsparse.ClientHello { return a.ch }

// Info devolve a análise do Initial (sem h3_settings, close e requests). Os campos ficam definidos
// quando Done; antes disso refletem o que já chegou. O ponteiro é do Assembler: copie antes de alterar
// se o Assembler continuar em uso.
func (a *Assembler) Info() *Info { return &a.info }

// Analyze é um atalho: alimenta um Assembler com os datagramas, em ordem, até terminar.
func Analyze(datagrams [][]byte, opts Options) *Assembler {
	a := NewAssembler(opts)
	for _, d := range datagrams {
		if a.Add(d) {
			break
		}
	}
	return a
}
