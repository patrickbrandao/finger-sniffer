package store

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"math"

	"github.com/patrickbrandao/finger-sniffer/pkg/fingerprint/ja4plus"
	"github.com/patrickbrandao/finger-sniffer/pkg/fingerprint/p0f"
)

// Análise IP e TCP de uma conexão (spec 013 RF-04..RF-12), feita pacote a pacote durante a correlação.
// "in" é o sentido cliente → espelho e "out" o espelho → cliente, como nos totais.

// Limites de memória por conexão.
const (
	maxWindowSeries = 512
	maxKeepalives   = 64
	maxIPIDs        = 64
)

// Tipos de opção TCP.
const (
	optEOL      = 0
	optNOP      = 1
	optMSS      = 2
	optWScale   = 3
	optSACKPerm = 4
	optSACK     = 5
	optTS       = 8
	optMD5      = 19
	optMPTCP    = 30
	optTFO      = 34
	optExp      = 254 // experimental; TFO antigo com o número mágico 0xF989
)

// timedLen é o par [t_ms, bytes] do openapi (TimedLength).
type timedLen [2]float64

type ipJSON struct {
	TTL          int    `json:"ttl"`
	TTLInitial   int    `json:"ttl_initial"`
	Hops         int    `json:"hops"`
	IPIDSyn      *int   `json:"ip_id_syn"`
	IPIDPattern  string `json:"ip_id_pattern"`
	DF           bool   `json:"df"`
	TOS          int    `json:"tos"`
	DSCP         int    `json:"dscp"`
	ECN          string `json:"ecn"`
	OptionsHex   string `json:"options_hex"`
	Fragmented   bool   `json:"fragmented"`
	FlowLabel    *int   `json:"flow_label"`
	TrafficClass *int   `json:"traffic_class"`
}

type tcpSynJSON struct {
	SrcPort    int     `json:"src_port"`
	ISN        int64   `json:"isn"`
	Window     int     `json:"window"`
	Flags      string  `json:"flags"`
	UrgentPtr  int     `json:"urgent_ptr"`
	HeaderLen  int     `json:"header_len"`
	Options    [][]any `json:"options"`
	PayloadB64 *string `json:"payload_b64"`
	TFO        bool    `json:"tfo"`
}

type tcpJSON struct {
	Syn             *tcpSynJSON `json:"syn,omitempty"`
	JA4T            *string     `json:"ja4t"`
	P0F             *string     `json:"p0f"`
	OSGuess         *string     `json:"os_guess"`
	WindowSeries    []timedLen  `json:"window_series"`
	AckPattern      string      `json:"ack_pattern"`
	PSHUsed         bool        `json:"psh_used"`
	KeepaliveProbes []timedLen  `json:"keepalive_probes"`
	ZeroWindow      bool        `json:"zero_window"`
	RSTWithData     bool        `json:"rst_with_data"`
	SegmentsIn      []timedLen  `json:"segments_in"`
	SegmentsOut     []timedLen  `json:"segments_out"`
	TSClockHz       *float64    `json:"ts_clock_hz"`
	TSInitial       *int64      `json:"ts_initial"`
	TSClockGroup    *string     `json:"ts_clock_group"`
	RTTHandshakeMs  *float64    `json:"rtt_handshake_ms"`
	RTTAppMs        *float64    `json:"rtt_app_ms"`
	SynCookieServer bool        `json:"syn_cookie_server"`
	RetransmitsIn   int         `json:"retransmits_in"`
}

// dirState guarda o que é de cada sentido no registro.
type dirState struct {
	isnSet  bool
	isn     uint32
	retrans int
	ooo     int
	segs    []timedLen
}

// tsSample é um TSval do cliente e o instante de captura.
type tsSample struct {
	t int64
	v uint32
}

// analysis é o estado da análise de uma conexão.
type analysis struct {
	ipSet      bool
	dataTOS    bool // TOS/ECN já vieram de um segmento com dados
	ip         ipJSON
	ipIDs      []uint16
	fragmented bool

	syn        *tcpSynJSON
	ja4t       *string
	p0fSig     *string
	osGuess    *string
	cliWS      int // -1 = sem window scale
	srvWS      int
	cliTS      bool
	cliSACK    bool
	synAckSeen bool
	srvTS      bool
	srvTSval   uint32
	srvSACK    bool

	dir          [2]dirState
	ws           wsConn
	window       []timedLen
	lastWin      int64
	keepalives   []timedLen
	zeroWindow   bool
	rstWithData  bool
	psh          bool
	cliPureAcks  int
	srvDataSegs  int
	tsFirst      tsSample
	tsLast       tsSample
	tsCount      int
	tsInitial    *int64
	clockGroup   *string
	cookie       bool
	cookieJudged bool

	// RTT da aplicação (spec 013 RF-11): último dado novo do espelho ainda sem resposta e o menor intervalo
	// até um dado do cliente que o confirma (o ACK cobre o fim desse dado, logo foi enviado depois de recebê-lo).
	srvPendTs  int64
	srvPendEnd uint32
	rttApp     int64 // ns; -1 = sem amostra
}

func newAnalysis() *analysis {
	return &analysis{cliWS: -1, srvWS: -1, lastWin: -1, rttApp: -1}
}

// ms converte um instante absoluto em ms relativos ao início da conexão (resolução de µs).
func msSince(start, ts int64) float64 {
	return math.Round(float64(ts-start)/1e3) / 1e3
}

// analyze atualiza a análise com um pacote já correlacionado.
func (c *conn) analyze(fi frameInfo, ts int64, cli bool, t *flowTable) {
	a := c.ana
	if cli {
		a.ipPacket(fi)
	}
	if c.l4 != protoTCP || len(fi.l4) < 20 {
		return
	}
	tcp := fi.l4
	flags := tcp[13]
	seq := binary.BigEndian.Uint32(tcp[4:8])
	win := int64(binary.BigEndian.Uint16(tcp[14:16]))
	payload := len(tcp) - fi.tcpDoff
	opts := parseOpts(tcp[20:fi.tcpDoff])
	d := &a.dir[1]
	if cli {
		d = &a.dir[0]
	}
	syn, ack, rst, fin := flags&tcpSYN != 0, flags&tcpACK != 0, flags&tcpRST != 0, flags&tcpFIN != 0

	switch {
	case syn && !ack && cli:
		if a.syn == nil {
			a.synPacket(fi, opts, t)
			d.isnSet, d.isn = true, seq
			a.cliWS, a.cliTS, a.cliSACK = opts.ws, opts.hasTS, opts.sackPerm
			if opts.hasTS {
				v := int64(opts.tsVal)
				a.tsInitial = &v
			}
		}
	case syn && ack && !cli:
		if !a.synAckSeen {
			a.synAckSeen = true
			d.isnSet, d.isn = true, seq
			a.srvWS, a.srvTS, a.srvTSval, a.srvSACK = opts.ws, opts.hasTS, opts.tsVal, opts.sackPerm
		}
	}

	if cli && opts.hasTS {
		s := tsSample{t: ts, v: opts.tsVal}
		if a.tsCount == 0 {
			a.tsFirst = s
		}
		a.tsLast = s
		a.tsCount++
	}

	// retransmissão, fora de ordem e keep-alive como o tshark (seqanalysis.go)
	di := 1
	if cli {
		di = 0
	}
	ackNum := binary.BigEndian.Uint32(tcp[8:12])
	res := a.ws.classify(di, ts, seq, ackNum, uint32(payload), flags, uint32(win), opts.sack) //nolint:gosec // payload < 64 KiB
	if res&segRetransmission != 0 {
		d.retrans++
	}
	if res&segOutOfOrder != 0 {
		d.ooo++
	}
	keepalive := res&segKeepAlive != 0
	if payload > 0 && !syn && !rst && !keepalive && res&segRetransmission == 0 {
		a.appRTT(cli, ts, seq+uint32(payload), ack, ackNum) //nolint:gosec // payload < 64 KiB
	}
	switch {
	case keepalive && cli:
		if len(a.keepalives) < maxKeepalives {
			a.keepalives = append(a.keepalives, timedLen{msSince(c.started, ts), float64(payload)})
		}
	case payload > 0 && !keepalive && len(d.segs) < t.segTracked:
		d.segs = append(d.segs, timedLen{msSince(c.started, ts), float64(payload)})
	}

	if cli {
		if flags&tcpPSH != 0 {
			a.psh = true
		}
		if rst && payload > 0 {
			a.rstWithData = true
		}
		if !rst {
			scaled := win
			if !syn && a.cliWS >= 0 && a.srvWS >= 0 {
				scaled = win << min(a.cliWS, 14)
			}
			if !syn && win == 0 {
				a.zeroWindow = true
			}
			if scaled != a.lastWin && len(a.window) < maxWindowSeries {
				a.window = append(a.window, timedLen{msSince(c.started, ts), float64(scaled)})
				a.lastWin = scaled
			}
		}
		// só os ACKs depois do primeiro dado do espelho contam (o ACK do handshake não)
		if ack && !syn && !fin && !rst && payload == 0 && !keepalive && a.srvDataSegs > 0 {
			a.cliPureAcks++
		}
	} else if payload > 0 && !syn {
		a.srvDataSegs++
	}
}

// appRTT acompanha o RTT da aplicação (spec 013 RF-11). Cada dado novo do espelho vira o pendente; o primeiro
// dado novo do cliente cujo ACK cobre o fim do pendente depende dele (Finished do TLS depois do voo do
// servidor, próxima requisição depois da resposta) e dá uma amostra. Dados do cliente que não confirmam o
// pendente foram enviados em paralelo e não contam. Fica a menor amostra, a que menos inclui o tempo de
// processamento do cliente.
func (a *analysis) appRTT(cli bool, ts int64, end uint32, hasAck bool, ackNum uint32) {
	if !cli {
		a.srvPendTs, a.srvPendEnd = ts, end
		return
	}
	if a.srvPendTs == 0 || !hasAck || !seqGE(ackNum, a.srvPendEnd) {
		return
	}
	if d := ts - a.srvPendTs; d >= 0 && (a.rttApp < 0 || d < a.rttApp) {
		a.rttApp = d
	}
	a.srvPendTs = 0
}

// ipPacket guarda o IP do primeiro pacote do cliente (o SYN, no TCP) e o IP ID de todos.
func (a *analysis) ipPacket(fi frameInfo) {
	ip := fi.l3
	if len(ip) < 20 {
		return
	}
	if fi.frag {
		a.fragmented = true
	}
	if fi.family == 4 && len(a.ipIDs) < maxIPIDs {
		a.ipIDs = append(a.ipIDs, binary.BigEndian.Uint16(ip[4:6]))
	}
	if a.ipSet {
		// TOS/DSCP/ECN do primeiro segmento TCP com dados (openapi IPInfo: SYN e primeiro segmento com dados): o
		// SYN nunca leva ECT (RFC 3168 6.1.1), então o ECN negociado só aparece nos dados.
		if !a.dataTOS && fi.payload > 0 && fi.proto == protoTCP {
			a.dataTOS = true
			a.setTOS(fi.family, ip)
		}
		return
	}
	a.ipSet = true
	a.dataTOS = fi.payload > 0
	r := &a.ip
	if fi.family == 4 {
		r.TTL = int(ip[8])
		id := int(binary.BigEndian.Uint16(ip[4:6]))
		r.IPIDSyn = &id
		r.DF = binary.BigEndian.Uint16(ip[6:8])&0x4000 != 0
		if ihl := int(ip[0]&0x0f) * 4; ihl > 20 && ihl <= len(ip) {
			r.OptionsHex = hex.EncodeToString(ip[20:ihl])
		}
	} else if len(ip) >= 40 {
		r.TTL = int(ip[7])
		fl := int(binary.BigEndian.Uint32(ip[0:4]) & 0xfffff)
		r.FlowLabel = &fl
	}
	a.setTOS(fi.family, ip)
	r.TTLInitial = initialTTL(r.TTL)
	r.Hops = r.TTLInitial - r.TTL
}

// setTOS preenche TOS/DSCP/ECN (e o traffic class do IPv6) a partir do cabeçalho IP.
func (a *analysis) setTOS(family int, ip []byte) {
	r := &a.ip
	var tos int
	if family == 4 {
		tos = int(ip[1])
	} else if len(ip) >= 40 {
		tos = int(binary.BigEndian.Uint32(ip[0:4])>>20) & 0xff
		tc := tos
		r.TrafficClass = &tc
	}
	r.TOS, r.DSCP = tos, tos>>2
	r.ECN = [...]string{"not-ect", "ect1", "ect0", "ce"}[tos&0x03]
}

func initialTTL(ttl int) int {
	switch {
	case ttl <= 32:
		return 32
	case ttl <= 64:
		return 64
	case ttl <= 128:
		return 128
	}
	return 255
}

// ipIDPattern classifica os IP IDs do cliente (spec 013 RF-05).
func ipIDPattern(ids []uint16) string {
	if len(ids) < 2 {
		if len(ids) == 1 && ids[0] == 0 {
			return "zero"
		}
		return "unknown"
	}
	zero, same, incr := true, true, true
	for i, id := range ids {
		if id != 0 {
			zero = false
		}
		if i == 0 {
			continue
		}
		if id != ids[0] {
			same = false
		}
		if d := id - ids[i-1]; d == 0 || d > 1024 { //nolint:gosec // i >= 1 aqui
			incr = false
		}
	}
	switch {
	case zero:
		return "zero"
	case same:
		return "constant"
	case incr:
		return "incremental"
	}
	return "random"
}

// synPacket guarda o SYN completo e calcula JA4T e p0f.
func (a *analysis) synPacket(fi frameInfo, o tcpOpts, t *flowTable) {
	tcp := fi.l4
	s := &tcpSynJSON{
		SrcPort:   int(binary.BigEndian.Uint16(tcp[0:2])),
		ISN:       int64(binary.BigEndian.Uint32(tcp[4:8])),
		Window:    int(binary.BigEndian.Uint16(tcp[14:16])),
		Flags:     tcpFlagsString(tcp[13]),
		UrgentPtr: int(binary.BigEndian.Uint16(tcp[18:20])),
		HeaderLen: fi.tcpDoff,
		Options:   o.list,
		TFO:       o.tfo,
	}
	if pl := tcp[fi.tcpDoff:]; len(pl) > 0 {
		b := base64.StdEncoding.EncodeToString(pl)
		s.PayloadB64 = &b
	}
	a.syn = s
	if v, err := ja4plus.JA4T(tcp); err == nil {
		a.ja4t = &v
	}
	if pk, err := p0f.Parse(fi.l3); err == nil && t.p0f != nil {
		if obs, err := t.p0f.Fingerprint(pk, 0); err == nil {
			a.p0fSig = &obs.RawSig
			if obs.Matched {
				g := obs.OS
				a.osGuess = &g
			}
		}
	}
}

// tcpOpts é o resultado da leitura das opções de um segmento.
type tcpOpts struct {
	list     [][]any
	ws       int
	hasTS    bool
	tsVal    uint32
	sackPerm bool
	sack     bool
	tfo      bool
}

// parseOpts lê as opções TCP na ordem, no formato do openapi (TCPOption). Opção malformada vira
// ["unknown", código, "<hex do resto>"] e encerra a leitura.
func parseOpts(b []byte) tcpOpts {
	o := tcpOpts{list: [][]any{}, ws: -1}
	for i := 0; i < len(b); {
		k := b[i]
		switch k {
		case optEOL:
			o.list = append(o.list, []any{"eol"})
			return o
		case optNOP:
			o.list = append(o.list, []any{"nop"})
			i++
			continue
		}
		if i+1 >= len(b) || int(b[i+1]) < 2 || i+int(b[i+1]) > len(b) { //nolint:gosec // i+1 < len(b) testado antes
			o.list = append(o.list, []any{"unknown", int(k), hex.EncodeToString(b[i:])})
			return o
		}
		l := int(b[i+1]) //nolint:gosec // i+1 < len(b) garantido acima
		v := b[i+2 : i+l]
		switch {
		case k == optMSS && l == 4:
			o.list = append(o.list, []any{"mss", int(binary.BigEndian.Uint16(v))})
		case k == optWScale && l == 3:
			o.ws = int(v[0])
			o.list = append(o.list, []any{"wscale", int(v[0])})
		case k == optSACKPerm && l == 2:
			o.sackPerm = true
			o.list = append(o.list, []any{"sack_perm"})
		case k == optSACK && (l-2)%8 == 0:
			o.sack = true
			e := []any{"sack"}
			for j := 0; j+8 <= len(v); j += 8 {
				e = append(e, int64(binary.BigEndian.Uint32(v[j:])), int64(binary.BigEndian.Uint32(v[j+4:])))
			}
			o.list = append(o.list, e)
		case k == optTS && l == 10:
			o.hasTS, o.tsVal = true, binary.BigEndian.Uint32(v[0:4])
			o.list = append(o.list, []any{"ts", int64(o.tsVal), int64(binary.BigEndian.Uint32(v[4:8]))})
		case k == optTFO:
			o.tfo = true
			o.list = append(o.list, []any{"tfo", hex.EncodeToString(v)})
		case k == optExp && len(v) >= 2 && v[0] == 0xf9 && v[1] == 0x89:
			o.tfo = true
			o.list = append(o.list, []any{"tfo", hex.EncodeToString(v[2:])})
		case k == optMD5:
			o.list = append(o.list, []any{"md5", hex.EncodeToString(v)})
		case k == optMPTCP:
			o.list = append(o.list, []any{"mptcp", hex.EncodeToString(v)})
		default:
			o.list = append(o.list, []any{"unknown", int(k), hex.EncodeToString(v)})
		}
		i += l
	}
	return o
}

// ackPattern classifica os ACKs do cliente para os dados do espelho: um ACK por segmento é imediato, um a
// cada dois (ou menos) é atrasado (delayed ACK).
func (a *analysis) ackPattern() string {
	if a.srvDataSegs < 4 {
		return "unknown"
	}
	r := float64(a.cliPureAcks) / float64(a.srvDataSegs)
	switch {
	case r >= 0.9:
		return "immediate"
	case r <= 0.6:
		return "delayed"
	}
	return "mixed"
}

// clockHz estima a frequência do TSval do cliente (precisa de 100 ms e 5 ticks).
func (a *analysis) clockHz() float64 {
	if a.tsCount < 2 {
		return 0
	}
	dt := float64(a.tsLast.t-a.tsFirst.t) / 1e9
	ticks := float64(a.tsLast.v - a.tsFirst.v)
	if dt < 0.1 || ticks < 5 || ticks > float64(math.MaxUint32/2) {
		return 0
	}
	return ticks / dt
}

// synCookie decide se o SYN-ACK do espelho veio de SYN cookie (spec 013 RF-12): o contador
// TcpExt SyncookiesSent subiu no intervalo do SYN-ACK e as opções batem com as de um cookie do Linux
// (sem timestamps: sem window scale nem SACK; com timestamps: os 6 bits baixos do TSval codificam o
// window scale do cliente e o SACK).
func (a *analysis) synCookie(counterRose bool) bool {
	if !counterRose || !a.synAckSeen {
		return false
	}
	if !a.cliTS || !a.srvTS {
		return a.srvWS < 0 && !a.srvSACK
	}
	want := uint32(0x0f)
	if a.cliWS >= 0 {
		want = uint32(a.cliWS) & 0x0f //nolint:gosec // 0..255
	}
	sack := a.srvTSval&0x10 != 0
	return a.srvTSval&0x0f == want && sack == a.cliSACK
}

// json monta o bloco tcp do registro.
func (a *analysis) tcpJSON(c *conn) *tcpJSON {
	r := &tcpJSON{
		Syn: a.syn, JA4T: a.ja4t, P0F: a.p0fSig, OSGuess: a.osGuess,
		WindowSeries: nonNil(a.window), AckPattern: a.ackPattern(), PSHUsed: a.psh,
		KeepaliveProbes: nonNil(a.keepalives), ZeroWindow: a.zeroWindow, RSTWithData: a.rstWithData,
		SegmentsIn: nonNil(a.dir[0].segs), SegmentsOut: nonNil(a.dir[1].segs),
		TSInitial: a.tsInitial, TSClockGroup: a.clockGroup, SynCookieServer: a.cookie,
		RetransmitsIn: a.dir[0].retrans,
	}
	if hz := a.clockHz(); hz > 0 {
		v := math.Round(hz*100) / 100
		r.TSClockHz = &v
	}
	if c.synAck != 0 && c.established != 0 {
		v := math.Round(float64(c.established-c.synAck)/1e3) / 1e3
		r.RTTHandshakeMs = &v
	}
	if a.rttApp >= 0 {
		v := math.Round(float64(a.rttApp)/1e3) / 1e3
		r.RTTAppMs = &v
	}
	return r
}

func (a *analysis) ipJSON() *ipJSON {
	if !a.ipSet {
		return nil
	}
	r := a.ip
	r.Fragmented = a.fragmented
	if len(a.ipIDs) > 0 {
		r.IPIDPattern = ipIDPattern(a.ipIDs)
	} else {
		r.IPIDPattern = "unknown"
	}
	return &r
}

func nonNil(x []timedLen) []timedLen {
	if x == nil {
		return []timedLen{}
	}
	return x
}
