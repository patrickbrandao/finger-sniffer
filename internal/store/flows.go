package store

import (
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"sync"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/patrickbrandao/finger-sniffer/pkg/fingerprint/p0f"
)

// flowKey identifica um fluxo independente do sentido (pontas em ordem canônica).
type flowKey struct {
	l4   uint8
	a, b netip.AddrPort
}

func keyOf(l4 uint8, x, y netip.AddrPort) flowKey {
	if x.Compare(y) > 0 {
		x, y = y, x
	}
	return flowKey{l4: l4, a: x, b: y}
}

// conn é o estado em memória de uma conexão aberta (spec 004 RF-02, spec 013 RF-01..RF-03 básicos).
type conn struct {
	id       string
	l4       uint8
	family   int
	client   netip.AddrPort // quem mandou o primeiro pacote (SYN, no TCP)
	server   netip.AddrPort
	started  int64
	lastSeen int64
	degraded bool

	syn, synAck, established, firstData        int64
	clientFin, serverFin, clientRst, serverRst int64
	recentData                                 [closeRing]dataSeg // últimos dados antes do 1º FIN/RST
	recentN                                    int
	dataAfterFin                               bool
	inSegs, outSegs, inData, outData           int
	inBytes, outBytes                          int64
	pcapBytes                                  int64
	truncated                                  bool
	closeAt                                    int64
	serverSeen                                 bool
	quicDCID                                   string // DCID do primeiro Initial QUIC do cliente (hex)
	ana                                        *analysis
	app                                        *appState // eventos de aplicação associados (spec 004)
}

// dataSeg é um segmento com dados, guardado para medir a ociosidade antes do fechamento.
type dataSeg struct {
	ts  int64
	cli bool
	n   int
}

// fromClient informa se o pacote foi enviado pelo cliente da conexão.
func (c *conn) fromClient(fi frameInfo) bool { return fi.srcAP() == c.client }

// observe atualiza o estado com um pacote.
func (c *conn) observe(fi frameInfo, ts int64, grace time.Duration) {
	c.lastSeen = ts
	cli := c.fromClient(fi)
	if cli {
		c.inSegs++
	} else {
		c.outSegs++
		c.serverSeen = true
	}
	if fi.payload > 0 {
		// só os dados até o primeiro FIN/RST contam para a ociosidade antes do fechamento (spec 013 RF-02):
		// o que vem depois (close_notify/GOAWAY do outro lado, "half-close test" do raw) já é o fechamento
		if c.clientFin == 0 && c.serverFin == 0 && c.clientRst == 0 && c.serverRst == 0 {
			c.recentData[c.recentN%closeRing] = dataSeg{ts: ts, cli: cli, n: fi.payload}
			c.recentN++
		}
		if cli {
			c.inData++
			c.inBytes += int64(fi.payload)
			if c.firstData == 0 {
				c.firstData = ts
			}
		} else {
			c.outData++
			c.outBytes += int64(fi.payload)
		}
		// Meio-fechamento: um lado fechou e o outro continua mandando dados.
		if (cli && c.serverFin != 0) || (!cli && c.clientFin != 0) {
			c.dataAfterFin = true
		}
	}
	if c.l4 != protoTCP {
		return
	}
	fl := fi.tcpFlags
	switch {
	case fl&tcpSYN != 0 && fl&tcpACK == 0 && cli && c.syn == 0:
		c.syn = ts
	case fl&tcpSYN != 0 && fl&tcpACK != 0 && !cli && c.synAck == 0:
		c.synAck = ts
	case fl&tcpACK != 0 && fl&tcpSYN == 0 && cli && c.synAck != 0 && c.established == 0:
		c.established = ts
	}
	if fl&tcpFIN != 0 {
		if cli && c.clientFin == 0 {
			c.clientFin = ts
		} else if !cli && c.serverFin == 0 {
			c.serverFin = ts
		}
	}
	if fl&tcpRST != 0 {
		if cli && c.clientRst == 0 {
			c.clientRst = ts
		} else if !cli && c.serverRst == 0 {
			c.serverRst = ts
		}
	}
	// Fecha depois de uma pequena folga para pegar o último ACK.
	if c.closeAt == 0 && (c.clientRst != 0 || c.serverRst != 0 || (c.clientFin != 0 && c.serverFin != 0)) {
		c.closeAt = ts + grace.Nanoseconds()
	}
}

// closing informa se a conexão já viu o fechamento (FIN dos dois lados ou RST).
func (c *conn) closing() bool { return c.closeAt != 0 }

// isStray decide o que vira pacote avulso em vez de conexão (spec 004 RF-03): TCP que nunca completou o
// handshake (SYN sem resposta, SYN recusado com RST, varreduras) e UDP sem nenhuma resposta.
func (c *conn) isStray() bool {
	if c.l4 == protoTCP {
		return c.synAck == 0
	}
	return !c.serverSeen
}

// flowTable guarda as conexões abertas. É usada pelo ingest e consultada pela API (registro ao vivo).
type flowTable struct {
	mu          sync.Mutex
	conns       map[flowKey]*conn
	byID        map[string]*conn
	reserved    map[flowKey]reservation // conn_id reservados por fs.v1.store.conn_id (ADR 0017)
	newID       func(ts int64) string
	grace       time.Duration
	tcpIdle     time.Duration
	udpIdle     time.Duration
	maxOpen     int
	maxNewPerS  int
	newInSecond int
	secondStart int64
	segTracked  int
	p0f         *p0f.DB
	clocks      clockRegistry
	cookies     cookieHistory
}

func newFlowTable(cfg IngestConfig) *flowTable {
	seg := cfg.SegmentsTracked
	if seg <= 0 {
		seg = 32
	}
	db := cfg.P0F
	if db == nil {
		db = &p0f.DB{} // sem banco: assinatura crua sem palpite de SO
	}
	return &flowTable{
		conns: map[flowKey]*conn{}, byID: map[string]*conn{}, reserved: map[flowKey]reservation{}, grace: cfg.CloseGrace, tcpIdle: cfg.TCPIdle,
		udpIdle: cfg.UDPIdle, maxOpen: cfg.MaxOpen, maxNewPerS: cfg.MaxNewPerS, newID: newULID,
		segTracked: seg, p0f: db,
	}
}

// finish fecha a análise de uma conexão que saiu da tabela: grupo de relógio e SYN cookie.
func (t *flowTable) finish(c *conn) {
	if c.ana.cookieJudged {
		return
	}
	c.ana.cookieJudged = true
	c.ana.clockGroup = t.clocks.assign(c, true)
	if c.synAck != 0 {
		c.ana.cookie = c.ana.synCookie(t.cookies.rose(c.synAck))
	}
}

// sampleCookies registra uma leitura do contador TcpExt SyncookiesSent.
func (t *flowTable) sampleCookies(ts, v int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.cookies.add(ts, v)
}

// newULID gera o conn_id com o instante do primeiro pacote.
func newULID(ts int64) string {
	return ulid.MustNew(ulid.Timestamp(time.Unix(0, ts)), ulid.DefaultEntropy()).String()
}

// live devolve o registro atual de uma conexão ainda aberta.
func (t *flowTable) live(id string) (connectionJSON, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	c, ok := t.byID[id]
	if !ok {
		return connectionJSON{}, false
	}
	r := c.record(0, "")
	if r.TCP != nil {
		// provisório: sem registrar grupo novo enquanto a conexão está aberta
		r.TCP.TSClockGroup = t.clocks.assign(c, false)
		if c.synAck != 0 {
			r.TCP.SynCookieServer = c.ana.synCookie(t.cookies.rose(c.synAck))
		}
	}
	return r, true
}

// result descreve o que o ingest deve fazer com um pacote.
type result struct {
	stray   bool  // gravar como pacote avulso, sem conexão
	conn    *conn // conexão do pacote
	created bool  // conexão nova (inserir a linha)
	ended   *conn // conexão anterior com a mesma 5-tupla que terminou agora (reuso)
}

// handle correlaciona um pacote (spec 004 RF-02/RF-03).
func (t *flowTable) handle(fi frameInfo, ts int64) result {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !fi.ok || !fi.ports || (fi.proto != protoTCP && fi.proto != protoUDP) {
		return result{stray: true}
	}
	k := keyOf(fi.proto, fi.srcAP(), fi.dstAP())
	c := t.conns[k]
	var res result

	isSYN := fi.proto == protoTCP && fi.tcpFlags&tcpSYN != 0 && fi.tcpFlags&tcpACK == 0
	// Um SYN novo sobre uma conexão que já fechou abre outra conexão (reuso da 5-tupla).
	// No QUIC, um Initial do cliente com DCID novo depois do close da conexão anterior abre outra (ADR 0019).
	newQUIC := false
	dcid, isInitial := "", false
	if fi.proto == protoUDP {
		dcid, isInitial = quicInitialDCID(fi.l4)
		newQUIC = c != nil && isInitial && c.closing() && c.fromClient(fi) && dcid != c.quicDCID
	}
	if c != nil && (newQUIC || (isSYN && (c.closing() || (c.established != 0 && c.fromClient(fi))))) {
		delete(t.conns, k)
		delete(t.byID, c.id)
		t.finish(c)
		res.ended, c = c, nil
	}
	if c == nil {
		// RST sem conexão conhecida é avulso.
		if fi.proto == protoTCP && fi.tcpFlags&tcpRST != 0 {
			return result{stray: true, ended: res.ended}
		}
		c = &conn{
			id: t.takeReserved(k, ts),
			l4: fi.proto, family: fi.family, client: fi.srcAP(), server: fi.dstAP(), started: ts,
			ana: newAnalysis(), app: newAppState(),
		}
		c.degraded = t.overloaded(ts)
		t.conns[k] = c
		t.byID[c.id] = c
		res.created = true
	}
	if isInitial && c.quicDCID == "" && c.fromClient(fi) {
		c.quicDCID = dcid
	}
	c.observe(fi, ts, t.grace)
	c.analyze(fi, ts, c.fromClient(fi), t)
	res.conn = c
	return res
}

// overloaded aplica o modo degradado (spec 004 RF-11): acima de maxOpen abertas ou maxNewPerS novas/s.
func (t *flowTable) overloaded(ts int64) bool {
	if ts-t.secondStart >= int64(time.Second) {
		t.secondStart, t.newInSecond = ts, 0
	}
	t.newInSecond++
	return len(t.conns) >= t.maxOpen || t.newInSecond > t.maxNewPerS
}

// due tira da tabela e devolve as conexões que terminaram (fechamento + folga, ou ociosidade).
func (t *flowTable) due(now int64) []*conn {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.expireReservations(now)
	var out []*conn
	for k, c := range t.conns {
		idle := t.tcpIdle
		// UDP com evento h3 e sem close (QUIC não tem FIN) usa a ociosidade do TCP (ADR 0019).
		if c.l4 == protoUDP && !c.app.isQUIC() {
			idle = t.udpIdle
		}
		if (c.closing() && now >= c.closeAt) || now-c.lastSeen > idle.Nanoseconds() {
			out = append(out, c)
			delete(t.conns, k)
			delete(t.byID, c.id)
			t.finish(c)
		}
	}
	return out
}

// quicInitialDCID devolve o DCID (hex) de um pacote Initial QUIC de cabeçalho longo; udp é o cabeçalho UDP com
// os dados. Versão 2 (RFC 9369) usa o tipo 1 para o Initial; v1 e versões desconhecidas, o tipo 0.
func quicInitialDCID(udp []byte) (string, bool) {
	if len(udp) < 8+7 {
		return "", false
	}
	p := udp[8:]
	if p[0]&0x80 == 0 {
		return "", false // cabeçalho curto
	}
	version := binary.BigEndian.Uint32(p[1:5])
	typ := (p[0] >> 4) & 0x03
	switch {
	case version == 0:
		return "", false // negociação de versão
	case version == 0x6b3343cf:
		if typ != 1 {
			return "", false
		}
	case typ != 0:
		return "", false
	}
	n := int(p[5])
	if n > 20 || len(p) < 6+n {
		return "", false
	}
	return hex.EncodeToString(p[6 : 6+n]), true
}

// open devolve quantas conexões estão abertas.
func (t *flowTable) open() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.conns)
}
