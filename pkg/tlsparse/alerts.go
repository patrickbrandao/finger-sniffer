package tlsparse

// Leitura dos alertas TLS em texto claro de um sentido do fluxo (spec 008 RF-04, ADR 0029). Usado pelo
// web (handshake do crypto/tls) e pelo raw (TLS opcional nas portas cruas).

// Tipos de conteúdo do registro TLS (RFC 8446 §5.1, RFC 5246 §6.2.1) usados pelo leitor de alertas.
const (
	// RecordTypeChangeCipherSpec é o tipo do registro ChangeCipherSpec.
	RecordTypeChangeCipherSpec = 0x14
	// RecordTypeApplicationData é o tipo dos registros cifrados (e dos dados de aplicação).
	RecordTypeApplicationData = 0x17
	// recordTypeHeartbeat é o maior tipo de conteúdo registrado (RFC 6520).
	recordTypeHeartbeat = 0x18
	// maxRecordLen é o maior tamanho de registro aceito: 2^14 de texto claro mais a folga de 2048 do
	// TLSCiphertext (RFC 5246 §6.2.3); acima disso o fluxo não é TLS e a leitura para.
	maxRecordLen = 1<<14 + 2048
	// alertLen é o tamanho da mensagem de alerta: nível (1) e descrição (1).
	alertLen = 2
)

// MaxAlerts é o teto de alertas guardados por sentido; os excedentes são contados em Dropped.
const MaxAlerts = 64

// Níveis de alerta (RFC 8446 §6).
const (
	AlertLevelWarning = 1
	AlertLevelFatal   = 2
)

// RecordAlert é um alerta TLS lido em texto claro: nível e descrição exatos dos bytes, e o offset (no sentido
// lido, desde o primeiro byte entregue ao leitor) do cabeçalho do registro que o trouxe.
type RecordAlert struct {
	Level       uint8
	Description uint8
	Offset      int64
}

// AlertReader lê, em pedaços de qualquer tamanho, os registros TLS de um sentido do fluxo e extrai os
// alertas em texto claro (tipo 0x15). Trata o registro partido entre pedaços, vários alertas num registro
// e o alerta partido entre dois registros de alerta seguidos (permitido no TLS ≤ 1.2).
//
// Os registros cifrados não são interpretados: os de tipo 0x17 e, depois do ChangeCipherSpec do sentido
// (TLS ≤ 1.2), os de tipo 0x15 com mais de 2 bytes (um alerta cifrado sempre leva MAC ou tag). Um registro
// de alerta de exatamente 2 bytes depois do ChangeCipherSpec continua sendo lido: no TLS 1.3 o
// ChangeCipherSpec é só de compatibilidade e o alerta em claro ainda pode vir. Um cabeçalho que não é de
// registro TLS (tipo fora de 0x14–0x18, versão sem 0x03 ou tamanho acima do máximo) para a leitura.
//
// O AlertReader não é seguro para uso concorrente.
type AlertReader struct {
	hdr  [RecordHeaderLen]byte
	hdrN int
	// need e reading descrevem o registro em leitura: bytes ainda por vir e se o conteúdo é lido como alerta.
	need    int
	reading bool
	recOff  int64
	// part guarda o primeiro byte de um alerta partido entre registros (partN = 1).
	part     byte
	partN    int
	partOff  int64
	ccs      bool
	stopped  bool
	off      int64
	alerts   []RecordAlert
	dropped  int
	lastType uint8
}

// NewAlertReader cria um leitor para um sentido do fluxo, a partir do primeiro byte dele.
func NewAlertReader() *AlertReader { return &AlertReader{} }

// Feed consome mais um pedaço do fluxo e devolve os alertas completados nele, na ordem. A fatia devolvida
// é nova a cada chamada (pode ser guardada).
func (r *AlertReader) Feed(b []byte) []RecordAlert {
	var out []RecordAlert
	for len(b) > 0 && !r.stopped {
		if r.need == 0 {
			n := copy(r.hdr[r.hdrN:], b)
			r.hdrN += n
			r.off += int64(n)
			b = b[n:]
			if r.hdrN < RecordHeaderLen {
				return out
			}
			r.startRecord()
			continue
		}
		n := min(r.need, len(b))
		if r.reading {
			out = r.readAlerts(b[:n], out)
		}
		r.need -= n
		r.off += int64(n)
		b = b[n:]
		if r.need == 0 {
			r.hdrN = 0
		}
	}
	return out
}

// startRecord interpreta o cabeçalho do registro que acabou de chegar.
func (r *AlertReader) startRecord() {
	typ, length := r.hdr[0], int(r.hdr[3])<<8|int(r.hdr[4])
	if typ < RecordTypeChangeCipherSpec || typ > recordTypeHeartbeat || r.hdr[1] != 0x03 || length > maxRecordLen {
		r.stopped = true
		return
	}
	r.recOff = r.off - RecordHeaderLen
	if typ != RecordTypeAlert || r.lastType != RecordTypeAlert {
		// Só um registro de alerta logo em seguida continua um alerta partido.
		r.partN = 0
	}
	r.lastType = typ
	r.need = length
	r.reading = typ == RecordTypeAlert && (!r.ccs || length == alertLen)
	if typ == RecordTypeChangeCipherSpec {
		r.ccs = true
	}
	if length == 0 {
		r.hdrN = 0
	}
}

// readAlerts lê o conteúdo de um registro de alerta em claro (pode vir em vários pedaços).
func (r *AlertReader) readAlerts(p []byte, out []RecordAlert) []RecordAlert {
	for _, c := range p {
		if r.partN == 0 {
			r.part, r.partN, r.partOff = c, 1, r.recOff
			continue
		}
		a := RecordAlert{Level: r.part, Description: c, Offset: r.partOff}
		r.partN = 0
		if len(r.alerts) >= MaxAlerts {
			r.dropped++
			continue
		}
		r.alerts = append(r.alerts, a)
		out = append(out, a)
	}
	return out
}

// Alerts devolve todos os alertas lidos até aqui, na ordem (cópia).
func (r *AlertReader) Alerts() []RecordAlert {
	return append([]RecordAlert(nil), r.alerts...)
}

// Dropped devolve quantos alertas passaram de MaxAlerts e não foram guardados.
func (r *AlertReader) Dropped() int { return r.dropped }

// Stopped informa se a leitura parou num cabeçalho que não é de registro TLS.
func (r *AlertReader) Stopped() bool { return r.stopped }

// SawChangeCipherSpec informa se o sentido já mandou ChangeCipherSpec.
func (r *AlertReader) SawChangeCipherSpec() bool { return r.ccs }
