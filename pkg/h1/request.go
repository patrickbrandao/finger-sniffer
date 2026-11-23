// Package h1 é o parser e o escritor HTTP/1.x do finger-sniffer (spec 009).
//
// Diferente de net/http, nada é normalizado: a caixa dos nomes, a ordem dos campos, o separador literal
// (":" e espaços), o valor com espaços e o terminador de cada linha (CRLF ou LF puro) chegam ao registro
// exatamente como o cliente mandou. O pacote é puro (sem rede): lê de um *bufio.Reader e escreve num
// io.Writer; tempos, offsets de fluxo e JA4H são preenchidos pelo servidor (task 022).
package h1

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"maps"
	"slices"
	"strings"
	"unicode/utf8"
	"unsafe"
)

// Terminadores de linha registrados em cada campo.
const (
	TermCRLF = "crlf"
	TermLF   = "lf"
)

// Formas do alvo da linha de requisição (RFC 9112 §3.2).
const (
	FormOrigin    = "origin"
	FormAbsolute  = "absolute"
	FormAuthority = "authority"
	FormAsterisk  = "asterisk"
)

// Upgrades reconhecidos (RF-09).
const (
	UpgradeH2C       = "h2c"
	UpgradeWebSocket = "websocket"
)

// DefaultMaxHeadBytes é o teto do cabeçalho de requisição (RF-10): acima dele o servidor responde 431.
const DefaultMaxHeadBytes = 1 << 20

// DefaultMaxFields é o teto de campos do cabeçalho e dos trailers (RF-10, ADR 0033): acima dele o cabeçalho
// vira 431 (head_too_large) e os trailers, 400.
const DefaultMaxFields = 1024

// Erros do parser. O *Request devolvido junto com eles vem preenchido até onde foi possível ler, para que o
// servidor registre os bytes crus mesmo quando responde 400 ou 431.
var (
	// ErrHeadTooLarge: o cabeçalho passou de MaxHeadBytes ou de MaxFields (o servidor responde 431).
	ErrHeadTooLarge = errors.New("h1: request head too large")
	// ErrMalformedRequestLine: linha de requisição sem método, alvo ou versão HTTP/.
	ErrMalformedRequestLine = errors.New("h1: malformed request line")
	// ErrMalformedField: linha de campo sem ":" ou com nome vazio.
	ErrMalformedField = errors.New("h1: malformed header field")
	// ErrObsFoldFirst: continuação obs-fold antes de qualquer campo.
	ErrObsFoldFirst = errors.New("h1: obs-fold without preceding field")
)

// Field é um campo como chegou: [nome na caixa original, separador literal, valor, terminador]
// (schema HTTPField do openapi). Serializa como array JSON de 4 strings.
type Field [4]string

// Name devolve o nome na caixa original.
func (f Field) Name() string { return f[0] }

// Sep devolve o separador literal (":" com os espaços em volta).
func (f Field) Sep() string { return f[1] }

// Value devolve o valor literal (espaços finais preservados).
func (f Field) Value() string { return f[2] }

// Term devolve o terminador ("crlf" ou "lf").
func (f Field) Term() string { return f[3] }

// RequestLine é a linha de requisição analisada.
type RequestLine struct {
	Method     string `json:"method"`
	Target     string `json:"target"`
	Form       string `json:"form"`
	Version    string `json:"version"`
	Terminator string `json:"terminator"`
	// TargetTruncated: Target cortado para caber no evento (ADR 0032); o alvo completo fica no fluxo `in`.
	TargetTruncated bool `json:"target_truncated,omitempty"`
	// MethodTruncated e VersionTruncated: cortados em MaxLineTokenEvent bytes para o evento (ADR 0070 item 3).
	MethodTruncated  bool `json:"method_truncated,omitempty"`
	VersionTruncated bool `json:"version_truncated,omitempty"`
}

// ExpectContinue registra o comportamento do cliente com `Expect: 100-continue` (RF-04); preenchido pelo
// servidor, que é quem mede a espera.
type ExpectContinue struct {
	Waited bool     `json:"waited"`
	WaitMs *float64 `json:"wait_ms"`
}

// ProxySignal é um sinal de proxy no caminho (RF-07).
type ProxySignal struct {
	Kind   string  `json:"kind"`
	Field  *string `json:"field"`
	Detail *string `json:"detail"`
}

// Controls são os controles de resposta aplicados (spec 005 RF-07); preenchidos pelo servidor.
type Controls struct {
	Params  map[string]string `json:"params,omitempty"`
	Clamped []string          `json:"clamped,omitempty"`
	Invalid []string          `json:"invalid,omitempty"`
	// Truncated: Params ou Invalid reduzidos para o evento caber no teto (ADR 0070 item 3).
	Truncated bool `json:"truncated,omitempty"`
}

// Request é uma requisição HTTP/1 com as tags JSON do schema HTTP1Request do openapi. O parser preenche
// cabeçalho, corpo e upgrade; o servidor preenche índice, tempos, offset de saída, sinais de proxy (com o
// contexto da conexão), JA4H, controles e a resposta enviada.
type Request struct {
	Index            int         `json:"index"`
	InOffset         int64       `json:"in_offset"`
	OutOffset        *int64      `json:"out_offset"`
	RawHead          []byte      `json:"raw_head_b64"`
	RawHeadTruncated bool        `json:"raw_head_truncated"`
	RequestLine      RequestLine `json:"request_line"`
	Fields           []Field     `json:"fields"`
	FieldsTruncated  bool        `json:"fields_truncated"`
	FieldCount       int         `json:"field_count"`
	HeadSize         int         `json:"head_size"`
	ObsFold          bool        `json:"obs_fold"`
	Duplicates       []string    `json:"duplicates"`
	HeadTooLarge     bool        `json:"head_too_large"`
	Body             *Body       `json:"body,omitempty"`

	ExpectContinue       *ExpectContinue `json:"expect_continue"`
	Pipelined            bool            `json:"pipelined"`
	Upgrade              *string         `json:"upgrade"`
	TFirstByteMs         *float64        `json:"t_first_byte_ms"`
	TSincePrevResponseMs *float64        `json:"t_since_prev_response_ms"`
	ProxySignals         []ProxySignal   `json:"proxy_signals"`
	JA4H                 *string         `json:"ja4h"`
	Controls             *Controls       `json:"controls,omitempty"`

	Status                int    `json:"status"`
	ResponseSent          []byte `json:"response_sent_b64"`
	ResponseSentTruncated bool   `json:"response_sent_truncated"`
	ResponseSentSize      int64  `json:"response_sent_size"`

	// Instantes da requisição e da resposta (RFC 3339 UTC com ns, relógio do servidor; nulos quando não
	// houve), preenchidos pelo servidor (spec 009 RF-06, ADR 0029).
	RequestStartedAt  *string `json:"request_started_at"`
	RequestEndedAt    *string `json:"request_ended_at"`
	ResponseStartedAt *string `json:"response_started_at"`
	ResponseEndedAt   *string `json:"response_ended_at"`

	// BufferedAfter é quantos bytes já estavam no buffer de leitura logo depois do fim desta requisição
	// (cabeçalho e corpo): > 0 indica a próxima requisição enviada sem esperar a resposta (RF-05).
	BufferedAfter int `json:"-"`
}

// Values devolve, na ordem, os valores dos campos com o nome dado (comparação sem caixa).
func (r *Request) Values(name string) []string {
	var out []string
	for _, f := range r.Fields {
		if strings.EqualFold(f[0], name) {
			out = append(out, f[2])
		}
	}
	return out
}

// Get devolve o primeiro valor do campo (sem espaços nas pontas) e se ele existe.
func (r *Request) Get(name string) (string, bool) {
	for _, f := range r.Fields {
		if strings.EqualFold(f[0], name) {
			return strings.Trim(f[2], " \t"), true
		}
	}
	return "", false
}

// ExpectsContinue diz se o cliente mandou `Expect: 100-continue` (RF-04).
func (r *Request) ExpectsContinue() bool {
	for _, v := range r.Values("Expect") {
		if strings.EqualFold(strings.Trim(v, " \t"), "100-continue") {
			return true
		}
	}
	return false
}

// LimitInline corta os bytes crus inline (cabeçalho, corpo e resposta) em max bytes cada, marcando os
// campos *_truncated (ADR 0018). max <= 0 não corta nada.
func (r *Request) LimitInline(maxBytes int) {
	if maxBytes <= 0 {
		return
	}
	if len(r.RawHead) > maxBytes {
		r.RawHead = r.RawHead[:maxBytes:maxBytes]
		r.RawHeadTruncated = true
	}
	if len(r.ResponseSent) > maxBytes {
		r.ResponseSent = r.ResponseSent[:maxBytes:maxBytes]
		r.ResponseSentTruncated = true
	}
	if r.Body != nil && len(r.Body.Raw) > maxBytes {
		r.Body.Raw = r.Body.Raw[:maxBytes:maxBytes]
		r.Body.RawTruncated = true
	}
}

// LimitTarget corta request_line.target em no máximo maxBytes bytes, sem partir uma runa UTF-8 válida
// (bytes que não são UTF-8 são cortados no teto exato), e marca target_truncated (ADR 0032).
func (r *Request) LimitTarget(maxBytes int) {
	if t, cut := cutRunes(r.RequestLine.Target, maxBytes); cut {
		r.RequestLine.Target = t
		r.RequestLine.TargetTruncated = true
	}
}

// MaxLineTokenEvent é o teto de método e versão no evento (ADR 0070 item 3).
const MaxLineTokenEvent = 256

// LimitLineTokens corta método e versão em MaxLineTokenEvent bytes (fronteira de runa), marcando
// method_truncated/version_truncated; o valor completo fica nos bytes crus e no fluxo `in`.
func (r *Request) LimitLineTokens() {
	if m, cut := cutRunes(r.RequestLine.Method, MaxLineTokenEvent); cut {
		r.RequestLine.Method, r.RequestLine.MethodTruncated = m, true
	}
	if v, cut := cutRunes(r.RequestLine.Version, MaxLineTokenEvent); cut {
		r.RequestLine.Version, r.RequestLine.VersionTruncated = v, true
	}
}

// cutRunes corta t em no máximo maxBytes bytes sem partir uma runa válida; cut informa se cortou.
func cutRunes(t string, maxBytes int) (string, bool) {
	if maxBytes <= 0 || len(t) <= maxBytes {
		return t, false
	}
	n := maxBytes
	if !utf8.RuneStart(t[n]) {
		// o corte cai no meio de uma sequência: recua até o início dela se for uma runa válida
		for back := 1; back < utf8.UTFMax && back <= n; back++ {
			if start := n - back; utf8.RuneStart(t[start]) {
				if c, size := utf8.DecodeRuneInString(t[start:]); (c != utf8.RuneError || size > 1) && start+size > n {
					n = start
				}
				break
			}
		}
	}
	return t[:n], true
}

// HalveControls reduz Params (pelas chaves em ordem) e Invalid à metade, marcando controls.truncated;
// devolve false quando não havia o que reduzir (ADR 0070 item 3).
func (r *Request) HalveControls() bool {
	c := r.Controls
	if c == nil || (len(c.Params) == 0 && len(c.Invalid) == 0) {
		return false
	}
	if n := len(c.Params); n > 0 {
		keys := slices.Sorted(maps.Keys(c.Params))
		for _, k := range keys[n/2:] {
			delete(c.Params, k)
		}
		if len(c.Params) == 0 {
			c.Params = nil
		}
	}
	c.Invalid = c.Invalid[:len(c.Invalid)/2]
	if len(c.Invalid) == 0 {
		c.Invalid = nil
	}
	c.Truncated = true
	return true
}

// LimitFields mantém só os primeiros campos cuja soma de tamanhos cabe em maxBytes, marcando
// fields_truncated (ADR 0018). field_count continua com o total recebido.
func (r *Request) LimitFields(maxBytes int) {
	total := 0
	for i, f := range r.Fields {
		total += len(f[0]) + len(f[1]) + len(f[2]) + len(f[3])
		if total > maxBytes {
			r.Fields = r.Fields[:i:i]
			r.FieldsTruncated = true
			return
		}
	}
}

// Reader lê requisições sucessivas de uma conexão.
type Reader struct {
	br *bufio.Reader
	// MaxHeadBytes é o teto do cabeçalho; 0 usa DefaultMaxHeadBytes.
	MaxHeadBytes int
	// MaxFields é o teto de campos do cabeçalho e dos trailers; 0 usa DefaultMaxFields.
	MaxFields int
	// Reserve, quando definido, pede n bytes ao orçamento de entrada antes de alocar memória para guardar
	// bytes do cabeçalho ou dos trailers (spec 009 RF-10, ADRs 0033 e 0036): o crescimento da capacidade de
	// RawHead, as cópias de cada campo e da linha de requisição e o crescimento das fatias de campos. false
	// encerra a leitura com ErrHeadTooLarge (431 no cabeçalho, 400 nos trailers) sem guardar o pedaço. Quem
	// define devolve a reserva ao fim da requisição.
	Reserve func(n int) bool
	// ReserveBody, quando definido, pede n bytes ao orçamento antes de guardar parte do corpo (bytes crus
	// inline, lista de pedaços chunked e extensões; spec 009 RF-03, ADR 0070 item 7). false não recusa a
	// requisição: o leitor para de guardar e marca raw_truncated/chunks_truncated. Quem define devolve a
	// reserva ao fim da requisição.
	ReserveBody func(n int) bool
	// copyBuf é o buffer de cópia do corpo, alocado uma vez por Reader (ADR 0070 item 5).
	copyBuf []byte
	// consumed conta os bytes já consumidos de br, para o InOffset de cada requisição.
	consumed int64
}

// NewReader cria um leitor sobre br.
func NewReader(br *bufio.Reader) *Reader {
	return &Reader{br: br}
}

// Consumed devolve quantos bytes o leitor já consumiu do fluxo.
func (r *Reader) Consumed() int64 { return r.consumed }

// Buffered devolve quantos bytes já estão no buffer, ainda não consumidos.
func (r *Reader) Buffered() int { return r.br.Buffered() }

func (r *Reader) maxHead() int {
	if r.MaxHeadBytes > 0 {
		return r.MaxHeadBytes
	}
	return DefaultMaxHeadBytes
}

func (r *Reader) maxFields() int {
	if r.MaxFields > 0 {
		return r.MaxFields
	}
	return DefaultMaxFields
}

// reserve pede n bytes ao orçamento (sempre true sem Reserve).
func (r *Reader) reserve(n int) bool {
	return n <= 0 || r.Reserve == nil || r.Reserve(n)
}

// minHeadBuf é a menor capacidade alocada para RawHead.
const minHeadBuf = 512

// fieldSize é o tamanho de um Field na fatia (4 cabeçalhos de string).
const fieldSize = int(unsafe.Sizeof(Field{}))

// growBuf garante capacidade para mais n bytes em *dst: a capacidade dobra (no mínimo minHeadBuf, no
// máximo capMax, salvo se o pedido passar disso) e o crescimento é reservado antes de alocar (ADR 0036).
func (r *Reader) growBuf(dst *[]byte, n, capMax int) bool {
	need := len(*dst) + n
	if need <= cap(*dst) {
		return true
	}
	newCap := min(max(2*cap(*dst), need, minHeadBuf), max(capMax, need))
	if !r.reserve(newCap - cap(*dst)) {
		return false
	}
	nb := make([]byte, len(*dst), newCap)
	copy(nb, *dst)
	*dst = nb
	return true
}

// appendField acrescenta f a *fs, reservando antes a cópia dos bytes do campo (size, feita por parseField)
// e o crescimento da fatia (capacidade dobrada, no máximo maxFields). false: sem orçamento.
func (r *Reader) appendField(fs *[]Field, f Field, size int) bool {
	grow := 0
	newCap := cap(*fs)
	if len(*fs) == cap(*fs) {
		newCap = min(max(2*cap(*fs), 8), max(r.maxFields(), len(*fs)+1))
		grow = (newCap - cap(*fs)) * fieldSize
	}
	if !r.reserve(size + grow) {
		return false
	}
	if grow > 0 {
		nf := make([]Field, len(*fs), newCap)
		copy(nf, *fs)
		*fs = nf
	}
	*fs = append(*fs, f)
	return true
}

// folder acumula as continuações obs-fold do último campo num strings.Builder e só grava o valor no campo
// quando ele termina (próximo campo, fim do cabeçalho ou erro): concatenar a cada linha custaria O(n²).
type folder struct {
	b      strings.Builder
	term   string
	active bool
	// reserve pede ao orçamento o crescimento do Builder antes de alocar (nil: sem orçamento).
	reserve func(n int) bool
}

// add acrescenta a continuação content (terminada por term) ao valor do campo prev: entra literalmente, com o
// terminador da linha anterior, sem desdobrar nada. false: sem orçamento para o crescimento.
func (f *folder) add(prev *Field, content []byte, term string) bool {
	t, extra := f.term, len(content)
	if !f.active {
		t, extra = prev[3], extra+len(prev[2])
	}
	extra += len(termBytes(t))
	if f.b.Cap()-f.b.Len() < extra {
		// strings.Builder.Grow(n) aloca 2*cap+n: é isso que se reserva.
		if f.reserve != nil && !f.reserve(f.b.Cap()+extra) {
			return false
		}
		f.b.Grow(extra)
	}
	if !f.active {
		f.active = true
		f.b.WriteString(prev[2])
		f.term = prev[3]
	}
	f.b.WriteString(termBytes(f.term))
	f.b.Write(content)
	f.term = term
	return true
}

// flush grava em prev o valor dobrado acumulado, se houver.
func (f *folder) flush(prev *Field) {
	if !f.active {
		return
	}
	prev[2] = f.b.String()
	prev[3] = f.term
	f.b.Reset()
	f.active = false
}

// readLine lê uma linha inteira (com o terminador) sem ultrapassar limit bytes. Devolve a linha crua; a
// fatia é nova (não aponta para o buffer do bufio). Com reserve, cada pedaço é reservado em r.Reserve antes
// de ser guardado.
func (r *Reader) readLine(limit int, reserve bool) ([]byte, error) {
	var line []byte
	for {
		chunk, err := r.br.ReadSlice('\n')
		if len(line)+len(chunk) > limit {
			// Consome só até o teto: o resto fica para trás porque a conexão vai ser encerrada com 431.
			keep := limit - len(line)
			if keep > 0 {
				line = append(line, chunk[:keep]...)
			}
			r.consumed += int64(len(chunk))
			return line, ErrHeadTooLarge
		}
		if reserve && r.Reserve != nil && len(chunk) > 0 && !r.Reserve(len(chunk)) {
			// Orçamento de entrada esgotado: trata como cabeçalho grande demais, sem guardar o pedaço.
			r.consumed += int64(len(chunk))
			return line, ErrHeadTooLarge
		}
		line = append(line, chunk...)
		r.consumed += int64(len(chunk))
		switch {
		case err == nil:
			return line, nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF):
			if len(line) == 0 {
				return nil, io.EOF
			}
			return line, io.ErrUnexpectedEOF
		default:
			return line, err
		}
	}
}

// readLineInto lê uma linha inteira (com o terminador) sem ultrapassar limit bytes e a acrescenta a *dst,
// cuja capacidade cresce até capMax com o crescimento reservado antes de alocar (ADR 0036). Devolve a linha
// (subfatia de *dst). Sem orçamento, ErrHeadTooLarge sem guardar o pedaço.
func (r *Reader) readLineInto(dst *[]byte, limit, capMax int) ([]byte, error) {
	start := len(*dst)
	for {
		chunk, err := r.br.ReadSlice('\n')
		got := len(*dst) - start
		if got+len(chunk) > limit {
			// Consome só até o teto: o resto fica para trás porque a conexão vai ser encerrada com 431.
			if keep := limit - got; keep > 0 && r.growBuf(dst, keep, capMax) {
				*dst = append(*dst, chunk[:keep]...)
			}
			r.consumed += int64(len(chunk))
			return (*dst)[start:], ErrHeadTooLarge
		}
		if len(chunk) > 0 && !r.growBuf(dst, len(chunk), capMax) {
			// Orçamento de entrada esgotado: trata como cabeçalho grande demais, sem guardar o pedaço.
			r.consumed += int64(len(chunk))
			return (*dst)[start:], ErrHeadTooLarge
		}
		*dst = append(*dst, chunk...)
		r.consumed += int64(len(chunk))
		switch {
		case err == nil:
			return (*dst)[start:], nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF):
			if len(*dst) == start {
				return nil, io.EOF
			}
			return (*dst)[start:], io.ErrUnexpectedEOF
		default:
			return (*dst)[start:], err
		}
	}
}

// splitTerm separa o conteúdo da linha do terminador.
func splitTerm(line []byte) ([]byte, string) {
	if bytes.HasSuffix(line, []byte("\r\n")) {
		return line[:len(line)-2], TermCRLF
	}
	if bytes.HasSuffix(line, []byte("\n")) {
		return line[:len(line)-1], TermLF
	}
	return line, ""
}

// ReadHead lê a linha de requisição e os campos até a linha vazia. Erro sem nenhum byte lido (io.EOF limpo,
// prazo de leitura vencido ou outro erro de leitura) devolve *Request nil: o cliente fechou ou ficou ocioso
// entre requisições. Nos demais erros, o *Request devolvido traz o que foi lido.
func (r *Reader) ReadHead() (*Request, error) {
	maxHead := r.maxHead()
	req := &Request{
		InOffset:     r.consumed,
		Fields:       []Field{},
		Duplicates:   []string{},
		ProxySignals: []ProxySignal{},
	}
	fold := folder{reserve: r.Reserve}
	flushFold := func() {
		if len(req.Fields) > 0 {
			fold.flush(&req.Fields[len(req.Fields)-1])
		}
	}
	fail := func(err error) (*Request, error) {
		flushFold()
		if errors.Is(err, io.EOF) { // EOF limpo no meio do cabeçalho é truncamento
			err = io.ErrUnexpectedEOF
		}
		req.HeadSize = len(req.RawHead)
		req.FieldCount = len(req.Fields)
		if errors.Is(err, ErrHeadTooLarge) {
			req.HeadTooLarge = true
		}
		return req, err
	}

	// Linhas vazias antes da linha de requisição são toleradas (RFC 9112 §2.2) e ficam nos bytes crus.
	var line []byte
	for {
		l, err := r.readLineInto(&req.RawHead, maxHead-len(req.RawHead), maxHead)
		if err != nil {
			if len(bytes.Trim(req.RawHead, "\r\n")) == 0 && !errors.Is(err, ErrHeadTooLarge) {
				// Nenhum byte da próxima requisição (no máximo linhas vazias toleradas): EOF limpo, prazo de
				// leitura vencido (ociosidade) ou erro de leitura. Não há requisição a registrar.
				return nil, err
			}
			return fail(err)
		}
		if c, _ := splitTerm(l); len(c) == 0 {
			continue
		}
		line = l
		break
	}
	// parseRequestLine copia a linha para uma string (método, alvo e versão apontam para ela).
	if c, _ := splitTerm(line); !r.reserve(len(c)) {
		return fail(ErrHeadTooLarge)
	}
	if err := parseRequestLine(line, &req.RequestLine); err != nil {
		return fail(err)
	}

	for {
		l, err := r.readLineInto(&req.RawHead, maxHead-len(req.RawHead), maxHead)
		if err != nil {
			return fail(err)
		}
		content, term := splitTerm(l)
		if len(content) == 0 {
			break
		}
		if content[0] == ' ' || content[0] == '\t' {
			// obs-fold: a continuação entra literalmente no valor do campo anterior, com o terminador da
			// linha anterior, sem desdobrar nada.
			if len(req.Fields) == 0 {
				return fail(ErrObsFoldFirst)
			}
			if !fold.add(&req.Fields[len(req.Fields)-1], content, term) {
				return fail(ErrHeadTooLarge)
			}
			req.ObsFold = true
			continue
		}
		flushFold()
		f, err := parseField(content, term)
		if err != nil {
			return fail(err)
		}
		// Teto de campos (RF-10): o campo excedente não entra e o resto do cabeçalho não é lido (431).
		if len(req.Fields) >= r.maxFields() {
			return fail(ErrHeadTooLarge)
		}
		// O campo é uma cópia de content (parseField): reserva os bytes dela e o crescimento da fatia.
		if !r.appendField(&req.Fields, f, len(content)) {
			return fail(ErrHeadTooLarge)
		}
	}
	flushFold()

	req.HeadSize = len(req.RawHead)
	req.FieldCount = len(req.Fields)
	req.Duplicates = duplicates(req.Fields)
	req.Upgrade = detectUpgrade(req)
	return req, nil
}

func termBytes(term string) string {
	if term == TermLF {
		return "\n"
	}
	return "\r\n"
}

// parseRequestLine separa método, alvo e versão. O alvo é tudo entre o primeiro e o último espaço, literal.
func parseRequestLine(line []byte, rl *RequestLine) error {
	content, term := splitTerm(line)
	rl.Terminator = term
	s := string(content)
	first := strings.IndexByte(s, ' ')
	last := strings.LastIndexByte(s, ' ')
	if first <= 0 || last == first || last == len(s)-1 {
		return ErrMalformedRequestLine
	}
	rl.Method = s[:first]
	rl.Target = s[first+1 : last]
	rl.Version = s[last+1:]
	if rl.Target == "" || !strings.HasPrefix(rl.Version, "HTTP/") {
		return ErrMalformedRequestLine
	}
	rl.Form = targetForm(rl.Method, rl.Target)
	return nil
}

// targetForm classifica o alvo (RFC 9112 §3.2).
func targetForm(method, target string) string {
	switch {
	case target == "*":
		return FormAsterisk
	case strings.HasPrefix(target, "/"):
		return FormOrigin
	case method == "CONNECT":
		return FormAuthority
	case isAbsolute(target):
		return FormAbsolute
	case strings.Contains(target, ":") && !strings.Contains(target, "/"):
		return FormAuthority
	default:
		return FormOrigin
	}
}

// isAbsolute reconhece "esquema://..." com esquema conforme a RFC 3986 (letra seguida de letras, dígitos,
// "+", "-" ou ".").
func isAbsolute(target string) bool {
	i := strings.Index(target, "://")
	if i <= 0 {
		return false
	}
	for j := 0; j < i; j++ {
		c := target[j]
		isAlpha := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		if j == 0 && !isAlpha {
			return false
		}
		if !isAlpha && (c < '0' || c > '9') && c != '+' && c != '-' && c != '.' {
			return false
		}
	}
	return true
}

// parseField separa nome, separador literal e valor. Espaços entre o nome e ":" (proibidos pela RFC, mas
// reflexo do que chegou) ficam no separador.
func parseField(content []byte, term string) (Field, error) {
	s := string(content)
	colon := strings.IndexByte(s, ':')
	if colon < 0 {
		return Field{}, ErrMalformedField
	}
	name := strings.TrimRight(s[:colon], " \t")
	if name == "" {
		return Field{}, ErrMalformedField
	}
	rest := s[colon+1:]
	value := strings.TrimLeft(rest, " \t")
	sep := s[len(name) : colon+1+len(rest)-len(value)]
	return Field{name, sep, value, term}, nil
}

// duplicates lista, em minúsculas e na ordem da primeira repetição, os nomes que aparecem mais de uma vez.
func duplicates(fields []Field) []string {
	seen := make(map[string]int, len(fields))
	out := []string{}
	for _, f := range fields {
		k := strings.ToLower(f[0])
		seen[k]++
		if seen[k] == 2 {
			out = append(out, k)
		}
	}
	return out
}

// detectUpgrade reconhece Upgrade h2c e websocket (RF-09).
func detectUpgrade(req *Request) *string {
	for _, v := range req.Values("Upgrade") {
		for _, tok := range strings.Split(v, ",") {
			tok = strings.Trim(tok, " \t")
			// Ignora a versão do protocolo ("websocket/13" não é padrão, mas aparece).
			if i := strings.IndexByte(tok, '/'); i >= 0 {
				tok = tok[:i]
			}
			switch {
			case strings.EqualFold(tok, UpgradeH2C):
				u := UpgradeH2C
				return &u
			case strings.EqualFold(tok, UpgradeWebSocket):
				u := UpgradeWebSocket
				return &u
			}
		}
	}
	return nil
}

// ReadRequest lê cabeçalho e corpo de uma requisição (sem tratar 100-continue: quem precisa decidir antes
// do corpo usa ReadHead e ReadBody separados).
func (r *Reader) ReadRequest(opts BodyOptions) (*Request, error) {
	req, err := r.ReadHead()
	if err != nil {
		return req, err
	}
	if err := r.ReadBody(req, opts); err != nil {
		return req, err
	}
	return req, nil
}
