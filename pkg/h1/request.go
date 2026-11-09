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
	"strings"
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

// Erros do parser. O *Request devolvido junto com eles vem preenchido até onde foi possível ler, para que o
// servidor registre os bytes crus mesmo quando responde 400 ou 431.
var (
	// ErrHeadTooLarge: o cabeçalho passou de MaxHeadBytes (o servidor responde 431).
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

// readLine lê uma linha inteira (com o terminador) sem ultrapassar limit bytes. Devolve a linha crua; a
// fatia é nova (não aponta para o buffer do bufio).
func (r *Reader) readLine(limit int) ([]byte, error) {
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

// ReadHead lê a linha de requisição e os campos até a linha vazia. io.EOF limpo (nenhum byte) indica que o
// cliente fechou entre requisições. Em erro, o *Request devolvido (quando não nil) traz o que foi lido.
func (r *Reader) ReadHead() (*Request, error) {
	maxHead := r.maxHead()
	req := &Request{
		InOffset:     r.consumed,
		Fields:       []Field{},
		Duplicates:   []string{},
		ProxySignals: []ProxySignal{},
	}
	fail := func(err error) (*Request, error) {
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
		l, err := r.readLine(maxHead - len(req.RawHead))
		req.RawHead = append(req.RawHead, l...)
		if err != nil {
			if errors.Is(err, io.EOF) && len(req.RawHead) == 0 {
				return nil, io.EOF
			}
			return fail(err)
		}
		if c, _ := splitTerm(l); len(c) == 0 {
			continue
		}
		line = l
		break
	}
	if err := parseRequestLine(line, &req.RequestLine); err != nil {
		return fail(err)
	}

	for {
		l, err := r.readLine(maxHead - len(req.RawHead))
		req.RawHead = append(req.RawHead, l...)
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
			prev := &req.Fields[len(req.Fields)-1]
			prev[2] += termBytes(prev[3]) + string(content)
			prev[3] = term
			req.ObsFold = true
			continue
		}
		f, err := parseField(content, term)
		if err != nil {
			return fail(err)
		}
		req.Fields = append(req.Fields, f)
	}

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
