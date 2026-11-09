package web

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/h1"
	"github.com/patrickbrandao/finger-sniffer/pkg/service"
)

// Tetos padrão dos controles (spec 005 RF-07, .env.example).
const (
	DefaultSizeMax  = 64 << 20
	DefaultDelayMax = 60 * time.Second
	DefaultHSizeMax = 1 << 20
	// DefaultChunkMax é o teto de chunk= (pedaço chunked): acima disso só gastaria memória.
	DefaultChunkMax = 1 << 20
)

// Tetos do registro dos parâmetros no evento (ADR 0018): a query cabe em 1 MiB de cabeçalho, mas o
// registro não precisa repetir tudo.
const (
	recordMaxParams   = 64
	recordMaxValueLen = 1024
)

// Valores de frame=, conn=, close= e continue=.
const (
	FrameCL      = "cl"
	FrameChunked = "chunked"
	FrameClose   = "close"

	ConnKeep  = "keep"
	ConnClose = "close"
	ConnNone  = "none"

	CloseAfter      = "after"
	CloseBeforeBody = "before-body"
	CloseMidBody    = "mid-body"

	ContinueSend = "send"
	ContinueSkip = "skip"
	ContinueLate = "late"
)

// TrailerName é o campo enviado como trailer com trailers=1.
const TrailerName = "X-Fs-Trailer"

// ControlLimits são os tetos dos controles (FS_SIZE_MAX, FS_DELAY_MAX, FS_HSIZE_MAX, FS_IDLE_MAX).
type ControlLimits struct {
	SizeMax  int64
	DelayMax time.Duration
	HSizeMax int
	ChunkMax int
	IdleMax  time.Duration
}

// withDefaults completa os tetos zerados com os padrões.
func (l ControlLimits) withDefaults() ControlLimits {
	if l.SizeMax <= 0 {
		l.SizeMax = DefaultSizeMax
	}
	if l.DelayMax <= 0 {
		l.DelayMax = DefaultDelayMax
	}
	if l.HSizeMax <= 0 {
		l.HSizeMax = DefaultHSizeMax
	}
	if l.ChunkMax <= 0 {
		l.ChunkMax = DefaultChunkMax
	}
	if l.IdleMax <= 0 {
		l.IdleMax = DefaultIdleMax
	}
	return l
}

// loadControlLimits lê FS_SIZE_MAX, FS_DELAY_MAX e FS_HSIZE_MAX (FS_IDLE_MAX já está na Config).
func loadControlLimits() (ControlLimits, error) {
	var l ControlLimits
	size, err := service.EnvInt("FS_SIZE_MAX", DefaultSizeMax)
	if err != nil {
		return l, err
	}
	if l.DelayMax, err = service.EnvDuration("FS_DELAY_MAX", DefaultDelayMax); err != nil {
		return l, err
	}
	if l.HSizeMax, err = service.EnvInt("FS_HSIZE_MAX", DefaultHSizeMax); err != nil {
		return l, err
	}
	if size <= 0 || l.DelayMax <= 0 || l.HSizeMax <= 0 {
		return l, fmt.Errorf("web: FS_SIZE_MAX, FS_DELAY_MAX and FS_HSIZE_MAX must be > 0")
	}
	l.SizeMax = int64(size)
	return l, nil
}

// Controls são os controles de resposta de /r e /p/<id>/r (spec 005 RF-07), já validados e com os
// tetos aplicados. Não dependem do protocolo: o HTTP/1 usa todos; o h2 (task 025) usa os que fazem
// sentido nele.
type Controls struct {
	// Interim são as respostas 1xx enviadas antes da final (status=103, status=100...), na ordem.
	Interim []int
	// Status é o código da resposta final (0 = padrão 200).
	Status int
	// Version é "HTTP/1.0" ou "HTTP/1.1" ("" = padrão).
	Version string
	// Size é o tamanho do corpo quando HasSize (corpo de padrão repetido no lugar do texto do espelho).
	Size    int64
	HasSize bool
	// Frame é FrameCL, FrameChunked ou FrameClose ("" = cl).
	Frame string
	// Chunk é o tamanho de cada pedaço chunked (0 = padrão do escritor).
	Chunk int
	// Trailers manda TrailerName depois do último pedaço.
	Trailers bool
	// Conn é ConnKeep, ConnClose ou ConnNone ("" = nenhum campo Connection).
	Conn string
	// KeepAlive é o valor do campo Keep-Alive ("" = sem o campo).
	KeepAlive string
	// Close é CloseAfter, CloseBeforeBody ou CloseMidBody ("" = não fecha).
	Close string
	// RST fecha com RST (SO_LINGER 0) em vez de FIN; sem close= implica close=after.
	RST bool
	// DelayHead e DelayBody atrasam o cabeçalho final e o corpo.
	DelayHead time.Duration
	DelayBody time.Duration
	// Idle troca a ociosidade da conexão (0 = mantém).
	Idle time.Duration
	// Fields são os campos extras (h=Nome:Valor), na ordem e na caixa recebidas.
	Fields []h1.HeaderField
	// HSize é o tamanho exato do cabeçalho final (0 = natural).
	HSize int
	// Continue é ContinueSend, ContinueSkip ou ContinueLate ("" = send).
	Continue string
	// Upgrade é "ws" para 101 + WebSocket (task 026).
	Upgrade string
	// NoAltSvc desliga o anúncio de h3 (alt_svc=0).
	NoAltSvc bool
	// Inline devolve o JSON da própria requisição no corpo (inline=1, RF-06).
	Inline bool
	// NoDate omite o Date automático (date=0, ADR 0021).
	NoDate bool

	// Record é o que vai no evento (controls: params, clamped, invalid).
	Record h1.Controls
	// errs são as explicações dos valores inválidos (corpo do 400).
	errs []string
}

// Valid informa se nenhum parâmetro foi recusado.
func (c *Controls) Valid() bool { return len(c.errs) == 0 }

// InvalidText é o corpo do 400: uma linha por parâmetro inválido.
func (c *Controls) InvalidText() string {
	return "invalid response controls:\n" + strings.Join(c.errs, "\n") + "\n"
}

// closes informa se a resposta termina com o servidor fechando a conexão.
func (c *Controls) closes() bool { return c.Close != "" || c.Frame == FrameClose }

func (c *Controls) invalid(name, value, why string) {
	c.Record.Invalid = appendOnce(c.Record.Invalid, name)
	c.errs = append(c.errs, fmt.Sprintf("%s=%s: %s", name, value, why))
}

func (c *Controls) clamp(name string) { c.Record.Clamped = appendOnce(c.Record.Clamped, name) }

func appendOnce(list []string, s string) []string {
	for _, v := range list {
		if v == s {
			return list
		}
	}
	return append(list, s)
}

// ParseControls interpreta a query de /r. Parâmetros desconhecidos (ex.: _=123 para furar cache) são
// registrados em params e ignorados; valores inválidos ficam em invalid e tornam a resposta um 400.
// Parâmetros repetidos valem o último, exceto h= e status= (que acumulam).
func ParseControls(rawQuery string, lim ControlLimits) *Controls {
	lim = lim.withDefaults()
	c := &Controls{}
	params := map[string]string{}
	for part := range strings.SplitSeq(rawQuery, "&") {
		if part == "" {
			continue
		}
		rk, rv, _ := strings.Cut(part, "=")
		k, err1 := url.QueryUnescape(rk)
		v, err2 := url.QueryUnescape(rv)
		if err1 != nil || err2 != nil {
			c.invalid(clip(rk), clip(rv), "bad percent-encoding")
			continue
		}
		recordParam(params, k, v)
		c.apply(k, v, lim)
	}
	if len(params) > 0 {
		c.Record.Params = params
	}
	c.finish()
	return c
}

// recordParam guarda o parâmetro no registro (repetidos juntados por "\n", que nunca aparece num valor
// válido de campo), dentro dos tetos do registro.
func recordParam(params map[string]string, k, v string) {
	k, v = clip(k), clip(v)
	if old, ok := params[k]; ok {
		if len(old) < recordMaxValueLen {
			params[k] = clip(old + "\n" + v)
		}
		return
	}
	if len(params) < recordMaxParams {
		params[k] = v
	}
}

func clip(s string) string {
	if len(s) > recordMaxValueLen {
		return s[:recordMaxValueLen]
	}
	return s
}

// apply interpreta um parâmetro.
func (c *Controls) apply(k, v string, lim ControlLimits) {
	switch k {
	case "status":
		c.applyStatus(v)
	case "ver":
		switch v {
		case "1.0", "1.1":
			c.Version = "HTTP/" + v
		default:
			c.invalid(k, v, "must be 1.0 or 1.1")
		}
	case "size":
		if n, ok := c.number(k, v, 0); ok {
			c.Size, c.HasSize = min(n, lim.SizeMax), true
			if n > lim.SizeMax {
				c.clamp(k)
			}
		}
	case "frame":
		c.Frame = c.oneOf(k, v, c.Frame, FrameCL, FrameChunked, FrameClose)
	case "chunk":
		if n, ok := c.number(k, v, 1); ok {
			c.Chunk = int(min(n, int64(lim.ChunkMax)))
			if n > int64(lim.ChunkMax) {
				c.clamp(k)
			}
		}
	case "trailers":
		c.Trailers = c.flag(k, v)
	case "conn":
		c.Conn = c.oneOf(k, v, c.Conn, ConnKeep, ConnClose, ConnNone)
	case "ka":
		c.applyKeepAlive(v)
	case "close":
		c.Close = c.oneOf(k, v, c.Close, CloseAfter, CloseBeforeBody, CloseMidBody)
	case "rst":
		c.RST = c.flag(k, v)
	case "delay_head", "delay_body":
		if n, ok := c.number(k, v, 0); ok {
			d := durationOf(n, time.Millisecond, lim.DelayMax)
			if n > lim.DelayMax.Milliseconds() {
				c.clamp(k)
			}
			if k == "delay_head" {
				c.DelayHead = d
			} else {
				c.DelayBody = d
			}
		}
	case "idle":
		if n, ok := c.number(k, v, 1); ok {
			c.Idle = durationOf(n, time.Second, lim.IdleMax)
			if n > int64(lim.IdleMax/time.Second) {
				c.clamp(k)
			}
		}
	case "h":
		c.applyField(v)
	case "hsize":
		if n, ok := c.number(k, v, 0); ok {
			c.HSize = int(min(n, int64(lim.HSizeMax)))
			if n > int64(lim.HSizeMax) {
				c.clamp(k)
			}
		}
	case "continue":
		c.Continue = c.oneOf(k, v, c.Continue, ContinueSend, ContinueSkip, ContinueLate)
	case "upgrade":
		c.Upgrade = c.oneOf(k, v, c.Upgrade, "ws")
	case "alt_svc":
		switch v {
		case "0":
			c.NoAltSvc = true
		case "1":
			c.NoAltSvc = false
		default:
			c.invalid(k, v, "must be 0 or 1")
		}
	case "inline":
		c.Inline = v == "1"
	case "date":
		if v == "0" {
			c.NoDate = true
		} else {
			c.invalid(k, v, "must be 0 (omit Date)")
		}
	}
}

// durationOf converte n unidades em duração com teto (sem estouro).
func durationOf(n int64, unit, maxD time.Duration) time.Duration {
	if n > int64(maxD/unit) {
		return maxD
	}
	return time.Duration(n) * unit
}

// number lê um inteiro decimal >= minV (sem sinal; valores enormes viram o teto de quem chama).
func (c *Controls) number(k, v string, minV int64) (int64, bool) {
	if v == "" || len(v) > 19 || strings.TrimLeft(v, "0123456789") != "" {
		c.invalid(k, v, "must be a decimal integer")
		return 0, false
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		c.invalid(k, v, "must be a decimal integer")
		return 0, false
	}
	if n < minV {
		c.invalid(k, v, fmt.Sprintf("must be >= %d", minV))
		return 0, false
	}
	return n, true
}

func (c *Controls) flag(k, v string) bool {
	switch v {
	case "1":
		return true
	case "0":
		return false
	}
	c.invalid(k, v, "must be 0 or 1")
	return false
}

func (c *Controls) oneOf(k, v, cur string, allowed ...string) string {
	for _, a := range allowed {
		if v == a {
			return v
		}
	}
	c.invalid(k, v, "must be one of "+strings.Join(allowed, ", "))
	return cur
}

func (c *Controls) applyStatus(v string) {
	n, err := strconv.Atoi(v)
	if err != nil || len(v) != 3 || n < 100 || n > 999 {
		c.invalid("status", v, "must be a 3-digit code 100..999")
		return
	}
	if n < 200 && n != 101 {
		// 1xx (exceto 101) é sempre provisória: sai antes da final (103 Early Hints, 100, 102...).
		c.Interim = append(c.Interim, n)
		return
	}
	if c.Status != 0 {
		c.invalid("status", v, "only one final status allowed")
		return
	}
	c.Status = n
}

// applyKeepAlive lê ka=timeout[,max].
func (c *Controls) applyKeepAlive(v string) {
	timeout, maxReq, hasMax := strings.Cut(v, ",")
	ok := isDigits(timeout) && (!hasMax || isDigits(maxReq))
	if !ok {
		c.invalid("ka", v, "must be timeout or timeout,max (decimal integers)")
		return
	}
	c.KeepAlive = "timeout=" + timeout
	if hasMax {
		c.KeepAlive += ", max=" + maxReq
	}
}

func isDigits(s string) bool {
	return s != "" && len(s) <= 10 && strings.TrimLeft(s, "0123456789") == ""
}

// applyField lê h=Nome:Valor. O nome é um token (RFC 9110 §5.6.2); o valor é o resto, literal (sem CR,
// LF nem NUL, que quebrariam o cabeçalho).
func (c *Controls) applyField(v string) {
	name, value, ok := strings.Cut(v, ":")
	switch {
	case !ok || !isToken(name):
		c.invalid("h", v, "must be Name:Value with a token name")
	case strings.ContainsAny(value, "\r\n\x00"):
		c.invalid("h", v, "value must not contain CR, LF or NUL")
	default:
		c.Fields = append(c.Fields, h1.HeaderField{Name: name, Value: value})
	}
}

func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b <= ' ' || b >= 0x7f || strings.IndexByte("\"(),/:;<=>?@[\\]{}", b) >= 0 {
			return false
		}
	}
	return true
}

// finish aplica as combinações entre parâmetros.
func (c *Controls) finish() {
	if c.Status == 101 && c.Upgrade == "" {
		c.invalid("status", "101", "requires upgrade=ws")
	}
	// chunk= e trailers=1 só existem em chunked: implicam frame=chunked quando frame= não veio.
	if c.Frame == "" && (c.Chunk > 0 || c.Trailers) {
		c.Frame = FrameChunked
	}
	// rst=1 sozinho fecha depois da resposta.
	if c.RST && c.Close == "" {
		c.Close = CloseAfter
	}
}
