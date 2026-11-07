package p0f

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
)

// Tipos de comparação da janela (fp_tcp.h).
const (
	winNormal uint8 = iota // valor literal
	winAny                 // "*"
	winMod                 // "%n"
	winMSS                 // "mss*n"
	winMTU                 // "mtu*n"
)

// Estados do leitor do p0f.fp (readfp.c).
const (
	needSect = iota
	needLabel
	needSys
	needSig
)

// Módulos do p0f.fp.
const (
	modNone = iota
	modTCP
	modMTU
	modHTTP
)

// nameChars são os caracteres aceitos em nomes de SO além de letras e dígitos (NAME_CHARS do p0f).
const nameChars = " ./-_!?()"

// tsig é a assinatura simplificada usada na comparação (struct tcp_sig), tanto para pacotes quanto para
// as linhas sig do p0f.fp.
type tsig struct {
	layout   []uint8
	quirks   uint32
	eolPad   uint8
	ipOptLen uint8
	ipVer    int8 // -1 = qualquer
	ttl      uint8
	mss      int32 // -1 = qualquer
	win      uint16
	winType  uint8
	wscale   int16 // -1 = qualquer
	payClass int8  // -1 = qualquer, 0 = sem dados, 1 = com dados
	totHdr   uint16
	ts1      uint32
}

// Record é uma assinatura TCP do p0f.fp com o rótulo que a precede.
type Record struct {
	// Line é a linha da assinatura no arquivo (a partir de 1).
	Line int
	// Label é o valor cru da linha label, por exemplo "s:unix:Linux:3.11 and newer".
	Label   string
	Generic bool
	// ClassID é o índice em DB.Classes; -1 para ferramentas ("!").
	ClassID int
	NameID  int
	Flavor  string
	LabelID int
	// BadTTL: assinatura com TTL aleatório ("ttl-").
	BadTTL bool
	// Sys são os sistemas da linha sys (só para ferramentas); "@classe" para classes.
	Sys []string
	sig tsig
}

// DB é o banco p0f.fp carregado.
type DB struct {
	// Classes são as classes de SO declaradas em "classes" (win, unix, other).
	Classes []string
	// Names é o registro de nomes de SO, na grafia da primeira ocorrência (como o p0f).
	Names []string
	// tcp[1] são as assinaturas de request (SYN) e tcp[0] as de response (SYN+ACK), na ordem do arquivo.
	tcp [2][]*Record
	// Sigs é o total de linhas sig lidas (tcp, mtu e http).
	Sigs int
}

// Class devolve o nome da classe do registro ("!" para ferramentas).
func (db *DB) Class(r *Record) string {
	if r.ClassID < 0 || r.ClassID >= len(db.Classes) {
		return "!"
	}
	return db.Classes[r.ClassID]
}

// Name devolve o nome do SO do registro, na grafia registrada.
func (db *DB) Name(r *Record) string { return db.Names[r.NameID] }

// TCPRecords devolve as assinaturas TCP de um sentido (true = SYN, false = SYN+ACK).
func (db *DB) TCPRecords(toServer bool) []*Record { return db.tcp[b2i(toServer)] }

// LoadDB lê o p0f.fp de um arquivo (FS_P0F_DB).
func LoadDB(path string) (*DB, error) {
	b, err := os.ReadFile(path) //nolint:gosec // caminho vem da configuração
	if err != nil {
		return nil, err
	}
	return ParseDB(bytes.NewReader(b))
}

// ParseDB lê o p0f.fp com as mesmas regras do p0f 3.09b: qualquer linha que o p0f recusaria (com FATAL)
// vira erro aqui, com o número da linha.
func ParseDB(r io.Reader) (*DB, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	p := &dbParser{db: &DB{}}
	// o p0f para no primeiro NUL do arquivo
	if i := bytes.IndexByte(data, 0); i >= 0 {
		data = data[:i]
	}
	for len(data) > 0 || p.line == 0 {
		p.line++
		line := data
		rest := []byte(nil)
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			line, rest = data[:i], data[i+1:]
		}
		line = bytes.TrimLeft(line, " \t")
		if len(line) > 0 && line[0] != ';' {
			if err := p.parseLine(string(line)); err != nil {
				return nil, fmt.Errorf("p0f.fp linha %d: %w", p.line, err)
			}
		}
		if rest == nil {
			break
		}
		data = rest
	}
	return p.db, nil
}

type dbParser struct {
	db       *DB
	line     int
	state    int
	mod      int
	toServer bool
	// rótulo corrente
	generic bool
	class   int
	nameID  int
	flavor  string
	labelID int
	label   string
	sys     []string
}

func (p *dbParser) parseLine(line string) error {
	if line[0] == '[' {
		return p.parseSection(line[1:])
	}
	// "nome = valor"
	i := 0
	for i < len(line) && (isAlpha(line[i]) || line[i] == '_') {
		i++
	}
	name := line[:i]
	j := i
	for j < len(line) && isBlank(line[j]) {
		j++
	}
	if i == 0 && j == 0 || j >= len(line) || line[j] != '=' {
		return fmt.Errorf("linha inesperada")
	}
	j++
	for j < len(line) && isBlank(line[j]) {
		j++
	}
	val := line[j:]
	switch name {
	case "classes":
		if p.state != needSect {
			return fmt.Errorf("'classes' fora do lugar")
		}
		return p.parseClasses(val)
	case "ua_os":
		if p.state != needLabel || !p.toServer || p.mod != modHTTP {
			return fmt.Errorf("'ua_os' fora do lugar")
		}
		return nil
	case "label":
		if p.state != needLabel && p.state != needSig {
			return fmt.Errorf("'label' fora do lugar")
		}
		if err := p.parseLabel(val); err != nil {
			return err
		}
		if p.mod != modMTU && p.class < 0 {
			p.state = needSys
		} else {
			p.state = needSig
		}
		return nil
	case "sys":
		if p.state != needSys {
			return fmt.Errorf("'sys' fora do lugar")
		}
		if err := p.parseSys(val); err != nil {
			return err
		}
		p.state = needSig
		return nil
	case "sig":
		if p.state != needSig {
			return fmt.Errorf("'sig' fora do lugar")
		}
		if p.mod == modTCP {
			if err := p.registerTCP(val); err != nil {
				return err
			}
		}
		// assinaturas [mtu] e [http:*] não são usadas pelo finger-sniffer
		p.db.Sigs++
		return nil
	}
	return fmt.Errorf("campo desconhecido %q", name)
}

func (p *dbParser) parseSection(s string) error {
	if s == "mtu]" {
		p.mod = modMTU
		p.state = needLabel
		return nil
	}
	mod, dir, ok := strings.Cut(s, ":")
	if !ok {
		return fmt.Errorf("seção malformada")
	}
	switch mod {
	case "tcp":
		p.mod = modTCP
	case "http":
		p.mod = modHTTP
	default:
		return fmt.Errorf("módulo desconhecido %q", mod)
	}
	switch dir {
	case "request]":
		p.toServer = true
	case "response]":
		p.toServer = false
	default:
		return fmt.Errorf("sentido desconhecido")
	}
	p.state = needLabel
	return nil
}

func (p *dbParser) parseClasses(val string) error {
	c := cstr(val)
	for c.at(0) != 0 {
		for isBlank(c.at(0)) || c.at(0) == ',' {
			c.i++
		}
		n := c.i
		for isAlnum(c.char(n)) {
			n++
		}
		if n == c.i || (c.char(n) != 0 && c.char(n) != ',') {
			return fmt.Errorf("classe malformada")
		}
		p.db.Classes = append(p.db.Classes, c.s[c.i:n])
		c.i = n
	}
	return nil
}

func (p *dbParser) parseLabel(val string) error {
	p.label = val
	if p.mod == modMTU {
		if val == "" {
			return fmt.Errorf("rótulo MTU vazio")
		}
		p.flavor = val
		return nil
	}
	c := cstr(val)
	switch c.at(0) {
	case 'g':
		p.generic = true
	case 's':
		p.generic = false
	default:
		return fmt.Errorf("classe do rótulo malformada")
	}
	if c.at(1) != ':' {
		return fmt.Errorf("classe do rótulo malformada")
	}
	c.i += 2
	n := c.i
	for isAlnum(c.char(n)) || c.char(n) == '!' {
		n++
	}
	if n == c.i || c.char(n) != ':' {
		return fmt.Errorf("classe do rótulo malformada")
	}
	if c.at(0) == '!' && c.at(1) == ':' {
		p.class = -1
	} else {
		id := -1
		for i, cl := range p.db.Classes {
			if strings.EqualFold(c.s[c.i:n], cl) {
				id = i
				break
			}
		}
		if id < 0 {
			return fmt.Errorf("classe desconhecida %q", c.s[c.i:n])
		}
		p.class = id
	}
	n++
	c.i = n
	for c.char(n) != 0 && (isAlnum(c.char(n)) || strings.IndexByte(nameChars, c.char(n)) >= 0) {
		n++
	}
	if n == c.i || c.char(n) != ':' {
		return fmt.Errorf("nome malformado")
	}
	p.nameID = p.lookupName(c.s[c.i:n])
	p.flavor = ""
	if n+1 < len(c.s) {
		p.flavor = c.s[n+1:]
	}
	p.labelID++
	return nil
}

func (p *dbParser) lookupName(name string) int {
	for i, n := range p.db.Names {
		if strings.EqualFold(n, name) {
			return i
		}
	}
	p.db.Names = append(p.db.Names, name)
	return len(p.db.Names) - 1
}

func (p *dbParser) parseSys(val string) error {
	p.sys = nil
	c := cstr(val)
	for c.at(0) != 0 {
		for isBlank(c.at(0)) || c.at(0) == ',' {
			c.i++
		}
		isClass := false
		if c.at(0) == '@' {
			isClass = true
			c.i++
		}
		n := c.i
		for c.char(n) != 0 && (isAlnum(c.char(n)) || strings.IndexByte(nameChars, c.char(n)) >= 0) {
			n++
		}
		if n == c.i || (c.char(n) != 0 && c.char(n) != ',') {
			return fmt.Errorf("sys malformado")
		}
		tok := c.s[c.i:n]
		if isClass {
			found := false
			for _, cl := range p.db.Classes {
				if strings.EqualFold(tok, cl) {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("classe desconhecida %q", tok)
			}
			p.sys = append(p.sys, "@"+tok)
		} else {
			p.sys = append(p.sys, p.db.Names[p.lookupName(tok)])
		}
		c.i = n
	}
	return nil
}

// registerTCP lê uma linha sig de [tcp:*] (tcp_register_sig). O cursor imita a aritmética de ponteiros do
// C, inclusive no "ttl-", em que o p0f pula dois caracteres a mais (funciona porque o tamanho das opções IP
// nessas assinaturas tem um dígito).
func (p *dbParser) registerTCP(val string) error {
	c := cstr(val)
	var s tsig
	switch c.at(0) {
	case '4':
		s.ipVer = 4
	case '6':
		s.ipVer = 6
	case '*':
		s.ipVer = -1
	default:
		return fmt.Errorf("versão de IP desconhecida")
	}
	if c.at(1) != ':' {
		return fmt.Errorf("assinatura malformada")
	}
	c.i += 2

	// TTL inicial (ttl, ttl+dist ou ttl-)
	n := c.skipDigits(c.i)
	if c.char(n) != ':' && c.char(n) != '+' && c.char(n) != '-' {
		return fmt.Errorf("assinatura malformada")
	}
	ittl := c.atol(c.i)
	if ittl < 1 || ittl > 255 {
		return fmt.Errorf("TTL inicial inválido")
	}
	c.i = n + 1
	badTTL := false
	switch {
	case c.char(n) == '-' && c.char(n+1) == ':':
		badTTL = true
		c.i += 2
	case c.char(n) == '+':
		n = c.skipDigits(n + 1)
		if c.char(n) != ':' {
			return fmt.Errorf("assinatura malformada")
		}
		add := c.atol(c.i)
		if add < 0 || ittl+add > 255 {
			return fmt.Errorf("TTL inicial inválido")
		}
		ittl += add
		c.i = n + 1
	}

	// tamanho das opções IP
	n = c.skipDigits(c.i)
	if c.char(n) != ':' {
		return fmt.Errorf("assinatura malformada")
	}
	olen := c.atol(c.i)
	if olen < 0 || olen > 255 {
		return fmt.Errorf("tamanho de opções IP inválido")
	}
	c.i = n + 1

	// MSS
	if c.at(0) == '*' && c.at(1) == ':' {
		s.mss = -1
		c.i += 2
	} else {
		n = c.skipDigits(c.i)
		if c.char(n) != ':' {
			return fmt.Errorf("assinatura malformada")
		}
		mss := c.atol(c.i)
		if mss < 0 || mss > 65535 {
			return fmt.Errorf("MSS inválido")
		}
		s.mss = int32(mss)
		c.i = n + 1
	}

	// janela, seguida de vírgula
	var win int64
	switch {
	case c.at(0) == '*' && c.at(1) == ',':
		s.winType = winAny
		c.i += 2
	case c.at(0) == '%':
		s.winType = winMod
		c.i++
		n = c.skipDigits(c.i)
		if c.char(n) != ',' {
			return fmt.Errorf("assinatura malformada")
		}
		win = c.atol(c.i)
		if win < 2 || win > 65535 {
			return fmt.Errorf("valor de '%%' inválido")
		}
		c.i = n + 1
	case strings.HasPrefix(c.s[c.i:], "mss*") || strings.HasPrefix(c.s[c.i:], "mtu*"):
		s.winType = winMTU
		if c.at(1) == 's' {
			s.winType = winMSS
		}
		c.i += 4
		n = c.skipDigits(c.i)
		if c.char(n) != ',' {
			return fmt.Errorf("assinatura malformada")
		}
		win = c.atol(c.i)
		if win < 1 || win > 1000 {
			return fmt.Errorf("multiplicador de MSS/MTU inválido")
		}
		c.i = n + 1
	default:
		s.winType = winNormal
		n = c.skipDigits(c.i)
		if c.char(n) != ',' {
			return fmt.Errorf("assinatura malformada")
		}
		win = c.atol(c.i)
		if win < 0 || win > 65535 {
			return fmt.Errorf("janela inválida")
		}
		c.i = n + 1
	}
	s.win = uint16(win)

	// window scale
	if c.at(0) == '*' && c.at(1) == ':' {
		s.wscale = -1
		c.i += 2
	} else {
		n = c.skipDigits(c.i)
		if c.char(n) != ':' {
			return fmt.Errorf("assinatura malformada")
		}
		sc := c.atol(c.i)
		if sc < 0 || sc > 255 {
			return fmt.Errorf("window scale inválido")
		}
		s.wscale = int16(sc)
		c.i = n + 1
	}

	if err := c.parseLayout(&s); err != nil {
		return err
	}
	if err := c.parseQuirks(&s); err != nil {
		return err
	}

	// classe de payload
	switch c.s[min(c.i, len(c.s)):] {
	case "*":
		s.payClass = -1
	case "0":
		s.payClass = 0
	case "+":
		s.payClass = 1
	default:
		return fmt.Errorf("classe de payload malformada")
	}

	s.ipOptLen = uint8(olen)
	s.ttl = uint8(ittl)

	// Como o p0f, recusa assinatura já coberta por outra (comparação exata, sem genéricas nem fuzzy).
	if m, _ := p.db.find(p.toServer, &s, true, 0); m.rec != nil {
		return fmt.Errorf("assinatura já coberta pela linha %d", m.rec.Line)
	}
	sys := p.sys
	if p.class >= 0 {
		sys = nil
	}
	rec := &Record{
		Line: p.line, Label: p.label, Generic: p.generic, ClassID: p.class, NameID: p.nameID,
		Flavor: p.flavor, LabelID: p.labelID, BadTTL: badTTL, Sys: sys, sig: s,
	}
	i := b2i(p.toServer)
	p.db.tcp[i] = append(p.db.tcp[i], rec)
	return nil
}

func (c *cursor) parseLayout(s *tsig) error {
	for c.at(0) != ':' {
		if len(s.layout) >= maxTCPOpt {
			return fmt.Errorf("opções TCP demais")
		}
		rest := c.s[min(c.i, len(c.s)):]
		switch {
		case strings.HasPrefix(rest, "eol"):
			s.layout = append(s.layout, optEOL)
			c.i += 3
			if c.at(0) != '+' {
				return fmt.Errorf("opção EOL malformada")
			}
			c.i++
			n := c.skipDigits(c.i)
			if c.char(n) == 0 {
				return fmt.Errorf("opções truncadas")
			}
			if c.char(n) != ':' {
				return fmt.Errorf("EOL precisa ser a última opção")
			}
			pad := c.atol(c.i)
			if pad < 0 || pad > 255 {
				return fmt.Errorf("padding do EOL inválido")
			}
			s.eolPad = uint8(pad)
			c.i = n
		case strings.HasPrefix(rest, "nop"):
			s.layout = append(s.layout, optNOP)
			c.i += 3
		case strings.HasPrefix(rest, "mss"):
			s.layout = append(s.layout, optMSS)
			c.i += 3
		case strings.HasPrefix(rest, "ws"):
			s.layout = append(s.layout, optWScale)
			c.i += 2
		case strings.HasPrefix(rest, "sok"):
			s.layout = append(s.layout, optSACKOK)
			c.i += 3
		case strings.HasPrefix(rest, "sack"):
			s.layout = append(s.layout, optSACK)
			c.i += 4
		case strings.HasPrefix(rest, "ts"):
			s.layout = append(s.layout, optTS)
			c.i += 2
		case c.at(0) == '?':
			c.i++
			n := c.skipDigits(c.i)
			if c.char(n) != ':' && c.char(n) != ',' {
				return fmt.Errorf("opção '?' malformada")
			}
			no := c.atol(c.i)
			if no < 0 || no > 255 {
				return fmt.Errorf("opção '?' inválida")
			}
			s.layout = append(s.layout, uint8(no))
			c.i = n
		default:
			return fmt.Errorf("opção TCP desconhecida")
		}
		if c.at(0) == ':' {
			break
		}
		if c.at(0) != ',' {
			return fmt.Errorf("opções TCP malformadas")
		}
		c.i++
	}
	c.i++
	return nil
}

var quirkTokens = []struct {
	tok  string
	bit  uint32
	not4 bool // inválido em IPv6
	not6 bool // inválido em IPv4
}{
	{"df", QuirkDF, true, false},
	{"id+", QuirkNZID, true, false},
	{"id-", QuirkZeroID, true, false},
	{"ecn", QuirkECN, false, false},
	{"0+", QuirkNZMBZ, true, false},
	{"flow", QuirkFlow, false, true},
	{"seq-", QuirkZeroSeq, false, false},
	{"ack+", QuirkNZAck, false, false},
	{"ack-", QuirkZeroAck, false, false},
	{"uptr+", QuirkNZURG, false, false},
	{"urgf+", QuirkURG, false, false},
	{"pushf+", QuirkPush, false, false},
	{"ts1-", QuirkZeroTS1, false, false},
	{"ts2+", QuirkNZTS2, false, false},
	{"opt+", QuirkOptEOLNZ, false, false},
	{"exws", QuirkOptExWS, false, false},
	{"bad", QuirkOptBad, false, false},
}

func (c *cursor) parseQuirks(s *tsig) error {
	for c.at(0) != ':' {
		rest := c.s[min(c.i, len(c.s)):]
		found := false
		for _, q := range quirkTokens {
			if !strings.HasPrefix(rest, q.tok) {
				continue
			}
			if q.not4 && s.ipVer == 6 {
				return fmt.Errorf("%q não vale para IPv6", q.tok)
			}
			if q.not6 && s.ipVer == 4 {
				return fmt.Errorf("%q não vale para IPv4", q.tok)
			}
			s.quirks |= q.bit
			c.i += len(q.tok)
			found = true
			break
		}
		if !found {
			return fmt.Errorf("quirk desconhecido")
		}
		if c.at(0) == ':' {
			break
		}
		if c.at(0) != ',' {
			return fmt.Errorf("quirks malformados")
		}
		c.i++
	}
	c.i++
	return nil
}

// cursor percorre uma string como um ponteiro de C: ler além do fim devolve o NUL.
type cursor struct {
	s string
	i int
}

func cstr(s string) *cursor { return &cursor{s: s} }

func (c *cursor) char(i int) byte {
	if i < 0 || i >= len(c.s) {
		return 0
	}
	return c.s[i]
}

func (c *cursor) at(off int) byte { return c.char(c.i + off) }

func (c *cursor) skipDigits(i int) int {
	for isDigit(c.char(i)) {
		i++
	}
	return i
}

// atol imita o atol do C: espaços iniciais, sinal opcional e dígitos; 0 quando não há número.
func (c *cursor) atol(i int) int64 {
	for isSpace(c.char(i)) {
		i++
	}
	neg := false
	if ch := c.char(i); ch == '+' || ch == '-' {
		neg = ch == '-'
		i++
	}
	var v int64
	for isDigit(c.char(i)) {
		v = v*10 + int64(c.char(i)-'0')
		if v > 1<<40 {
			v = 1 << 40 // evita estouro; qualquer valor assim já está fora das faixas válidas
		}
		i++
	}
	if neg {
		return -v
	}
	return v
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }
func isAlpha(b byte) bool { return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' }
func isAlnum(b byte) bool { return isAlpha(b) || isDigit(b) }
func isBlank(b byte) bool { return b == ' ' || b == '\t' }
func isSpace(b byte) bool { return b == ' ' || b >= '\t' && b <= '\r' }

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
