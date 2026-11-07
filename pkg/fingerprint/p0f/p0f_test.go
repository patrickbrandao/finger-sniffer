package p0f

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fixtureDB é um p0f.fp pequeno, escrito para os testes, que passa por todos os ramos do leitor.
const fixtureDB = `; comentário
classes = win,unix,other

[mtu]
label = Ethernet or modem
sig   = 1500

[tcp:request]
label = s:unix:Linux:3.11 and newer
sig   = *:64:0:*:mss*20,10:mss,sok,ts,nop,ws:df,id+:0
sig   = *:64:0:*:mss*20,7:mss,sok,ts,nop,ws:df,id+:0

label = g:unix:Linux:2.2.x-3.x
sig   = *:64:0:*:*,*:mss,sok,ts,nop,ws:df,id+:0

label = s:win:Windows:7 or 8
sig   = *:128:0:*:8192,8:mss,nop,ws,nop,nop,sok:df,id+:0

label = s:unix:Mac OS X:
sig   = 4:64+3:0:*:%8192,*:mss,nop,ws,nop,nop,ts,sok,eol+1:df,id+:0

label = s:unix:linux:MTU
sig   = 4:64:0:1460:mtu*4,7:mss,sok,ts,nop,ws:df,id+:0

label = s:other:Weird:stack
sig   = 6:64:0:*:*,*:?34,mss,sack:flow,seq-,ack+,ack-,uptr+,urgf+,pushf+,ts1-,ts2+,opt+,exws,bad,ecn:+
sig   = *:255-:4:*:*,*::0+,id-:*

label = s:!:nmap:SYN scan
sys   = @unix,@win,Linux, Mac OS X
sig   = *:64-:0:1460:1024,0:mss::0

[tcp:response]
label = s:unix:Linux:peer
sig   = *:64:0:*:mss*10,7:mss,sok,ts,nop,ws:df:0

[http:request]
ua_os = Linux,Windows
label = s:!:wget:
sys   = Linux
sig   = *:Host,User-Agent::Wget

[http:response]
label = g:!:server:
sys   = @unix
sig   = *:Server::
`

func loadFixture(t *testing.T) *DB {
	t.Helper()
	db, err := ParseDB(strings.NewReader(fixtureDB))
	if err != nil {
		t.Fatal(err)
	}
	return db
}

// syn monta um pacote IPv4 + TCP. opts recebe padding até múltiplo de 4.
type pktSpec struct {
	v6       bool
	ttl      uint8
	tos      uint8
	id       uint16
	df       bool
	mbz      bool
	frag     bool
	proto    uint8
	ipOpts   []byte
	flow     uint32
	flags    uint8
	win      uint16
	seq      uint32
	ack      uint32
	urg      uint16
	res      uint8
	opts     []byte
	payload  []byte
	trailing int // bytes de padding do Ethernet depois do pacote
}

func build(s pktSpec) []byte {
	opts := append([]byte(nil), s.opts...)
	for len(opts)%4 != 0 {
		opts = append(opts, 0)
	}
	tcp := make([]byte, 20, 20+len(opts)+len(s.payload))
	binary.BigEndian.PutUint16(tcp[0:], 40000)
	binary.BigEndian.PutUint16(tcp[2:], 443)
	binary.BigEndian.PutUint32(tcp[4:], s.seq)
	binary.BigEndian.PutUint32(tcp[8:], s.ack)
	tcp[12] = byte((20+len(opts))/4)<<4 | s.res
	tcp[13] = s.flags
	binary.BigEndian.PutUint16(tcp[14:], s.win)
	binary.BigEndian.PutUint16(tcp[18:], s.urg)
	tcp = append(append(tcp, opts...), s.payload...)
	proto := s.proto
	if proto == 0 {
		proto = 6
	}
	var ip []byte
	if s.v6 {
		ip = make([]byte, 40)
		binary.BigEndian.PutUint32(ip[0:], 6<<28|uint32(s.tos)<<20|s.flow)
		binary.BigEndian.PutUint16(ip[4:], uint16(len(tcp)))
		ip[6] = proto
		ip[7] = s.ttl
	} else {
		hl := 20 + len(s.ipOpts)
		ip = make([]byte, hl)
		ip[0] = 4<<4 | byte(hl/4)
		ip[1] = s.tos
		binary.BigEndian.PutUint16(ip[2:], uint16(hl+len(tcp)))
		binary.BigEndian.PutUint16(ip[4:], s.id)
		var fo uint16
		if s.df {
			fo |= 0x4000
		}
		if s.mbz {
			fo |= 0x8000
		}
		if s.frag {
			fo |= 0x2000
		}
		binary.BigEndian.PutUint16(ip[6:], fo)
		ip[8] = s.ttl
		ip[9] = proto
		copy(ip[20:], s.ipOpts)
	}
	return append(append(ip, tcp...), make([]byte, s.trailing)...)
}

var (
	linuxOpts = []byte{2, 4, 5, 0xb4, 4, 2, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0, 1, 3, 3, 7}
	winOpts   = []byte{2, 4, 5, 0xb4, 1, 3, 3, 8, 1, 1, 4, 2}
	macOpts   = []byte{2, 4, 5, 0xb4, 1, 3, 3, 6, 1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0, 4, 2, 0, 0}
)

func fp(t *testing.T, db *DB, s pktSpec, synMSS uint16) Observation {
	t.Helper()
	p, err := Parse(build(s))
	if err != nil {
		t.Fatal(err)
	}
	o, err := db.Fingerprint(p, synMSS)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func TestFixtureDB(t *testing.T) {
	db := loadFixture(t)
	if got := strings.Join(db.Classes, ","); got != "win,unix,other" {
		t.Fatalf("classes = %s", got)
	}
	// a grafia do nome é a da primeira ocorrência ("Linux"), mesmo com "linux" depois
	if db.Names[0] != "Linux" {
		t.Fatalf("names = %v", db.Names)
	}
	if n := len(db.TCPRecords(true)); n != 9 {
		t.Fatalf("%d assinaturas de request", n)
	}
	if n := len(db.TCPRecords(false)); n != 1 {
		t.Fatalf("%d assinaturas de response", n)
	}
	if db.Sigs != 13 {
		t.Fatalf("Sigs = %d", db.Sigs)
	}
	tool := db.TCPRecords(true)[8]
	if db.Class(tool) != "!" || !tool.BadTTL || strings.Join(tool.Sys, "|") != "@unix|@win|Linux|Mac OS X" {
		t.Fatalf("ferramenta: %+v", tool)
	}
	if db.Name(db.TCPRecords(true)[4]) != "Mac OS X" || db.TCPRecords(true)[4].Flavor != "" {
		t.Fatalf("mac: %+v", db.TCPRecords(true)[4])
	}
}

func TestMatch(t *testing.T) {
	db := loadFixture(t)
	cases := []struct {
		name   string
		spec   pktSpec
		synMSS uint16
		os     string
		dist   string
		params string
		raw    string
		app    bool
	}{
		{
			name: "exata", spec: pktSpec{ttl: 57, df: true, id: 1, flags: 0x02, win: 29200, seq: 1, opts: linuxOpts},
			os: "Linux 3.11 and newer", dist: "7", params: "none",
			raw: "4:57+7:0:1460:mss*20,7:mss,sok,ts,nop,ws:df,id+:0",
		},
		{
			name: "genérica", spec: pktSpec{ttl: 64, df: true, id: 1, flags: 0x02, win: 1000, seq: 1, opts: linuxOpts},
			os: "Linux 2.2.x-3.x", dist: "0", params: "generic",
			raw: "4:64+0:0:1460:1000,7:mss,sok,ts,nop,ws:df,id+:0",
		},
		{
			name: "fuzzy por quirk (df sumiu, id- apareceu)", spec: pktSpec{ttl: 64, flags: 0x02, win: 29200, seq: 1, opts: linuxOpts},
			os: "Linux 3.11 and newer", dist: "0", params: "fuzzy",
			raw: "4:64+0:0:1460:mss*20,7:mss,sok,ts,nop,ws:id-:0",
		},
		{
			name: "fuzzy por TTL", spec: pktSpec{ttl: 120, df: true, id: 1, flags: 0x02, win: 29200, seq: 1, opts: linuxOpts},
			os: "Linux 3.11 and newer", dist: "8", params: "fuzzy",
			raw: "4:120+8:0:1460:mss*20,7:mss,sok,ts,nop,ws:df,id+:0",
		},
		{
			name: "windows com TOS", spec: pktSpec{ttl: 113, tos: 0x28, df: true, id: 9, flags: 0x02, win: 8192, seq: 1, opts: winOpts},
			os: "Windows 7 or 8", dist: "15", params: "tos:0x0a",
			raw: "4:113+15:0:1460:8192,8:mss,nop,ws,nop,nop,sok:df,id+:0",
		},
		{
			name: "janela módulo e ttl+dist", spec: pktSpec{ttl: 64, df: true, id: 1, flags: 0x02, win: 16384, seq: 1, opts: macOpts},
			os: "Mac OS X", dist: "3", params: "none",
			raw: "4:64+0:0:1460:16384,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,id+:0",
		},
		{
			name: "multiplicador de MTU", spec: pktSpec{ttl: 64, df: true, id: 1, flags: 0x02, win: 6000, seq: 1, opts: linuxOpts},
			os: "Linux MTU", dist: "0", params: "none",
			raw: "4:64+0:0:1460:mtu*4,7:mss,sok,ts,nop,ws:df,id+:0",
		},
		{
			name: "ferramenta com TTL aleatório", spec: pktSpec{ttl: 40, df: false, id: 7, flags: 0x02, win: 1024, seq: 1, opts: []byte{2, 4, 5, 0xb4}},
			os: "nmap SYN scan", dist: "<= 24", params: "random_ttl", app: true,
			raw: "4:40+24:0:1460:1024,0:mss::0",
		},
		{
			// só o ecn a mais seria fuzzy, mas ferramenta não aceita fuzzy: sem palpite e distância 0
			name: "ferramenta não aceita fuzzy", spec: pktSpec{ttl: 40, tos: 0x01, id: 7, flags: 0x02, win: 1024, seq: 1, opts: []byte{2, 4, 5, 0xb4}},
			os: "???", dist: "0", params: "none",
			raw: "4:40+24:0:1460:1024,0:mss:ecn:0",
		},
		{
			name: "sem correspondência e distância grande", spec: pktSpec{ttl: 200, df: true, id: 1, flags: 0x02, win: 1, seq: 1, opts: []byte{1, 1, 1, 1}},
			os: "???", dist: "55", params: "excess_dist",
			raw: "4:200+?:0:0:1,0:nop,nop,nop,nop:df,id+:0",
		},
		{
			name: "IPv6 com tudo", synMSS: 0,
			spec: pktSpec{
				v6: true, ttl: 64, tos: 0x01, flow: 1, flags: 0x02 | 0x20 | 0x08 | 0xc0, win: 5, seq: 0, ack: 1 << 24,
				urg: 0, res: 1, opts: []byte{34, 2, 2, 4, 5, 0xb4, 5, 10, 0, 0, 0, 0, 0, 0, 0, 0, 3, 3, 15, 8, 10, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1},
				payload: []byte("x"),
			},
			// o byte não nulo depois do EOL é o último: eol+2 e sem opt+, como no p0f
			os: "???", dist: "0", params: "none",
			raw: "6:64+0:0:1460:5,15:?34,mss,sack,ws,ts,eol+2:ecn,flow,seq-,ack+,urgf+,pushf+,ts1-,ts2+,exws:+",
		},
		{
			// a assinatura diz olen 4, mas com "ttl-" o p0f lê 0 (ver TestBadTTLPointer)
			name: "bit reservado e ttl-", spec: pktSpec{ttl: 255, mbz: true, flags: 0x02, win: 3, seq: 1},
			os: "Weird stack", dist: "<= 0", params: "random_ttl",
			raw: "4:255+0:0:0:3,0::id-,0+:0",
		},
		{
			name: "opções IP", spec: pktSpec{ttl: 64, df: true, id: 1, ipOpts: []byte{1, 1, 1, 0}, flags: 0x02, win: 3, seq: 1, opts: linuxOpts},
			os: "???", dist: "0", params: "none",
			raw: "4:64+0:4:1460:3,7:mss,sok,ts,nop,ws:df,id+:0",
		},
		{
			name: "SYN+ACK com MSS do outro lado", synMSS: 1460,
			spec: pktSpec{ttl: 64, df: true, id: 0, flags: 0x12, win: 14600, seq: 1, ack: 1, opts: []byte{2, 4, 5, 0x00, 4, 2, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0, 1, 3, 3, 7}},
			os:   "Linux peer", dist: "0", params: "none",
			raw: "4:64+0:0:1280:mss*10,7:mss,sok,ts,nop,ws:df:0",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := fp(t, db, c.spec, c.synMSS)
			if o.OS != c.os || o.Dist != c.dist || o.Params != c.params || o.RawSig != c.raw || o.App != c.app {
				t.Fatalf("obs = %+v\nquer os=%q dist=%q params=%q raw=%q app=%v", o, c.os, c.dist, c.params, c.raw, c.app)
			}
		})
	}
}

// TestBadTTLPointer: no "ttl-" o leitor do p0f avança dois caracteres a mais e lê o tamanho das opções IP a
// partir do ":" (atol dá 0). Reproduzido de propósito: "*:255-:4:..." fica com olen 0.
func TestBadTTLPointer(t *testing.T) {
	db := loadFixture(t)
	r := db.TCPRecords(true)[7]
	if !r.BadTTL || r.sig.ipOptLen != 0 || r.sig.ttl != 255 {
		t.Fatalf("registro: %+v", r)
	}
}

func TestFingerprintModes(t *testing.T) {
	db := loadFixture(t)
	o := fp(t, db, pktSpec{ttl: 64, flags: 0x02, win: specialWin, seq: 1, opts: []byte{2, 4, 0x05, 0x33}}, 0)
	if o.Mod != "sendsyn probe" {
		t.Fatalf("sendsyn: %+v", o)
	}
	o = fp(t, db, pktSpec{ttl: 64, flags: 0x12, win: 1, seq: 1, ack: 1, opts: []byte{2, 4, 0x05, 0x33}}, 0)
	if o.Mod != "syn+ack" || !strings.HasPrefix(o.RawSig, "4:64+0:0:*:") {
		t.Fatalf("sendsyn response: %+v", o)
	}
	p, err := Parse(build(pktSpec{ttl: 64, flags: 0x10, win: 1, seq: 1, ack: 1}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Fingerprint(p, 0); !errors.Is(err, ErrNotSYN) {
		t.Fatalf("ACK: %v", err)
	}
	// SYN+ACK com MSS pequeno do outro lado: o quociente estoura o s16 como no p0f e não vira multiplicador
	o = fp(t, db, pktSpec{ttl: 64, flags: 0x12, win: 65535, seq: 1, ack: 1, opts: []byte{2, 4, 0x01, 0x00}}, 1)
	if !strings.Contains(o.RawSig, ":65535,0:") {
		t.Fatalf("quociente: %s", o.RawSig)
	}
}

func TestParseErrors(t *testing.T) {
	cases := map[string]struct {
		b   []byte
		err error
	}{
		"curto":            {make([]byte, 39), ErrShort},
		"versão":           {append([]byte{0x50}, make([]byte, 59)...), ErrVersion},
		"udp":              {build(pktSpec{proto: 17, flags: 2}), ErrNotTCP},
		"udp v6":           {build(pktSpec{v6: true, proto: 17, flags: 2}), ErrNotTCP},
		"fragmento":        {build(pktSpec{frag: true, flags: 2}), ErrFragment},
		"SYN+FIN":          {build(pktSpec{flags: 0x03}), ErrFlags},
		"FIN+RST":          {build(pktSpec{flags: 0x05}), ErrFlags},
		"sem flags":        {build(pktSpec{flags: 0x08}), ErrFlags},
		"tot_len grande":   {func() []byte { b := build(pktSpec{flags: 2}); b[3] = 0xff; return b }(), ErrShort},
		"v6 pay_len":       {func() []byte { b := build(pktSpec{v6: true, flags: 2}); b[5] = 0xff; return b }(), ErrShort},
		"ihl pequeno":      {func() []byte { b := build(pktSpec{flags: 2}); b[0] = 0x44; return b }(), ErrShort},
		"doff pequeno":     {func() []byte { b := build(pktSpec{flags: 2}); b[32] = 0x40; return b }(), ErrShort},
		"doff além do fim": {func() []byte { b := build(pktSpec{flags: 2}); b[32] = 0xf0; return b }(), ErrShort},
	}
	for name, c := range cases {
		if _, err := Parse(c.b); !errors.Is(err, c.err) {
			t.Errorf("%s: err = %v, quer %v", name, err, c.err)
		}
	}
	// padding do Ethernet depois do pacote é ignorado (vale o tot_len)
	p, err := Parse(build(pktSpec{flags: 2, ttl: 64, trailing: 6}))
	if err != nil || p.PayLen != 0 {
		t.Fatalf("padding: %+v %v", p, err)
	}
}

func TestOptionQuirks(t *testing.T) {
	cases := []struct {
		name   string
		opts   []byte
		flags  uint8
		quirks uint32
		layout string
	}{
		{"EOL com lixo", []byte{0, 1, 3, 3, 7, 0, 0, 0}, 2, QuirkOptEOLNZ, "0"},
		// o não nulo é o último byte: o p0f não marca opt+ (ponteiro já passou dele)
		{"EOL com lixo no último byte", []byte{1, 1, 1, 0, 0, 0, 0, 9}, 2, 0, "1,1,1,0"},
		{"MSS truncado", []byte{1, 1, 1, 2}, 2, QuirkOptBad, "1,1,1,2"},
		{"MSS tamanho errado", []byte{2, 3, 5, 0xb4}, 2, QuirkOptBad, "2"},
		{"WS truncado", []byte{1, 1, 1, 3}, 2, QuirkOptBad, "1,1,1,3"},
		{"WS tamanho errado", []byte{3, 4, 1, 1}, 2, QuirkOptBad, "3,1"},
		{"SACKOK truncado", []byte{1, 1, 1, 4}, 2, QuirkOptBad, "1,1,1,4"},
		{"SACKOK tamanho errado", []byte{4, 3, 1, 1}, 2, QuirkOptBad, "4,1,1"},
		{"SACK sem tamanho", []byte{1, 1, 1, 5}, 2, QuirkOptBad, "1,1,1,5"},
		{"SACK curto", []byte{5, 9, 1, 1}, 2, QuirkOptBad, "5"},
		{"SACK passa do fim", []byte{5, 10, 1, 1}, 2, QuirkOptBad, "5"},
		{"TS truncado", []byte{8, 10, 1, 1}, 2, QuirkOptBad, "8"},
		{"TS tamanho errado e ts2 em SYN+ACK", []byte{8, 9, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1}, 0x12, QuirkOptBad, "8,1,1"},
		{"desconhecida sem tamanho", []byte{1, 1, 1, 30}, 2, QuirkOptBad, "1,1,1,30"},
		{"desconhecida tamanho 41", []byte{30, 41, 1, 1}, 2, QuirkOptBad, "30"},
		{"desconhecida passa do fim", []byte{30, 8, 1, 1}, 2, QuirkOptBad, "30"},
		{"25 NOPs", []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}, 2, QuirkOptBad, strings.TrimSuffix(strings.Repeat("1,", 24), ",")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, err := Parse(build(pktSpec{flags: c.flags, ack: 1, seq: 1, opts: c.opts, df: true, id: 1}))
			if err != nil {
				t.Fatal(err)
			}
			got := p.Quirks &^ (QuirkDF | QuirkNZID)
			var l []string
			for _, k := range p.Layout {
				l = append(l, itoa(int(k)))
			}
			if got != c.quirks || strings.Join(l, ",") != c.layout {
				t.Fatalf("quirks = %#x layout = %v; quer %#x %s", got, l, c.quirks, c.layout)
			}
		})
	}
}

func itoa(i int) string {
	if i < 10 {
		return string(rune('0' + i))
	}
	return itoa(i/10) + string(rune('0'+i%10))
}

func TestParseDBErrors(t *testing.T) {
	head := "classes = win,unix,other\n[tcp:request]\nlabel = s:unix:Linux:x\n"
	sig := func(s string) string { return head + "sig = " + s + "\n" }
	cases := map[string]string{
		"classes depois de seção":   "[tcp:request]\nclasses = a\n",
		"classes com espaço no fim": "classes = win, \n",
		"classes malformada":        "classes = w-n\n",
		"linha inesperada":          "= 1\n",
		"sem igual":                 "label x\n",
		"campo desconhecido":        "[tcp:request]\nfoo = 1\n",
		"seção sem sentido":         "[tcp]\n",
		"módulo desconhecido":       "[udp:request]\n",
		"sentido desconhecido":      "[tcp:sideways]\n",
		"ua_os fora do http":        "[tcp:request]\nua_os = x\n",
		"label fora do lugar":       "label = s:unix:Linux:\n",
		"sys fora do lugar":         head + "sys = Linux\n",
		"sig fora do lugar":         "[tcp:request]\nsig = *:64:0:*:*,*::0:0\n",
		"rótulo MTU vazio":          "[mtu]\nlabel = \n",
		"rótulo sem s/g":            "classes = unix\n[tcp:request]\nlabel = x:unix:Linux:\n",
		"rótulo sem dois pontos":    "classes = unix\n[tcp:request]\nlabel = s-unix:Linux:\n",
		"classe vazia":              "classes = unix\n[tcp:request]\nlabel = s::Linux:\n",
		"classe desconhecida":       "classes = unix\n[tcp:request]\nlabel = s:win:Linux:\n",
		"nome vazio":                "classes = unix\n[tcp:request]\nlabel = s:unix::\n",
		"nome sem fim":              "classes = unix\n[tcp:request]\nlabel = s:unix:Linux\n",
		"sys malformado":            "classes = unix\n[tcp:request]\nlabel = s:!:nmap:\nsys = a;b\n",
		"sys classe desconhecida":   "classes = unix\n[tcp:request]\nlabel = s:!:nmap:\nsys = @win\n",
		"versão IP":                 sig("5:64:0:*:*,*::0:0"),
		"versão sem dois pontos":    sig("4-64:0:*:*,*::0:0"),
		"ttl malformado":            sig("4:64x:0:*:*,*::0:0"),
		"ttl zero":                  sig("4:0:0:*:*,*::0:0"),
		"ttl+ malformado":           sig("4:64+1x:0:*:*,*::0:0"),
		"ttl+ estoura":              sig("4:250+10:0:*:*,*::0:0"),
		"olen malformado":           sig("4:64:x:*:*,*::0:0"),
		"olen grande":               sig("4:64:256:*:*,*::0:0"),
		"mss malformado":            sig("4:64:0:x:*,*::0:0"),
		"mss grande":                sig("4:64:0:65536:*,*::0:0"),
		"janela % malformada":       sig("4:64:0:*:%x,*::0:0"),
		"janela % pequena":          sig("4:64:0:*:%1,*::0:0"),
		"mss* malformado":           sig("4:64:0:*:mss*x,*::0:0"),
		"mss* grande":               sig("4:64:0:*:mss*1001,*::0:0"),
		"janela malformada":         sig("4:64:0:*:x,*::0:0"),
		"janela grande":             sig("4:64:0:*:65536,*::0:0"),
		"wscale malformado":         sig("4:64:0:*:*,x::0:0"),
		"wscale grande":             sig("4:64:0:*:*,256::0:0"),
		"opções demais":             sig("4:64:0:*:*,*:" + strings.TrimSuffix(strings.Repeat("nop,", 25), ",") + "::0"),
		"EOL sem +":                 sig("4:64:0:*:*,*:eol:df:0"),
		"EOL truncado":              sig("4:64:0:*:*,*:eol+1"),
		"EOL não é a última":        sig("4:64:0:*:*,*:eol+1,nop::0"),
		"EOL grande":                sig("4:64:0:*:*,*:eol+256::0"),
		"? malformado":              sig("4:64:0:*:*,*:?x::0"),
		"? grande":                  sig("4:64:0:*:*,*:?256::0"),
		"opção desconhecida":        sig("4:64:0:*:*,*:foo::0"),
		"opções malformadas":        sig("4:64:0:*:*,*:nop;nop::0"),
		"df em IPv6":                sig("6:64:0:*:*,*::df:0"),
		"flow em IPv4":              sig("4:64:0:*:*,*::flow:0"),
		"quirk desconhecido":        sig("4:64:0:*:*,*::foo:0"),
		"quirks malformados":        sig("4:64:0:*:*,*::df;ecn:0"),
		"payload malformado":        sig("4:64:0:*:*,*::df:1"),
		"assinatura repetida":       head + "sig = 4:64:0:*:*,*::df:0\nsig = 4:64:0:*:*,*::df:0\n",
	}
	for name, src := range cases {
		if _, err := ParseDB(strings.NewReader(src)); err == nil {
			t.Errorf("%s: sem erro", name)
		}
	}
	// arquivo vazio e NUL no meio: sem erro (o p0f para no NUL)
	if db, err := ParseDB(strings.NewReader("")); err != nil || db.Sigs != 0 {
		t.Fatalf("vazio: %v", err)
	}
	if db, err := ParseDB(strings.NewReader("classes = a\x00lixo sem sentido")); err != nil || len(db.Classes) != 1 {
		t.Fatalf("NUL: %v", err)
	}
}

func TestLoadDB(t *testing.T) {
	p := filepath.Join(t.TempDir(), "p0f.fp")
	if err := os.WriteFile(p, []byte(fixtureDB), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDB(p); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDB(p + ".nada"); err == nil {
		t.Fatal("arquivo inexistente sem erro")
	}
}

func TestRealDBLoads(t *testing.T) {
	db := realDB(t)
	if len(db.TCPRecords(true)) != 91 || len(db.TCPRecords(false)) != 101 || db.Sigs != 322 {
		t.Fatalf("p0f.fp real: %d request, %d response, %d sigs", len(db.TCPRecords(true)), len(db.TCPRecords(false)), db.Sigs)
	}
}

func FuzzParse(f *testing.F) {
	f.Add(build(pktSpec{ttl: 64, df: true, id: 1, flags: 2, win: 29200, seq: 1, opts: linuxOpts}))
	f.Add(build(pktSpec{v6: true, ttl: 64, flags: 0x12, win: 1, opts: macOpts, payload: []byte("x")}))
	f.Add(build(pktSpec{flags: 2, opts: []byte{0, 1, 3, 3, 7, 0, 0, 0}}))
	db, err := ParseDB(strings.NewReader(fixtureDB))
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := Parse(b)
		if err != nil {
			return
		}
		if len(p.Layout) > maxTCPOpt {
			t.Fatalf("%d opções", len(p.Layout))
		}
		if o, err := db.Fingerprint(p, 1460); err == nil && o.RawSig == "" {
			t.Fatal("assinatura vazia")
		}
	})
}

func FuzzParseDB(f *testing.F) {
	f.Add(fixtureDB)
	f.Add("classes = a\n[tcp:request]\nlabel = s:a:X:\nsig = *:64-:0:*:*,*::0:0\n")
	f.Fuzz(func(t *testing.T, s string) {
		db, err := ParseDB(strings.NewReader(s))
		if err != nil {
			return
		}
		// o que carregou precisa servir para comparar sem pânico
		p, err := Parse(build(pktSpec{ttl: 64, df: true, id: 1, flags: 2, win: 29200, seq: 1, opts: linuxOpts}))
		if err != nil {
			t.Fatal(err)
		}
		_, _ = db.Fingerprint(p, 0)
	})
}
