package bot

import (
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// Versões das regras e das listas nesta entrega: sem sinais nem listas ainda (segunda onda, ADRs 0049 e 0050).
const (
	RulesVersion = "none"
	ListsVersion = "none"
)

// Classes do veredito (ADR 0049 item 3).
const (
	ClassHuman   = "human"
	ClassGoodBot = "good_bot"
	ClassBot     = "bot"
	ClassSuspect = "suspect"
	ClassUnknown = "unknown"
)

// Verdict é o schema Verdict do openapi do bot.
type Verdict struct {
	Class        string        `json:"class"`
	Score        int           `json:"score"`
	Signals      []Signal      `json:"signals"`
	View         View          `json:"view"`
	Fingerprints *Fingerprints `json:"fingerprints,omitempty"`
	Crawler      *string       `json:"crawler"`
	RulesVersion string        `json:"rules_version"`
	ListsVersion string        `json:"lists_version"`
	Subject      Subject       `json:"subject"`
	Ts           string        `json:"ts"`
}

// Signal é um sinal presente no veredito.
type Signal struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Weight int    `json:"weight"`
	Detail string `json:"detail,omitempty"`
}

// View diz o que havia para decidir.
type View struct {
	TCP        bool `json:"tcp"`
	TLS        bool `json:"tls"`
	HTTP       bool `json:"http"`
	H2         bool `json:"h2"`
	H3         bool `json:"h3"`
	Behavior   bool `json:"behavior"`
	ParseError bool `json:"parse_error,omitempty"`
}

// Fingerprints são as fingerprints vistas (todas anuláveis).
type Fingerprints struct {
	JA3        *string `json:"ja3"`
	JA3N       *string `json:"ja3n"`
	JA4        *string `json:"ja4"`
	JA4R       *string `json:"ja4_r"`
	JA4O       *string `json:"ja4_o"`
	Akamai     *string `json:"akamai"`
	JA4H       *string `json:"ja4h"`
	JA4T       *string `json:"ja4t"`
	P0fOS      *string `json:"p0f_os"`
	TTLInitial *int    `json:"ttl_initial"`
	UAFamily   *string `json:"ua_family"`
	UAOS       *string `json:"ua_os"`
}

// Subject é o sujeito do veredito.
type Subject struct {
	Kind     string    `json:"kind"`
	Site     *string   `json:"site"`
	Src      *endpoint `json:"src,omitempty"`
	DstPort  *int      `json:"dst_port"`
	FsConnID *string   `json:"fs_conn_id"`
	ConnID   *string   `json:"conn_id"`
	ProbeID  *string   `json:"probe_id"`
	Method   *string   `json:"method"`
	Path     *string   `json:"path"`
}

// VerdictEvent é o evento do feed e do webhook.
type VerdictEvent struct {
	Kind    string   `json:"kind"`
	Ts      string   `json:"ts"`
	Verdict *Verdict `json:"verdict,omitempty"`
	Dropped int      `json:"dropped,omitempty"`
}

// unknownVerdict monta o veredito desta entrega: sem regras, a classe é sempre `unknown` com score 0; `view` diz
// o que já havia das duas visões.
func unknownVerdict(subject Subject, view View, now time.Time) Verdict {
	return Verdict{
		Class: ClassUnknown, Score: 0, Signals: []Signal{}, View: view, RulesVersion: RulesVersion,
		ListsVersion: ListsVersion, Subject: subject, Ts: event.FormatTime(now),
	}
}

func ptr[T any](v T) *T { return &v }

// optString devolve nil para vazio.
func optString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
