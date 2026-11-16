package bot

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// Estágios de fs.v1.store.connection (asyncapi 0.6.0, StoreConnectionPayload).
const (
	StageOpened  = "opened"
	StageUpdated = "updated"
	StageClosed  = "closed"
)

// droppedRecordFields são as partes do Connection que o índice não guarda: listas que crescem com a conexão e
// não entram nos sinais da spec 018 (os resumos das requisições vêm do fork).
var droppedRecordFields = []string{"http", "websocket", "raw"}

// storeConnectionPayload é o payload de fs.v1.store.connection.
type storeConnectionPayload struct {
	Stage               string          `json:"stage"`
	ConnectionTruncated bool            `json:"connection_truncated,omitempty"`
	Connection          json.RawMessage `json:"connection"`
}

// connectionSummary são os campos do Connection usados para indexar (ConnectionSummary do openapi do store).
type connectionSummary struct {
	ConnID  string   `json:"conn_id"`
	ProbeID *string  `json:"probe_id"`
	Proto   string   `json:"proto"`
	L4      string   `json:"l4"`
	Src     endpoint `json:"src"`
	Dst     endpoint `json:"dst"`
	Started string   `json:"started"`
}

type endpoint struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

// errBadStoreConnection marca uma mensagem fora do contrato.
var errBadStoreConnection = errors.New("bot: invalid fs.v1.store.connection")

// ParseStoreConnection lê uma mensagem de fs.v1.store.connection.
func ParseStoreConnection(data []byte) (*StoreConn, error) {
	env, err := event.Decode(data)
	if err != nil {
		return nil, err
	}
	var p storeConnectionPayload
	if err := json.Unmarshal(env.Payload, &p); err != nil {
		return nil, fmt.Errorf("%w: %w", errBadStoreConnection, err)
	}
	switch p.Stage {
	case StageOpened, StageUpdated, StageClosed:
	default:
		return nil, fmt.Errorf("%w: stage %q", errBadStoreConnection, p.Stage)
	}
	var s connectionSummary
	if err := json.Unmarshal(p.Connection, &s); err != nil {
		return nil, fmt.Errorf("%w: %w", errBadStoreConnection, err)
	}
	if !ulidPattern(s.ConnID) {
		return nil, fmt.Errorf("%w: conn_id %q", errBadStoreConnection, s.ConnID)
	}
	c := &StoreConn{ConnID: s.ConnID, Stage: p.Stage, L4: s.L4, Proto: s.Proto, SrcPort: s.Src.Port, DstPort: s.Dst.Port}
	if s.ProbeID != nil {
		c.ProbeID = *s.ProbeID
	}
	if c.SrcIP, err = netip.ParseAddr(s.Src.IP); err != nil {
		return nil, fmt.Errorf("%w: src.ip", errBadStoreConnection)
	}
	c.DstIP, _ = netip.ParseAddr(s.Dst.IP)
	if s.Src.Port < 0 || s.Src.Port > 65535 || s.Dst.Port < 0 || s.Dst.Port > 65535 {
		return nil, fmt.Errorf("%w: port", errBadStoreConnection)
	}
	c.Started, _ = time.Parse(time.RFC3339Nano, s.Started)
	c.Record = slimRecord(p.Connection)
	return c, nil
}

// slimRecord tira do Connection as listas que o índice não guarda.
func slimRecord(raw json.RawMessage) json.RawMessage {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil
	}
	for _, k := range droppedRecordFields {
		delete(m, k)
	}
	out, err := json.Marshal(m)
	if err != nil {
		return nil
	}
	return out
}

// StoreFeed recebe fs.v1.store.connection e alimenta o índice (spec 018 RF-02).
type StoreFeed struct {
	ix       *Index
	now      func() time.Time
	messages atomic.Int64
	invalid  atomic.Int64
	last     atomic.Int64 // unix nano da última mensagem válida
}

// NewStoreFeed cria o receptor.
func NewStoreFeed(ix *Index, now func() time.Time) *StoreFeed {
	if now == nil {
		now = time.Now
	}
	return &StoreFeed{ix: ix, now: now}
}

// Handle trata uma mensagem; inválida é contada e ignorada.
func (f *StoreFeed) Handle(data []byte) error {
	c, err := ParseStoreConnection(data)
	if err != nil {
		f.invalid.Add(1)
		return err
	}
	now := f.now()
	f.messages.Add(1)
	f.last.Store(now.UnixNano())
	f.ix.PutStore(c, now)
	return nil
}

// Messages conta as mensagens válidas (bot_store_feed_messages_total).
func (f *StoreFeed) Messages() int64 { return f.messages.Load() }

// Invalid conta as mensagens fora do contrato.
func (f *StoreFeed) Invalid() int64 { return f.invalid.Load() }

// LastMessage é o instante da última mensagem válida (zero se nenhuma).
func (f *StoreFeed) LastMessage() time.Time {
	if n := f.last.Load(); n != 0 {
		return time.Unix(0, n)
	}
	return time.Time{}
}

// ulidPattern confere o formato ULID do contrato (^[0-9A-HJKMNP-TV-Z]{26}$).
func ulidPattern(s string) bool {
	if len(s) != 26 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'A' && c <= 'Z' && c != 'I' && c != 'L' && c != 'O' && c != 'U':
		default:
			return false
		}
	}
	return true
}
