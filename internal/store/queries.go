package store

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/probe"
)

// Queries responde às consultas da API (spec 004) a partir do SQLite e do estado ao vivo do ingest.
type Queries struct {
	db   *sql.DB
	live func(id string) (connectionJSON, bool)
	now  func() time.Time
	// pollEvery é o intervalo do long-poll de /probes/{id}?wait.
	pollEvery time.Duration
	snaplen   uint32
}

// NewQueries cria o leitor.
func NewQueries(db *sql.DB, live func(string) (connectionJSON, bool), snaplen uint32) *Queries {
	if live == nil {
		live = func(string) (connectionJSON, bool) { return connectionJSON{}, false }
	}
	return &Queries{db: db, live: live, now: time.Now, pollEvery: 200 * time.Millisecond, snaplen: snaplen}
}

// Erros de consulta mapeados para HTTP.
var (
	ErrNotFound   = errors.New("not found or expired")
	errBadRequest = errors.New("bad request")
)

type badRequest struct{ msg string }

func (b badRequest) Error() string { return b.msg }
func (b badRequest) Unwrap() error { return errBadRequest }

func bad(format string, a ...any) error { return badRequest{fmt.Sprintf(format, a...)} }

var connIDRe = regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{26}$`)

// ValidConnID confere o formato ULID.
func ValidConnID(id string) bool { return connIDRe.MatchString(id) }

// ListFilter são os filtros de /connections (e parte deles de /packets e /dns).
type ListFilter struct {
	SrcIP   string
	DstPort int // -1 = sem filtro
	Since   int64
	Until   int64
	Probe   string
	Limit   int
}

// ParseListFilter valida os parâmetros de consulta.
func ParseListFilter(get func(string) string) (ListFilter, error) {
	f := ListFilter{DstPort: -1, Limit: 100}
	if v := get("src_ip"); v != "" {
		a, err := netip.ParseAddr(v)
		if err != nil {
			return f, bad("invalid src_ip %q", v)
		}
		f.SrcIP = a.String()
	}
	if v := get("dst_port"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > 65535 {
			return f, bad("invalid dst_port %q", v)
		}
		f.DstPort = n
	}
	for _, p := range []struct {
		name string
		dst  *int64
	}{{"since", &f.Since}, {"until", &f.Until}} {
		if v := get(p.name); v != "" {
			t, err := time.Parse(time.RFC3339Nano, v)
			if err != nil {
				return f, bad("invalid %s %q (RFC 3339)", p.name, v)
			}
			*p.dst = t.UnixNano()
		}
	}
	if v := get("probe"); v != "" {
		if !probe.Valid(v) {
			return f, bad("invalid probe %q", v)
		}
		f.Probe = v
	}
	if v := get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 1000 {
			return f, bad("invalid limit %q (1..1000)", v)
		}
		f.Limit = n
	}
	return f, nil
}

// summaryJSON é o schema ConnectionSummary.
type summaryJSON struct {
	ConnID   string       `json:"conn_id"`
	ProbeID  *string      `json:"probe_id"`
	Proto    string       `json:"proto"`
	L4       string       `json:"l4"`
	Family   int          `json:"family"`
	Src      endpointJSON `json:"src"`
	Dst      endpointJSON `json:"dst"`
	Started  string       `json:"started"`
	Ended    *string      `json:"ended"`
	Requests int          `json:"requests"`
	Degraded bool         `json:"degraded"`
}

// Connections lista conexões, mais novas primeiro.
func (q *Queries) Connections(ctx context.Context, f ListFilter) ([]summaryJSON, error) {
	var where []string
	var args []any
	if f.SrcIP != "" {
		where, args = append(where, "src_ip = ?"), append(args, f.SrcIP)
	}
	if f.DstPort >= 0 {
		where, args = append(where, "dst_port = ?"), append(args, f.DstPort)
	}
	if f.Since != 0 {
		where, args = append(where, "started_ns >= ?"), append(args, f.Since)
	}
	if f.Until != 0 {
		where, args = append(where, "started_ns <= ?"), append(args, f.Until)
	}
	if f.Probe != "" {
		where, args = append(where, "probe_id = ?"), append(args, f.Probe)
	}
	sqlq := `SELECT conn_id, probe_id, proto, l4, family, src_ip, src_port, dst_ip, dst_port, started_ns, ended_ns, degraded,
		coalesce(json_extract(record_json, '$.requests'), 0) FROM connections`
	if len(where) > 0 {
		sqlq += " WHERE " + strings.Join(where, " AND ") //nolint:gosec // só trechos fixos; valores vão como parâmetros
	}
	sqlq += " ORDER BY started_ns DESC LIMIT ?"
	rows, err := q.db.QueryContext(ctx, sqlq, append(args, f.Limit)...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []summaryJSON{}
	for rows.Next() {
		var s summaryJSON
		var probeID sql.NullString
		var started int64
		var ended sql.NullInt64
		var degraded int
		if err := rows.Scan(&s.ConnID, &probeID, &s.Proto, &s.L4, &s.Family, &s.Src.IP, &s.Src.Port, &s.Dst.IP, &s.Dst.Port,
			&started, &ended, &degraded, &s.Requests); err != nil {
			return nil, err
		}
		if probeID.Valid {
			s.ProbeID = &probeID.String
		}
		s.Started = event.FormatTime(time.Unix(0, started))
		if ended.Valid {
			s.Ended = tsPtr(ended.Int64)
		}
		s.Degraded = degraded == 1
		out = append(out, s)
	}
	return out, rows.Err()
}

// Connection devolve o registro completo; conexões abertas vêm do estado ao vivo do ingest.
func (q *Queries) Connection(ctx context.Context, id string) (json.RawMessage, error) {
	if !ValidConnID(id) {
		return nil, bad("invalid conn_id %q", id)
	}
	var rec string
	var ended sql.NullInt64
	err := q.db.QueryRowContext(ctx, "SELECT record_json, ended_ns FROM connections WHERE conn_id = ?", id).Scan(&rec, &ended)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if !ended.Valid {
		if r, ok := q.live(id); ok {
			return json.Marshal(r)
		}
	}
	return json.RawMessage(rec), nil
}

// Pcap devolve o pcap da conexão; para conexões abertas, monta o parcial a partir dos pacotes já gravados.
func (q *Queries) Pcap(ctx context.Context, id string) ([]byte, error) {
	if !ValidConnID(id) {
		return nil, bad("invalid conn_id %q", id)
	}
	var data []byte
	err := q.db.QueryRowContext(ctx, "SELECT data FROM pcaps WHERE conn_id = ?", id).Scan(&data)
	if err == nil {
		return data, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	rows, err := q.db.QueryContext(ctx, "SELECT ts_ns, wire_len, frame FROM packets WHERE conn_id = ? ORDER BY id", id)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	pcap := pcapHeader(q.snaplen)
	n := 0
	for rows.Next() {
		var ts int64
		var wl int
		var f []byte
		if err := rows.Scan(&ts, &wl, &f); err != nil {
			return nil, err
		}
		pcap = appendPcapRecord(pcap, ts, wl, f)
		n++
	}
	if n == 0 {
		return nil, ErrNotFound
	}
	return pcap, rows.Err()
}

// Raw devolve os bytes de aplicação de um sentido (preenchidos pelos serviços de aplicação na F3).
func (q *Queries) Raw(ctx context.Context, id, dir string) ([]byte, error) {
	if !ValidConnID(id) {
		return nil, bad("invalid conn_id %q", id)
	}
	d := 0
	switch dir {
	case "in":
	case "out":
		d = 1
	default:
		return nil, bad("dir must be in or out")
	}
	rows, err := q.db.QueryContext(ctx, "SELECT data FROM raw_streams WHERE conn_id = ? AND dir = ? ORDER BY offset", id, d)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []byte
	n := 0
	for rows.Next() {
		var b []byte
		if err := rows.Scan(&b); err != nil {
			return nil, err
		}
		out = append(out, b...)
		n++
	}
	if n == 0 {
		return nil, ErrNotFound
	}
	return out, rows.Err()
}

// Packets lista pacotes avulsos, mais novos primeiro.
func (q *Queries) Packets(ctx context.Context, f ListFilter) ([]json.RawMessage, error) {
	var where []string
	var args []any
	if f.SrcIP != "" {
		where, args = append(where, "src_ip = ?"), append(args, f.SrcIP)
	}
	if f.Since != 0 {
		where, args = append(where, "ts_ns >= ?"), append(args, f.Since)
	}
	if f.Until != 0 {
		where, args = append(where, "ts_ns <= ?"), append(args, f.Until)
	}
	sqlq := "SELECT record_json, frame FROM stray_packets"
	if len(where) > 0 {
		sqlq += " WHERE " + strings.Join(where, " AND ") //nolint:gosec // só trechos fixos; valores vão como parâmetros
	}
	sqlq += " ORDER BY ts_ns DESC, id DESC LIMIT ?"
	rows, err := q.db.QueryContext(ctx, sqlq, append(args, f.Limit)...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []json.RawMessage{}
	for rows.Next() {
		var rec string
		var frame []byte
		if err := rows.Scan(&rec, &frame); err != nil {
			return nil, err
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(rec), &m); err != nil {
			return nil, err
		}
		m["frame_b64"] = base64.StdEncoding.EncodeToString(frame)
		b, _ := json.Marshal(m)
		out = append(out, b)
	}
	return out, rows.Err()
}

// DNS lista consultas DNS, mais novas primeiro.
func (q *Queries) DNS(ctx context.Context, f ListFilter) ([]json.RawMessage, error) {
	var where []string
	var args []any
	if f.Probe != "" {
		where, args = append(where, "probe_id = ?"), append(args, f.Probe)
	}
	if f.Since != 0 {
		where, args = append(where, "ts_ns >= ?"), append(args, f.Since)
	}
	sqlq := "SELECT record_json FROM dns_queries"
	if len(where) > 0 {
		sqlq += " WHERE " + strings.Join(where, " AND ") //nolint:gosec // só trechos fixos; valores vão como parâmetros
	}
	sqlq += " ORDER BY ts_ns DESC, id DESC LIMIT ?"
	return q.rawList(ctx, sqlq, append(args, f.Limit)...)
}

func (q *Queries) rawList(ctx context.Context, sqlq string, args ...any) ([]json.RawMessage, error) {
	rows, err := q.db.QueryContext(ctx, sqlq, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []json.RawMessage{}
	for rows.Next() {
		var rec string
		if err := rows.Scan(&rec); err != nil {
			return nil, err
		}
		out = append(out, json.RawMessage(rec))
	}
	return out, rows.Err()
}

// probeJSON é o schema Probe.
type probeJSON struct {
	ProbeID     string            `json:"probe_id"`
	AllClosed   bool              `json:"all_closed"`
	Connections []json.RawMessage `json:"connections"`
	DNS         []json.RawMessage `json:"dns"`
}

// Probe devolve as conexões e consultas DNS do probe. Com wait > 0, espera até haver ao menos uma conexão e
// nenhuma aberta, ou até o prazo acabar (máx. 60 s); só consultas DNS (ou nada) não encerram a espera. No fim do
// prazo devolve o estado atual, ou ErrNotFound se o probe não tem nada.
func (q *Queries) Probe(ctx context.Context, id string, wait time.Duration) (probeJSON, error) {
	if !probe.Valid(id) {
		return probeJSON{}, bad("invalid probe id %q", id)
	}
	if wait > 60*time.Second {
		wait = 60 * time.Second
	}
	deadline := q.now().Add(wait)
	for {
		p, open, err := q.probeOnce(ctx, id)
		if err != nil {
			return p, err
		}
		if (len(p.Connections) > 0 && !open) || !q.now().Before(deadline) {
			if len(p.Connections) == 0 && len(p.DNS) == 0 {
				return p, ErrNotFound
			}
			return p, nil
		}
		select {
		case <-ctx.Done():
			return p, ctx.Err()
		case <-time.After(q.pollEvery):
		}
	}
}

func (q *Queries) probeOnce(ctx context.Context, id string) (probeJSON, bool, error) {
	p := probeJSON{ProbeID: id, Connections: []json.RawMessage{}, DNS: []json.RawMessage{}}
	rows, err := q.db.QueryContext(ctx, "SELECT conn_id, record_json, ended_ns FROM connections WHERE probe_id = ? ORDER BY started_ns", id)
	if err != nil {
		return p, false, err
	}
	open := false
	for rows.Next() {
		var cid, rec string
		var ended sql.NullInt64
		if err := rows.Scan(&cid, &rec, &ended); err != nil {
			_ = rows.Close()
			return p, false, err
		}
		if !ended.Valid {
			open = true
			if r, ok := q.live(cid); ok {
				b, _ := json.Marshal(r)
				rec = string(b)
			}
		}
		p.Connections = append(p.Connections, json.RawMessage(rec))
	}
	_ = rows.Close()
	dns, err := q.rawList(ctx, "SELECT record_json FROM dns_queries WHERE probe_id = ? ORDER BY ts_ns", id)
	if err != nil {
		return p, false, err
	}
	p.DNS = dns
	p.AllClosed = !open
	return p, open, nil
}

// DeleteProbe apaga o probe, suas conexões (com pacotes, pcaps e bytes, em cascata) e consultas DNS.
func (q *Queries) DeleteProbe(ctx context.Context, w *sql.DB, id string) error {
	if !probe.Valid(id) {
		return bad("invalid probe id %q", id)
	}
	var total int64
	for _, s := range []string{
		"DELETE FROM connections WHERE probe_id = ? AND ended_ns IS NOT NULL",
		"DELETE FROM dns_queries WHERE probe_id = ?",
		"DELETE FROM probes WHERE probe_id = ?",
	} {
		res, err := w.ExecContext(ctx, s, id)
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		total += n
	}
	if total == 0 {
		return ErrNotFound
	}
	return nil
}
