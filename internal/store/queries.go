package store

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
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
	// waiters limita os long-polls simultâneos de /probes/{id}?wait (ADR 0032): acima, 503 na hora.
	waiters chan struct{}
	// probeReads conta as leituras completas do probe (record_json); os testes conferem que o wait lê uma vez.
	probeReads atomic.Int64
	// openSummary, se definido, dá o resumo ao vivo de uma conexão aberta sem montar o registro inteiro; sem ele,
	// a lista usa live (task 176).
	openSummary func(id string) (summaryJSON, bool)
}

// WithOpenSummary liga o acessor de resumo ao vivo usado por /connections.
func (q *Queries) WithOpenSummary(f func(string) (summaryJSON, bool)) *Queries {
	q.openSummary = f
	return q
}

// Tetos de /probes/{id} (ADR 0032): esperas simultâneas e itens por lista na resposta.
const (
	probeWaitMax  = 64
	probeMaxItems = 1000
)

// NewQueries cria o leitor.
func NewQueries(db *sql.DB, live func(string) (connectionJSON, bool), snaplen uint32) *Queries {
	if live == nil {
		live = func(string) (connectionJSON, bool) { return connectionJSON{}, false }
	}
	return &Queries{
		db: db, live: live, now: time.Now, pollEvery: 50 * time.Millisecond, snaplen: snaplen,
		waiters: make(chan struct{}, probeWaitMax),
	}
}

// Erros de consulta mapeados para HTTP.
var (
	ErrNotFound   = errors.New("not found or expired")
	errBadRequest = errors.New("bad request")
	// errBusy é um teto de concorrência da API atingido (503 com Retry-After, ADR 0032).
	errBusy = errors.New("busy")
)

type busyError struct{ msg string }

func (b busyError) Error() string { return b.msg }
func (b busyError) Unwrap() error { return errBusy }

// errProbeWaitBusy: as 64 vagas de ?wait estão ocupadas.
var errProbeWaitBusy = busyError{"too many waiting requests, retry later"}

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

// Limites de time.Time representáveis em nanossegundos Unix num int64 (cerca de 1677 a 2262).
var (
	minUnixNanoTime = time.Unix(0, math.MinInt64)
	maxUnixNanoTime = time.Unix(0, math.MaxInt64)
)

// saturatedUnixNano devolve t.UnixNano() saturado nos limites do int64. Fora da faixa o UnixNano é indefinido
// (estoura): uma data muito antiga vira o mínimo e uma muito futura o máximo, então until=9999-... equivale a
// "sem limite superior" e since=9999-... não casa com nada (task 159).
func saturatedUnixNano(t time.Time) int64 {
	switch {
	case t.Before(minUnixNanoTime):
		return math.MinInt64
	case t.After(maxUnixNanoTime):
		return math.MaxInt64
	}
	return t.UnixNano()
}

// ParseListFilter valida os parâmetros de consulta.
func ParseListFilter(get func(string) string) (ListFilter, error) {
	f := ListFilter{DstPort: -1, Limit: 100}
	if v := get("src_ip"); v != "" {
		a, err := netip.ParseAddr(v)
		if err != nil {
			return f, bad("invalid src_ip %q", v)
		}
		// IPv4 mapeado em IPv6 vale o IPv4: o store grava os endereços IPv4 assim (task 177)
		f.SrcIP = a.Unmap().String()
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
			*p.dst = saturatedUnixNano(t)
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
		if !ended.Valid {
			// conexão aberta: o record_json do banco é o da criação (spec 004 "Dados"); requests, proto e
			// probe_id vêm do estado ao vivo, como em GET /connections/{id} e no feed (task 176)
			if l, ok := q.liveSummary(s.ConnID); ok {
				s = l
			}
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// liveSummary é o resumo ao vivo de uma conexão aberta (false se ela já saiu da tabela do ingest).
func (q *Queries) liveSummary(id string) (summaryJSON, bool) {
	if q.openSummary != nil {
		return q.openSummary(id)
	}
	r, ok := q.live(id)
	if !ok {
		return summaryJSON{}, false
	}
	return summaryFrom(r), true
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
		// IP do cliente: a origem quando o pacote entra, o destino quando sai (como o filtro do tempo real)
		where, args = append(where, "((dir = 0 AND src_ip = ?) OR (dir = 1 AND dst_ip = ?))"), append(args, f.SrcIP, f.SrcIP)
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
		m := decodeObject([]byte(rec))
		if m == nil {
			return nil, fmt.Errorf("bad record_json")
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
	ProbeID   string `json:"probe_id"`
	AllClosed bool   `json:"all_closed"`
	// Truncated: connections ou dns passou de probeMaxItems e foi cortada (ADR 0032).
	Truncated bool `json:"truncated,omitempty"`
	// WaitMet só aparece com wait (ADR 0029): true quando saiu pelo critério, false pelo fim do prazo.
	WaitMet     *bool             `json:"wait_met,omitempty"`
	Connections []json.RawMessage `json:"connections"`
	DNS         []json.RawMessage `json:"dns"`
}

// ProbeWait é o critério do long-poll de /probes/{id} (spec 004, ADR 0029). Wait 0 responde na hora.
type ProbeWait struct {
	Wait time.Duration
	// Given indica que o parâmetro wait veio na consulta (wait=0s também traz wait_met).
	Given bool
	// Settle é o silêncio exigido: nenhuma conexão do probe criada, correlacionada ou fechada nesse intervalo.
	Settle time.Duration
	// MinConns é o mínimo de conexões (0 vale 1).
	MinConns int
}

// Probe devolve as conexões e consultas DNS do probe. Com Wait > 0, espera até haver ao menos MinConns conexões,
// nenhuma aberta e nenhuma mudança nas conexões do probe nos últimos Settle, ou até o prazo acabar (máx. 60 s);
// só consultas DNS (ou nada) não encerram a espera. No fim do prazo devolve o estado atual, ou ErrNotFound se o
// probe não tem nada. O laço lê só o resumo das conexões (probeStateOf); o registro completo, com o teto de
// probeMaxItems por lista, é lido uma vez, na saída (ADR 0032). Com as probeWaitMax vagas de espera ocupadas,
// um Wait > 0 recebe errProbeWaitBusy na hora.
func (q *Queries) Probe(ctx context.Context, id string, pw ProbeWait) (probeJSON, error) {
	if !probe.Valid(id) {
		return probeJSON{}, bad("invalid probe id %q", id)
	}
	wait := min(pw.Wait, 60*time.Second)
	if wait > 0 {
		// Só quem vai esperar ocupa vaga; sem vaga, recusa na hora em vez de enfileirar.
		select {
		case q.waiters <- struct{}{}:
			defer func() { <-q.waiters }()
		default:
			return probeJSON{}, errProbeWaitBusy
		}
	}
	minConns := max(pw.MinConns, 1)
	deadline := q.now().Add(wait)
	var last probeState
	var lastChange time.Time
	for {
		st, err := q.probeStateOf(ctx, id)
		if err != nil {
			return probeJSON{}, err
		}
		now := q.now()
		// Mudança no conjunto (conexão nova, correlacionada ao probe ou fechada) vista pelo próprio poll; na
		// primeira leitura vale o instante em que o store registrou a última mudança no banco.
		switch {
		case lastChange.IsZero():
			lastChange = time.Unix(0, min(st.updated, now.UnixNano()))
		case st.conns != last.conns || st.closed != last.closed:
			lastChange = now
		}
		last = st
		met := st.conns >= int64(minConns) && st.closed == st.conns && now.Sub(lastChange) >= pw.Settle
		if met || !now.Before(deadline) {
			p, err := q.probeFull(ctx, id)
			if err != nil {
				return p, err
			}
			if len(p.Connections) == 0 && len(p.DNS) == 0 {
				return p, ErrNotFound
			}
			// all_closed olha o conjunto inteiro (mesmo com truncated), como o critério.
			p.AllClosed = st.closed == st.conns
			if pw.Given || wait > 0 {
				p.WaitMet = &met
			}
			return p, nil
		}
		select {
		case <-ctx.Done():
			return probeJSON{}, ctx.Err()
		case <-time.After(q.pollEvery):
		}
	}
}

// probeState resume as conexões do probe (o conjunto inteiro, sem teto) para o critério do wait e para detectar
// mudanças entre leituras: conexão nova ou correlacionada ao probe muda conns, fechada muda closed (apagada pela
// retenção também muda conns).
type probeState struct {
	conns, closed int64
	updated       int64 // maior updated_ns das conexões (instante da última mudança, na primeira leitura)
}

// probeStateOf lê o resumo das conexões do probe numa consulta de agregados, sem record_json.
func (q *Queries) probeStateOf(ctx context.Context, id string) (probeState, error) {
	var st probeState
	err := q.db.QueryRowContext(ctx, `SELECT COUNT(*), COUNT(ended_ns), COALESCE(MAX(updated_ns), 0)
		FROM connections WHERE probe_id = ?`, id).Scan(&st.conns, &st.closed, &st.updated)
	return st, err
}

// probeFull lê os registros do probe com o teto de probeMaxItems por lista (lê um a mais para saber se cortou);
// conexão aberta vem do estado ao vivo.
func (q *Queries) probeFull(ctx context.Context, id string) (probeJSON, error) {
	q.probeReads.Add(1)
	p := probeJSON{ProbeID: id, Connections: []json.RawMessage{}, DNS: []json.RawMessage{}}
	rows, err := q.db.QueryContext(ctx, "SELECT conn_id, record_json, ended_ns FROM connections WHERE probe_id = ? ORDER BY started_ns LIMIT ?", id, probeMaxItems+1)
	if err != nil {
		return p, err
	}
	for rows.Next() {
		var cid, rec string
		var ended sql.NullInt64
		if err := rows.Scan(&cid, &rec, &ended); err != nil {
			_ = rows.Close()
			return p, err
		}
		if len(p.Connections) == probeMaxItems {
			p.Truncated = true
			break
		}
		if !ended.Valid {
			if r, ok := q.live(cid); ok {
				b, _ := json.Marshal(r)
				rec = string(b)
			}
		}
		p.Connections = append(p.Connections, json.RawMessage(rec))
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return p, err
	}
	dns, err := q.rawList(ctx, "SELECT record_json FROM dns_queries WHERE probe_id = ? ORDER BY ts_ns LIMIT ?", id, probeMaxItems+1)
	if err != nil {
		return p, err
	}
	if len(dns) > probeMaxItems {
		dns, p.Truncated = dns[:probeMaxItems], true
	}
	p.DNS = dns
	return p, nil
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
