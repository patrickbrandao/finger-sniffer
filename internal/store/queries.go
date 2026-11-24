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
	"slices"
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
	// blobs limita os downloads de /pcap e /raw em andamento (as duas rotas somadas, ADR 0032): acima, 503.
	blobs chan struct{}
	// blobWrite é o prazo de escrita de cada resposta de /pcap e /raw (ADR 0032).
	blobWrite time.Duration
	// probeReads conta as leituras completas do probe (record_json); os testes conferem que o wait lê uma vez.
	probeReads atomic.Int64
	// openSummary, se definido, dá o resumo ao vivo de uma conexão aberta sem montar o registro inteiro; sem ele,
	// a lista usa live (task 176).
	openSummary func(id string) (summaryJSON, bool)
	// livePcap, se definido, monta o pcap parcial de uma conexão aberta a partir da memória do ingest (task 248).
	livePcap func(id string, snaplen uint32) ([]byte, int, bool)
	// hide e unhide avisam o ingest das conexões abertas de um probe apagado (SetHideOpen).
	hide, unhide func(ids []string)
	// deletes deixa um único DELETE de probe por vez no escritor, que o ingest usa pela mesma conexão: sem isso,
	// centenas de DELETE simultâneos disputam a conexão com o ingest num sorteio (task 317). Os demais esperam.
	deletes chan struct{}
	// deleteTx e deleteMax contam as transações de DELETE no escritor e o máximo simultâneo (para os testes).
	deleteTx, deleteNow, deleteMax atomic.Int64
	// budget é o orçamento das respostas JSON em andamento e respMax o teto de uma resposta (ADR 0066).
	budget  *jsonBudget
	respMax int64
}

// WithLivePcap liga o acessor do pcap parcial das conexões abertas, cujos pacotes ficam na memória do ingest
// (task 248).
func (q *Queries) WithLivePcap(f func(id string, snaplen uint32) ([]byte, int, bool)) *Queries {
	q.livePcap = f
	return q
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

// Downloads de BLOB (ADR 0032): no máximo blobMax respostas de /pcap e /raw em andamento, cada uma com
// blobWriteTimeout para ser escrita; o cliente que não lê nesse prazo tem a conexão encerrada.
const (
	blobMax          = 4
	blobWriteTimeout = 60 * time.Second
)

// NewQueries cria o leitor.
func NewQueries(db *sql.DB, live func(string) (connectionJSON, bool), snaplen uint32) *Queries {
	if live == nil {
		live = func(string) (connectionJSON, bool) { return connectionJSON{}, false }
	}
	return &Queries{
		db: db, live: live, now: time.Now, pollEvery: 50 * time.Millisecond, snaplen: snaplen,
		waiters: make(chan struct{}, probeWaitMax),
		blobs:   make(chan struct{}, blobMax), blobWrite: blobWriteTimeout,
		deletes: make(chan struct{}, 1),
		budget:  newJSONBudget(jsonBudgetMax), respMax: jsonResponseMax,
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

// Tetos de concorrência atingidos: as 64 vagas de ?wait e as 4 de download de BLOB.
var (
	errProbeWaitBusy = busyError{"too many waiting requests, retry later"}
	errBlobBusy      = busyError{"too many downloads in progress, retry later"}
)

// acquireBlob ocupa uma vaga de download de BLOB, sem esperar; release devolve a vaga.
func (q *Queries) acquireBlob() (release func(), err error) {
	select {
	case q.blobs <- struct{}{}:
		return func() { <-q.blobs }, nil
	default:
		return nil, errBlobBusy
	}
}

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

// listFilterParams é o conjunto comum de filtros das listas da API (ADR 0077 item 1).
var listFilterParams = []string{"src_ip", "dst_port", "since", "until", "probe"}

// rejectUndeclared devolve 400 quando a consulta traz um filtro do conjunto comum que a rota não declara no
// openapi (ADR 0077 item 1): aceitá-lo sem aplicar devolveria a mesma página em silêncio. Parâmetros fora do
// conjunto comum (ex.: _=<cache-buster>) seguem ignorados.
func rejectUndeclared(has func(string) bool, route string, declared ...string) error {
	for _, name := range listFilterParams {
		if has(name) && !slices.Contains(declared, name) {
			return bad("parameter %s not supported on %s", name, route)
		}
	}
	return nil
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
	// Discarded: ver connectionJSON.Discarded (só no connection.closed do tempo real, ADR 0076).
	Discarded string `json:"discarded,omitempty"`
}

// Filtros dos probes apagados (ADR 0068 item 2): enquanto a linha de deleted_probes existir, as conexões e as
// consultas do probe até o corte somem de todas as leituras; o laço de retenção as apaga em lotes.
const (
	visibleConn = `NOT EXISTS (SELECT 1 FROM deleted_probes d WHERE d.probe_id = connections.probe_id AND connections.conn_id <= d.conn_cut)`
	visibleDNS  = `NOT EXISTS (SELECT 1 FROM deleted_probes d WHERE d.probe_id = dns_queries.probe_id AND dns_queries.id <= d.dns_cut)`
)

// deletedConn diz se a conexão é de um probe apagado ainda à espera do apagamento em lotes (sem linha: false).
func (q *Queries) deletedConn(ctx context.Context, id string) (bool, error) {
	var n int
	err := q.db.QueryRowContext(ctx, "SELECT count(*) FROM connections WHERE conn_id = ? AND NOT "+visibleConn, id).Scan(&n)
	return n > 0, err
}

// cut abre o teto de uma resposta, ligado à reserva da requisição (se houver).
func (q *Queries) cut(ctx context.Context) *respCut {
	return &respCut{res: reservationFrom(ctx), max: q.respMax}
}

// summarySize estima os bytes de um ConnectionSummary indentado: as chaves e a pontuação fixas mais os valores.
func summarySize(s summaryJSON) int {
	n := 360 + len(s.ConnID) + len(s.Proto) + len(s.L4) + len(s.Src.IP) + len(s.Dst.IP) + len(s.Started)
	if s.ProbeID != nil {
		n += len(*s.ProbeID)
	}
	if s.Ended != nil {
		n += len(*s.Ended)
	}
	return n
}

// Connections lista conexões, mais novas primeiro; a lista para antes de limit quando o corpo passaria do teto
// de uma resposta (ADR 0066 item 2).
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
	where = append(where, visibleConn)
	// requests vem da coluna (task 380): o json_extract do record_json decodificava o registro inteiro por linha
	sqlq := `SELECT conn_id, probe_id, proto, l4, family, src_ip, src_port, dst_ip, dst_port, started_ns, ended_ns, degraded,
		requests FROM connections`
	sqlq += " WHERE " + strings.Join(where, " AND ") //nolint:gosec // só trechos fixos; valores vão como parâmetros
	sqlq += " ORDER BY started_ns DESC LIMIT ?"
	rows, err := q.db.QueryContext(ctx, sqlq, append(args, f.Limit)...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []summaryJSON{}
	cut := q.cut(ctx)
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
		if ok, err := cut.take(summarySize(s)); err != nil {
			return nil, err
		} else if !ok {
			break
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
	err := q.db.QueryRowContext(ctx, "SELECT record_json, ended_ns FROM connections WHERE conn_id = ? AND "+visibleConn, id).Scan(&rec, &ended)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if !ended.Valid {
		if r, ok := q.live(id); ok {
			b, err := json.Marshal(r)
			if err != nil {
				return nil, err
			}
			rec = string(b)
		}
	}
	// Registro único: conta inteiro no orçamento, sem corte (ADR 0066 item 2).
	if err := reservationFrom(ctx).add(len(rec)); err != nil {
		return nil, err
	}
	return json.RawMessage(rec), nil
}

// Pcap devolve o pcap da conexão; para conexões abertas, monta o parcial a partir dos pacotes já gravados.
func (q *Queries) Pcap(ctx context.Context, id string) ([]byte, error) {
	if !ValidConnID(id) {
		return nil, bad("invalid conn_id %q", id)
	}
	if del, err := q.deletedConn(ctx, id); err != nil || del {
		return nil, errOr(err, ErrNotFound)
	}
	var data []byte
	err := q.db.QueryRowContext(ctx, "SELECT data FROM pcaps WHERE conn_id = ?", id).Scan(&data)
	if err == nil {
		return data, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	// Conexão aberta: os pacotes estão na memória do ingest ou, se ela passou para a tabela, em packets.
	if q.livePcap != nil {
		if pcap, n, ok := q.livePcap(id, q.snaplen); ok {
			if n == 0 {
				return nil, ErrNotFound
			}
			return pcap, nil
		}
		// A finalização pode ter gravado o pcap e liberado a memória entre as duas leituras.
		if err := q.db.QueryRowContext(ctx, "SELECT data FROM pcaps WHERE conn_id = ?", id).Scan(&data); err == nil {
			return data, nil
		}
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
	if del, err := q.deletedConn(ctx, id); err != nil || del {
		return nil, errOr(err, ErrNotFound)
	}
	// Reserva o tamanho final de uma vez: o append em dobro reservaria até 2× os 16 MiB do fluxo (task 129).
	var total int64
	if err := q.db.QueryRowContext(ctx, "SELECT COALESCE(SUM(length(data)), 0) FROM raw_streams WHERE conn_id = ? AND dir = ?", id, d).Scan(&total); err != nil {
		return nil, err
	}
	rows, err := q.db.QueryContext(ctx, "SELECT data FROM raw_streams WHERE conn_id = ? AND dir = ? ORDER BY offset", id, d)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := make([]byte, 0, total)
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
	cut := q.cut(ctx)
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
		if ok, err := cut.take(len(b)); err != nil {
			return nil, err
		} else if !ok {
			break
		}
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
	// until inclusivo, como em /connections e /packets: o cliente anda para trás repetindo com o ts da mais velha
	// recebida e descarta as linhas repetidas da borda (ADR 0077 item 1); o índice dns_queries_probe atende.
	if f.Until != 0 {
		where, args = append(where, "ts_ns <= ?"), append(args, f.Until)
	}
	where = append(where, visibleDNS)
	sqlq := "SELECT record_json FROM dns_queries WHERE " + strings.Join(where, " AND ")
	sqlq += " ORDER BY ts_ns DESC, id DESC LIMIT ?"
	list, _, err := q.rawList(ctx, q.cut(ctx), sqlq, append(args, f.Limit)...)
	return list, err
}

// rawList lê record_json até o fim das linhas ou o teto da resposta (cut); capped diz se parou pelo teto.
func (q *Queries) rawList(ctx context.Context, cut *respCut, sqlq string, args ...any) (_ []json.RawMessage, capped bool, _ error) {
	rows, err := q.db.QueryContext(ctx, sqlq, args...)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = rows.Close() }()
	out := []json.RawMessage{}
	for rows.Next() {
		var rec string
		if err := rows.Scan(&rec); err != nil {
			return nil, false, err
		}
		ok, err := cut.take(len(rec))
		if err != nil {
			return nil, false, err
		}
		if !ok {
			return out, true, nil
		}
		out = append(out, json.RawMessage(rec))
	}
	return out, false, rows.Err()
}

// probeJSON é o schema Probe.
type probeJSON struct {
	ProbeID   string `json:"probe_id"`
	AllClosed bool   `json:"all_closed"`
	// Truncated: connections ou dns passou de probeMaxItems e foi cortada (ADR 0032), ou o corpo passaria do teto
	// de uma resposta (ADR 0066).
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
		FROM connections WHERE probe_id = ? AND `+visibleConn, id).Scan(&st.conns, &st.closed, &st.updated)
	return st, err
}

// probeFull lê os registros do probe com o teto de probeMaxItems por lista (lê um a mais para saber se capped) e o
// teto de bytes da resposta (ADR 0066), somados à reserva da requisição; conexão aberta vem do estado ao vivo.
func (q *Queries) probeFull(ctx context.Context, id string) (probeJSON, error) {
	q.probeReads.Add(1)
	p := probeJSON{ProbeID: id, Connections: []json.RawMessage{}, DNS: []json.RawMessage{}}
	cut := q.cut(ctx)
	rows, err := q.db.QueryContext(ctx, "SELECT conn_id, record_json, ended_ns FROM connections WHERE probe_id = ? AND "+visibleConn+" ORDER BY started_ns LIMIT ?", id, probeMaxItems+1)
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
		ok, err := cut.take(len(rec))
		if err != nil {
			_ = rows.Close()
			return p, err
		}
		if !ok {
			p.Truncated = true
			break
		}
		p.Connections = append(p.Connections, json.RawMessage(rec))
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return p, err
	}
	dns, capped, err := q.rawList(ctx, cut, "SELECT record_json FROM dns_queries WHERE probe_id = ? AND "+visibleDNS+" ORDER BY ts_ns LIMIT ?", id, probeMaxItems+1)
	if err != nil {
		return p, err
	}
	if capped {
		p.Truncated = true
	}
	if len(dns) > probeMaxItems {
		dns, p.Truncated = dns[:probeMaxItems], true
	}
	p.DNS = dns
	return p, nil
}

// SetHideOpen liga o DELETE de probe ao ingest: hide recebe os conn_id abertos do probe apagado, que o ingest
// passa a descartar até a conexão fechar (ADR 0034 item 8), e unhide desfaz se a transação falhar.
func (q *Queries) SetHideOpen(hide, unhide func(ids []string)) { q.hide, q.unhide = hide, unhide }

// DeleteProbe apaga o probe numa transação curta (ADR 0068, ajusta a ADR 0034 item 8): grava o corte em
// deleted_probes (maior conn_id e maior id de dns_queries do probe) e passa ao ingest as conexões abertas (hide),
// que ele descarta até fecharem. Um probe só existe enquanto houver conexão ou consulta DNS visível com o seu ID:
// sem nenhuma, 404 (ADR 0077 item 2, sem a tabela probes). Daí em diante todas as leituras excluem as linhas até o
// corte, e o laço de retenção as apaga em lotes curtos (Retention.purgeDeleted). Tráfego novo com o mesmo ID fica
// acima do corte e aparece como probe novo. O escritor tem uma só conexão com o banco: nenhum lote do ingest roda
// entre a leitura dos conn_id abertos e o commit, e o conjunto do ingest é preenchido antes do commit.
func (q *Queries) DeleteProbe(ctx context.Context, w *sql.DB, id string) error {
	if !probe.Valid(id) {
		return bad("invalid probe id %q", id)
	}
	// Pelo leitor primeiro: um probe sem nada a apagar (o laço anônimo de DELETE) não toca o escritor (task 317).
	var any int
	err := q.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM connections WHERE probe_id = ? AND `+visibleConn+`)
		OR EXISTS (SELECT 1 FROM dns_queries WHERE probe_id = ? AND `+visibleDNS+`)`, id, id).Scan(&any)
	if err != nil {
		return err
	}
	if any == 0 {
		return ErrNotFound
	}
	select {
	case q.deletes <- struct{}{}:
		defer func() { <-q.deletes }()
	case <-ctx.Done():
		return ctx.Err()
	}
	q.deleteTx.Add(1)
	if n := q.deleteNow.Add(1); n > q.deleteMax.Load() {
		q.deleteMax.Store(n)
	}
	defer q.deleteNow.Add(-1)
	tx, err := w.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var open []string
	rows, err := tx.QueryContext(ctx, "SELECT conn_id FROM connections WHERE probe_id = ? AND ended_ns IS NULL AND "+visibleConn, id)
	if err != nil {
		return err
	}
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			_ = rows.Close()
			return err
		}
		open = append(open, c)
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	// visible conta o que o DELETE esconde agora; os cortes cobrem também o que um DELETE anterior já escondeu.
	var visible int64
	var connCut string
	var dnsCut int64
	if err := tx.QueryRowContext(ctx, `SELECT
		(SELECT count(*) FROM connections WHERE probe_id = ? AND `+visibleConn+`) +
		(SELECT count(*) FROM dns_queries WHERE probe_id = ? AND `+visibleDNS+`),
		coalesce((SELECT max(conn_id) FROM connections WHERE probe_id = ?), ''),
		coalesce((SELECT max(id) FROM dns_queries WHERE probe_id = ?), 0)`, id, id, id, id).Scan(&visible, &connCut, &dnsCut); err != nil {
		return err
	}
	if visible == 0 {
		return ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO deleted_probes (probe_id, conn_cut, dns_cut, deleted_ns) VALUES (?, ?, ?, ?)
		ON CONFLICT (probe_id) DO UPDATE SET conn_cut = max(conn_cut, excluded.conn_cut), dns_cut = max(dns_cut, excluded.dns_cut),
		deleted_ns = excluded.deleted_ns`, id, connCut, dnsCut, q.now().UnixNano()); err != nil {
		return err
	}
	if len(open) > 0 && q.hide != nil {
		q.hide(open)
	}
	if err := tx.Commit(); err != nil {
		if len(open) > 0 && q.unhide != nil {
			q.unhide(open)
		}
		return err
	}
	return nil
}

// errOr devolve err se houver, senão alt.
func errOr(err, alt error) error {
	if err != nil {
		return err
	}
	return alt
}
