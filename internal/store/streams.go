package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// storeStream grava um pedaço de fs.v1.web.stream.bytes / fs.v1.raw.read em raw_streams pelo offset (ADR 0018).
// Devolve keep=true e o evento a guardar em app_events: os eventos que não são de fluxo, sem mudança, e o
// pedaço com truncated, sem os dados, que marca o sentido em raw_truncated.
func (in *Ingestor) storeStream(ctx context.Context, tx *sql.Tx, ev appEvent, tg target) (appEvent, bool, error) {
	if !isStreamSubject(ev.subject) {
		return ev, true, nil
	}
	var sb event.StreamBytes
	if err := json.Unmarshal(ev.env.Payload, &sb); err != nil || (sb.Dir != event.DirectionIn && sb.Dir != event.DirectionOut) || sb.Offset < 0 {
		in.metrics.Add("store_bad_events_total", 1)
		return ev, false, nil
	}
	limit := int64(in.cfg.RawStreamMax)
	if limit <= 0 {
		limit = event.DefaultRawStreamMaxBytes
	}
	data := sb.Data
	if sb.Offset+int64(len(data)) > limit {
		// O produtor já corta; o store garante o teto mesmo assim.
		if sb.Offset >= limit {
			data = nil
		} else {
			data = data[:limit-sb.Offset]
		}
		sb.Truncated = true
	}
	// Modo degradado (spec 004 RF-11): sem bytes crus.
	if len(data) > 0 && !tg.degraded {
		if _, err := tx.ExecContext(ctx, "INSERT OR REPLACE INTO raw_streams (conn_id, dir, offset, data) VALUES (?, ?, ?, ?)",
			tg.id, dirIndex(sb.Dir), sb.Offset, data); err != nil {
			return ev, false, fmt.Errorf("insert raw stream: %w", err)
		}
		in.metrics.Add("store_raw_stream_bytes_total", float64(len(data)))
	}
	if !sb.Truncated {
		return ev, false, nil
	}
	// Guarda só a marca de truncado (sem os dados) em app_events, para o registro poder ser refeito.
	sb.Data = nil
	env := ev.env
	env.Payload, _ = json.Marshal(sb)
	ev.env = env
	ev.data, _ = json.Marshal(env)
	return ev, true, nil
}
