package store

import (
	"context"
	"database/sql"
)

// upsertProbe registra o probe visto em ts (first_seen/last_seen, spec 004 "Comportamento").
func upsertProbe(ctx context.Context, tx *sql.Tx, id string, ts int64) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO probes (probe_id, first_seen, last_seen) VALUES (?, ?, ?)
		ON CONFLICT (probe_id) DO UPDATE SET first_seen = min(first_seen, excluded.first_seen),
		last_seen = max(last_seen, excluded.last_seen)`, id, ts, ts)
	return err
}
