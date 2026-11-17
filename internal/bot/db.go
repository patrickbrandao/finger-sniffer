package bot

import (
	"context"
	"database/sql"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/pressly/goose/v3"
	_ "modernc.org/sqlite" // driver "sqlite" em Go puro (ADR 0009)

	botmigrations "github.com/patrickbrandao/finger-sniffer/database/sqlite/bot"
)

// keyUsageRetention é quanto o uso diário das chaves fica no banco (ADR 0052 item 1).
const keyUsageRetention = 90 * 24 * time.Hour

// OpenDB abre (ou cria) o banco do bot em disco e aplica as migrations (ADR 0047 item 2). WAL com
// synchronous=NORMAL: a queda do host perde no máximo as últimas transações, nunca corrompe o banco; a CLI abre o
// mesmo arquivo com o serviço rodando (spec 018 RF-10).
func OpenDB(ctx context.Context, path string) (*sql.DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil { //nolint:gosec // FS_BOT_DB, da configuração
		return nil, err
	}
	dsn := "file:" + path + "?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4)
	// auto_vacuum só vale antes da primeira tabela; num banco já criado o PRAGMA não muda nada.
	for _, p := range []string{"PRAGMA auto_vacuum=INCREMENTAL", "PRAGMA journal_mode=WAL"} {
		if _, err := db.ExecContext(ctx, p); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("bot: %s: %w", p, err)
		}
	}
	prov, err := goose.NewProvider(goose.DialectSQLite3, db, botmigrations.FS)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("bot: goose: %w", err)
	}
	if _, err := prov.Up(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("bot: migrations: %w", err)
	}
	return db, nil
}

// dbFileSize soma o arquivo do banco e o WAL.
func dbFileSize(path string) (size int64) {
	for _, s := range []string{"", "-wal"} {
		if st, err := os.Stat(path + s); err == nil {
			size += st.Size()
		}
	}
	return size
}

// ipKey é o IP em 16 bytes (IPv4 mapeado em IPv6), a forma guardada no banco.
func ipKey(a netip.Addr) []byte {
	// As16 de um IPv4 já devolve a forma ::ffff:a.b.c.d.
	b := a.Unmap().As16()
	return b[:]
}

// prefixRange devolve o primeiro e o último endereço do prefixo em 16 bytes, para o BETWEEN no banco.
func prefixRange(p netip.Prefix) (lo, hi []byte) {
	p = p.Masked()
	bits := p.Bits()
	if p.Addr().Is4() {
		bits += 96
	}
	first := ipKey(p.Addr())
	last := make([]byte, 16)
	copy(last, first)
	for i := bits; i < 128; i++ {
		last[i/8] |= 1 << (7 - uint(i%8))
	}
	return first, last
}

// ParseIPOrPrefix lê "ip" ou "ip/len" (IPv4 mapeado vira IPv4).
func ParseIPOrPrefix(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		if p.Addr().Is4In6() && p.Bits() >= 96 {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("bot: invalid ip or prefix: %q", s)
	}
	a = a.Unmap().WithZone("")
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// Forget apaga os agregados do IP ou prefixo (ADR 0052 item 5) e devolve quantas linhas saíram.
func Forget(ctx context.Context, db *sql.DB, p netip.Prefix) (int64, error) {
	lo, hi := prefixRange(p)
	res, err := db.ExecContext(ctx, "DELETE FROM ip_hourly WHERE ip BETWEEN ? AND ?", lo, hi)
	if err != nil {
		return 0, fmt.Errorf("bot: forget: %w", err)
	}
	return res.RowsAffected()
}

// Purge apaga os agregados mais velhos que retention e o uso diário das chaves mais velho que 90 dias. Devolve as
// linhas removidas dos agregados (bot_purged_total{reason=age}).
//
// Sai toda linha cujo período (hora em ip_hourly, dia em fp_daily) começou antes do corte: o dado mais velho que
// sobra tem no máximo retention, e com o expurgo a cada purgeInterval (1 h) nada passa de 7 dias e 1 hora (spec 018
// RF-08, ADR 0052 item 1). O corte pelo índice do período (hour < corte/3600) deixava a hora inteira do corte e
// mais o intervalo do expurgo (~7 d 2 h; no fp_daily, ~8 dias).
func Purge(ctx context.Context, db *sql.DB, now time.Time, retention time.Duration) (int64, error) {
	cut := now.Add(-retention).Unix()
	var total int64
	for _, q := range []struct {
		sql string
		arg int64
	}{
		{"DELETE FROM ip_hourly WHERE hour < ?", ceilDiv(cut, 3600)},
		{"DELETE FROM fp_daily WHERE day < ?", ceilDiv(cut, 86400)},
	} {
		res, err := db.ExecContext(ctx, q.sql, q.arg)
		if err != nil {
			return total, fmt.Errorf("bot: purge: %w", err)
		}
		n, _ := res.RowsAffected()
		total += n
	}
	usageCut := now.Add(-keyUsageRetention).Unix() / 86400
	if _, err := db.ExecContext(ctx, "DELETE FROM key_usage_daily WHERE day < ?", usageCut); err != nil {
		return total, fmt.Errorf("bot: purge: %w", err)
	}
	// Pedidos da CLI concluídos há mais de 24 h (ADR 0056 item 2); fora de bot_purged_total, que é dos agregados.
	if _, err := db.ExecContext(ctx, "DELETE FROM control_requests WHERE done_at IS NOT NULL AND done_at < ?",
		now.Add(-controlRetention).Unix()); err != nil {
		return total, fmt.Errorf("bot: purge: %w", err)
	}
	return total, vacuum(ctx, db)
}

// PurgeSize expurga antecipadamente as horas mais antigas enquanto o banco (arquivo + WAL) passar de maxBytes
// (spec 018 RF-08). Cada passo apaga a hora mais antiga de ip_hourly e os dias de fp_daily anteriores a ela, devolve
// as páginas livres (incremental_vacuum) e trunca o WAL. Devolve as linhas removidas (bot_purged_total{reason=size}).
func PurgeSize(ctx context.Context, db *sql.DB, path string, maxBytes int64) (int64, error) {
	var total int64
	for maxBytes > 0 && dbFileSize(path) > maxBytes {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		var hour sql.NullInt64
		if err := db.QueryRowContext(ctx, "SELECT MIN(hour) FROM ip_hourly").Scan(&hour); err != nil {
			return total, fmt.Errorf("bot: purge size: %w", err)
		}
		var day sql.NullInt64
		if err := db.QueryRowContext(ctx, "SELECT MIN(day) FROM fp_daily").Scan(&day); err != nil {
			return total, fmt.Errorf("bot: purge size: %w", err)
		}
		if !hour.Valid && !day.Valid {
			return total, nil // nada mais a expurgar
		}
		type stmt struct {
			sql string
			arg int64
		}
		stmts := []stmt{{"DELETE FROM fp_daily WHERE day <= ?", day.Int64}}
		if hour.Valid {
			// fp_daily sai junto quando o dia dela termina antes da hora mais antiga.
			stmts = []stmt{{"DELETE FROM ip_hourly WHERE hour <= ?", hour.Int64}, {"DELETE FROM fp_daily WHERE day < ?", hour.Int64 / 24}}
		}
		for _, q := range stmts {
			res, err := db.ExecContext(ctx, q.sql, q.arg)
			if err != nil {
				return total, fmt.Errorf("bot: purge size: %w", err)
			}
			n, _ := res.RowsAffected()
			total += n
		}
		if err := vacuum(ctx, db); err != nil {
			return total, err
		}
	}
	return total, nil
}

// vacuum devolve as páginas livres ao sistema (auto_vacuum=INCREMENTAL) e trunca o WAL para o tamanho do arquivo
// refletir o expurgo.
func vacuum(ctx context.Context, db *sql.DB) error {
	for _, p := range []string{"PRAGMA incremental_vacuum", "PRAGMA wal_checkpoint(TRUNCATE)"} {
		if _, err := db.ExecContext(ctx, p); err != nil {
			return fmt.Errorf("bot: %s: %w", p, err)
		}
	}
	return nil
}

// ceilDiv é a divisão arredondada para cima (a > 0 nos cortes do expurgo; para baixo de zero, trunca como o Go).
func ceilDiv(a, b int64) int64 {
	q := a / b
	if a%b > 0 {
		q++
	}
	return q
}
