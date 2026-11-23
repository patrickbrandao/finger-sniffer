package bot

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"slices"
	"strings"
	"text/tabwriter"
	"time"
)

// ErrUsage indica comando ou argumentos inválidos (saída 2).
var ErrUsage = errors.New("bot: usage")

// IsCLI diz se os argumentos são um comando da CLI (spec 018 RF-10) em vez de subir o serviço.
func IsCLI(args []string) bool {
	return len(args) > 0 && (args[0] == "key" || args[0] == "forget" || args[0] == "lists")
}

const cliUsage = `usage:
  finger-sniffer-bot key create --name NAME --domains a.com,*.b.com [--rate N] [--burst N] [--daily N]
                                [--ingest-rate N] [--ingest-burst N] [--mode observe|block] [--webhook-url https://...] [--webhook-classes bot,suspect]
  finger-sniffer-bot key list
  finger-sniffer-bot key revoke <id|prefix>
  finger-sniffer-bot key rotate <id|prefix>
  finger-sniffer-bot forget <ip|prefix>
  finger-sniffer-bot lists refresh [name]
`

// RunCLI executa um comando da CLI no banco em disco (FS_BOT_DB), com o serviço rodando ou não (WAL).
func RunCLI(ctx context.Context, args []string, dbPath string, out, errOut io.Writer, now time.Time) error {
	if !IsCLI(args) {
		_, _ = fmt.Fprint(errOut, cliUsage)
		return ErrUsage
	}
	db, err := OpenDB(ctx, dbPath)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	switch args[0] {
	case "forget":
		return cliForget(ctx, db, args[1:], out, errOut, now)
	case "lists":
		if len(args) < 2 || args[1] != "refresh" || len(args) > 3 {
			_, _ = fmt.Fprint(errOut, cliUsage)
			return ErrUsage
		}
		return cliListsRefresh(ctx, db, args[2:], out, errOut, now)
	}
	if len(args) < 2 {
		_, _ = fmt.Fprint(errOut, cliUsage)
		return ErrUsage
	}
	switch args[1] {
	case "create":
		return cliKeyCreate(ctx, db, args[2:], out, errOut, now)
	case "list":
		return cliKeyList(ctx, db, out)
	case "revoke", "rotate":
		if len(args) != 3 {
			_, _ = fmt.Fprint(errOut, cliUsage)
			return ErrUsage
		}
		if args[1] == "revoke" {
			k, err := RevokeKey(ctx, db, args[2], now)
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintf(out, "revoked %s (fsk_%s…, %s)\n", k.ID, k.Prefix, k.Name)
			return nil
		}
		k, secret, err := RotateKey(ctx, db, args[2])
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(out, "rotated %s (%s); the old key stops working within %s\nkey: %s\n(shown only once)\n",
			k.ID, k.Name, keyReload, secret)
		return nil
	}
	_, _ = fmt.Fprint(errOut, cliUsage)
	return ErrUsage
}

func cliKeyCreate(ctx context.Context, db *sql.DB, args []string, out, errOut io.Writer, now time.Time) error {
	fs := flag.NewFlagSet("key create", flag.ContinueOnError)
	fs.SetOutput(errOut)
	var o KeyOptions
	var domains, classes string
	fs.StringVar(&o.Name, "name", "", "key name (client)")
	fs.StringVar(&domains, "domains", "", "authorized domains, comma separated (example.com or *.example.com)")
	fs.IntVar(&o.RatePerS, "rate", 0, fmt.Sprintf("requests per second (default %d)", DefaultRatePerS))
	fs.IntVar(&o.Burst, "burst", 0, fmt.Sprintf("bucket size (default %d)", DefaultBurst))
	fs.IntVar(&o.DailyQuota, "daily", 0, fmt.Sprintf("daily quota (default %d)", DefaultDailyQuota))
	fs.IntVar(&o.IngestRate, "ingest-rate", 0, fmt.Sprintf("ingest records per second on the public port (default %d)", DefaultIngestRate))
	fs.IntVar(&o.IngestBurst, "ingest-burst", 0, fmt.Sprintf("ingest records bucket size (default %d)", DefaultIngestBurst))
	fs.StringVar(&o.Mode, "mode", ModeObserve, "observe or block")
	fs.StringVar(&o.WebhookURL, "webhook-url", "", "https URL for the verdict webhook")
	fs.StringVar(&classes, "webhook-classes", "", "verdict classes sent to the webhook (default bot,suspect)")
	if err := fs.Parse(args); err != nil {
		return ErrUsage
	}
	if fs.NArg() > 0 {
		_, _ = fmt.Fprintf(errOut, "unexpected arguments: %s\n", strings.Join(fs.Args(), " "))
		return ErrUsage
	}
	o.Domains = strings.Split(domains, ",")
	if classes != "" {
		o.WebhookClasses = strings.Split(classes, ",")
	}
	k, secret, whSecret, err := CreateKey(ctx, db, o, now)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(out, "id: %s\nname: %s\ndomains: %s\nmode: %s\nlimits: %d/s burst %d, %d/day\n"+
		"ingest: %d records/s burst %d\nkey: %s\n",
		k.ID, k.Name, strings.Join(k.Domains, ","), k.Mode, k.Rate(), k.BurstSize(), k.Quota(), k.IngestRateOrDefault(),
		k.IngestBurstOrDefault(), secret)
	if whSecret != nil {
		_, _ = fmt.Fprintf(out, "webhook: %s (%s)\nwebhook secret: %s\n", k.WebhookURL, strings.Join(k.WebhookClasses, ","),
			hex.EncodeToString(whSecret))
	}
	_, _ = fmt.Fprintf(out, "(shown only once; the key works within %s)\n", keyReload)
	return nil
}

func cliKeyList(ctx context.Context, db *sql.DB, out io.Writer) error {
	keys, err := ListKeys(ctx, db)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "ID\tPREFIX\tNAME\tDOMAINS\tMODE\tRATE\tBURST\tDAILY\tWEBHOOK\tCREATED\tREVOKED")
	for _, k := range keys {
		revoked := "-"
		if k.RevokedAt != nil {
			revoked = k.RevokedAt.Format(time.RFC3339)
		}
		wh := "-"
		if k.WebhookURL != "" {
			wh = k.WebhookURL
		}
		_, _ = fmt.Fprintf(tw, "%s\tfsk_%s\t%s\t%s\t%s\t%d\t%d\t%d\t%s\t%s\t%s\n", k.ID, k.Prefix, k.Name,
			strings.Join(k.Domains, ","), k.Mode, k.Rate(), k.BurstSize(), k.Quota(), wh, k.CreatedAt.Format(time.RFC3339), revoked)
	}
	return tw.Flush()
}

// cliForget apaga o disco (funciona com o serviço parado) e pede ao serviço em execução que apague a memória e o
// disco de novo (ADR 0056 item 2); espera até 10 s pela resposta.
func cliForget(ctx context.Context, db *sql.DB, args []string, out, errOut io.Writer, now time.Time) error {
	if len(args) != 1 {
		_, _ = fmt.Fprint(errOut, cliUsage)
		return ErrUsage
	}
	p, err := ParseIPOrPrefix(args[0])
	if err != nil {
		return err
	}
	n, err := Forget(ctx, db, p)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(out, "forgot %s: %d aggregate rows deleted\n", p, n)
	arg := p.String()
	id, err := insertControl(ctx, db, opForget, &arg, now)
	if err != nil {
		return err
	}
	raw, done, err := waitControl(ctx, db, id, forgetWait)
	if err != nil {
		return err
	}
	if !done {
		// O disco já está limpo; o pedido fica pendente e o serviço o executa quando voltar.
		_, _ = fmt.Fprintf(out, "service memory: not reached within %s (service not running?); "+
			"in-memory data expires within 10 min\n", forgetWait)
		return nil
	}
	var r forgetResult
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		return fmt.Errorf("bot: forget result: %w", err)
	}
	if r.Error != "" {
		return fmt.Errorf("bot: forget in the service: %s", r.Error)
	}
	_, _ = fmt.Fprintf(out, "service memory: reached (%d connections, %d aggregate entries, %d robot checks; "+
		"%d more rows deleted)\n", r.Index, r.Agg, r.Verify, r.Rows)
	return nil
}

// cliListsRefresh pede ao serviço que baixe as listas (todas ou uma) e espera até 120 s; o download, a validação e
// a troca são do serviço, que tem a rede e as permissões da unit (ADR 0056 item 2).
func cliListsRefresh(ctx context.Context, db *sql.DB, args []string, out, errOut io.Writer, now time.Time) error {
	var arg *string
	if len(args) > 0 {
		name := args[0]
		arg = &name
	}
	id, err := insertControl(ctx, db, opListsRefresh, arg, now)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(errOut, "waiting for the service (up to %s)...\n", refreshWait)
	raw, done, err := waitControl(ctx, db, id, refreshWait)
	if err != nil {
		return err
	}
	if !done {
		return fmt.Errorf("%w: no answer within %s", errNoService, refreshWait)
	}
	var r refreshResult
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		return fmt.Errorf("bot: lists refresh result: %w", err)
	}
	if r.Error != "" {
		return fmt.Errorf("%w: %s", errRefreshFailed, r.Error)
	}
	names := make([]string, 0, len(r.Lists))
	for name := range r.Lists {
		names = append(names, name)
	}
	slices.Sort(names)
	failed := 0
	for _, name := range names {
		_, _ = fmt.Fprintf(out, "%s: %s\n", name, r.Lists[name])
		if r.Lists[name] != "ok" {
			failed++
		}
	}
	if failed > 0 {
		return fmt.Errorf("%w: %d of %d lists", errRefreshFailed, failed, len(names))
	}
	return nil
}
