package bot

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// Operações da tabela control_requests (spec 018 RF-10, ADR 0056 item 2).
const (
	opForget       = "forget"
	opListsRefresh = "lists_refresh"
	// refreshForcePrefix marca no arg o lists refresh --force <nome> (ADR 0077 item 3, sem migration).
	refreshForcePrefix = "force:"
	// controlRetention é quanto um pedido concluído fica no banco (o arg do forget é dado pessoal, ADR 0052).
	controlRetention = 24 * time.Hour
)

// Prazos da CLI à espera do serviço (ADR 0056 item 2); variáveis só para os testes encurtarem.
var (
	forgetWait  = 10 * time.Second
	refreshWait = 120 * time.Second
	controlPoll = 200 * time.Millisecond
)

// errNoService é a CLI sem resposta do serviço dentro do prazo.
var errNoService = errors.New("bot: the service did not answer (is finger-sniffer-bot running?)")

// errRefreshFailed é o lists refresh com alguma lista que falhou.
var errRefreshFailed = errors.New("bot: lists refresh failed")

// forgetResult é o result de um forget: o que saiu da memória do serviço e do disco na segunda passada.
type forgetResult struct {
	Index  int `json:"index"`
	Agg    int `json:"aggregates"`
	Verify int `json:"robot_checks"`
	// Webhook são os eventos com IP do prefixo tirados das filas do webhook (task 299).
	Webhook int    `json:"webhook"`
	Rows    int64  `json:"rows"`
	Error   string `json:"error,omitempty"`
}

// refreshResult é o result de um lists refresh: "ok" ou a mensagem de erro por lista.
type refreshResult struct {
	Lists map[string]string `json:"lists,omitempty"`
	Error string            `json:"error,omitempty"`
}

// controlRequest é um pedido pendente.
type controlRequest struct {
	id        int64
	op        string
	arg       sql.NullString
	createdAt int64
}

// insertControl grava um pedido e devolve o id.
func insertControl(ctx context.Context, db *sql.DB, op string, arg *string, now time.Time) (int64, error) {
	res, err := db.ExecContext(ctx, "INSERT INTO control_requests (op, arg, created_at) VALUES (?, ?, ?)", op, arg, now.Unix())
	if err != nil {
		return 0, fmt.Errorf("bot: control request: %w", err)
	}
	return res.LastInsertId()
}

// waitControl espera o serviço concluir o pedido até d; done=false quando o prazo acabou.
func waitControl(ctx context.Context, db *sql.DB, id int64, d time.Duration) (result string, done bool, err error) {
	deadline := time.Now().Add(d)
	t := time.NewTicker(controlPoll)
	defer t.Stop()
	for {
		var doneAt sql.NullInt64
		var res sql.NullString
		if err := db.QueryRowContext(ctx, "SELECT done_at, result FROM control_requests WHERE id = ?", id).Scan(&doneAt, &res); err != nil {
			return "", false, fmt.Errorf("bot: control request: %w", err)
		}
		if doneAt.Valid {
			return res.String, true, nil
		}
		if !time.Now().Before(deadline) {
			return "", false, nil
		}
		select {
		case <-ctx.Done():
			return "", false, ctx.Err()
		case <-t.C:
		}
	}
}

// pendingControls lê os pedidos ainda não concluídos, do mais antigo ao mais novo.
func pendingControls(ctx context.Context, db *sql.DB) ([]controlRequest, error) {
	rows, err := db.QueryContext(ctx, "SELECT id, op, arg, created_at FROM control_requests WHERE done_at IS NULL ORDER BY id")
	if err != nil {
		return nil, fmt.Errorf("bot: control requests: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []controlRequest
	for rows.Next() {
		var r controlRequest
		if err := rows.Scan(&r.id, &r.op, &r.arg, &r.createdAt); err != nil {
			return nil, fmt.Errorf("bot: control requests: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// finishControl grava o resultado (JSON) e done_at.
func finishControl(ctx context.Context, db *sql.DB, id int64, now time.Time, result any) error {
	b, err := json.Marshal(result)
	if err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, "UPDATE control_requests SET done_at = ?, result = ? WHERE id = ?", now.Unix(), string(b), id); err != nil {
		return fmt.Errorf("bot: control request %d: %w", id, err)
	}
	return nil
}

// handleControls executa os pedidos pendentes da CLI (no ciclo de 2 s da recarga das chaves). O forget roda aqui
// mesmo, na goroutine do flush dos agregados, então nenhum flush concorrente regrava o que acabou de sair; o lists
// refresh pode levar até 120 s e roda à parte, um por vez.
func (s *Server) handleControls(ctx context.Context) {
	if s.deps.DB == nil {
		return
	}
	reqs, err := pendingControls(ctx, s.deps.DB)
	if err != nil {
		if ctx.Err() == nil {
			s.deps.Log.Warn("bot: control requests", "err", err)
		}
		return
	}
	for _, r := range reqs {
		var err error
		switch r.op {
		case opForget:
			err = s.controlForget(ctx, r)
		case opListsRefresh:
			err = s.controlRefresh(ctx, r)
		}
		if err != nil && ctx.Err() == nil {
			s.deps.Log.Warn("bot: control request", "op", r.op, "err", err)
		}
	}
}

// controlForget apaga o prefixo da memória e do disco de novo e conclui o pedido.
func (s *Server) controlForget(ctx context.Context, r controlRequest) error {
	p, err := ParseIPOrPrefix(r.arg.String)
	if err != nil {
		return finishControl(ctx, s.deps.DB, r.id, s.deps.Now(), forgetResult{Error: err.Error()})
	}
	res := s.ForgetMemory(p)
	if res.Rows, err = Forget(ctx, s.deps.DB, p); err != nil {
		return err // fica pendente; o próximo ciclo tenta de novo
	}
	return finishControl(ctx, s.deps.DB, r.id, s.deps.Now(), res)
}

// ForgetMemory apaga da memória do serviço tudo do prefixo (ADR 0052 item 5, ADR 0056 item 2): as duas visões do
// índice (com os vereditos guardados nas conexões), os acumuladores, contadores de caminhos e o cache de
// comportamento dos agregados, o cache da verificação de robô e os eventos do prefixo nas filas do webhook
// (inclusive o que espera nova tentativa; um POST já em andamento termina, sem nova tentativa).
func (s *Server) ForgetMemory(p netip.Prefix) forgetResult {
	res := forgetResult{Index: s.index.Forget(p), Agg: s.agg.Forget(p), Webhook: s.hooks.Forget(p)}
	if s.lists != nil && s.lists.Verifier() != nil {
		res.Verify = s.lists.Verifier().Forget(p)
	}
	return res
}

// controlRefresh dispara o lists refresh em segundo plano (um por vez; os outros esperam o próximo ciclo). Pedido
// mais velho que o prazo da CLI não é mais esperado por ninguém: sai concluído como expirado, sem baixar nada.
func (s *Server) controlRefresh(ctx context.Context, r controlRequest) error {
	now := s.deps.Now()
	if now.Sub(time.Unix(r.createdAt, 0)) > refreshWait {
		return finishControl(ctx, s.deps.DB, r.id, now, refreshResult{Error: "expired"})
	}
	if s.lists == nil {
		return finishControl(ctx, s.deps.DB, r.id, now, refreshResult{Error: "lists disabled"})
	}
	if !s.refreshing.CompareAndSwap(false, true) {
		return nil
	}
	s.bg.Add(1)
	go func() {
		defer s.bg.Done()
		defer s.refreshing.Store(false)
		errs := map[string]error{}
		if name, ok := strings.CutPrefix(r.arg.String, refreshForcePrefix); ok && r.arg.Valid {
			// --force <nome>: sem a regra da queda (ADR 0077 item 3); nomes do catálogo são [a-z0-9_]+, sem ambiguidade
			errs[name] = s.lists.RefreshForced(ctx, name)
		} else if r.arg.Valid && r.arg.String != "" {
			errs[r.arg.String] = s.lists.Refresh(ctx, r.arg.String)
		} else {
			errs = s.lists.RefreshAll(ctx)
		}
		if ctx.Err() != nil {
			return // serviço parando: o pedido fica pendente
		}
		res := refreshResult{Lists: map[string]string{}}
		for name, err := range errs {
			res.Lists[name] = "ok"
			if err != nil {
				res.Lists[name] = err.Error()
			}
		}
		if len(errs) == 0 {
			res.Error = "no downloaded lists"
		}
		if err := finishControl(ctx, s.deps.DB, r.id, s.deps.Now(), res); err != nil && ctx.Err() == nil {
			s.deps.Log.Warn("bot: lists refresh", "err", err)
		}
	}()
	return nil
}
