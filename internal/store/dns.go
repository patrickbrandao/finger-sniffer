package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
)

// dnsHead são os campos de DNSQuery que viram colunas de dns_queries.
type dnsHead struct {
	ProbeID  *string `json:"probe_id"`
	Resolver struct {
		IP   string `json:"ip"`
		Port int    `json:"port"`
	} `json:"resolver"`
	Proto string `json:"proto"`
	QName string `json:"qname"`
	QType string `json:"qtype"`
}

// insertDNS grava uma consulta DNS (fs.v1.dns.query → dns_queries). record_json é o payload DNSQuery com o
// conn_id da conexão TCP correlacionada, quando houver.
func (in *Ingestor) insertDNS(ctx context.Context, tx *sql.Tx, ev appEvent, connID *string) error {
	var h dnsHead
	if err := json.Unmarshal(ev.env.Payload, &h); err != nil {
		in.log.Warn("bad dns event", "err", err)
		in.metrics.Add("store_bad_events_total", 1)
		return nil
	}
	var rec map[string]any
	_ = json.Unmarshal(ev.env.Payload, &rec)
	probeID := h.ProbeID
	if probeID == nil || *probeID == "" {
		probeID = ev.env.ProbeID
	}
	if probeID != nil && *probeID == "" {
		probeID = nil
	}
	rec["probe_id"] = probeID
	rec["conn_id"] = connID
	if _, ok := rec["ts"]; !ok {
		rec["ts"] = ev.env.Ts
	}
	// Sem resolver no payload, a ponta do cliente da 5-tupla é o resolver.
	if h.Resolver.IP == "" && ev.hasFlow() {
		h.Resolver.IP, h.Resolver.Port = ev.client.Addr().String(), int(ev.client.Port())
		rec["resolver"] = endpointJSON{IP: h.Resolver.IP, Port: h.Resolver.Port}
	}
	if h.Proto == "" {
		h.Proto = l4Name(ev.l4)
		if !ev.hasFlow() {
			h.Proto = "udp"
		}
		rec["proto"] = h.Proto
	}
	if h.Proto != "udp" && h.Proto != "tcp" {
		in.metrics.Add("store_bad_events_total", 1)
		return nil
	}
	data, _ := json.Marshal(rec)
	if _, err := tx.ExecContext(ctx, `INSERT INTO dns_queries (ts_ns, probe_id, conn_id, resolver_ip, resolver_port, proto, qname,
		qtype, record_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ev.ts, probeID, connID, h.Resolver.IP, h.Resolver.Port, h.Proto, h.QName, h.QType, string(data)); err != nil {
		return fmt.Errorf("insert dns query: %w", err)
	}
	in.metrics.Add("store_dns_queries_total", 1)
	in.liveDNS(ev.ts, data, h.Resolver.IP, connID, probeID)
	if probeID != nil {
		return upsertProbe(ctx, tx, *probeID, ev.ts)
	}
	return nil
}
