package store

import (
	"encoding/json"
	"net/netip"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// Eventos ao vivo gerados pelo ingest (spec 004 "Tempo real"): acumulados durante a transação do lote e
// publicados no hub só depois do commit (ADR 0020); lote desfeito descarta.

// requestCount conta as requisições HTTP (h1+h2+h3) já vistas.
func (l *layers) requestCount() int { return len(l.http1) + len(l.h2Streams) + len(l.h3Requests) }

// summaryFrom reduz o registro ao ConnectionSummary.
func summaryFrom(r connectionJSON) summaryJSON {
	return summaryJSON{
		ConnID: r.ConnID, ProbeID: r.ProbeID, Proto: r.Proto, L4: r.L4, Family: r.Family, Src: r.Src, Dst: r.Dst,
		Started: r.Started, Ended: r.Ended, Requests: r.Requests, Degraded: r.Degraded,
	}
}

// liveSummary monta o resumo de uma conexão aberta sem refazer o registro inteiro. Chamado com a trava.
func (c *conn) liveSummary() summaryJSON {
	l4 := l4Name(c.l4)
	s := summaryJSON{
		ConnID: c.id, Proto: l4, L4: l4, Family: c.family,
		Src:     endpointJSON{IP: c.client.Addr().String(), Port: int(c.client.Port())},
		Dst:     endpointJSON{IP: c.server.Addr().String(), Port: int(c.server.Port())},
		Started: event.FormatTime(time.Unix(0, c.started)), Degraded: c.degraded,
	}
	if c.app != nil {
		s.Proto, s.Requests = c.app.proto(l4), c.app.requestCount()
		if c.app.probeID != nil {
			p := *c.app.probeID
			s.ProbeID = &p
		}
	}
	return s
}

// openSummary devolve o resumo da conexão aberta com o ID dado.
func (t *flowTable) openSummary(id string) (summaryJSON, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	c := t.byID[id]
	if c == nil {
		return summaryJSON{}, false
	}
	return c.liveSummary(), true
}

// liveConn acumula um connection.* a partir do resumo.
func (in *Ingestor) liveConn(kind string, s summaryJSON, origin int64) {
	if in.live == nil {
		return
	}
	data, _ := json.Marshal(s)
	probe := ""
	if s.ProbeID != nil {
		probe = *s.ProbeID
	}
	src, _ := netip.ParseAddr(s.Src.IP)
	in.liveBatch = append(in.liveBatch, newLiveMsg(kind, origin, s.ConnID, probe, src, s.Dst.Port, data))
}

// liveApp acumula o http.request de um evento de aplicação associado à conexão id.
func (in *Ingestor) liveApp(ev appEvent, id, probe string) {
	if in.live == nil {
		return
	}
	switch ev.subject {
	case event.SubjectWebHTTP1Request, event.SubjectWebHTTP2Stream, event.SubjectWebHTTP3Request:
	default:
		return
	}
	if ev.env.ProbeID != nil && *ev.env.ProbeID != "" {
		probe = *ev.env.ProbeID
	}
	in.liveBatch = append(in.liveBatch, newLiveMsg(LiveHTTPRequest, ev.ts, id, probe, ev.client.Addr(), int(ev.server.Port()), ev.env.Payload))
}

// liveDNS acumula um dns.query (record é o DNSQuery gravado).
func (in *Ingestor) liveDNS(ts int64, record []byte, resolver string, connID, probe *string) {
	if in.live == nil {
		return
	}
	src, _ := netip.ParseAddr(resolver)
	in.liveBatch = append(in.liveBatch, newLiveMsg(LiveDNSQuery, ts, strOrEmpty(connID), strOrEmpty(probe), src.Unmap(), 53, record))
}

// liveStray acumula um packet.stray (sem o frame: o feed fica leve; o frame está em /api/v1/packets).
func (in *Ingestor) liveStray(fi frameInfo, ts int64, rec strayJSON) {
	if in.live == nil {
		return
	}
	data, _ := json.Marshal(rec)
	src, port := fi.src, int(fi.dport)
	if rec.Dir == "out" {
		src, port = fi.dst, int(fi.sport)
	}
	in.liveBatch = append(in.liveBatch, newLiveMsg(LivePacketStray, ts, "", "", src, port, data))
}

// publishLive entrega ao hub o que o lote confirmado produziu.
func (in *Ingestor) publishLive() {
	if len(in.liveBatch) == 0 {
		return
	}
	in.live.Publish(in.liveBatch...)
	in.liveBatch = nil
}

func strOrEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
