package store

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// appEvent é um evento de aplicação (fs.v1.web.*, fs.v1.raw.*, fs.v1.dns.query) já decodificado.
type appEvent struct {
	subject        string
	env            event.Envelope
	data           []byte // mensagem original (envelope + payload), gravada em app_events
	ts             int64
	l4             uint8
	client, server netip.AddrPort
}

func (e appEvent) key() flowKey { return keyOf(e.l4, e.client, e.server) }

// isAppSubject informa se o subject é de evento de aplicação consumido pelo store.
func isAppSubject(s string) bool {
	return strings.HasPrefix(s, "fs.v1.web.") || strings.HasPrefix(s, "fs.v1.raw.") || s == event.SubjectDNSQuery
}

// isStreamSubject informa se o subject é de fluxo de bytes (vai para raw_streams).
func isStreamSubject(s string) bool {
	return s == event.SubjectWebStreamBytes || s == event.SubjectRawRead
}

// parseAppEvent decodifica o envelope e a 5-tupla. Campos desconhecidos são ignorados (ADR 0001).
func parseAppEvent(subject string, data []byte) (appEvent, error) {
	env, err := event.Decode(data)
	if err != nil {
		return appEvent{}, err
	}
	ev := appEvent{subject: subject, env: env, data: data}
	when, err := env.Time()
	if err != nil {
		return appEvent{}, fmt.Errorf("app event: ts: %w", err)
	}
	ev.ts = when.UnixNano()
	if env.Flow == nil {
		return ev, nil // sem flow (ex. DNS sem 5-tupla): só o que não depende de conexão
	}
	switch env.Flow.L4 {
	case "tcp":
		ev.l4 = protoTCP
	case "udp":
		ev.l4 = protoUDP
	default:
		return appEvent{}, fmt.Errorf("app event: l4 %q", env.Flow.L4)
	}
	if ev.client, err = addrPort(env.Flow.SrcIP, env.Flow.SrcPort); err != nil {
		return appEvent{}, err
	}
	if ev.server, err = addrPort(env.Flow.DstIP, env.Flow.DstPort); err != nil {
		return appEvent{}, err
	}
	return ev, nil
}

// hasFlow informa se o evento traz a 5-tupla.
func (e appEvent) hasFlow() bool { return e.l4 != 0 }

// appState acumula o que os eventos de aplicação acrescentam ao registro de uma conexão. É reconstruído a partir
// de app_events quando a conexão já foi gravada (evento tardio), por isso add precisa ser determinístico.
type appState struct {
	probeID      *string
	rawTruncated [2]bool // in, out
	events       int
	layers
}

func newAppState() *appState { return &appState{} }

// add incorpora um evento; devolve true se o probe da conexão foi definido agora.
func (a *appState) add(ev appEvent) (probeSet bool) {
	a.events++
	if a.probeID == nil && ev.env.ProbeID != nil && *ev.env.ProbeID != "" {
		p := *ev.env.ProbeID
		a.probeID = &p
		probeSet = true
	}
	if isStreamSubject(ev.subject) {
		var sb event.StreamBytes
		if json.Unmarshal(ev.env.Payload, &sb) == nil && sb.Truncated {
			a.rawTruncated[dirIndex(sb.Dir)] = true
		}
	}
	a.addLayer(ev)
	return probeSet
}

// apply escreve no registro os campos que vêm da aplicação.
func (a *appState) apply(r *connectionJSON) {
	if a == nil {
		return
	}
	if a.probeID != nil {
		p := *a.probeID
		r.ProbeID = &p
	}
	if a.rawTruncated[0] || a.rawTruncated[1] {
		r.RawTruncated = &rawTruncatedJSON{In: a.rawTruncated[0], Out: a.rawTruncated[1]}
	}
	a.applyLayers(r)
}

// dirIndex converte in/out em 0/1 (mesma convenção de raw_streams.dir).
func dirIndex(dir string) int {
	if dir == event.DirectionOut {
		return 1
	}
	return 0
}

// eventOnlyRecord monta o registro de uma conexão conhecida só pelos eventos (capture fora do ar): sem pacotes,
// times.syn nulo, sem ip/tcp, sem pcap.
func eventOnlyRecord(id string, ev appEvent, end int64) connectionJSON {
	family := 4
	if ev.client.Addr().Is6() {
		family = 6
	}
	r := connectionJSON{
		ConnID: id, Proto: l4Name(ev.l4), L4: l4Name(ev.l4), Family: family,
		Src:     endpointJSON{IP: ev.client.Addr().String(), Port: int(ev.client.Port())},
		Dst:     endpointJSON{IP: ev.server.Addr().String(), Port: int(ev.server.Port())},
		Started: event.FormatTime(time.Unix(0, ev.ts)), Ended: tsPtr(end),
		Close: closeJSON{By: "unknown", How: "timeout"},
	}
	if ev.l4 == protoTCP {
		r.Times = &timesJSON{End: tsPtr(end)}
	}
	return r
}
