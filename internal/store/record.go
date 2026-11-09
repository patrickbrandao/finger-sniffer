package store

import (
	"encoding/json"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// Estruturas do registro de conexão (schema Connection do openapi.yaml): resumo, times, close, totals, ip e
// tcp (análise em analysis.go); as camadas de aplicação vêm na F3.

type endpointJSON struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

type timesJSON struct {
	Syn         *string `json:"syn"`
	SynAck      *string `json:"syn_ack"`
	Established *string `json:"established"`
	TLSDone     *string `json:"tls_done"`
	FirstData   *string `json:"first_data"`
	ClientFin   *string `json:"client_fin"`
	ServerFin   *string `json:"server_fin"`
	ClientRst   *string `json:"client_rst"`
	ServerRst   *string `json:"server_rst"`
	End         *string `json:"end"`
}

type closeJSON struct {
	By                string   `json:"by"`
	How               string   `json:"how"`
	IdleBeforeCloseMs *float64 `json:"idle_before_close_ms"`
	HalfClose         bool     `json:"half_close"`
}

type dirTotalsJSON struct {
	AppBytes     int64 `json:"app_bytes"`
	Segments     int   `json:"segments"`
	DataSegments int   `json:"data_segments"`
	Retransmits  int   `json:"retransmits"`
	OutOfOrder   int   `json:"out_of_order"`
}

type totalsJSON struct {
	In  dirTotalsJSON `json:"in"`
	Out dirTotalsJSON `json:"out"`
}

// connectionJSON é o registro gravado em connections.record_json.
type connectionJSON struct {
	ConnID        string            `json:"conn_id"`
	ProbeID       *string           `json:"probe_id"`
	Proto         string            `json:"proto"`
	L4            string            `json:"l4"`
	Family        int               `json:"family"`
	Src           endpointJSON      `json:"src"`
	Dst           endpointJSON      `json:"dst"`
	Started       string            `json:"started"`
	Ended         *string           `json:"ended"`
	Requests      int               `json:"requests"`
	Degraded      bool              `json:"degraded"`
	PcapTruncated bool              `json:"pcap_truncated"`
	RawTruncated  *rawTruncatedJSON `json:"raw_truncated,omitempty"`
	Times         *timesJSON        `json:"times,omitempty"`
	Close         closeJSON         `json:"close"`
	Totals        totalsJSON        `json:"totals"`
	IP            *ipJSON           `json:"ip,omitempty"`
	TCP           *tcpJSON          `json:"tcp,omitempty"`
	// Camadas de aplicação (spec 004, tabela de montagem); tls/http/http2/http3/raw seguem os esquemas do contrato
	// como chegaram nos eventos.
	TLS       json.RawMessage   `json:"tls,omitempty"`
	HTTP      []json.RawMessage `json:"http,omitempty"`
	HTTP2     json.RawMessage   `json:"http2,omitempty"`
	HTTP3     json.RawMessage   `json:"http3,omitempty"`
	WebSocket *wsJSON           `json:"websocket,omitempty"`
	Raw       json.RawMessage   `json:"raw,omitempty"`
}

// rawTruncatedJSON marca os sentidos cujo fluxo passou de FS_RAW_STREAM_MAX_BYTES (ADR 0018).
type rawTruncatedJSON struct {
	In  bool `json:"in"`
	Out bool `json:"out"`
}

func tsPtr(ns int64) *string {
	if ns == 0 {
		return nil
	}
	s := event.FormatTime(time.Unix(0, ns))
	return &s
}

// record monta o registro da conexão; ended=0 indica conexão ainda aberta.
func (c *conn) record(ended int64, how string) connectionJSON {
	r := connectionJSON{
		ConnID: c.id, Proto: l4Name(c.l4), L4: l4Name(c.l4), Family: c.family,
		Src:     endpointJSON{IP: c.client.Addr().String(), Port: int(c.client.Port())},
		Dst:     endpointJSON{IP: c.server.Addr().String(), Port: int(c.server.Port())},
		Started: event.FormatTime(time.Unix(0, c.started)), Ended: tsPtr(ended),
		Degraded: c.degraded, PcapTruncated: c.truncated,
		Close: closeJSON{By: "unknown", How: "open"},
		Totals: totalsJSON{
			In: dirTotalsJSON{
				AppBytes: c.inBytes, Segments: c.inSegs, DataSegments: c.inData,
				Retransmits: c.ana.dir[0].retrans, OutOfOrder: c.ana.dir[0].ooo,
			},
			Out: dirTotalsJSON{
				AppBytes: c.outBytes, Segments: c.outSegs, DataSegments: c.outData,
				Retransmits: c.ana.dir[1].retrans, OutOfOrder: c.ana.dir[1].ooo,
			},
		},
		IP: c.ana.ipJSON(),
	}
	if c.l4 == protoTCP {
		r.TCP = c.ana.tcpJSON(c)
		r.Times = &timesJSON{
			Syn: tsPtr(c.syn), SynAck: tsPtr(c.synAck), Established: tsPtr(c.established), FirstData: tsPtr(c.firstData),
			ClientFin: tsPtr(c.clientFin), ServerFin: tsPtr(c.serverFin), ClientRst: tsPtr(c.clientRst),
			ServerRst: tsPtr(c.serverRst), End: tsPtr(ended),
		}
	}
	if ended != 0 {
		r.Close = c.closeInfo(how)
	}
	c.app.apply(&r)
	return r
}

// closeInfo decide quem fechou e como (spec 013 RF-02).
func (c *conn) closeInfo(how string) closeJSON {
	ci := closeJSON{By: "unknown", How: how, HalfClose: c.dataAfterFin}
	type ev struct {
		ts      int64
		by, how string
	}
	first := ev{}
	for _, e := range []ev{
		{c.clientFin, "client", "fin"},
		{c.serverFin, "server", "fin"},
		{c.clientRst, "client", "rst"},
		{c.serverRst, "server", "rst"},
	} {
		if e.ts != 0 && (first.ts == 0 || e.ts < first.ts) {
			first = e
		}
	}
	if first.ts != 0 {
		ci.By, ci.How = first.by, first.how
		if c.lastData != 0 && c.lastData <= first.ts {
			ms := float64(first.ts-c.lastData) / 1e6
			ci.IdleBeforeCloseMs = &ms
		}
	}
	return ci
}

// strayJSON é o registro de stray_packets.record_json (schema StrayPacket sem o frame).
type strayJSON struct {
	Ts       string        `json:"ts"`
	Dir      string        `json:"dir"`
	L4       string        `json:"l4"`
	Family   int           `json:"family,omitempty"`
	Src      *endpointJSON `json:"src,omitempty"`
	Dst      *endpointJSON `json:"dst,omitempty"`
	TCPFlags *string       `json:"tcp_flags"`
	Length   int           `json:"length"`
	Summary  string        `json:"summary"`
}

func strayRecord(fi frameInfo, ts int64, dir uint8, wireLen int) strayJSON {
	r := strayJSON{Ts: event.FormatTime(time.Unix(0, ts)), Dir: "in", L4: l4Name(fi.proto), Length: wireLen}
	if dir == event.DirOut {
		r.Dir = "out"
	}
	if !fi.ok {
		r.L4, r.Summary = "other", "non-IP frame"
		return r
	}
	r.Family = fi.family
	r.Src = &endpointJSON{IP: fi.src.String(), Port: int(fi.sport)}
	r.Dst = &endpointJSON{IP: fi.dst.String(), Port: int(fi.dport)}
	r.Summary = r.L4 + " " + fi.src.String() + " > " + fi.dst.String()
	if fi.proto == protoTCP && fi.ports {
		f := tcpFlagsString(fi.tcpFlags)
		r.TCPFlags = &f
		r.Summary += " [" + f + "]"
	}
	return r
}
