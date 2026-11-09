package web

import (
	"bytes"

	"github.com/patrickbrandao/finger-sniffer/pkg/detect"
	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/probe"
)

// maxRawReads limita a lista reads_in do evento (cada item é pequeno; o resto só entra no fluxo in).
const maxRawReads = 8192

// serveRaw trata a conexão como TCP cru em modo sink (spec 005 RF-02, "raw/unknown"): lê e descarta até o
// cliente fechar ou a ociosidade vencer, publica os bytes no fluxo in e, no fim, fs.v1.web.raw.session com
// o schema do raw (spec 006). Uma primeira linha "PROBE <id>" é reconhecida como nas portas cruas.
func (c *conn) serveRaw(ic *idleConn, res detect.Result) {
	s := c.srv
	t := newTap(ic, s.cfg.RawStreamMax, s.now, c.emitStream)
	sess := rawSession{Mode: probe.ModeSink, ReadsIn: [][2]any{}, WritesOut: [][2]any{}}
	var first []byte
	buf := make([]byte, 32<<10)
	for {
		n, err := t.Read(buf)
		if n > 0 {
			if len(sess.ReadsIn) < maxRawReads {
				sess.ReadsIn = append(sess.ReadsIn, [2]any{msSince(c.acceptAt, s.now()), n})
			}
			if len(first) < probe.MaxLineLen {
				first = append(first, buf[:min(n, probe.MaxLineLen-len(first))]...)
			}
			t.flush()
		}
		if err != nil {
			break
		}
	}
	if res.Protocol == detect.ProbeLine {
		if i := bytes.IndexByte(first, '\n'); i >= 0 {
			line := first[:i+1]
			if pl, err := probe.ParseLine(line); err == nil {
				c.setProbe(pl.ID)
			}
			sess.ProbeLine = ptr(string(bytes.TrimRight(line, "\r\n")))
		}
	}
	t.flush()
	c.publish(event.SubjectWebRawSession, s.now(), "", sess)
}
