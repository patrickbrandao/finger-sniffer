package web

import (
	"bytes"

	"github.com/patrickbrandao/finger-sniffer/pkg/detect"
	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/probe"
)

// Teto da lista reads_in (ADR 0070 item 7): as primeiras rawReadsFixed entradas são retenção fixa (16 KiB);
// as seguintes, até maxRawReads, reservam do orçamento a capacidade que a lista ganha. Sem orçamento ou no
// teto, a lista para e reads_in_truncated fica true; os bytes seguem inteiros no fluxo in.
const (
	maxRawReads   = 8192
	rawReadsFixed = 1024
	// timedLengthSize é o tamanho de uma entrada (dois float64).
	timedLengthSize = 16
)

// timedLength é uma entrada [t_ms, bytes] de reads_in/writes_out, sem caixa (o mesmo tipo do raw); o JSON
// é o mesmo de antes ([[t_ms, bytes], ...]).
type timedLength [2]float64

// appendRead acrescenta uma leitura à lista, reservando no hold o crescimento acima das entradas fixas;
// false quando a lista não pode crescer (teto ou orçamento).
func appendRead(list *[]timedLength, hold *budgetHold, e timedLength) bool {
	l := *list
	if len(l) >= maxRawReads {
		return false
	}
	if len(l) == cap(l) {
		newCap := min(max(2*cap(l), 64), maxRawReads)
		if extra := newCap - max(cap(l), rawReadsFixed); newCap > rawReadsFixed && extra > 0 &&
			!hold.reserveQuiet(int64(extra*timedLengthSize)) {
			return false
		}
		grown := make([]timedLength, len(l), newCap)
		copy(grown, l)
		l = grown
	}
	*list = append(l, e)
	return true
}

// serveRaw trata a conexão como TCP cru em modo sink (spec 005 RF-02, "raw/unknown"): lê e descarta até o
// cliente fechar ou a ociosidade vencer, publica os bytes no fluxo in e, no fim, fs.v1.web.raw.session com
// o schema do raw (spec 006). Uma primeira linha "PROBE <id>" é reconhecida como nas portas cruas.
func (c *conn) serveRaw(ic *idleConn, res detect.Result) {
	s := c.srv
	t := newTap(ic, s.cfg.RawStreamMax, s.now, c.emitStream, s.budget)
	sess := rawSession{Mode: probe.ModeSink, ReadsIn: []timedLength{}, WritesOut: []timedLength{}}
	hold := s.budget.newHold(0)
	defer hold.releaseAll()
	var first []byte
	buf := make([]byte, 32<<10)
	for {
		n, err := t.Read(buf)
		if n > 0 {
			if sess.ReadsInTruncated ||
				!appendRead(&sess.ReadsIn, hold, timedLength{msSince(c.acceptAt, s.now()), float64(n)}) {
				sess.ReadsInTruncated = true
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
			// como no raw: a linha como recebida, com o terminador CRLF ou LF (spec 006 RF-04, task 181)
			sess.ProbeLine = ptr(string(line))
		}
	}
	t.flush()
	// ts = accept, como no fs.v1.raw.session (ADR 0025, task 180)
	c.publish(event.SubjectWebRawSession, c.acceptAt, "", sess)
}
