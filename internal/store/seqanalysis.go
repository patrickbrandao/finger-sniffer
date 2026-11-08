package store

// Classificação de segmentos TCP como o tshark (Wireshark 4.4, tcp_analyze_sequence_number em
// epan/dissectors/packet-tcp.c): keep-alive, retransmissão (comum, rápida e espúria) e fora de ordem. O
// objetivo é que retransmits/out_of_order e keepalive_probes do registro batam com tcp.analysis.* do
// tshark sobre o mesmo pcap. Nenhum código do Wireshark foi copiado; a lógica foi reescrita, com os mesmos
// critérios, inclusive os detalhes que mudam a contagem:
//   - a comparação usa os números de sequência crus (não relativos), e 0 significa "ainda não visto";
//   - o limite de fora de ordem é o iRTT (SYN → primeiro ACK puro) ou 3 ms;
//   - na retransmissão rápida o tshark compara o seq cru com bordas SACK relativas, então qualquer SACK
//     já visto no outro sentido basta (com 2 ACKs duplicados e menos de 20 ms do último ACK);
//   - uma "atualização de janela" com opção SACK é reclassificada como ACK duplicado (dissector da opção
//     SACK, issue 14937 do Wireshark).

const (
	wsFIN = 0x01
	wsSYN = 0x02
	wsRST = 0x04
	wsACK = 0x10

	wsMaxUnacked = 10000 // TCP_MAX_UNACKED_SEGMENTS
)

// Resultado da classificação de um segmento.
const (
	segKeepAlive = 1 << iota
	segRetransmission
	segOutOfOrder
	segZeroWindowProbe
)

type wsUnacked struct {
	seq, nextseq uint32
	ts           int64
}

// wsDir é o estado de um sentido (tcp_flow_t + tcp_analyze_seq_flow_info_t, só o que a classificação usa).
type wsDir struct {
	nextseq     uint32
	nextseqTime int64
	lastack     uint32
	lastackTime int64
	dupacks     int
	lastacklen  uint32
	window      uint32
	windowSet   bool
	lastFlags   int
	sackSeen    bool
	segments    []wsUnacked
}

// wsConn junta os dois sentidos e o iRTT.
type wsConn struct {
	dir      [2]wsDir // 0 = cliente → espelho, 1 = espelho → cliente
	mruSyn   int64
	firstRTT int64
}

func seqLT(a, b uint32) bool { return int32(a-b) < 0 }  //nolint:gosec // comparação de sequência com wrap
func seqLE(a, b uint32) bool { return int32(a-b) <= 0 } //nolint:gosec // idem
func seqGT(a, b uint32) bool { return int32(a-b) > 0 }  //nolint:gosec // idem
func seqGE(a, b uint32) bool { return int32(a-b) >= 0 } //nolint:gosec // idem

// classify analisa um segmento do sentido d (0 ou 1) e devolve os flags seg*.
func (w *wsConn) classify(d int, ts int64, seq, ack, seglen uint32, flags uint8, window uint32, hasSACK bool) int {
	fwd, rev := &w.dir[d], &w.dir[1-d]
	res := 0
	ctl := flags&(wsSYN|wsFIN|wsRST) != 0
	windowUpdate := seglen == 0 && window != 0 && fwd.windowSet && window != fwd.window &&
		seq == fwd.nextseq && ack == fwd.lastack && !ctl

	switch {
	case seglen == 1 && seq == fwd.nextseq && rev.windowSet && rev.window == 0:
		// sonda de janela zero: o tshark pula keep-alive e ACK duplicado
		res |= segZeroWindowProbe
	default:
		if (seglen == 0 || seglen == 1) && seq == fwd.nextseq-1 && !ctl {
			res |= segKeepAlive
		}
		sameAsLast := seglen == 0 && window != 0 && fwd.windowSet && window == fwd.window &&
			seq == fwd.nextseq && ack == fwd.lastack && !ctl
		// ACK de keep-alive não conta como ACK duplicado
		if sameAsLast && rev.lastFlags&segKeepAlive == 0 {
			fwd.dupacks++
		}
	}
	if ack != fwd.lastack {
		fwd.dupacks = 0
	}

	notAdvanced := fwd.nextseq != 0 && seqLT(seq, fwd.nextseq)
	if (seglen > 0 || flags&(wsSYN|wsFIN) != 0) && res&segKeepAlive == 0 {
		res |= w.retransmission(fwd, rev, ts, seq, seglen, flags, notAdvanced)
	}

	// guarda o segmento até ser confirmado
	next := seq + seglen
	if flags&(wsSYN|wsFIN) != 0 {
		next++
	}
	if (seglen > 0 || flags&(wsSYN|wsFIN) != 0) && len(fwd.segments) < wsMaxUnacked {
		fwd.segments = append(fwd.segments, wsUnacked{seq: seq, nextseq: next, ts: ts})
	}
	extra := uint32(0)
	if flags&(wsSYN|wsFIN) != 0 {
		extra = 1
	}
	if fwd.nextseq == 0 || seqGT(next, fwd.nextseq+extra) {
		fwd.lastacklen = seglen
	}
	if (fwd.nextseq == 0 || seqGT(next, fwd.nextseq)) && res&segZeroWindowProbe == 0 {
		fwd.nextseq, fwd.nextseqTime = next, ts
	}
	fwd.window, fwd.windowSet = window, true
	fwd.lastack, fwd.lastackTime = ack, ts
	fwd.lastFlags = res

	// tira do outro sentido o que este ACK confirma
	out := rev.segments[:0]
	for _, u := range rev.segments {
		switch {
		case ack == u.nextseq:
		case seqGT(ack, u.seq) && seqLE(ack, u.nextseq):
			u.seq = ack
			out = append(out, u)
			continue
		case seqGT(u.nextseq, ack):
			out = append(out, u)
			continue
		}
	}
	rev.segments = out

	// SACK fica registrado depois da análise, como as opções no tshark
	if hasSACK {
		fwd.sackSeen = true
		if windowUpdate {
			fwd.dupacks++
		}
	}
	// iRTT: primeiro ACK puro depois do SYN do cliente
	if flags&(wsSYN|wsACK) == wsACK && w.mruSyn != 0 && w.firstRTT == 0 {
		w.firstRTT = ts - w.mruSyn
	}
	if flags&(wsSYN|wsACK) == wsSYN {
		w.mruSyn = ts
	}
	return res
}

func (w *wsConn) retransmission(fwd, rev *wsDir, ts int64, seq, seglen uint32, flags uint8, notAdvanced bool) int {
	if seglen > 1 && fwd.nextseq-1 == seq {
		notAdvanced = false
	}
	// espúria: dados já confirmados pelo outro lado
	if seglen > 0 && rev.lastack != 0 && seqLE(seq+seglen, rev.lastack) {
		return segRetransmission
	}
	if !notAdvanced {
		return 0
	}
	// retransmissão rápida
	sinceAck := ts - rev.lastackTime

	if sinceAck < 20e6 && rev.dupacks >= 2 && (rev.lastack == seq || rev.sackSeen) {
		return segRetransmission
	}
	// fora de ordem
	thres := w.firstRTT
	if thres == 0 {
		thres = 3e6
	}
	seen := false
	for _, u := range fwd.segments {
		if seqGE(seq, u.seq) && seqLE(seq+seglen, u.nextseq) {
			seen = true
			break
		}
	}
	if ts-fwd.nextseqTime < thres && !seen {
		extra := uint32(0)
		if flags&(wsSYN|wsFIN) != 0 {
			extra = 1
		}
		if fwd.nextseq != seq+seglen+extra || fwd.lastacklen == 0 {
			return segOutOfOrder
		}
	}
	return segRetransmission
}
