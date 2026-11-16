package store

import (
	"context"
	"database/sql"
	"time"
)

// Pacotes das conexões abertas em memória (task 248, ADR 0043 alternativa b).
//
// Antes, cada pacote virava uma linha em packets assim que chegava e, na finalização, era lido de volta, copiado
// para o pcap e apagado: três escritas por pacote (linha, índice packets_conn e a remoção) a cada lote, ~240 KB
// de WAL por conexão na carga 200/50. No disco do finger-01 (fsync lento) esse volume alongava o checkpoint do
// WAL, que segura o escritor. Agora os pacotes ficam no buffer da conexão até a finalização, que grava o pcap
// direto. A tabela packets fica para o que não cabe na memória e para o reinício:
//   - conexão com mais de defaultPktConnMax no buffer, ou o total passando de defaultPktMemMax: o buffer é copiado para packets
//     no lote em curso e daí em diante os pacotes dela vão direto para a tabela (como antes);
//   - pacotes tardios de conexões já finalizadas continuam passando pela tabela (writeLate);
//   - no desligamento, spillAll copia os buffers para packets, e recoverOrphans monta o pcap das órfãs no
//     reinício como antes. Uma queda abrupta perde os pacotes em memória das conexões abertas (a órfã fica com o
//     registro e um pcap só com o cabeçalho), como já acontece com os eventos pendentes (drainPending).
//
// O buffer só é escrito pelo laço de ingest, sob flowTable.mu (a API lê o pcap parcial das conexões abertas,
// livePcap). A foto de cada buffer no início do lote (pktSnap) desfaz o lote cuja transação foi desfeita.
const (
	// defaultPktConnMax é o máximo em memória por conexão; acima disso, ela passa a gravar em packets.
	defaultPktConnMax = 1 << 20
	// defaultPktMemMax é o máximo em memória somando todas as conexões.
	defaultPktMemMax = 64 << 20
	// pktOverhead é o custo contado por pacote além do frame (bufPkt).
	pktOverhead = 32
)

// spillState diz onde estão os pacotes de uma conexão.
type spillState uint8

const (
	spillNone    spillState = iota // só na memória
	spillPending                   // copiados para packets no lote em curso; a memória fica até o commit
	spillDone                      // em packets; a memória foi liberada
)

// bufPkt é um pacote no buffer: o frame está em pktBuf.arena[off:off+n].
type bufPkt struct {
	ts     int64
	off, n int32
	wl     int32
	dir    uint8
}

// pktBuf são os pacotes em memória de uma conexão, na ordem de chegada.
type pktBuf struct {
	arena []byte
	pkts  []bufPkt
	spill spillState
	mark  uint64 // lote (Ingestor.pktSerial) em que a foto para o rollback foi tirada
}

func (b *pktBuf) size() int64 { return int64(len(b.arena)) + int64(len(b.pkts))*pktOverhead }

func (b *pktBuf) frame(p bufPkt) []byte { return b.arena[p.off : p.off+p.n] }

// pcap monta o pcap com os pacotes do buffer.
func (b *pktBuf) pcap(snaplen uint32) []byte {
	out := make([]byte, 0, 24+len(b.arena)+16*len(b.pkts))
	out = append(out, pcapHeader(snaplen)...)
	for _, p := range b.pkts {
		out = appendPcapRecord(out, p.ts, int(p.wl), b.frame(p))
	}
	return out
}

// pktSnap é o buffer de uma conexão no início do lote, com o orçamento do pcap (pcapFrame).
type pktSnap struct {
	c                       *conn
	npk, narena             int
	spill                   spillState
	pcapBytes, pcapHdrBytes int64
}

// touchPkts tira a foto do buffer da conexão para o rollback, uma vez por lote, antes de pcapFrame.
func (in *Ingestor) touchPkts(c *conn) {
	if c.buf.mark == in.pktSerial {
		return
	}
	c.buf.mark = in.pktSerial
	in.pktUndo = append(in.pktUndo, pktSnap{
		c: c, npk: len(c.buf.pkts), narena: len(c.buf.arena), spill: c.buf.spill,
		pcapBytes: c.pcapBytes, pcapHdrBytes: c.pcapHdrBytes,
	})
}

// storePkt guarda um pacote da conexão: no buffer ou, se ela já passou para a tabela (ou passa agora), em packets.
func (in *Ingestor) storePkt(ctx context.Context, ins *sql.Stmt, c *conn, ts int64, dir uint8, wl int, frame []byte) error {
	add := int64(len(frame)) + pktOverhead
	if c.buf.spill == spillNone && (c.buf.size()+add > in.pktConnMax || in.pktMem+add > in.pktMemMax) {
		if err := in.spillConn(ctx, ins, c); err != nil {
			return err
		}
	}
	if c.buf.spill != spillNone {
		_, err := ins.ExecContext(ctx, c.id, ts, int(dir), wl, frame)
		return err
	}
	in.flows.mu.Lock()
	c.buf.pkts = append(c.buf.pkts, bufPkt{ts: ts, off: int32(len(c.buf.arena)), n: int32(len(frame)), wl: int32(wl), dir: dir}) //nolint:gosec // frame < 64 KiB, arena ≤ pktConnMax
	c.buf.arena = append(c.buf.arena, frame...)
	in.flows.mu.Unlock()
	in.pktMem += add
	return nil
}

// spillConn copia o buffer da conexão para packets na transação em curso. A memória fica até o commit
// (commitPkts), para o rollback e para a API, que até lá não vê as linhas.
func (in *Ingestor) spillConn(ctx context.Context, ins *sql.Stmt, c *conn) error {
	for _, p := range c.buf.pkts {
		if _, err := ins.ExecContext(ctx, c.id, p.ts, int(p.dir), int(p.wl), c.buf.frame(p)); err != nil {
			return err
		}
	}
	in.flows.mu.Lock()
	c.buf.spill = spillPending
	in.flows.mu.Unlock()
	return nil
}

// commitPkts, depois do commit do lote, libera a memória das conexões que passaram para a tabela e das
// despejadas.
func (in *Ingestor) commitPkts() {
	for _, s := range in.pktUndo {
		if s.c.buf.spill == spillPending {
			in.releasePkts(s.c, spillDone)
			in.metrics.Add("store_packet_spills_total", 1)
		}
	}
	in.pktUndo = in.pktUndo[:0]
	in.dropPkts()
}

// discardPkts, no rollback do lote, devolve cada buffer ao que era no início do lote (as linhas copiadas para
// packets saíram com a transação).
func (in *Ingestor) discardPkts() {
	in.flows.mu.Lock()
	for i := len(in.pktUndo) - 1; i >= 0; i-- {
		s := in.pktUndo[i]
		b := &s.c.buf
		before := b.size()
		b.pkts, b.arena, b.spill = b.pkts[:s.npk], b.arena[:s.narena], s.spill
		in.pktMem -= before - b.size()
		s.c.pcapBytes, s.c.pcapHdrBytes = s.pcapBytes, s.pcapHdrBytes
	}
	in.flows.mu.Unlock()
	in.pktUndo = in.pktUndo[:0]
	in.dropPkts()
}

// dropPkts libera os buffers das conexões despejadas no lote (a linha sai com as filhas).
func (in *Ingestor) dropPkts() {
	for _, c := range in.pktDrop {
		in.releasePkts(c, spillDone)
	}
	in.pktDrop = in.pktDrop[:0]
}

// releasePkts libera o buffer da conexão (finalizada, despejada ou copiada para a tabela).
func (in *Ingestor) releasePkts(c *conn, state spillState) {
	in.flows.mu.Lock()
	in.pktMem -= c.buf.size()
	c.buf.pkts, c.buf.arena, c.buf.spill = nil, nil, state
	in.flows.mu.Unlock()
}

// finalized tira as conexões do conjunto à espera da finalização e libera os buffers delas.
func (in *Ingestor) finalized(conns ...*conn) {
	for _, c := range conns {
		in.releasePkts(c, spillDone)
	}
	in.flows.finalized(conns...)
}

// spillAll, no desligamento, copia para packets os buffers de todas as conexões em memória (abertas e à espera
// da finalização), para recoverOrphans montar o pcap delas no reinício.
func (in *Ingestor) spillAll() {
	conns := in.flows.memConns(in.toFinalize)
	if len(conns) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := func() error {
		tx, err := in.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback() }()
		ins, err := tx.PrepareContext(ctx, "INSERT INTO packets (conn_id, ts_ns, dir, wire_len, frame) VALUES (?, ?, ?, ?, ?)")
		if err != nil {
			return err
		}
		defer func() { _ = ins.Close() }()
		for _, c := range conns {
			for _, p := range c.buf.pkts {
				if _, err := ins.ExecContext(ctx, c.id, p.ts, int(p.dir), int(p.wl), c.buf.frame(p)); err != nil {
					return err
				}
			}
		}
		return tx.Commit()
	}()
	if err != nil {
		in.log.Error("spill packets on shutdown", "err", err, "connections", len(conns))
		return
	}
	for _, c := range conns {
		in.releasePkts(c, spillDone)
	}
}

// memConns devolve as conexões com pacotes só na memória: as da tabela e as de extra (fila de finalização).
func (t *flowTable) memConns(extra []*conn) []*conn {
	t.mu.Lock()
	defer t.mu.Unlock()
	seen := map[*conn]struct{}{}
	var out []*conn
	add := func(c *conn) {
		if _, ok := seen[c]; ok || c.buf.spill != spillNone || len(c.buf.pkts) == 0 || c.unstored {
			return
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	for _, c := range t.byID {
		add(c)
	}
	for _, c := range t.finalizing {
		add(c)
	}
	for _, c := range extra {
		add(c)
	}
	return out
}

// livePcap monta o pcap parcial de uma conexão aberta (ou à espera da finalização) a partir do buffer e devolve
// quantos pacotes ele tem (0 para a conexão de um probe apagado). ok falso: a conexão não está na memória ou os
// pacotes dela estão em packets.
func (t *flowTable) livePcap(id string, snaplen uint32) (pcap []byte, n int, ok bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	c := t.byID[id]
	if c == nil {
		c = t.finalizing[id]
	}
	if c == nil || c.buf.spill == spillDone {
		return nil, 0, false
	}
	if _, hidden := t.hidden[id]; hidden {
		return nil, 0, true // probe apagado (ADR 0034 item 8): não há pcap
	}
	return c.buf.pcap(snaplen), len(c.buf.pkts), true
}

// finalPkt é um pacote lido na finalização.
type finalPkt struct {
	ts      int64
	dir     uint8
	wireLen int
	frame   []byte
}

// finalPkts devolve os pacotes da conexão a finalizar: do buffer ou, se ela passou para a tabela, de packets.
// Os frames do buffer valem até releasePkts (depois do commit).
func (in *Ingestor) finalPkts(ctx context.Context, tx *sql.Tx, c *conn) ([]finalPkt, error) {
	if c.buf.spill != spillDone {
		out := make([]finalPkt, len(c.buf.pkts))
		for i, p := range c.buf.pkts {
			out[i] = finalPkt{ts: p.ts, dir: p.dir, wireLen: int(p.wl), frame: c.buf.frame(p)}
		}
		return out, nil
	}
	rows, err := tx.QueryContext(ctx, "SELECT ts_ns, dir, wire_len, frame FROM packets WHERE conn_id = ? ORDER BY id", c.id)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []finalPkt
	for rows.Next() {
		var p finalPkt
		if err := rows.Scan(&p.ts, &p.dir, &p.wireLen, &p.frame); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
