package store

import (
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// quicLong devolve um pacote QUIC v1 de cabeçalho longo do tipo typ (0 Initial, 2 Handshake) com DCID e SCID.
func quicLong(typ byte, dcid, scid []byte, size int) []byte {
	p := []byte{0xc0 | typ<<4 | 0x03}
	p = binary.BigEndian.AppendUint32(p, 1)
	p = append(p, byte(len(dcid)))
	p = append(p, dcid...)
	p = append(p, byte(len(scid)))
	p = append(p, scid...)
	return append(p, make([]byte, size-len(p))...)
}

// TestQUICCloseBeforeSecondInitial (task 125): o fim do QUIC do web aplicado antes do lote com o 2º Initial do
// cliente (DCID = SCID do espelho) não divide a conexão; um Initial realmente novo depois do fim abre outra.
func TestQUICCloseBeforeSecondInitial(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	in.flows.newID = fixedIDs()
	srvCID := []byte{0x5e, 0x5e, 0x5e, 0x5e, 0x01, 0x02, 0x03, 0x04}
	cliCID := []byte{0xc1, 0xc1, 0xc1, 0xc1}
	cl := &event.HTTP3Close{By: "client", How: event.QUICCloseConnection}
	// 1º voo do cliente e resposta do espelho (Initial + Handshake com o SCID escolhido por ele).
	run(t, in, 50, udpBatch(quicClient, quicMirror, []udpPkt{
		{0, true, quicLong(0, dcidA, cliCID, 1200)},
		{10, false, quicLong(0, cliCID, srvCID, 1200)},
		{11, false, quicLong(2, cliCID, srvCID, 900)},
	}), h3Msg(t, event.SubjectWebHTTP3Connection, quicClient, dcidA, 30, h3Conn("h3", true, nil)))
	// O fim chega antes dos pacotes do 2º voo, capturados antes dele.
	run(t, in, 60, h3Msg(t, event.SubjectWebHTTP3Connection, quicClient, dcidA, 80, h3Conn("h3", true, cl)))
	run(t, in, 4000, udpBatch(quicClient, quicMirror, []udpPkt{
		{20, true, quicLong(0, srvCID, cliCID, 1200)}, // 2º Initial coalescido com Handshake
		{25, true, quicShort(60)},
		{40, false, quicShort(900)},
		{70, true, quicShort(30)},
	}))
	if n := count(t, db, "SELECT count(*) FROM connections"); n != 1 {
		t.Fatalf("connection split: %d rows", n)
	}
	if n := count(t, db, "SELECT count(*) FROM stray_packets"); n != 0 {
		t.Fatalf("stray packets: %d", n)
	}
	var id string
	if err := db.QueryRow("SELECT conn_id FROM connections").Scan(&id); err != nil {
		t.Fatal(err)
	}
	r := recordOf(t, in, id)
	if r.Totals.In.Segments != 4 || r.Totals.Out.Segments != 3 || r.Proto != "quic/h3" || r.Close.How != "quic_close" {
		t.Fatalf("in=%d out=%d proto=%s close=%+v", r.Totals.In.Segments, r.Totals.Out.Segments, r.Proto, r.Close)
	}
	// Initial de conexão nova na mesma 5-tupla depois do fim (DCID novo): abre outra conexão.
	run(t, in, 6000, udpBatch(quicClient, quicMirror, quicPackets(dcidB, 4100)),
		h3Msg(t, event.SubjectWebHTTP3Connection, quicClient, dcidB, 4130, h3Conn("h3", true, nil)))
	if n := count(t, db, "SELECT count(*) FROM connections"); n != 2 {
		t.Fatalf("new Initial after close: %d rows", n)
	}
}

// TestQUICLongSCID cobre a leitura do SCID nos cabeçalhos longos.
func TestQUICLongSCID(t *testing.T) {
	udp := func(p []byte) []byte { return append(make([]byte, 8), p...) }
	scid := []byte{1, 2, 3}
	if s, ok := quicLongSCID(udp(quicLong(2, dcidA, scid, 100))); !ok || s != hex.EncodeToString(scid) {
		t.Fatalf("handshake: %q %v", s, ok)
	}
	for name, p := range map[string][]byte{
		"short":     quicShort(40),
		"vn":        {0xc0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0},
		"truncated": {0xc0, 0, 0, 0, 1, 4, 1, 2, 3, 4, 5, 1},
		"too long":  {0xc0, 0, 0, 0, 1, 0, 21, 0, 0, 0, 0},
	} {
		if _, ok := quicLongSCID(udp(p)); ok {
			t.Errorf("%s: accepted", name)
		}
	}
}
