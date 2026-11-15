package store

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// Testes do relógio de captura (ADR 0041 item 2, task 242): o ingest atrasado L em relação à parede (cada lote
// processado L depois do instante de captura dos seus pacotes) dá os mesmos registros que o ingest em dia.

// lags são os atrasos simulados: acima da ociosidade do meio-aberto (10 s) e acima da do UDP e de eventOnlyIdle
// (30 s) e do max_age do stream (60 s).
var lags = []time.Duration{20 * time.Second, 70 * time.Second}

// stepAt faz o que o laço Run faz com um lote buscado: process com a parede em base+wallMs e, depois,
// afterBatch (fluxos vencidos e finalização).
func stepAt(t *testing.T, in *Ingestor, wall time.Duration, msgs ...fakeMsg) {
	t.Helper()
	in.now = func() time.Time { return time.Unix(0, base).Add(wall) }
	src := make([]msgSource, len(msgs))
	for i, m := range msgs {
		src[i] = m
	}
	if err := in.process(context.Background(), src); err != nil {
		t.Fatal(err)
	}
	in.afterBatch(context.Background())
}

func ms(n int) time.Duration { return time.Duration(n) * time.Millisecond }

// TestLagTCPHandshakeSplit: SYN/SYN-ACK num lote e o ACK do handshake no seguinte, FIN dos dois lados num lote
// e o ACK final depois da folga de fechamento: um registro completo, nenhum avulso, o ACK final como tardio.
func TestLagTCPHandshakeSplit(t *testing.T) {
	for _, lag := range lags {
		t.Run(lag.String(), func(t *testing.T) {
			in, db := newTestIngestor(t, nil) // CloseGrace 1 s
			stepAt(t, in, lag+ms(10), batch(client, mirror, protoTCP, fullTCP[:2]))
			stepAt(t, in, lag+ms(40), batch(client, mirror, protoTCP, fullTCP[2:6]))
			stepAt(t, in, lag+ms(1050), batch(client, mirror, protoTCP, fullTCP[6:8]))
			// sem o ACK final, a conexão fecha na folga (1 s depois do 2º FIN) pelo relógio de captura
			stepAt(t, in, lag+ms(2051))
			if n := count(t, db, "SELECT count(*) FROM connections WHERE ended_ns IS NOT NULL"); n != 1 {
				t.Fatalf("closed connections after the grace: %d", n)
			}
			// ACK final atrasado: tardio da conexão gravada, não fragmento nem avulso
			stepAt(t, in, lag+ms(2100), batch(client, mirror, protoTCP, []pkt{{2060, true, tcpACK, 0}}))
			stepAt(t, in, lag+ms(20_000))
			if n := count(t, db, "SELECT count(*) FROM connections"); n != 1 {
				t.Fatalf("connections: %d", n)
			}
			if n := count(t, db, "SELECT count(*) FROM stray_packets"); n != 0 {
				t.Fatalf("stray packets: %d", n)
			}
			if v := in.metrics.Get("store_late_packets_total"); v != 1 {
				t.Fatalf("late packets: %v", v)
			}
			id, r := onlyConn(t, db)
			if r.Times == nil || r.Times.Syn == nil || r.Times.Established == nil || r.Close.How != "fin" || r.Close.By != "client" {
				t.Fatalf("times=%+v close=%+v", r.Times, r.Close)
			}
			if r.Totals.In.Segments != 6 || r.Totals.Out.Segments != 3 {
				t.Fatalf("totals %+v", r.Totals)
			}
			var data []byte
			if err := db.QueryRow("SELECT data FROM pcaps WHERE conn_id = ?", id).Scan(&data); err != nil {
				t.Fatal(err)
			}
			checkPcap(t, data, 9)
		})
	}
}

// TestLagQUICBeforeH3Event: datagramas QUIC antes do evento h3, eventos e mais datagramas depois, close do web:
// um registro quic/h3 fechado por quic_close, sem avulsos.
func TestLagQUICBeforeH3Event(t *testing.T) {
	for _, lag := range lags {
		t.Run(lag.String(), func(t *testing.T) {
			in, db := newTestIngestor(t, nil)
			msgs := h3Session(t, 1000)
			stepAt(t, in, lag+ms(60), msgs[0])
			stepAt(t, in, lag+ms(70), msgs[1:6]...)
			stepAt(t, in, lag+ms(900), udpBatch(quicClient, quicMirror, []udpPkt{
				{500, true, quicShort(40)}, {520, false, quicShort(400)}, {900, true, quicShort(30)},
			}))
			stepAt(t, in, lag+ms(1000), msgs[6])
			stepAt(t, in, lag+ms(2001)) // folga de 1 s depois do close do web
			if n := count(t, db, "SELECT count(*) FROM connections"); n != 1 {
				t.Fatalf("connections: %d", n)
			}
			if n := count(t, db, "SELECT count(*) FROM stray_packets"); n != 0 {
				t.Fatalf("stray packets: %d", n)
			}
			id, r := onlyConn(t, db)
			checkH3Record(t, r, 1000)
			if r.Totals.In.Segments != 5 || r.Totals.Out.Segments != 3 {
				t.Fatalf("totals %+v", r.Totals)
			}
			if count(t, db, "SELECT count(*) FROM pcaps WHERE conn_id = ?", id) != 1 {
				t.Fatal("pcap")
			}
		})
	}
}

// TestLagEventOnly: conexão conhecida só pelos eventos (sem pacotes), com o 2º evento 25 s depois do 1º: continua
// sendo a mesma conexão em memória (sem ir ao banco) e dá um registro.
func TestLagEventOnly(t *testing.T) {
	for _, lag := range lags {
		t.Run(lag.String(), func(t *testing.T) {
			in, db := newTestIngestor(t, nil)
			stepAt(t, in, lag, appMsg(t, event.SubjectRawSession, "tcp", client, mirror, 0, probeID, map[string]any{"mode": "echo"}))
			stepAt(t, in, lag+ms(2100)) // passou pendingWait: cria a conexão só de eventos
			if len(in.eventOnly) != 1 {
				t.Fatalf("event-only connections: %d", len(in.eventOnly))
			}
			stepAt(t, in, lag+ms(25_000), appMsg(t, event.SubjectWebHTTP1Request, "tcp", client, mirror, 25_000, probeID,
				http1Payload(0, "HTTP/1.1")))
			if len(in.eventOnly) != 1 {
				t.Fatalf("event-only connection forgotten before eventOnlyIdle (capture clock): %d", len(in.eventOnly))
			}
			if n := count(t, db, "SELECT count(*) FROM connections"); n != 1 {
				t.Fatalf("connections: %d", n)
			}
			if n := count(t, db, "SELECT count(*) FROM app_events"); n != 2 {
				t.Fatalf("app events: %d", n)
			}
		})
	}
}

// TestLagReservation: conn_id reservado pelo web no accept (parede) continua valendo para o SYN que o ingest só
// processa 70 s depois, com o stream inteiro atrasado.
func TestLagReservation(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	lag := 70 * time.Second
	id, reserved := in.flows.connID(protoTCP, client, mirror, base, base)
	if !reserved {
		t.Fatal("not reserved")
	}
	// tráfego de outra 5-tupla, atrasado como o resto do stream
	other := netip.AddrPortFrom(client.Addr().Next(), 41000)
	stepAt(t, in, lag-ms(5000), batch(other, mirror, protoTCP, []pkt{{-5000, true, tcpSYN, 0}}))
	stepAt(t, in, lag, batch(client, mirror, protoTCP, fullTCP[:3]))
	var got string
	if err := db.QueryRow("SELECT conn_id FROM connections WHERE src_port = ?", int(client.Port())).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != id {
		t.Fatalf("conn_id %s, reserved %s", got, id)
	}
}

// TestLagIdleWithoutTraffic: sem tráfego novo (T parado), o relógio de captura anda com a parede e a ociosidade
// do TCP estabelecido vence no prazo de sempre, contado do último pacote.
func TestLagIdleWithoutTraffic(t *testing.T) {
	in, db := newTestIngestor(t, nil) // TCPIdle 150 s
	lag := 20 * time.Second
	stepAt(t, in, lag+ms(40), batch(client, mirror, protoTCP, fullTCP[:6]))
	stepAt(t, in, lag+ms(40)+150*time.Second)
	if n := count(t, db, "SELECT count(*) FROM connections WHERE ended_ns IS NULL"); n != 1 {
		t.Fatalf("closed before the idle timeout: %d open", n)
	}
	stepAt(t, in, lag+ms(41)+150*time.Second)
	_, r := onlyConn(t, db)
	if r.Ended == nil || r.Close.How != "timeout" {
		t.Fatalf("not closed by idle: %+v", r.Close)
	}
}

// TestCaptureClock: C = min(parede, T + (parede − P)).
func TestCaptureClock(t *testing.T) {
	var c captureClock
	if c.at(1000) != 1000 {
		t.Fatal("nothing observed: wall")
	}
	c.observe(100, 1000) // 900 atrás
	if c.at(1000) != 100 || c.at(1500) != 600 {
		t.Fatalf("behind: %d %d", c.at(1000), c.at(1500))
	}
	c.observe(50, 1600) // instante mais antigo não recua
	if c.at(1600) != 700 {
		t.Fatalf("older ts moved the clock: %d", c.at(1600))
	}
	c.observe(5000, 2000) // ts à frente da parede: C não passa da parede
	if c.at(2100) != 2100 {
		t.Fatalf("ahead: %d", c.at(2100))
	}
}
