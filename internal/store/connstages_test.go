package store

import (
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// Estágios garantidos da ADR 0076: o opened do canal do bot só com a conexão estabelecida e um closed para cada
// opened nos dois canais (com discarded quando a conexão sai do banco sem registro).

// stageRec é um estágio visto num dos canais.
type stageRec struct {
	stage     string // opened, updated, closed
	id        string
	discarded string
	ts        string
	started   string
	conn      connectionJSON // só no canal do bot
	connRaw   []byte
	raw       []byte
}

// stagesHarness liga ao ingestor o canal do bot e o tempo real, e acumula o que cada um recebeu.
type stagesHarness struct {
	in   *Ingestor
	p    *connPublisher
	sink *pubSink
	live func() []*liveMsg
	bot  []stageRec
	feed []stageRec
}

func newStagesHarness(t *testing.T, mut func(*IngestConfig)) *stagesHarness {
	t.Helper()
	in, p, sink := newPubIngestor(t, mut)
	h := NewHub(4096, 4)
	in.SetLive(h)
	c, err := h.join(LiveFilter{DstPort: -1}, "ws")
	if err != nil {
		t.Fatal(err)
	}
	return &stagesHarness{in: in, p: p, sink: sink, live: func() []*liveMsg {
		var out []*liveMsg
		for len(c.ch) > 0 {
			out = append(out, <-c.ch)
		}
		return out
	}}
}

// collect drena os dois canais e devolve o que chegou desde a última chamada.
func (h *stagesHarness) collect(t *testing.T) (bot, feed []stageRec) {
	t.Helper()
	for _, m := range drainPub(t, h.p, h.sink) {
		bot = append(bot, stageRec{
			stage: m.pay.Stage, id: m.conn.ConnID, discarded: m.conn.Discarded, ts: m.env.Ts, started: m.conn.Started,
			conn: m.conn, connRaw: m.pay.Connection, raw: m.raw,
		})
	}
	for _, m := range h.live() {
		stage, ok := strings.CutPrefix(m.kind, "connection.")
		if !ok {
			continue
		}
		ev, s := liveData(t, m)
		feed = append(feed, stageRec{stage: stage, id: s.ConnID, discarded: s.Discarded, ts: ev.Ts, started: s.Started})
	}
	h.bot = append(h.bot, bot...)
	h.feed = append(h.feed, feed...)
	return bot, feed
}

// stageList resume os estágios de uma conexão: "opened,closed:stray".
func stageList(rs []stageRec, id string) string {
	var out []string
	for _, r := range rs {
		if r.id != id {
			continue
		}
		s := r.stage
		if r.discarded != "" {
			s += ":" + r.discarded
		}
		out = append(out, s)
	}
	return strings.Join(out, ",")
}

// checkStageInvariant: por conn_id, no máximo um opened e, havendo opened, exatamente um closed depois dele; nada
// antes do opened (ADR 0076 item 2).
func checkStageInvariant(t *testing.T, channel string, rs []stageRec) {
	t.Helper()
	type st struct{ opened, closed, before int }
	seen := map[string]*st{}
	for _, r := range rs {
		s := seen[r.id]
		if s == nil {
			s = &st{}
			seen[r.id] = s
		}
		switch r.stage {
		case event.StageOpened:
			s.opened++
		case event.StageClosed:
			if s.opened == 0 {
				s.before++
			}
			s.closed++
		default:
			if s.opened == 0 || s.closed > 0 {
				s.before++
			}
		}
	}
	for id, s := range seen {
		if s.opened > 1 || s.before > 0 || (s.opened == 1 && s.closed != 1) || (s.opened == 0 && s.closed > 0) {
			t.Errorf("%s: %s has %s", channel, id, stageList(rs, id))
		}
	}
}

// checkInvariant fecha tudo o que estiver aberto (ociosidade) e confere a invariante nos dois canais.
func (h *stagesHarness) checkInvariant(t *testing.T) {
	t.Helper()
	const later = 10_000_000 // ms: além de toda ociosidade
	processAt(t, h.in, later)
	run(t, h.in, later)
	h.collect(t)
	checkStageInvariant(t, "bot", h.bot)
	checkStageInvariant(t, "feed", h.feed)
}

// onlyID devolve o conn_id único visto no tempo real.
func onlyID(t *testing.T, rs []stageRec) string {
	t.Helper()
	id := ""
	for _, r := range rs {
		if id != "" && r.id != id {
			t.Fatalf("more than one connection: %s, %s", id, r.id)
		}
		id = r.id
	}
	if id == "" {
		t.Fatal("no connection")
	}
	return id
}

// TestStagesStraySYN: SYN e retransmissões sem SYN-ACK até virar avulso → nada no canal do bot; no tempo real,
// connection.opened e um connection.closed com discarded stray no instante da decisão, junto dos packet.stray.
func TestStagesStraySYN(t *testing.T) {
	h := newStagesHarness(t, nil)
	run(t, h.in, 0, batch(client, mirror, protoTCP, []pkt{{0, true, tcpSYN, 0}, {1000, true, tcpSYN, 0}, {3000, true, tcpSYN, 0}}))
	decided := time.Unix(0, base).Add(20 * time.Second)
	h.in.now = func() time.Time { return decided }
	run(t, h.in, 20_000)
	bot, feed := h.collect(t)
	if len(bot) != 0 {
		t.Fatalf("stray SYN published %d bot stages: %s", len(bot), bot[0].raw)
	}
	id := onlyID(t, feed)
	if got := stageList(feed, id); got != "opened,closed:stray" {
		t.Fatalf("feed %q", got)
	}
	if feed[1].ts != event.FormatTime(decided) {
		t.Fatalf("closed ts %s, want the decision %s", feed[1].ts, event.FormatTime(decided))
	}
	if n := count(t, h.in.db, "SELECT count(*) FROM connections"); n != 0 {
		t.Fatalf("%d connections", n)
	}
	h.checkInvariant(t)
}

// TestStagesNeverEstablished: SYN, SYN-ACK e RST, ou SYN-ACK seguido de silêncio → nada no canal do bot; no tempo
// real, opened e closed normais (a conexão tem registro).
func TestStagesNeverEstablished(t *testing.T) {
	h := newStagesHarness(t, nil)
	other := netip.MustParseAddrPort("192.0.2.11:5000")
	run(t, h.in, 0,
		batch(client, mirror, protoTCP, []pkt{{0, true, tcpSYN, 0}, {10, false, tcpSYN | tcpACK, 0}, {20, true, tcpRST, 0}}),
		batch(other, mirror, protoTCP, []pkt{{0, true, tcpSYN, 0}, {10, false, tcpSYN | tcpACK, 0}}))
	run(t, h.in, 20_000)
	bot, feed := h.collect(t)
	if len(bot) != 0 {
		t.Fatalf("never established published to the bot: %s", bot[0].raw)
	}
	if n := count(t, h.in.db, "SELECT count(*) FROM connections WHERE ended_ns IS NOT NULL"); n != 2 {
		t.Fatalf("%d stored connections", n)
	}
	ids := map[string]bool{}
	for _, r := range feed {
		ids[r.id] = true
	}
	for id := range ids {
		if got := stageList(feed, id); got != "opened,closed" {
			t.Fatalf("feed %s %q", id, got)
		}
	}
	if len(ids) != 2 {
		t.Fatalf("feed connections %d", len(ids))
	}
	h.checkInvariant(t)
}

// TestStagesHandshake: handshake completo → opened no lote do ACK, com started do SYN e times.established, e
// closed no fim; evento de aplicação antes do ACK → um opened com o estado fundido, sem updated antes.
func TestStagesHandshake(t *testing.T) {
	h := newStagesHarness(t, func(c *IngestConfig) { c.CloseGrace = 100 * time.Millisecond })
	run(t, h.in, 0, batch(client, mirror, protoTCP, fullTCP[:2]))
	if bot, _ := h.collect(t); len(bot) != 0 {
		t.Fatalf("opened before the ACK: %s", bot[0].raw)
	}
	run(t, h.in, 30, batch(client, mirror, protoTCP, fullTCP[2:6]))
	bot, _ := h.collect(t)
	if len(bot) != 1 || bot[0].stage != event.StageOpened {
		t.Fatalf("ACK batch: %d stages", len(bot))
	}
	o := bot[0].conn
	if o.Started != event.FormatTime(time.Unix(0, base)) || o.Times == nil || o.Times.Established == nil ||
		*o.Times.Established != event.FormatTime(time.Unix(0, base+20e6)) || o.Ended != nil {
		t.Fatalf("opened %s", bot[0].raw)
	}
	run(t, h.in, 3000, batch(client, mirror, protoTCP, fullTCP[6:]))
	bot, _ = h.collect(t)
	if len(bot) != 1 || bot[0].stage != event.StageClosed || bot[0].discarded != "" || bot[0].id != o.ConnID {
		t.Fatalf("closed: %v", stageList(bot, o.ConnID))
	}

	// Evento de aplicação antes do ACK: opened com a camada de aplicação; o ACK depois não publica de novo.
	other := netip.MustParseAddrPort("192.0.2.11:5000")
	run(t, h.in, 5000, batch(other, mirror, protoTCP, fullTCP[:2]))
	run(t, h.in, 5010, appMsg(t, event.SubjectWebHTTP1Request, "tcp", other, mirror, 15, probeID, http1Payload(0, "HTTP/1.1")))
	bot, _ = h.collect(t)
	if len(bot) != 1 || bot[0].stage != event.StageOpened || len(bot[0].conn.HTTP) != 1 || bot[0].conn.Requests != 1 ||
		bot[0].conn.Times.Established != nil {
		t.Fatalf("event before the ACK: %v", stageList(bot, onlyID(t, bot)))
	}
	run(t, h.in, 5020, batch(other, mirror, protoTCP, fullTCP[2:6]))
	if bot, _ = h.collect(t); len(bot) != 0 {
		t.Fatalf("ACK after the opened published %s", stageList(bot, bot[0].id))
	}
	run(t, h.in, 9000, batch(other, mirror, protoTCP, fullTCP[6:]))
	h.collect(t)
	if got := stageList(h.bot, bot0ID(h.bot, 1)); got != "opened,closed" {
		t.Fatalf("event-first stages %q", got)
	}
	h.checkInvariant(t)
}

// bot0ID devolve o conn_id da n-ésima conexão (ordem do primeiro estágio) no canal.
func bot0ID(rs []stageRec, n int) string {
	var ids []string
	seen := map[string]bool{}
	for _, r := range rs {
		if !seen[r.id] {
			seen[r.id] = true
			ids = append(ids, r.id)
		}
	}
	if n < len(ids) {
		return ids[n]
	}
	return ""
}

// TestStagesUDP: UDP com uma resposta só → nada no canal do bot; UDP com datagrama do cliente depois da resposta →
// opened/closed.
func TestStagesUDP(t *testing.T) {
	h := newStagesHarness(t, nil)
	dnsSrv := netip.MustParseAddrPort("170.247.40.86:5353")
	run(t, h.in, 0, batch(client, dnsSrv, protoUDP, []pkt{{0, true, 0, 40}, {5, false, 0, 80}}))
	run(t, h.in, 40_000)
	bot, feed := h.collect(t)
	if len(bot) != 0 {
		t.Fatalf("answered once published to the bot: %s", bot[0].raw)
	}
	if got := stageList(feed, onlyID(t, feed)); got != "opened,closed" {
		t.Fatalf("feed %q", got)
	}

	other := netip.MustParseAddrPort("192.0.2.11:5000")
	run(t, h.in, 41_000, batch(other, dnsSrv, protoUDP, []pkt{{41_000, true, 0, 40}, {41_005, false, 0, 80}}))
	if bot, _ = h.collect(t); len(bot) != 0 {
		t.Fatal("opened on the answer")
	}
	run(t, h.in, 41_100, batch(other, dnsSrv, protoUDP, []pkt{{41_100, true, 0, 40}}))
	run(t, h.in, 80_000)
	bot, _ = h.collect(t)
	if got := stageList(bot, onlyID(t, bot)); got != "opened,closed" {
		t.Fatalf("conversed UDP %q", got)
	}
	if bot[0].started != event.FormatTime(time.Unix(0, base+41_000e6)) {
		t.Fatalf("started %s", bot[0].started)
	}
	h.checkInvariant(t)
}

// TestStagesEvicted: despejada pela tabela cheia → closed com discarded evicted (no canal do bot só a conversada,
// pela ADR 0069 o UDP não-QUIC respondido); o closed do bot é o golden store.connection.closed.discarded.json.
func TestStagesEvicted(t *testing.T) {
	h := newStagesHarness(t, nil)
	// TCP meio aberto despejado pela 5-tupla nova: só o tempo real tinha o opened.
	h.in.flows.maxFlows = 1
	other := netip.MustParseAddrPort("192.0.2.11:5000")
	run(t, h.in, 0, batch(client, mirror, protoTCP, []pkt{{0, true, tcpSYN, 0}}))
	h.in.now = func() time.Time { return time.Unix(0, base).Add(time.Second) }
	run(t, h.in, 10, batch(other, mirror, protoTCP, []pkt{{10, true, tcpSYN, 0}}))
	bot, feed := h.collect(t)
	if len(bot) != 0 {
		t.Fatalf("half-open published to the bot: %s", bot[0].raw)
	}
	first := bot0ID(feed, 0)
	if got := stageList(feed, first); got != "opened,closed:evicted" {
		t.Fatalf("evicted half-open %q", got)
	}
	for _, r := range feed {
		if r.id == first && r.stage == event.StageClosed && r.ts != event.FormatTime(time.Unix(0, base).Add(time.Second)) {
			t.Fatalf("evicted ts %s, want the store clock", r.ts)
		}
	}

	// UDP não-QUIC conversado despejado pelo teto do respondido (ADR 0069 item 2).
	h2 := newStagesHarness(t, nil)
	h2.in.flows.maxAnswered = 1
	dnsSrv := netip.MustParseAddrPort("170.247.40.86:5353")
	run(t, h2.in, 0, batch(client, dnsSrv, protoUDP, []pkt{{0, true, 0, 40}, {5, false, 0, 80}, {10, true, 0, 40}}))
	run(t, h2.in, 20, batch(other, dnsSrv, protoUDP, []pkt{{20, true, 0, 40}, {25, false, 0, 80}}))
	bot, feed = h2.collect(t)
	id := bot0ID(bot, 0)
	if got := stageList(bot, id); got != "opened,closed:evicted" {
		t.Fatalf("bot evicted UDP %q", got)
	}
	if got := stageList(feed, id); got != "opened,closed:evicted" {
		t.Fatalf("feed evicted UDP %q", got)
	}
	closed := bot[len(bot)-1]
	if closed.conn.Ended == nil || closed.conn.Totals.In.Segments != 2 {
		t.Fatalf("evicted record must be the memory state: %s", closed.raw)
	}
	if _, err := NewQueries(h2.in.db, h2.in.flows.live, 65535).Connection(t.Context(), id); err == nil {
		t.Fatal("evicted connection still in the API")
	}
	checkEventGolden(t, filepath.Join("testdata", "events", "store.connection.closed.discarded.json"), closed.raw)
	validateContract(t, "Connection", closed.connRaw)
	h.checkInvariant(t)
	h2.checkInvariant(t)
}

// TestStagesDeletedProbe: conexão estabelecida de um probe apagado pelo DELETE → closed com discarded deleted nos
// dois canais quando ela sai da tabela.
func TestStagesDeletedProbe(t *testing.T) {
	h := newStagesHarness(t, func(c *IngestConfig) { c.CloseGrace = 100 * time.Millisecond })
	run(t, h.in, 0, batch(client, mirror, protoTCP, fullTCP[:6]),
		appMsg(t, event.SubjectWebHTTP1Request, "tcp", client, mirror, 40, probeID, http1Payload(0, "HTTP/1.1")))
	id := openIDs(h.in)[0]
	h.in.flows.hide([]string{id})
	if _, err := h.in.db.Exec("DELETE FROM connections WHERE conn_id = ?", id); err != nil {
		t.Fatal(err)
	}
	run(t, h.in, 3000, batch(client, mirror, protoTCP, fullTCP[6:]))
	h.collect(t)
	if got := stageList(h.bot, id); got != "opened,updated,closed:deleted" {
		t.Fatalf("bot %q", got)
	}
	if got := stageList(h.feed, id); !strings.HasPrefix(got, "opened,") || !strings.HasSuffix(got, ",closed:deleted") {
		t.Fatalf("feed %q", got)
	}
	h.checkInvariant(t)
}

// TestStagesEventOnlyExpired: conexão só de eventos expirada por ociosidade → closed nos dois canais, com o
// registro gravado (sem discarded); com a linha apagada antes, discarded deleted.
func TestStagesEventOnlyExpired(t *testing.T) {
	h := newStagesHarness(t, nil)
	other := netip.MustParseAddrPort("192.0.2.11:5000")
	processAt(t, h.in, 0, appMsg(t, event.SubjectWebHTTP1Request, "tcp", client, mirror, 0, probeID, http1Payload(0, "HTTP/1.1")),
		appMsg(t, event.SubjectWebHTTP1Request, "tcp", other, mirror, 0, probeID, http1Payload(0, "HTTP/1.1")))
	processAt(t, h.in, 2500) // passou de pendingWait: cria as conexões só de eventos
	bot, feed := h.collect(t)
	if strings.Count(stageList(bot, bot0ID(bot, 0))+stageList(bot, bot0ID(bot, 1)), "opened") != 2 ||
		strings.Count(stageList(feed, bot0ID(feed, 0))+stageList(feed, bot0ID(feed, 1)), "opened") != 2 {
		t.Fatalf("event-only opened: bot %d feed %d", len(bot), len(feed))
	}
	gone := ""
	for _, r := range bot {
		if r.conn.Src.Port == int(other.Port()) {
			gone = r.id
		}
	}
	if _, err := h.in.db.Exec("DELETE FROM connections WHERE conn_id = ?", gone); err != nil {
		t.Fatal(err)
	}
	processAt(t, h.in, 40_000)
	h.collect(t)
	kept := bot0ID(h.bot, 0)
	if kept == gone {
		kept = bot0ID(h.bot, 1)
	}
	for _, ch := range []struct {
		name string
		rs   []stageRec
	}{{"bot", h.bot}, {"feed", h.feed}} {
		if got := stageList(ch.rs, kept); !strings.HasPrefix(got, "opened") || !strings.HasSuffix(got, "closed") {
			t.Fatalf("%s expired %q", ch.name, got)
		}
		if got := stageList(ch.rs, gone); !strings.HasPrefix(got, "opened") || !strings.HasSuffix(got, ",closed:deleted") {
			t.Fatalf("%s deleted %q", ch.name, got)
		}
	}
	if len(h.in.eventOnly) != 0 {
		t.Fatalf("event-only kept: %d", len(h.in.eventOnly))
	}
	h.checkInvariant(t)
}

// TestStagesRollback: o opened do bot e o closed da despejada sobrevivem ao lote desfeito (a reentrega refaz o
// opened uma vez; o despejo é refeito no lote seguinte), e a invariante vale nos dois canais.
func TestStagesRollback(t *testing.T) {
	h := newStagesHarness(t, func(c *IngestConfig) { c.CloseGrace = 100 * time.Millisecond })
	run(t, h.in, 0, batch(client, mirror, protoTCP, fullTCP[:2]))
	// Lote com o ACK e um evento desfeito: nenhum opened; a reentrega publica um.
	ack := batch(client, mirror, protoTCP, fullTCP[2:6])
	ev := appMsg(t, event.SubjectWebHTTP1Request, "tcp", client, mirror, 40, probeID, http1Payload(0, "HTTP/1.1"))
	undo := failOn(t, h.in.db, "app_events")
	if err := processErr(h.in, ack, ev); err == nil {
		t.Fatal("injected failure did not abort the batch")
	}
	undo()
	if bot, _ := h.collect(t); len(bot) != 0 {
		t.Fatalf("rolled back batch published %s", bot[0].stage)
	}
	run(t, h.in, 50, ack, ev)
	run(t, h.in, 3000, batch(client, mirror, protoTCP, fullTCP[6:]))
	h.collect(t)
	id := bot0ID(h.bot, 0)
	if got := stageList(h.bot, id); !strings.HasPrefix(got, "opened") || strings.Count(got, "opened") != 1 || !strings.HasSuffix(got, "closed") {
		t.Fatalf("bot after rollback %q", got)
	}

	// Despejo num lote desfeito: a linha volta com o rollback e o lote seguinte a apaga com o closed.
	h.in.flows.maxFlows = 1
	a := netip.MustParseAddrPort("192.0.2.20:6000")
	b := netip.MustParseAddrPort("192.0.2.21:6000")
	run(t, h.in, 4000, batch(a, mirror, protoTCP, []pkt{{4000, true, tcpSYN, 0}}))
	undo = failOn(t, h.in.db, "connections")
	if err := processErr(h.in, batch(b, mirror, protoTCP, []pkt{{4010, true, tcpSYN, 0}})); err == nil {
		t.Fatal("injected failure did not abort the batch")
	}
	undo()
	if n := count(t, h.in.db, "SELECT count(*) FROM connections WHERE src_port = 6000"); n != 1 {
		t.Fatalf("evicted row must come back with the rollback: %d", n)
	}
	run(t, h.in, 4020, batch(b, mirror, protoTCP, []pkt{{4010, true, tcpSYN, 0}}))
	h.collect(t)
	var aID string
	for _, r := range h.feed {
		if r.stage == event.StageClosed && r.discarded == discardedEvicted {
			aID = r.id
		}
	}
	if aID == "" || stageList(h.feed, aID) != "opened,closed:evicted" {
		t.Fatalf("evicted after rollback %q", stageList(h.feed, aID))
	}
	if n := count(t, h.in.db, "SELECT count(*) FROM connections WHERE conn_id = ?", aID); n != 0 {
		t.Fatal("evicted row kept")
	}
	h.checkInvariant(t)
}

// TestStagesAdoptedEventOnly: a conexão só de eventos adotada pelos pacotes atrasados (mesmo conn_id) tem um
// opened e um closed em cada canal: o opened da criação e o closed da conexão dos pacotes.
func TestStagesAdoptedEventOnly(t *testing.T) {
	h := newStagesHarness(t, func(c *IngestConfig) { c.CloseGrace = 100 * time.Millisecond })
	processAt(t, h.in, 0, appMsg(t, event.SubjectWebHTTP1Request, "tcp", client, mirror, 40, probeID, http1Payload(0, "HTTP/1.1")))
	processAt(t, h.in, 2500)
	run(t, h.in, 2600, batch(client, mirror, protoTCP, fullTCP))
	run(t, h.in, 5000)
	h.collect(t)
	id := onlyID(t, h.feed)
	if got := stageList(h.bot, id); strings.Count(got, "opened") != 1 || !strings.HasSuffix(got, "closed") {
		t.Fatalf("bot adopted %q", got)
	}
	if got := stageList(h.feed, id); strings.Count(got, "opened") != 1 || !strings.HasSuffix(got, "closed") {
		t.Fatalf("feed adopted %q", got)
	}
	h.checkInvariant(t)
}

// TestStagesOrphans: órfã do reinício publica closed no tempo real e, no canal do bot, só se o registro gravado
// mostrar a conexão estabelecida (ADR 0076 item 1).
func TestStagesOrphans(t *testing.T) {
	h := newStagesHarness(t, nil)
	other := netip.MustParseAddrPort("192.0.2.11:5000")
	run(t, h.in, 0, batch(client, mirror, protoTCP, fullTCP[:6]), batch(other, mirror, protoTCP, fullTCP[:2]))
	bot, _ := h.collect(t)
	est := onlyID(t, bot)
	// Reinício: a memória do ingest some, as linhas ficam abertas no banco.
	h.in.flows = newFlowTable(h.in.cfg)
	if err := h.in.recoverOrphans(t.Context()); err != nil {
		t.Fatal(err)
	}
	bot, feed := h.collect(t)
	if len(bot) != 1 || bot[0].id != est || bot[0].stage != event.StageClosed {
		t.Fatalf("bot orphans: %d stages", len(bot))
	}
	if len(feed) != 2 || feed[0].stage != event.StageClosed || feed[1].stage != event.StageClosed {
		t.Fatalf("feed orphans: %d stages", len(feed))
	}
	checkStageInvariant(t, "bot", h.bot)
	checkStageInvariant(t, "feed", h.feed)
}
