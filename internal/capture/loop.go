package capture

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/service"
)

// Erros de leitura independentes da plataforma; o adaptador do AF_PACKET (capture_linux.go) traduz os do gopacket
// para estes, e o laço (runLoop) fica testável fora do Linux.
var (
	// errReadTimeout: o poll venceu o prazo sem pacote (afpacket.ErrTimeout).
	errReadTimeout = errors.New("capture: read timeout")
	// errReadPoll: o poll voltou com POLLERR (afpacket.ErrPoll), ou seja, o socket tem sk_err ligado.
	errReadPoll = errors.New("capture: poll error")
)

// pollErrorLimit é quanto tempo seguido de POLLERR o laço tolera antes de devolver erro. O sk_err (ENETDOWN, por
// exemplo, depois de a interface cair) só é limpo por recvmsg/SO_ERROR, que o anel TPACKET nunca chama; um socket
// novo nasce limpo, então o melhor é sair e deixar o systemd reabrir.
const pollErrorLimit = time.Second

// frameInfo é o que o laço usa dos metadados de captura de cada pacote.
type frameInfo struct {
	Timestamp     time.Time
	Length        int
	CaptureLength int
}

// kernelStats são as estatísticas do socket (spec 003 RF-07).
type kernelStats struct {
	Packets, Drops, QueueFreezes uint64
}

// packetReader é a fonte de pacotes do laço: o socket AF_PACKET em produção, um leitor falso nos testes.
type packetReader interface {
	// ReadPacket devolve o próximo frame (válido até a próxima chamada), errReadTimeout, errReadPoll ou outro erro
	// fatal.
	ReadPacket() ([]byte, frameInfo, error)
	Stats() (kernelStats, error)
}

// loopEnv reúne o que o laço precisa além do leitor.
type loopEnv struct {
	metrics   *service.Metrics
	health    *Health
	cls       *classifier
	batch     *Batcher
	batchWait time.Duration
	publish   func(*nats.Msg)
	// refresh relê os endereços locais (a cada 30 s); nil não relê.
	refresh func()
	// pollLimit sobrescreve pollErrorLimit (testes); zero usa o padrão.
	pollLimit time.Duration
}

// runLoop lê e publica os pacotes até ctx terminar ou a leitura falhar.
func runLoop(ctx context.Context, r packetReader, e loopEnv) error {
	m := e.metrics
	limit := e.pollLimit
	if limit <= 0 {
		limit = pollErrorLimit
	}
	flush := func() {
		if msg := e.batch.Take(); msg != nil {
			e.publish(msg)
			m.Add("capture_batches_total", 1)
		}
	}
	stats := time.NewTicker(time.Second)
	defer stats.Stop()
	refresh := time.NewTicker(30 * time.Second)
	defer refresh.Stop()
	// Início da sequência atual de POLLERR (zero = nenhuma).
	var pollSince time.Time

	for ctx.Err() == nil {
		select {
		case <-stats.C:
			if s, err := r.Stats(); err == nil {
				m.Set("capture_kernel_packets_total", float64(s.Packets))
				m.Set("capture_kernel_drops_total", float64(s.Drops))
				m.Set("capture_queue_freezes_total", float64(s.QueueFreezes))
				e.health.ObserveDrops(s.Drops)
			}
		case <-refresh.C:
			if e.refresh != nil {
				e.refresh()
			}
		default:
		}

		data, ci, err := r.ReadPacket()
		if err != nil {
			switch {
			case errors.Is(err, errReadTimeout):
				pollSince = time.Time{}
				if e.batch.Due(time.Now()) {
					flush()
				}
				continue
			case errors.Is(err, errReadPoll):
				now := time.Now()
				m.Add("capture_poll_errors_total", 1)
				e.health.ObservePollError()
				if pollSince.IsZero() {
					pollSince = now
				} else if now.Sub(pollSince) >= limit {
					flush()
					return errors.New("capture: socket error (POLLERR)")
				}
				if e.batch.Due(now) {
					flush()
				}
				// Sem pausa o poll volta na hora e o laço gira a 100% de um núcleo.
				sleepCtx(ctx, e.batchWait)
				continue
			}
			flush()
			return fmt.Errorf("capture: read: %w", err)
		}
		pollSince = time.Time{}
		handlePacket(data, ci, e, flush)
	}
	flush()
	return nil
}

// handlePacket classifica um frame, atualiza as métricas e o põe no lote.
func handlePacket(data []byte, ci frameInfo, e loopEnv, flush func()) {
	m, cls := e.metrics, e.cls
	fr := parseFrame(data)
	if cls.excludedPort(fr) {
		m.Add("capture_filtered_userspace_total", 1)
		return
	}
	dir := cls.direction(fr)
	fl := cls.flags(ci.Length, ci.CaptureLength)
	if cls.oversize(ci.Length) {
		e.health.ObserveSuspect(1)
	}
	if fl&event.FlagOffloadSuspect != 0 {
		m.Add("capture_offload_suspect_total", 1)
	}
	if fl&event.FlagTruncated != 0 {
		m.Add("capture_truncated_total", 1)
	}
	if dir == event.DirOut {
		m.Add("capture_packets_out_total", 1)
	} else {
		m.Add("capture_packets_in_total", 1)
	}
	if ci.Length > int(m.Get("capture_max_frame_bytes")) {
		m.Set("capture_max_frame_bytes", float64(ci.Length))
	}
	now := time.Now()
	pkt := event.Packet{TsNs: ci.Timestamp.UnixNano(), Dir: dir, Flags: fl, WireLen: uint32(ci.Length), Frame: data} //nolint:gosec // frame <= maxSnap
	if !e.batch.Fits(pkt) {
		flush()
	}
	if e.batch.Add(pkt, now) || e.batch.Due(now) {
		flush()
	}
}

// sleepCtx dorme d ou até ctx terminar.
func sleepCtx(ctx context.Context, d time.Duration) {
	if d <= 0 {
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
