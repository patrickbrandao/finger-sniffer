//go:build linux

package capture

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"

	"github.com/gopacket/gopacket/afpacket"
	"golang.org/x/net/bpf"

	"github.com/patrickbrandao/finger-sniffer/pkg/service"
)

// Run abre a captura e publica os lotes até ctx terminar.
func Run(ctx context.Context, svc *service.Service, cfg Config) error {
	ifc, err := net.InterfaceByName(cfg.Iface)
	if err != nil {
		return fmt.Errorf("capture: %w", err)
	}
	prog, err := ExcludeFilter(cfg.Exclude, cfg.Snaplen)
	if err != nil {
		return err
	}
	raw, err := bpf.Assemble(prog)
	if err != nil {
		return fmt.Errorf("capture: bpf: %w", err)
	}

	tp, err := afpacket.NewTPacket(
		afpacket.OptInterface(cfg.Iface),
		afpacket.OptFrameSize(1<<16),
		afpacket.OptBlockSize(1<<20),
		afpacket.OptNumBlocks(16),
		afpacket.OptBlockTimeout(cfg.BlockTimeout),
		afpacket.OptPollTimeout(cfg.BatchWait),
		afpacket.SocketRaw,
		afpacket.TPacketVersion3,
	)
	if err != nil {
		return fmt.Errorf("capture: afpacket: %w", err)
	}
	defer tp.Close()
	if err := tp.SetBPF(raw); err != nil {
		return fmt.Errorf("capture: attach bpf: %w", err)
	}

	health := NewHealth(cfg.Iface, cfg.NetStatus)
	// Leitura inicial dos offloads (RF-06); o heartbeat (Status) a refaz a cada 5 s.
	aggOn, aggErr := health.Refresh()
	// Sem endereços no start a direção fica "in" até a próxima releitura (30 s); o serviço sobe assim mesmo.
	cls := &classifier{local: refreshLocal(svc.Log, cfg.Iface, nil, ifc.Addrs), excluded: toSet(cfg.Exclude), mtu: ifc.MTU, aggregating: health.Aggregating}
	svc.SetStatus(health.Status)
	batch := NewBatcher(cfg.BatchMax, cfg.BatchWait, cfg.Iface)
	m := svc.Metrics
	initMetrics(m)
	svc.Log.Info("capture started", "iface", cfg.Iface, "exclude", cfg.Exclude, "bpf_len", len(raw),
		"snaplen", cfg.Snaplen, "block_timeout", cfg.BlockTimeout.String(), "aggregating_offloads", aggOn,
		"offload_check_error", errString(aggErr))

	return runLoop(ctx, tpacketReader{tp}, loopEnv{
		metrics: m, health: health, cls: cls, batch: batch, batchWait: cfg.BatchWait, publish: svc.Producer.Publish,
		refresh: func() { cls.local = refreshLocal(svc.Log, cfg.Iface, cls.local, ifc.Addrs) },
	})
}

// tpacketReader adapta o *afpacket.TPacket ao packetReader do laço, traduzindo os erros do gopacket.
type tpacketReader struct{ tp *afpacket.TPacket }

func (r tpacketReader) ReadPacket() ([]byte, frameInfo, error) {
	data, ci, err := r.tp.ZeroCopyReadPacketData()
	switch {
	case err == nil:
		return data, frameInfo{Timestamp: ci.Timestamp, Length: ci.Length, CaptureLength: ci.CaptureLength}, nil
	case errors.Is(err, afpacket.ErrTimeout):
		return nil, frameInfo{}, errReadTimeout
	case errors.Is(err, afpacket.ErrPoll):
		return nil, frameInfo{}, errReadPoll
	}
	return nil, frameInfo{}, err
}

func (r tpacketReader) Stats() (kernelStats, error) {
	_, s3, err := r.tp.SocketStats()
	if err != nil {
		return kernelStats{}, err
	}
	return kernelStats{Packets: uint64(s3.Packets()), Drops: uint64(s3.Drops()), QueueFreezes: uint64(s3.QueueFreezes())}, nil
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// localAddrs lê os endereços locais da interface por addrs (ifc.Addrs, que pode falhar por erro de netlink).
func localAddrs(addrs func() ([]net.Addr, error)) (map[netip.Addr]bool, error) {
	list, err := addrs()
	if err != nil {
		return nil, err
	}
	m := map[netip.Addr]bool{}
	for _, a := range list {
		if p, err := netip.ParsePrefix(a.String()); err == nil {
			m[p.Addr()] = true
		}
	}
	return m, nil
}

// refreshLocal relê os endereços locais. Erro ou lista vazia não substitui a lista anterior (old), senão todo
// pacote de saída passaria a sair como "in" até a próxima releitura; registra Warn e devolve old (nil no start).
func refreshLocal(log *slog.Logger, iface string, old map[netip.Addr]bool, addrs func() ([]net.Addr, error)) map[netip.Addr]bool {
	fresh, err := localAddrs(addrs)
	if err != nil || len(fresh) == 0 {
		log.Warn("capture: local addresses unavailable; keeping previous list", "iface", iface,
			"err", errString(err), "kept", len(old))
		return old
	}
	return fresh
}
