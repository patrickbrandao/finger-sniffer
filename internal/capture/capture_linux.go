//go:build linux

package capture

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/gopacket/gopacket/afpacket"
	"golang.org/x/net/bpf"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/service"
)

// Run abre a captura e publica os lotes até ctx terminar.
func Run(ctx context.Context, svc *service.Service, cfg Config) error {
	ifc, err := net.InterfaceByName(cfg.Iface)
	if err != nil {
		return fmt.Errorf("capture: %w", err)
	}
	prog, err := ExcludeFilter(cfg.Exclude)
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

	cls := &classifier{local: localAddrs(ifc), excluded: toSet(cfg.Exclude), mtu: ifc.MTU}
	health := NewHealth(cfg.Iface, cfg.NetStatus)
	svc.SetStatus(health.Status)
	batch := NewBatcher(cfg.BatchMax, cfg.BatchWait, cfg.Iface)
	m := svc.Metrics
	svc.Log.Info("capture started", "iface", cfg.Iface, "exclude", cfg.Exclude, "bpf_len", len(raw),
		"block_timeout", cfg.BlockTimeout.String())

	flush := func() {
		if msg := batch.Take(); msg != nil {
			svc.Producer.Publish(msg)
			m.Add("capture_batches_total", 1)
		}
	}
	stats := time.NewTicker(time.Second)
	defer stats.Stop()
	refresh := time.NewTicker(30 * time.Second)
	defer refresh.Stop()

	for ctx.Err() == nil {
		select {
		case <-stats.C:
			_, s3, err := tp.SocketStats()
			if err == nil {
				m.Set("capture_kernel_packets_total", float64(s3.Packets()))
				m.Set("capture_kernel_drops_total", float64(s3.Drops()))
				m.Set("capture_queue_freezes_total", float64(s3.QueueFreezes()))
				health.ObserveDrops(uint64(s3.Drops()))
			}
		case <-refresh.C:
			cls.local = localAddrs(ifc)
		default:
		}

		data, ci, err := tp.ZeroCopyReadPacketData()
		if err != nil {
			if errors.Is(err, afpacket.ErrTimeout) || errors.Is(err, afpacket.ErrPoll) {
				if batch.Due(time.Now()) {
					flush()
				}
				continue
			}
			return fmt.Errorf("capture: read: %w", err)
		}
		fr := parseFrame(data)
		if cls.excludedPort(fr) {
			m.Add("capture_filtered_userspace_total", 1)
			continue
		}
		dir := cls.direction(fr)
		fl := cls.flags(ci.Length, ci.CaptureLength)
		if fl&event.FlagOffloadSuspect != 0 {
			health.ObserveSuspect(1)
			m.Add("capture_offload_suspect_total", 1)
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
		if batch.Add(event.Packet{TsNs: ci.Timestamp.UnixNano(), Dir: dir, Flags: fl, WireLen: uint32(ci.Length), Frame: data}, now) || //nolint:gosec // frame < 64 KiB
			batch.Due(now) {
			flush()
		}
	}
	flush()
	return nil
}

func localAddrs(ifc *net.Interface) map[netip.Addr]bool {
	m := map[netip.Addr]bool{}
	addrs, _ := ifc.Addrs()
	for _, a := range addrs {
		if p, err := netip.ParsePrefix(a.String()); err == nil {
			m[p.Addr()] = true
		}
	}
	return m
}
