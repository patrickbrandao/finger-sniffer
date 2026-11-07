//go:build spike && linux

// Comando spikecap: captura AF_PACKET (TPACKET_V3) e publica lotes FSPB v1 no JetStream (task 006).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gopacket/gopacket/afpacket"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/patrickbrandao/finger-sniffer/test/spike/flow"
	"github.com/patrickbrandao/finger-sniffer/test/spike/fspb"
)

const subject = "fs.v1.capture.packet"

func main() {
	iface := flag.String("iface", "eth0", "interface")
	natsURL := flag.String("nats", "nats://127.0.0.1:4222", "NATS URL")
	exclude := flag.String("exclude-ports", "48022,48161,9000,9001", "portas excluídas")
	maxBatch := flag.Int("batch", 256, "pacotes por lote")
	maxWait := flag.Duration("batch-wait", 5*time.Millisecond, "espera máxima do lote")
	flag.Parse()

	excluded := map[uint16]bool{}
	for _, p := range strings.Split(*exclude, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err == nil {
			excluded[uint16(n)] = true //nolint:gosec // porta
		}
	}
	local := localAddrs(*iface)

	tp, err := afpacket.NewTPacket(
		afpacket.OptInterface(*iface),
		afpacket.OptFrameSize(1<<16),
		afpacket.OptBlockSize(1<<20),
		afpacket.OptNumBlocks(16),
		afpacket.OptPollTimeout(*maxWait),
		afpacket.SocketRaw,
		afpacket.TPacketVersion3,
	)
	if err != nil {
		log.Fatalf("afpacket: %v", err)
	}
	defer tp.Close()

	nc, err := nats.Connect(*natsURL)
	if err != nil {
		log.Fatalf("nats: %v", err)
	}
	defer nc.Close()
	js, err := jetstream.New(nc, jetstream.WithPublishAsyncMaxPending(512))
	if err != nil {
		log.Fatalf("jetstream: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var (
		buf                                 = make([]byte, 0, 1<<20)
		count, published, pubErrs, filtered int64
		packets, bytesIn                    int64
		maxFrame                            int
		first                               time.Time
	)
	flush := func() {
		if count == 0 {
			return
		}
		msg := nats.NewMsg(subject)
		msg.Header.Set("Fs-Schema-Version", "1")
		msg.Header.Set("Fs-Service", "capture")
		msg.Header.Set("Fs-Service-Version", "spike")
		msg.Header.Set("Fs-Format", "fspb1")
		msg.Header.Set("Fs-Count", strconv.FormatInt(count, 10))
		msg.Header.Set("Fs-Iface", *iface)
		// Diagnóstico do spike: quando o lote saiu do capture.
		msg.Header.Set("Fs-Batch-Ns", strconv.FormatInt(time.Now().UnixNano(), 10))
		msg.Data = append([]byte(nil), buf...)
		if _, err := js.PublishMsgAsync(msg); err != nil {
			pubErrs++
		} else {
			published++
		}
		buf, count = buf[:0], 0
	}

	report := time.NewTicker(5 * time.Second)
	defer report.Stop()
	start := time.Now()
	for ctx.Err() == nil {
		select {
		case <-report.C:
			_, s3, _ := tp.SocketStats()
			out, _ := json.Marshal(map[string]any{
				"t": time.Since(start).Seconds(), "packets": packets, "bytes": bytesIn, "filtered": filtered,
				"batches": published, "publish_errors": pubErrs, "max_frame": maxFrame,
				"kernel_packets": s3.Packets(), "kernel_drops": s3.Drops(), "queue_freezes": s3.QueueFreezes(),
				"pending": js.PublishAsyncPending(),
			})
			fmt.Println(string(out))
		default:
		}

		data, ci, err := tp.ZeroCopyReadPacketData()
		if err != nil {
			// Prazo do poll: fecha lote parcial.
			if count > 0 && time.Since(first) >= *maxWait {
				flush()
			}
			continue
		}
		info := flow.Parse(data)
		if info.OK && (excluded[info.SrcPort] || excluded[info.DstPort]) {
			filtered++
			continue
		}
		dir := uint8(fspb.DirIn)
		if info.OK && local[info.Src] {
			dir = fspb.DirOut
		}
		var flags uint8
		if ci.Length > 1514 {
			flags |= fspb.FlagOffloadSuspect
		}
		if ci.CaptureLength < ci.Length {
			flags |= fspb.FlagTruncated
		}
		if count == 0 {
			first = time.Now()
		}
		buf = fspb.Append(buf, fspb.Record{
			TsNs: ci.Timestamp.UnixNano(), Dir: dir, Flags: flags,
			WireLen: uint32(ci.Length), Frame: data, //nolint:gosec // frame < 64 KiB
		})
		count++
		packets++
		bytesIn += int64(len(data))
		maxFrame = max(maxFrame, ci.Length)
		if count >= int64(*maxBatch) || time.Since(first) >= *maxWait {
			flush()
		}
	}
	flush()
	<-js.PublishAsyncComplete()
}

// localAddrs lista os IPs da interface (para decidir a direção).
func localAddrs(name string) map[netip.Addr]bool {
	m := map[netip.Addr]bool{}
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		log.Fatalf("iface: %v", err)
	}
	addrs, _ := ifc.Addrs()
	for _, a := range addrs {
		if p, err := netip.ParsePrefix(a.String()); err == nil {
			m[p.Addr()] = true
		}
	}
	return m
}
