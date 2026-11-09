package capture

import "github.com/patrickbrandao/finger-sniffer/pkg/service"

// startMetrics são os contadores que o heartbeat leva desde o start, mesmo zerados, para que o store os exponha
// no /metrics antes do primeiro evento (spec 003 "Métricas"). Os nomes seguem docs/metrics.md: o heartbeat é um
// mapa plano sem rótulos, por isso o sentido vai no nome (capture_packets_in_total/_out_total).
var startMetrics = []string{
	"capture_packets_in_total",
	"capture_packets_out_total",
	"capture_batches_total",
	"capture_kernel_packets_total",
	"capture_kernel_drops_total",
	"capture_queue_freezes_total",
	"capture_filtered_userspace_total",
	"capture_offload_suspect_total",
	"capture_truncated_total",
	service.MetricDropped,
}

// initMetrics cria os contadores de startMetrics com 0 sem apagar valores já existentes.
func initMetrics(m *service.Metrics) {
	for _, name := range startMetrics {
		m.Add(name, 0)
	}
}
