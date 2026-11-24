package bot

import (
	"slices"
	"strconv"
	"testing"

	"github.com/patrickbrandao/finger-sniffer/internal/bot/agg"
	"github.com/patrickbrandao/finger-sniffer/internal/bot/rules"
)

// signalDetail devolve o detail do sinal no veredito ("", false sem ele).
func signalDetail(v Verdict, id string) (string, bool) {
	for _, s := range v.Signals {
		if s.ID == id {
			return s.Detail, true
		}
	}
	return "", false
}

// TestTTLSeen: as máscaras da hora viram listas crescentes por classe de SO, sem as classes vazias.
func TestTTLSeen(t *testing.T) {
	if got := ttlSeen([3]agg.TTLMasks{}); got != nil {
		t.Fatalf("sem máscaras: %+v", got)
	}
	got := ttlSeen([3]agg.TTLMasks{{TCP: 0b0010, H3: 0b0100}, {}, {TCP: 0b1011}})
	want := []rules.TTLSeen{{OS: "windows", TCP: []int{64}, H3: []int{128}}, {OS: "other", TCP: []int{32, 64, 255}}}
	if len(got) != len(want) {
		t.Fatalf("%+v", got)
	}
	for i := range want {
		if got[i].OS != want[i].OS || !slices.Equal(got[i].TCP, want[i].TCP) || !slices.Equal(got[i].H3, want[i].H3) {
			t.Fatalf("%+v, quer %+v", got, want)
		}
	}
}

// TestAggTTLTCPH3Mismatch: task 314 — o TTL inicial das conexões TCP e h3 do mesmo IP + site entra no comportamento
// da hora pela classe de SO do UA e dá ttl_tcp_h3_mismatch às requisições seguintes da mesma classe (ADR 0078 item 1).
func TestAggTTLTCPH3Mismatch(t *testing.T) {
	f := newFixture(t)
	port := 50300
	auth := func(proto, ua, ttl string) Verdict {
		port++
		h := traefixAuthHeaders("01JC0X3K8V2T7Q9F4M6P1"+strconv.Itoa(port), port, proto, ua)
		h["X-Traefix-Ttl"] = ttl
		if proto != "h3" {
			h["X-Traefix-Ja4t"] = ja4tFull
		}
		_, _, v, _ := f.authVerdict("internal", "", h)
		return v
	}
	// Windows: TCP com TTL 64 (proxy Linux no caminho) e h3 com 128 (a pilha do PC)
	if v := auth("h2", uaChromeWindows, "52"); slices.Contains(signalIDList(v.Signals), rules.SignalTTLTCPH3Mismatch) {
		t.Fatalf("sem h3 ainda: %v", signalIDList(v.Signals))
	}
	auth("h3", uaChromeWindows, "116")
	v := auth("h2", uaChromeWindows, "52")
	if d, ok := signalDetail(v, rules.SignalTTLTCPH3Mismatch); !ok || d != "ua os windows: initial ttl tcp [64], h3 [128] in the hour" {
		t.Fatalf("windows: %q %v", d, signalIDList(v.Signals))
	}
	// h3 também leva a marca
	if v := auth("h3", uaChromeWindows, "116"); !slices.Contains(signalIDList(v.Signals), rules.SignalTTLTCPH3Mismatch) {
		t.Fatalf("h3 sem a marca: %v", signalIDList(v.Signals))
	}
	// outra classe (macOS) no mesmo NAT: só os seus TTLs contam, TCP 64 e h3 64 se cruzam
	auth("h2", uaChrome, "52")
	if v := auth("h3", uaChrome, "52"); slices.Contains(signalIDList(v.Signals), rules.SignalTTLTCPH3Mismatch) {
		t.Fatalf("macos: %v", signalIDList(v.Signals))
	}
}

// TestAggRelayRTTGap: task 314 — as conexões TCP com tempos de relay do mesmo IP + site na hora dão
// relay_rtt_gap_agg a partir de 5 (ADR 0078 item 2); origem privada e h3 não contam.
func TestAggRelayRTTGap(t *testing.T) {
	port := 50400
	auth := func(f *fixture, ip, proto string) Verdict {
		port++
		h := traefixAuthHeaders("01JC0X3K8V2T7Q9F4M6P1"+strconv.Itoa(port), port, proto, uaChrome)
		h["X-Traefix-Src-Ip"], h["X-Traefix-Timing"] = ip, timingRelay
		_, _, v, _ := f.authVerdict("internal", "", h)
		return v
	}
	t.Run("fires from 5", func(t *testing.T) {
		f := newFixture(t)
		for i := range 5 {
			if v := auth(f, "198.51.100.90", "h2"); slices.Contains(signalIDList(v.Signals), rules.SignalRelayRTTGapAgg) {
				t.Fatalf("conexão %d, com %d antes: %v", i+1, i, signalIDList(v.Signals))
			}
		}
		v := auth(f, "198.51.100.90", "h2")
		d, ok := signalDetail(v, rules.SignalRelayRTTGapAgg)
		if !ok || d != "5 tcp connections in the hour: rtt gap > 10 ms in 5, > 30% of tcp rtt in 5, first byte > 5 ms in 5" ||
			!slices.Contains(signalIDList(v.Signals), rules.SignalRelayRTTGap) {
			t.Fatalf("agregado: %q %v", d, signalIDList(v.Signals))
		}
		// a conexão h3 do mesmo cliente leva a marca sem somar nas contagens
		if v := auth(f, "198.51.100.90", "h3"); !slices.Contains(signalIDList(v.Signals), rules.SignalRelayRTTGapAgg) {
			t.Fatalf("h3 sem a marca: %v", signalIDList(v.Signals))
		}
		if d, _ := signalDetail(auth(f, "198.51.100.90", "h2"), rules.SignalRelayRTTGapAgg); d[:1] != "6" {
			t.Fatalf("h3 contou: %q", d)
		}
	})
	t.Run("private origin and h3 do not count", func(t *testing.T) {
		f := newFixture(t)
		for range 6 {
			auth(f, "10.0.0.9", "h2")
		}
		if v := auth(f, "10.0.0.9", "h2"); slices.Contains(signalIDList(v.Signals), rules.SignalRelayRTTGapAgg) {
			t.Fatalf("origem privada: %v", signalIDList(v.Signals))
		}
		for range 6 {
			auth(f, "198.51.100.91", "h3")
		}
		if v := auth(f, "198.51.100.91", "h3"); slices.Contains(signalIDList(v.Signals), rules.SignalRelayRTTGapAgg) {
			t.Fatalf("h3: %v", signalIDList(v.Signals))
		}
	})
}
