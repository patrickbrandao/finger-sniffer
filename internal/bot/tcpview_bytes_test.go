package bot

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/netip"
	"runtime"
	"testing"
)

// tcpViewRecords são n objetos tcp do registro de conexão como o traefix manda (p0f e rttMicros vêm e o bot os
// ignora). `typical`: o SYN cru de um golden (curl no Linux) com o JA4T, o raw_sig, o TTL e o rttMicros prontos,
// iguais em toda conexão (textos compartilhados). `hostile`: sem SYN, JA4T e raw_sig prontos únicos por conexão
// (janela diferente), nada se compartilha.
func tcpViewRecords(t testing.TB, n int, hostile bool) [][]byte {
	t.Helper()
	g := loadGoldenSYNs(t, "curl-linux-v4")[0]
	syn := base64.StdEncoding.EncodeToString(g.ip)
	out := make([][]byte, 0, n)
	for i := range n {
		raw := fmt.Sprintf(`{"ja4t":%q,"p0f":%q,"ttl":53,"rttMicros":1834,"syn":%q}`, g.ja4t, g.p0fSig, syn)
		if hostile {
			raw = fmt.Sprintf(`{"ja4t":"%d_2-4-8-1-3_1460_7","p0f":"4:53+11:0:1460:%d,7:mss,sok,ts,nop,ws:df,id+:0","ttl":53,"rttMicros":1834}`,
				1_000_000+i, 1_000_000+i)
		}
		out = append(out, []byte(raw))
	}
	return out
}

// tcpViews monta as visões dos objetos como o ingest (buildTCPView).
func tcpViews(t testing.TB, recs [][]byte) []*ForkTCP {
	t.Helper()
	src := netip.MustParseAddr("198.51.100.7")
	out := make([]*ForkTCP, 0, len(recs))
	for i, raw := range recs {
		var tcp *traefixTCP
		if err := json.Unmarshal(raw, &tcp); err != nil {
			t.Fatal(err)
		}
		v := buildTCPView(tcp, src, nil).view
		if v == nil || v.JA4T == "" || v.MTUImplied() == nil {
			t.Fatalf("visão %d: %+v", i, v)
		}
		out = append(out, v)
	}
	return out
}

// TestIndexBytesTCPView: task 309 — o que a visão TCP do traefix soma ao connCost: a estrutura e só os textos que
// ela criou no interner (o JA4T único da hostil; o compartilhado conta uma vez, na primeira conexão). O heap medido
// fica no BenchmarkIndexTCPViewMemory, que mede sozinho.
func TestIndexBytesTCPView(t *testing.T) {
	saved := shared
	t.Cleanup(func() { shared = saved })
	for _, hostile := range []bool{false, true} {
		shared = &interner{max: maxInterned}
		views := tcpViews(t, tcpViewRecords(t, 3, hostile))
		for i, v := range views {
			want := forkTCPBytes
			if hostile || i == 0 {
				want += strBytes(len(v.JA4T))
			}
			if v.cost != want {
				t.Errorf("hostile=%v, conexão %d: custo %d, quer %d", hostile, i, v.cost, want)
			}
		}
	}
}

// BenchmarkIndexTCPViewMemory: task 309 (ADRs 0061 item 3 e 0064 item 3) — custo em bytes por conexão da visão TCP
// do traefix no índice, medido no heap, contra o que ela soma ao connCost (ADR 0057 item 2: ±25%), com 20 000
// visões típicas (textos compartilhados) e hostis (textos únicos). Antes da task 309: 150/264 B no heap.
func BenchmarkIndexTCPViewMemory(b *testing.B) {
	saved := shared
	b.Cleanup(func() { shared = saved })
	const n = 20_000
	for _, hostile := range []bool{false, true} {
		b.Run(fmt.Sprintf("hostile=%v", hostile), func(b *testing.B) {
			recs := tcpViewRecords(b, n, hostile)
			for range b.N {
				shared = &interner{max: maxInterned}
				before := heapObjects()
				views := tcpViews(b, recs)
				used := heapObjects() - before - float64(allocBytes(uintptr(cap(views))*ptrSize))
				var accounted int64
				for _, v := range views {
					accounted += v.cost
				}
				b.ReportMetric(used/n, "heap-B/conn")
				b.ReportMetric(float64(accounted)/n, "accounted-B/conn")
				b.ReportMetric(float64(accounted)/used, "accounted/heap")
				if r := float64(accounted) / used; r < 0.75 || r > 1.25 {
					b.Errorf("contabilidade fora de ±25%%: %d contabilizados, %.0f no heap (%.2f)", accounted, used, r)
				}
				runtime.KeepAlive(views)
			}
			runtime.KeepAlive(recs)
		})
	}
}

// TestForkTCPCompact: a visão TCP guarda o MSS e a família em vez dos três ponteiros e cabe na classe de 48 bytes
// do alocador (task 309); os derivados saem iguais aos do store (spec 013 RF-06a) nas duas famílias.
func TestForkTCPCompact(t *testing.T) {
	if forkTCPBytes > 48 {
		t.Errorf("ForkTCP custa %d bytes, quer ≤ 48", forkTCPBytes)
	}
	ja4t := "64240_2-4-8-1-3_1400_7"
	for _, tc := range []struct {
		src            string
		mtu, reduction int
	}{
		{"198.51.100.7", 1440, 60},
		{"2001:db8::7", 1460, 40},
	} {
		v := buildTCPView(&traefixTCP{JA4T: &ja4t}, netip.MustParseAddr(tc.src), nil).view
		if v == nil || deref2(v.SynMSS()) != 1400 || deref2(v.MTUImplied()) != tc.mtu || deref2(v.MSSReduction()) != tc.reduction {
			t.Errorf("%s: %+v", tc.src, v)
			continue
		}
		r := v.rules()
		if deref2(r.MTUImplied) != tc.mtu || deref2(r.MSSReduction) != tc.reduction || r.JA4T != ja4t {
			t.Errorf("%s: regras %+v", tc.src, r)
		}
	}
	// sem MSS no JA4T (lista de opções sem o 2): nenhum derivado
	noMSS := "64240_4-8-1-3_1460_7"
	if v := buildTCPView(&traefixTCP{JA4T: &noMSS}, netip.MustParseAddr("198.51.100.7"), nil).view; v == nil ||
		v.SynMSS() != nil || v.MTUImplied() != nil || v.MSSReduction() != nil || v.rules().MTUImplied != nil {
		t.Errorf("sem MSS: %+v", v)
	}
}
