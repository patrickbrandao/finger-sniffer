package p0f

import (
	"os"
	"path"
	"testing"

	"github.com/patrickbrandao/finger-sniffer/pkg/fingerprint/internal/pcaptest"
)

// requireRealDB é ligado pelos testes linux_priv (vps602), onde o p0f.fp do deploy precisa existir.
var requireRealDB = false

// realDB carrega o p0f.fp real: FS_P0F_DB ou o caminho do deploy. Sem ele o teste é pulado (o p0f.fp é
// LGPL e não vai para o repositório; na vps602 o verify-full roda este teste com o arquivo instalado).
func realDB(t *testing.T) *DB {
	t.Helper()
	p := os.Getenv("FS_P0F_DB")
	if p == "" {
		p = "/finger-sniffer/etc/p0f.fp"
	}
	if _, err := os.Stat(p); err != nil {
		if requireRealDB {
			t.Fatalf("p0f.fp não encontrado em %s", p)
		}
		t.Skipf("p0f.fp não encontrado (%s); defina FS_P0F_DB", p)
	}
	db, err := LoadDB(p)
	if err != nil {
		t.Fatal(err)
	}
	return db
}

type flowState struct {
	seq    uint32
	synMSS uint16
	acked  bool
}

// observe percorre um pcap como o p0f -r: SYN abre o fluxo (repetição do mesmo SYN é ignorada), SYN+ACK só
// conta com fluxo aberto e uma vez, e assinatura de ferramenta encerra o fluxo.
func observe(t *testing.T, db *DB, file string) []pcaptest.P0FObs {
	t.Helper()
	pkts, err := pcaptest.Read(file)
	if err != nil {
		t.Fatal(err)
	}
	flows := map[string]*flowState{}
	var out []pcaptest.P0FObs
	for _, raw := range pkts {
		if raw.Tunneled {
			continue
		}
		p, err := Parse(raw.IP)
		if err != nil {
			continue
		}
		var key string
		cli, srv := raw.Src, raw.Dst
		switch {
		case p.IsSYN():
			key = pcaptest.FlowKey(raw.Src, raw.Dst)
			if f := flows[key]; f != nil && f.seq == p.Seq {
				continue
			}
			flows[key] = &flowState{seq: p.Seq}
		case p.IsSYNACK():
			key = pcaptest.FlowKey(raw.Dst, raw.Src)
			cli, srv = raw.Dst, raw.Src
			f := flows[key]
			if f == nil || f.acked {
				continue
			}
			f.acked = true
		default:
			continue
		}
		f := flows[key]
		o, err := db.Fingerprint(p, f.synMSS)
		if err != nil {
			t.Fatal(err)
		}
		if p.IsSYN() {
			f.synMSS = p.MSS
		}
		if o.Matched && o.Class == "!" {
			delete(flows, key)
		}
		if o.Mod != "syn" && o.Mod != "syn+ack" {
			continue
		}
		fields := map[string]string{"dist": o.Dist, "params": o.Params, "raw_sig": o.RawSig}
		if o.App {
			fields["app"] = o.OS
		} else {
			fields["os"] = o.OS
		}
		out = append(out, pcaptest.P0FObs{File: path.Base(file), Mod: o.Mod, Cli: cli, Srv: srv, Fields: fields})
	}
	return out
}

// TestP0FGolden compara assinatura e palpite com o p0f -r (testdata/p0f.golden.log, gerado por
// testdata/regen.sh): todas as observações syn e syn+ack, na mesma ordem.
func TestP0FGolden(t *testing.T) {
	db := realDB(t)
	golden, err := pcaptest.P0FGolden()
	if err != nil {
		t.Fatal(err)
	}
	byFile := map[string][]pcaptest.P0FObs{}
	for _, g := range golden {
		byFile[g.File] = append(byFile[g.File], g)
	}
	files, err := pcaptest.Files()
	if err != nil {
		t.Fatal(err)
	}
	total, syns := 0, 0
	for _, file := range files {
		name := path.Base(file)
		ours := observe(t, db, file)
		want := byFile[name]
		if len(ours) != len(want) {
			t.Errorf("%s: %d observações, p0f -r tem %d", name, len(ours), len(want))
		}
		for i := range min(len(ours), len(want)) {
			g, o := want[i], ours[i]
			total++
			if g.Mod == "syn" {
				syns++
			}
			if g.Mod != o.Mod || g.Cli != o.Cli || g.Srv != o.Srv {
				t.Errorf("%s #%d: %s %s→%s, p0f -r: %s %s→%s", name, i, o.Mod, o.Cli, o.Srv, g.Mod, g.Cli, g.Srv)
				continue
			}
			for _, k := range []string{"os", "app", "dist", "params", "raw_sig"} {
				if g.Fields[k] != o.Fields[k] {
					t.Errorf("%s #%d %s %s: %s = %q, p0f -r = %q", name, i, g.Mod, g.Cli, k, o.Fields[k], g.Fields[k])
				}
			}
		}
	}
	if syns < 70 {
		t.Fatalf("gabarito com só %d SYNs; regere com testdata/regen.sh", syns)
	}
	t.Logf("%d observações (%d SYNs) conferidas contra o p0f -r", total, syns)
}
