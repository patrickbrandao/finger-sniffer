//go:build load

package main

// Classificação das falhas do gerador (conexões com erro no cliente, puladas pelo teto) pelo critério da ADR 0046
// item 2 (task 256): a falha é aceita como do cliente só quando, na mesma janela, o espelho não a acompanha (modo
// degradado desligado; kernel_drops, flows_dropped, conntrack -S drop/insert_failed/early_drop e nr_throttled sem
// crescer; backlog do ingest < 1 s) e os erros se concentram num caminho do cliente (família, protocolo) e não num
// serviço. O relatório diz qual condição sustenta a decisão, sem leitura manual dos brutos.

import (
	"fmt"
	"strings"
)

// Veredito das falhas do gerador.
const (
	genNoFailure    = "sem falha do gerador"
	genClientFault  = "falha do cliente aceita"
	genMirrorFault  = "falha do espelho"
	genPathShareMin = 0.8 // fração mínima dos erros num caminho (família/transporte) para dizer "concentrados"
)

// genFailureIn são os números da janela que o critério usa; -1 (ou nil) = não medido.
type genFailureIn struct {
	Errors       map[string]int // tipo do mix (h1, h3, raw-echo...) → conexões com erro no cliente
	Skipped      int
	H3Family     string  // "4" ou "6"
	Degraded     float64 // registros degraded da carga + Δ fs_store_connections_degraded_total
	KernelDrops  float64
	FlowsDropped float64          // Δ fs_store_flows_dropped_total (todos os motivos); -1 sem as coletas
	Conntrack    map[string]int64 // Δ do conntrack -S; nil sem os arquivos
	Throttled    map[string]int64 // Δ nr_throttled das units do espelho (-1 = sem a coluna)
	BacklogMax   float64          // máximo de fs_store_ingest_backlog_seconds nas amostras da janela
	BacklogN     int              // amostras do backlog na janela
}

type genCond struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	OK    bool   `json:"ok"`
}

// genFailure é o resultado: condições do servidor, distribuição dos erros por caminho e serviço e o veredito.
type genFailure struct {
	Errors     int            `json:"client_errors"`
	Skipped    int            `json:"skipped"`
	Conditions []genCond      `json:"conditions"`
	ByPath     map[string]int `json:"errors_by_path"` // "tcp/ipv4 h2" → n
	Verdict    string         `json:"verdict"`
	Reason     string         `json:"reason"`
}

// kindService diz qual serviço do espelho atende o tipo do mix.
func kindService(kind string) string {
	if strings.HasPrefix(kind, "raw") {
		return "raw"
	}
	return "web"
}

// kindPath é o caminho do cliente do tipo: o TCP sai sempre por IPv4 (run.go), o h3 pela família de -h3-family.
func kindPath(kind, h3Family string) string {
	if kind == "h3" {
		return "udp/ipv" + h3Family
	}
	return "tcp/ipv4"
}

func classifyGenFailure(in genFailureIn) genFailure {
	out := genFailure{Skipped: in.Skipped, ByPath: map[string]int{}}
	byPath, bySvc := map[string]int{}, map[string]int{}
	for k, n := range in.Errors {
		if n <= 0 {
			continue
		}
		out.Errors += n
		p := kindPath(k, in.H3Family)
		byPath[p] += n
		bySvc[kindService(k)] += n
		out.ByPath[p+" "+k] += n
	}
	cond := func(name, value string, ok bool) { out.Conditions = append(out.Conditions, genCond{name, value, ok}) }
	cond("modo degradado desligado (degraded 0)", fmtF(in.Degraded), in.Degraded == 0)
	cond("kernel_drops sem crescer", fmtF(in.KernelDrops), in.KernelDrops == 0)
	if in.FlowsDropped < 0 {
		cond("flows_dropped sem crescer", "não medido", false)
	} else {
		cond("flows_dropped sem crescer", fmtF(in.FlowsDropped), in.FlowsDropped == 0)
	}
	if in.Conntrack == nil {
		cond("conntrack -S drop/insert_failed/early_drop sem crescer", "não medido", false)
	} else {
		d, i, e := in.Conntrack["drop"], in.Conntrack["insert_failed"], in.Conntrack["early_drop"]
		cond("conntrack -S drop/insert_failed/early_drop sem crescer", fmt.Sprintf("%d / %d / %d", d, i, e), d == 0 && i == 0 && e == 0)
	}
	var thr []string
	thrOK, thrSeen := true, false
	for _, u := range keys(in.Throttled) {
		if v := in.Throttled[u]; v >= 0 {
			thrSeen = true
			thrOK = thrOK && v == 0
			if v != 0 {
				thr = append(thr, fmt.Sprintf("%s %d", u, v))
			}
		}
	}
	switch {
	case !thrSeen:
		cond("nr_throttled sem crescer (units do espelho)", "não medido", false)
	case thrOK:
		cond("nr_throttled sem crescer (units do espelho)", "0 em todas", true)
	default:
		cond("nr_throttled sem crescer (units do espelho)", strings.Join(thr, ", "), false)
	}
	if in.BacklogN == 0 {
		cond("backlog do ingest < 1 s", "sem amostras", false)
	} else {
		cond("backlog do ingest < 1 s", fmt.Sprintf("máx %.2f s (%d amostras)", in.BacklogMax, in.BacklogN), in.BacklogMax < 1)
	}

	// caminho do cliente: os erros se concentram numa família/transporte ou se espalham por mais de um serviço (o
	// que um defeito de um serviço não explica); concentrados num só serviço por vários caminhos, a falha é dele
	if out.Errors > 0 {
		pathOK, pathWhy := true, ""
		top, topN := "", 0
		for _, p := range keys(byPath) {
			if byPath[p] > topN {
				top, topN = p, byPath[p]
			}
		}
		share := float64(topN) / float64(out.Errors)
		svcs := keys(bySvc)
		switch {
		case share >= genPathShareMin:
			pathWhy = fmt.Sprintf("%.0f%% em %s", 100*share, top)
		case len(svcs) >= 2:
			pathWhy = fmt.Sprintf("espalhados por %s", strings.Join(svcs, " e "))
		default:
			pathOK = false
			pathWhy = fmt.Sprintf("só no serviço %s, por %d caminhos (maior %.0f%% em %s)", svcs[0], len(byPath), 100*share, top)
		}
		cond("erros concentrados num caminho do cliente, não num serviço", pathWhy, pathOK)
	}

	var bad, good []string
	for _, c := range out.Conditions {
		if c.OK {
			good = append(good, c.Name+": "+c.Value)
		} else {
			bad = append(bad, c.Name+": "+c.Value)
		}
	}
	switch {
	case out.Errors == 0 && out.Skipped == 0:
		out.Verdict, out.Reason = genNoFailure, "0 erros no cliente e 0 puladas"
	case len(bad) == 0:
		out.Verdict, out.Reason = genClientFault, "ADR 0046 item 2: "+strings.Join(good, "; ")
	default:
		out.Verdict, out.Reason = genMirrorFault, "condição não atendida: "+strings.Join(bad, "; ")
	}
	return out
}

// renderGenFailure escreve a seção do summary.md.
func renderGenFailure(b *strings.Builder, gf genFailure) {
	fmt.Fprintf(b, "\nFalhas do gerador (ADR 0046 item 2): %d conexões com erro no cliente, %d puladas pelo teto → **%s**.\n\n",
		gf.Errors, gf.Skipped, gf.Verdict)
	b.WriteString("| Condição | Medido | Atende |\n| --- | --- | --- |\n")
	for _, c := range gf.Conditions {
		ok := "sim"
		if !c.OK {
			ok = "**não**"
		}
		fmt.Fprintf(b, "| %s | %s | %s |\n", c.Name, c.Value, ok)
	}
	if len(gf.ByPath) > 0 {
		b.WriteString("\nErros no cliente por caminho (família/transporte) e tipo:\n\n| Caminho | Tipo | Serviço | Erros |\n| --- | --- | --- | --- |\n")
		for _, k := range keys(gf.ByPath) {
			p, kind, _ := strings.Cut(k, " ")
			fmt.Fprintf(b, "| %s | %s | %s | %d |\n", p, kind, kindService(kind), gf.ByPath[k])
		}
	}
}
