// Package docs confere a documentação derivada (este arquivo não é documentação: só testa os links).
package docs

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/patrickbrandao/finger-sniffer/internal/bot/webhook"
)

// linkRe acha links Markdown [texto](alvo); imagens e links externos são filtrados depois.
var linkRe = regexp.MustCompile(`\]\(([^)\s]+)\)`)

// headingRe acha títulos ATX para montar as âncoras no estilo do GitHub.
var headingRe = regexp.MustCompile(`(?m)^#{1,6} (.+)$`)

// slug imita o GitHub: minúsculas, sem pontuação (exceto - e _), espaços viram "-".
func slug(h string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(h)) {
		switch {
		case r == ' ':
			b.WriteRune('-')
		case r == '-' || r == '_':
			b.WriteRune(r)
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r > 127:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// stripFences remove os blocos de código (um "# comentário" dentro deles não é título).
func stripFences(s string) string {
	return regexp.MustCompile("(?s)```.*?```").ReplaceAllString(s, "")
}

// stripCode remove também os trechos de código, onde "](" não é link.
func stripCode(s string) string {
	return regexp.MustCompile("`[^`\n]*`").ReplaceAllString(stripFences(s), "")
}

func anchors(t *testing.T, path string) map[string]bool {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	out := map[string]bool{}
	for _, m := range headingRe.FindAllStringSubmatch(stripFences(string(data)), -1) {
		out[slug(m[1])] = true
	}
	return out
}

// TestRelativeLinks: todo link relativo dos .md de docs/ aponta para um arquivo existente e, com âncora, para um
// título existente.
func TestRelativeLinks(t *testing.T) {
	files, err := filepath.Glob("*.md")
	if err != nil || len(files) == 0 {
		t.Fatalf("nenhum .md em docs/: %v", err)
	}
	sub, _ := filepath.Glob("*/*.md")
	files = append(files, sub...)
	// O README de raiz também é do papel docs (spec 002) e aponta para docs/, specs e contratos.
	files = append(files, filepath.Join("..", "README.md"))
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range linkRe.FindAllStringSubmatch(stripCode(string(data)), -1) {
			target := m[1]
			if strings.Contains(target, "://") || strings.HasPrefix(target, "mailto:") {
				continue
			}
			file, anchor, _ := strings.Cut(target, "#")
			dest := f
			if file != "" {
				dest = filepath.Join(filepath.Dir(f), file)
				if _, err := os.Stat(dest); err != nil {
					t.Errorf("%s: link quebrado %q", f, target)
					continue
				}
			}
			if anchor != "" && strings.HasSuffix(dest, ".md") && !anchors(t, dest)[anchor] {
				t.Errorf("%s: âncora inexistente %q", f, target)
			}
		}
	}
}

// TestIndexListsGuides: o README lista todos os guias da pasta.
func TestIndexListsGuides(t *testing.T) {
	readme, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob("*.md")
	for _, f := range files {
		if f != "README.md" && !strings.Contains(string(readme), "]("+f+")") {
			t.Errorf("README.md não lista %s", f)
		}
	}
}

// TestIndexListsDevDocs: o índice de dev/ lista todos os documentos da pasta.
func TestIndexListsDevDocs(t *testing.T) {
	readme, err := os.ReadFile(filepath.Join("dev", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join("dev", "*.md"))
	for _, f := range files {
		name := filepath.Base(f)
		if name != "README.md" && !strings.Contains(string(readme), "]("+name+")") {
			t.Errorf("dev/README.md não lista %s", name)
		}
	}
}

// TestRootReadme: o README de raiz traz o aviso de tráfego público e aponta para docs, specs, contratos e licença.
func TestRootReadme(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	for _, want := range []string{
		"](docs/README.md)", "](docs/probes.md)", "](specs/INDEX.md)", "](cmd/finger-sniffer-store/openapi.yaml)",
		"](eventbus/nats/asyncapi.yaml)", "](LICENSE)", "](NOTICE)", "FoxIO License 1.1",
		"público", "10 minutos", "make verify-quick", "make deploy", "make tools",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("README.md sem %q", want)
		}
	}
}

// TestProbesMatrix: probes.md tem uma receita por caso da matriz da spec 017 (1–13), cada uma com o que procurar,
// os campos estáveis e as diferenças esperadas por proxy (ADR 0022), e documenta o Date e o date=0 (ADR 0021).
func TestProbesMatrix(t *testing.T) {
	data, err := os.ReadFile("probes.md")
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	heads := regexp.MustCompile(`(?m)^### Caso (\d+):`).FindAllStringSubmatchIndex(s, -1)
	if len(heads) != 13 {
		t.Fatalf("probes.md tem %d casos, quero 13", len(heads))
	}
	for i, h := range heads {
		num := s[h[2]:h[3]]
		if want := strconv.Itoa(i + 1); num != want {
			t.Errorf("caso fora de ordem: %s, quero %s", num, want)
		}
		end := len(s)
		if i+1 < len(heads) {
			end = heads[i+1][0]
		}
		body := s[h[0]:end]
		for _, want := range []string{"```console", "**Procurar**", "**Estáveis**", "**Diferenças esperadas**"} {
			if !strings.Contains(body, want) {
				t.Errorf("caso %s sem %q", num, want)
			}
		}
	}
	for _, want := range []string{
		"`date=0`", "### `Date`", "proxy HTTP", "túnel CONNECT", "HTTPS-proxy",
		"`PROXY:PORTA`", "absolute-form", "`Proxy-Connection`",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("probes.md sem %q", want)
		}
	}
}

func TestSlug(t *testing.T) {
	cases := map[string]string{
		"Controles de resposta: `/p/<id>/r?...`": "controles-de-resposta-pidr",
		"HTTP/1, h2 e h3":                        "http1-h2-e-h3",
		"Probe: `GET /api/v1/probes/{id}`":       "probe-get-apiv1probesid",
	}
	for in, want := range cases {
		if got := slug(in); got != want {
			t.Errorf("slug(%q) = %q, quero %q", in, got, want)
		}
	}
}

// TestHTTP3Fields: http3.md descreve os campos do HTTP3Info que os clientes e a página usam, inclusive os do contrato
// 0.3.2.
func TestHTTP3Fields(t *testing.T) {
	data, err := os.ReadFile("http3.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"`h3_settings`", "`h3_control_stream_seen`", "`transport_params`", "`date`"} {
		if !strings.Contains(string(data), want) {
			t.Errorf("http3.md sem %s", want)
		}
	}
}

// TestAuditF5Docs: os guias refletem os contratos (0.3.3, hoje 0.6.x) e as decisões da auditoria F5 (ADR 0023, e a 0026 no lugar da 0024): erros
// da API, métricas do capture publicadas desde a partida e as diferenças esperadas que a auditoria explicou.
func TestAuditF5Docs(t *testing.T) {
	want := map[string][]string{
		"api.md": {
			"versão 0.6.x", "## Erros", "de caminho", "rota inexistente", "`OPTIONS`", "204", "500",
			"invalid conn_id", "`started`", "`ended`", "/api/v1/dns",
		},
		"metrics.md": {
			"`fs_capture_packets_in_total`", "`fs_capture_packets_out_total`", "`fs_capture_truncated_total`",
			"`fs_capture_offload_suspect_total`", "`fs_capture_filtered_userspace_total`",
			"`fs_dropped_events_total`", "`fs_store_late_packets_total`", "desde a partida",
		},
		"probes.md": {
			"GOAWAY PROTOCOL_ERROR", "`streams[]`", "`Upgrade: h2c`", "`PS`", "`websocket.close.by: client`",
			"`close.by: server`", "`conn=close`", "`close=after`", "`ts_clock_group`", "**por par",
			"`times` vem `null`", "ADR 0026", "confirmou o recebimento", "IPs públicos",
		},
		"http3.md": {"ADR", "0026-fechamento-rapido-e-ajustes-da-release.md", "p95 ≤ 500 ms", "p95 252 ms", "`wait`"},
		"dev/auditoria-f5.md": {
			"## Resolução das tarefas 086 e 087", "ADR", "0.3.3", "task 089", "task 090",
			"**substituída** pela", "0026-fechamento-rapido-e-ajustes-da-release.md", "task 072",
		},
	}
	for file, items := range want {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, w := range items {
			if !strings.Contains(string(data), w) {
				t.Errorf("%s sem %q", file, w)
			}
		}
	}
}

// TestListenAndRecordReadyDocs: os guias dizem onde a API escuta (task 082, ADR 0023) e explicam o tempo até o
// registro com o rótulo reason e FS_TCP_CLOSE_GRACE (tasks 077 e 090), sem a folga antiga de 2 s do QUIC nem a
// meta provisória de 3 s da ADR 0024 (substituída pela 0026, task 109).
func TestListenAndRecordReadyDocs(t *testing.T) {
	want := map[string][]string{
		"api.md": {
			"`127.0.0.1`", "`FS_LISTEN_IPV4`", "`FS_LISTEN_IPV6`", "**nunca** em todos os endereços",
			"`FS_TCP_CLOSE_GRACE`", "`nat on mirror ports`", "`conntrack_loaded`", "differs from store",
		},
		"../README.md": {"`127.0.0.1`", "`FS_LISTEN_IPV4`/`FS_LISTEN_IPV6`"},
		"metrics.md": {
			"## Tempo até o registro", "`fs_store_record_ready_seconds{reason}`", "`close`", "`quic_close`",
			"`idle`", "`FS_TCP_CLOSE_GRACE`", "**100 ms**", "de 0 a 500 ms", "task 077", "task 090",
			"lida em `close` e `quic_close`", "fora da meta",
		},
		"http3.md": {"task 090", "100 ms", "#tempo-até-o-registro"},
		"probes.md": {
			"`FS_TCP_CLOSE_GRACE` (100 ms)", "task 090", "p95 ≤ 500 ms (ADR 0026)",
			"`packet.stray` decidido por ociosidade", "instante em que o store decidiu", "ADR 0026 §5",
		},
	}
	// frases da folga antiga do QUIC que não podem voltar
	banned := map[string][]string{
		"http3.md":   {"~2 s depois", "Esse atraso de ~2 s", "ADR 0024", "0024-registro-quic", "p95 ≤ 3 s"},
		"probes.md":  {"cerca de 2 s depois", "uns 2 s depois", "ADR 0024", "de 3 s"},
		"metrics.md": {"ADR [0024]", "0024-registro-quic", "p95 ≤ 3 s"},
	}
	for file, items := range want {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, w := range items {
			if !strings.Contains(string(data), w) {
				t.Errorf("%s sem %q", file, w)
			}
		}
		for _, b := range banned[file] {
			if strings.Contains(string(data), b) {
				t.Errorf("%s ainda diz %q", file, b)
			}
		}
	}
}

// TestConnectionCloseDocs: o guia não diz que o espelho fecha por causa do `Connection: close` da requisição
// (spec 005 RF-08, task 119); explica quem fecha, o pendurado até a ociosidade e como pedir o fechamento.
func TestConnectionCloseDocs(t *testing.T) {
	data, err := os.ReadFile("probes.md")
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	for _, w := range []string{
		"**`Connection: close` na requisição não faz o espelho fechar**", "espera o\nservidor fechar",
		"`idle_before_close_ms` ≈ 120000", "`/p/<id>/r?close=after`", "`idle=<s>`",
		"o `Connection: close` **não** faz o espelho fechar",
	} {
		if !strings.Contains(s, w) {
			t.Errorf("probes.md sem %q", w)
		}
	}
	for _, b := range []string{
		"o espelho fecha porque o cliente pediu `Connection: close`",
		"`frame=close`, `Connection: close` na requisição",
	} {
		if strings.Contains(s, b) {
			t.Errorf("probes.md ainda diz %q", b)
		}
	}
}

// TestContracts04Docs: api.md e probes.md descrevem os campos e parâmetros dos contratos 0.4.x (ADR 0029,
// mantidos no 0.6.x,
// task 124): settle/min_conns/wait_met e seus 400, os 4 instantes, ip.packets, TFO, alertas e keepalive.
func TestContracts04Docs(t *testing.T) {
	want := map[string][]string{
		"api.md": {
			"versão 0.6.x", "`settle`", "`min_conns`", "`wait_met`", "inclusive `wait=0s`",
			"settle and min_conns require wait", "`settle` fora de `0s`–`10s`", "`min_conns` fora de 1–1000",
			"`request_started_at`", "`request_ended_at`", "`response_started_at`", "`response_ended_at`",
			"Cada instante é **independente**", "RST_STREAM", "`ip.packets`", "`first_data`",
		},
		"probes.md": {
			"?wait=30s&settle=1s", "`wait_met: true`", "`&min_conns=N`", "--tcp-fastopen", "`tcp.syn.payload_b64`",
			"#### TCP Fast Open", "`0x15`", "**sem duplicar**", "`unknown_ca`", "**não mandam keepalive TCP**",
			"`ip.packets.{syn,ack,first_data}`", "os instantes `request_started_at`",
		},
	}
	for f, ws := range want {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		s := string(data)
		for _, w := range ws {
			if !strings.Contains(s, w) {
				t.Errorf("%s sem %q", f, w)
			}
		}
		if strings.Contains(s, "?wait=10s") && f == "probes.md" {
			t.Errorf("probes.md ainda coleta com ?wait=10s")
		}
	}
}

// TestMSSWindowDocs: probes.md ensina a ler o MSS, o MTU implícito e o teto pela janela só com campos do contrato
// (task 195): a conta sem timestamps, as referências 1460/1440, o aviso de clamping, a janela do SYN sem escala e
// a série da janela; sem citar consumidor específico (ADR 0028).
func TestMSSWindowDocs(t *testing.T) {
	data, err := os.ReadFile("probes.md")
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	for _, w := range []string{
		"#### MSS, MTU implícito e teto de throughput pela janela", `["mss", N]`, "`N + 40`", "`N + 60`",
		"Não some os 12 bytes", "1460 (IPv4) e 1440 (IPv6)", "PPPoE", "IPsec", "MSS clamping",
		"GRE (sem e com chave)", "6in4, 6rd, IPIP", "jumbo frames", "MTU mínimo do IPv6",
		"`janela_max = window × 2^S`", "nunca é escalada", "`teto_Mbps = janela × 8 / rtt_handshake_ms / 1000`",
		"`tcp.window_series`", "o SYN visto é o do proxy", "túnel L3",
	} {
		if !strings.Contains(s, w) {
			t.Errorf("probes.md sem %q", w)
		}
	}
	if strings.Contains(strings.ToLower(s), "tcp-analyzer") {
		t.Errorf("probes.md cita consumidor específico (ADR 0028)")
	}
}

// TestContracts05Docs: api.md e probes.md descrevem os campos do contrato 0.5.0 (ADR 0031, task 198): MSS e MTU
// pelo SYN, a tabela de referência com a ressalva do clamping, a leitura certa de segments_in e o ip.src_kind;
// o caso 7 nomeia o HTTPS-proxy sem a porta de um consumidor (task 189).
func TestContracts05Docs(t *testing.T) {
	want := map[string][]string{
		"api.md": {
			"versão 0.6.x", "contrato (0.6.x)", "ADRs 0029, 0031 e 0032", "### MSS, MTU implícito e tipo da origem",
			"`tcp.syn_mss`", "`tcp.mtu_implied`", "`tcp.mss_reduction`", "`ip.src_kind`",
			"anteriores ao 0.5.0", "`1460 − syn_mss`", "`1440 − syn_mss`", "MSS clamping",
			"`shared`", "`teredo`", "`6to4`", "`nat64`", "`other`", "`global`", ".tcp.syn_mss", ".ip.src_kind",
		},
		"probes.md": {
			"`tcp.syn_mss`", "`tcp.mtu_implied`", "`tcp.mss_reduction`", "`ip.src_kind`",
			"| Redução | MTU implícito | Causas prováveis (ou MSS clamping no mesmo valor) |",
			"| 220 (só IPv6) | 1280 |", "**Segmentos do cliente.**", "**não** se compara com `syn_mss`",
			"MSS do SYN-ACK do espelho", "1448 e\n1428", "PMTUD do cliente", "**Tipo da origem.**",
			"`teredo` (`2001::/32`)", "`6to4` (`2002::/16`)", "caminho é interno à operadora",
			"**na frente do servidor**", "**Não** indica NAT64 nem 464XLAT do cliente", ".tcp.mtu_implied",
			"Por\n  HTTPS-proxy também",
		},
	}
	for f, ws := range want {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		s := string(data)
		for _, w := range ws {
			if !strings.Contains(s, w) {
				t.Errorf("%s sem %q", f, w)
			}
		}
		for _, b := range []string{"4443", "versão 0.4.x", "contrato (0.4.x)", "versão 0.5.x", "contrato (0.5.x)"} {
			if strings.Contains(s, b) {
				t.Errorf("%s ainda diz %q", f, b)
			}
		}
	}
}

// TestContracts06Docs: os guias descrevem o contrato openapi 0.6.0 / asyncapi 0.5.0 (ADR 0032, task 207): teto do
// probe com truncated, 503 com Retry-After do wait e dos downloads, as marcas de corte novas, o WebSocket sem
// frames, e o filtro kind sem stream.dropped (task 178).
func TestContracts06Docs(t *testing.T) {
	want := map[string][]string{
		"api.md": {
			"versão 0.6.x", "ADR 0032", "**1000 conexões**", "`truncated: true`",
			"conjunto inteiro", "`GET /api/v1/connections?probe=<id>`", "**64** esperas `wait` simultâneas",
			"`Retry-After: 1`", "**4** downloads", "**60 s**", "### Marcas de corte e valores especiais (0.6.0)",
			"**ausente equivale a `false`**", "`http[].request_line.target_truncated`", "`tls.lists_truncated`",
			"`http3.transport_params_truncated`", "`http3.h3_settings_truncated`",
			"**continuam calculados\nsobre o ClientHello completo**", "`frames: []`", "`http2.streams[].stream_id` igual a `0`",
			"`http2.streams[].status` igual a `0`", "**com o terminador**", "só UDP", "IP do **cliente**", "ADR 0034",
			"suas conexões fechadas", "`http[].head_too_large`", "`http[].body.chunks_truncated`",
		},
		"realtime.md": {
			"`stream.dropped` **não é filtrável**", `invalid kind "stream.dropped"`,
			"`connection.opened`, `connection.updated`, `connection.closed`, `http.request`, `dns.query`, `packet.stray` |",
		},
		"http3.md":  {"`transport_params_truncated`", "`h3_settings_truncated`", "1024 parâmetros", "256 pares"},
		"probes.md": {"`websocket.frames: []`", "com o terminador CRLF ou LF", "o TCP fica fora desse limite", "não entra no `kind`"},
	}
	banned := map[string][]string{
		"api.md":      {"versão 0.5.x", "contrato (0.5.x)", "todas as conexões (completas)", "| 503 | só em", "<<<<<<<"},
		"realtime.md": {"lista separada por vírgula de tipos (abaixo)"},
		"probes.md":   {"ou descarta (`rate_limited: true`)"},
	}
	for f, ws := range want {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		s := string(data)
		for _, w := range ws {
			if !strings.Contains(s, w) {
				t.Errorf("%s sem %q", f, w)
			}
		}
		for _, b := range banned[f] {
			if strings.Contains(s, b) {
				t.Errorf("%s ainda diz %q", f, b)
			}
		}
	}
}

// Nomes de métricas no código (task 188): constantes Metric* (ou metric*, no bot) e literais passados a Metrics.Add/Set (ou m.Add/Set
// no capture), e os nomes das métricas nativas do store (prometheus Name/NewDesc).
var (
	metricConstRe   = regexp.MustCompile(`\b[mM]etric\w*\s*=\s*"([a-z0-9_]+)"`)
	metricLiteralRe = regexp.MustCompile(`(?:[mM]etrics|\bm)\.(?:Add|Set)\("([a-z0-9_]+)"`)
	metricNativeRe  = regexp.MustCompile(`(?:Name:\s*|NewDesc\()"(fs_[a-z0-9_]+)"`)
	replacedRe      = regexp.MustCompile(`"([a-z0-9_]+)":\s*true`)
)

// codeMetrics varre internal/ e pkg/service (sem testes) e devolve os nomes como aparecem no /metrics.
func codeMetrics(t *testing.T) map[string]string {
	t.Helper()
	replaced := map[string]bool{}
	src, err := os.ReadFile("../internal/store/metrics.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	i := strings.Index(s, "var replacedHeartbeat")
	if i < 0 {
		t.Fatal("replacedHeartbeat não achado em internal/store/metrics.go")
	}
	block := s[i : i+strings.Index(s[i:], "\n}")]
	for _, m := range replacedRe.FindAllStringSubmatch(block, -1) {
		replaced[m[1]] = true
	}
	if len(replaced) == 0 {
		t.Fatal("replacedHeartbeat vazio: o padrão do teste ficou velho")
	}
	out := map[string]string{}
	for _, root := range []string{"../internal", "../pkg/service"} {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for _, re := range []*regexp.Regexp{metricConstRe, metricLiteralRe} {
				for _, m := range re.FindAllStringSubmatch(string(data), -1) {
					if !replaced[m[1]] {
						out["fs_"+m[1]] = path
					}
				}
			}
			for _, m := range metricNativeRe.FindAllStringSubmatch(string(data), -1) {
				out[m[1]] = path
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return out
}

// TestMetricsDocCoversCode falha se uma métrica publicada pelo código (heartbeat ou nativa do store) faltar em
// docs/metrics.md (task 188).
func TestMetricsDocCoversCode(t *testing.T) {
	data, err := os.ReadFile("metrics.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(data)
	names := codeMetrics(t)
	// sanidade: o varredor acha os contadores de cada serviço e os nativos
	for _, n := range []string{
		"fs_capture_batches_total", "fs_web_acme_failures_total", "fs_raw_events_oversize_total",
		"fs_dns_rate_limited_total", "fs_store_bad_batches_total", "fs_dropped_events_total",
		"fs_web_h3_init_table_full_total", "fs_store_flows_dropped_total", "fs_store_live_dropped_total",
		"fs_bot_verdicts_total", "fs_bot_webhook_sent_total", "fs_bot_list_entries", "fs_bot_index_bytes",
	} {
		if _, ok := names[n]; !ok {
			t.Errorf("varredura do código não achou %s", n)
		}
	}
	if _, ok := names["fs_store_stray_total"]; ok {
		t.Error("nome de replacedHeartbeat não deveria entrar na lista")
	}
	nameRe := regexp.MustCompile("`" + `(fs_[a-z0-9_]+)`)
	documented := map[string]bool{}
	for _, m := range nameRe.FindAllStringSubmatch(doc, -1) {
		documented[m[1]] = true
	}
	for n, path := range names {
		if !documented[n] {
			t.Errorf("docs/metrics.md não cita %s (de %s)", n, path)
		}
	}
	// os alertas pedidos na task 188
	for _, q := range []string{
		"increase(fs_web_events_oversize_total[5m]) > 0", "increase(fs_store_bad_batches_total[5m]) > 0",
		"increase(fs_web_acme_failures_total[1h]) > 0",
	} {
		if !strings.Contains(doc, q) {
			t.Errorf("docs/metrics.md sem a consulta %q", q)
		}
	}
}

// probeURLNoPortRe acha URL da zona dos probes sem porta explícita; no finger-01 ela cairia no traefik (ADR 0038).
var probeURLNoPortRe = regexp.MustCompile(`(?:https?|wss?)://[^\s/"'` + "`" + `]*finger-west-01\.badblock\.net\.br/`)

// fenceRe acha os blocos de código, onde ficam os comandos que o leitor copia.
var fenceRe = regexp.MustCompile("(?s)```.*?```")

// TestFinger01Docs: os guias e o README de raiz descrevem o finger-01 (ADRs 0038 e 0039, task 233): sem o servidor
// e a zona anteriores fora das notas históricas de dev/, com hosts, zona, portas, Alt-Svc, HTTPS RR com prefixo,
// certificados A/B, limites, sysctls do host e o conntrack informativo; nenhum comando sonda a zona sem porta.
func TestFinger01Docs(t *testing.T) {
	// montados por partes para que o grep do critério de aceite da task 233 não ache este arquivo
	old := []string{"vps" + "602", "dns" + "-monitor"}
	files, _ := filepath.Glob("*.md")
	files = append(files, filepath.Join("..", "README.md"))
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		s := string(data)
		for _, b := range old {
			if strings.Contains(strings.ToLower(s), b) {
				t.Errorf("%s ainda cita %q (ADR 0038)", f, b)
			}
		}
		for _, block := range fenceRe.FindAllString(s, -1) {
			for _, m := range probeURLNoPortRe.FindAllString(block, -1) {
				t.Errorf("%s: comando com URL da zona sem porta (cai no traefik): %q", f, m)
			}
		}
	}
	// registros históricos de dev/: ficam como estão, com a nota no topo
	devs, _ := filepath.Glob(filepath.Join("dev", "*.md"))
	for _, f := range devs {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "vps"+"602") && !strings.Contains(string(data), "Medido no servidor anterior (vps"+"602), [ADR 0038]") {
			t.Errorf("%s cita o servidor anterior sem a nota histórica da ADR 0038", f)
		}
	}
	want := map[string][]string{
		"README.md": {
			"`finger-01.badblock.net.br`", "`finger-west-01.badblock.net.br`", "`170.247.40.86`",
			"`2804:231c:e500:cafe::86`", "`ens192`", "TCP **8080** e **8443**", "UDP **8443**", "`h3=\":8443\"; ma=60`",
			"`_8443._https.<nome>`", "NODATA", "**A**", "**B**", "TLS-ALPN-01", "`finger-sniffer.slice`",
			"`MemoryMax=10G`", "`CPUQuota=800%`", "store 6G", "`FS_MAX_CONNS=1000`", "`FS_MAX_NEW_CONNS_PER_S=250`", "192 MiB",
			"3 GiB", "128 MiB", "`net.ipv4.ip_default_ttl=128`", "`net.ipv4.tcp_mtu_probing=1`", "traefik",
		},
		"api.md": {
			"`https://finger-01.badblock.net.br:9000`", "`[2804:231c:e500:cafe::86]`", "3 GiB", "`nat on mirror ports`",
			"`conntrack_loaded`", "`nft_ruleset_lines`", "**tolerados**", "`net.ipv4.ip_default_ttl=128`",
			"`net.ipv4.tcp_mtu_probing=1`", "`ens192`", "padrão 1000 conexões simultâneas", "400 simultâneas e 100 novas/s",
			"`db space <n>% free`", "`db full`", "`fs_store_db_fs_bytes`", "`fs_store_db_full_total`",
			"`fs_store_db_full_dropped_total`", "`fs_store_purged_total{reason=\"space\"}`", "some no reinício do\n  host",
		},
		"http3.md":  {"**UDP 8443**", "`Alt-Svc: h3=\":8443\"; ma=60`", "_8443._https.", "RFC 9460 §2.3", "NODATA", "`alpn=\"h2\"`"},
		"probes.md": {"| TCP 8080, 8443 |", "| UDP 8443 |", "_8443._https.$H", "traefik", "padrão 192 MiB", "(1000) sessões"},
		"../README.md": {
			"`finger-01.badblock.net.br`", "`<id>.finger-west-01.badblock.net.br`", "| TCP 8080, 8443 |", "| UDP 8443 |",
			"traefik", "`ens192`", "finger-west-01.badblock.net.br:8443/p/", "finger-01.badblock.net.br:9000",
		},
	}
	for f, ws := range want {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, w := range ws {
			if !strings.Contains(string(data), w) {
				t.Errorf("%s sem %q", f, w)
			}
		}
	}
}

// TestFinger01Recaptured confere que as saídas recapturadas no finger-01 (task 233) estão nos docs: SYN-ACK do
// host no pcap, registros HTTPS com os hints, health com o motivo do certificado B provisório e o TFO sem cookie.
func TestFinger01Recaptured(t *testing.T) {
	want := map[string][]string{
		"api.md": {
			"Win=65160 Len=0 MSS=1460 SACK_PERM=1", "WS=4096", "janela 64260 e MSS 1440", "`cert_self_signed`", "\"nft_ruleset_lines\":57",
			"\"versions_match\": true", "\"iface\":\"ens192\"", "Host: k3x9q2mz7a.finger-west-01.badblock.net.br:8443",
		},
		"http3.md": {
			"alpn=\"h3,h2\" ipv4hint=170.247.40.86 ipv6hint=2804:231c:e500:cafe::86", "HTTP/3 200",
			"Saída real no finger-01", "\"value\": \"k3x9q2mz7a.finger-west-01.badblock.net.br:8443\"",
		},
		"probes.md": {
			"recapturadas no finger-01", "{\"tfo\":true,\"syn_data\":null,\"syn_len\":64,\"first_data_len\":162}",
			"conferidos no\nfinger-01.",
		},
	}
	for f, ws := range want {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, w := range ws {
			if !strings.Contains(string(data), w) {
				t.Errorf("%s sem a saída recapturada %q", f, w)
			}
		}
		// a data da captura no servidor anterior não pode ficar nas saídas trocadas
		if strings.Contains(string(data), "Mon, 09 Nov 2026") {
			t.Errorf("%s ainda tem a data da captura no servidor anterior", f)
		}
	}
}

// TestCertBAndRNF01 confere as ADRs 0043–0046 nos docs (tasks 249 e 257): o certificado B e a rota do traefik só
// com finger-01.badblock.net.br, a garantia do RNF-01 em 400/100 e o limite conhecido da v0.3.0 resolvido na F7.
func TestCertBAndRNF01(t *testing.T) {
	read := func(f string) string {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	tmsoft := "finger-01.tmsoft" + ".com.br"
	readme := read("README.md")
	api := read("api.md")
	for f, s := range map[string]string{"README.md": readme, "api.md": api, "../README.md": read("../README.md")} {
		for _, line := range strings.Split(s, "\n") {
			// o nome tmsoft só pode aparecer como nome de ssh do host, nunca ligado ao certificado B
			if strings.Contains(line, tmsoft) && (strings.Contains(line, "**B**") || strings.Contains(line, "TLS-ALPN-01")) {
				t.Errorf("%s liga %s ao certificado B: %q", f, tmsoft, line)
			}
			if strings.Contains(line, tmsoft) && !strings.Contains(line, "ssh") {
				t.Errorf("%s cita %s fora do papel de nome de ssh: %q", f, tmsoft, line)
			}
		}
		for _, bad := range []string{
			"garantia do RNF-01: 200", "garantia é 200", "200 e 50 novas/s", "200 conexões simultâneas", "meta da fase F7",
			"correção na F7", "ADR 0042",
		} {
			if strings.Contains(s, bad) {
				t.Errorf("%s ainda diz %q (RNF-01 é 400/100, ADR 0046)", f, bad)
			}
		}
	}
	for _, w := range []string{
		"- **B**: só `finger-01.badblock.net.br`", "garantia do RNF-01: 400 conexões simultâneas\n  e 100 novas/s",
		"0046-rnf-01-400-100-com-o-banco-em-ram.md", "Limite conhecido da `v0.3.0` no finger-01 (ADR 0043), **resolvido na F7**",
		"feed p99 ~1,9 s", "registro p95 ~1,5 s", "IO do disco da VM", "feed p99 352 ms", "registro p95 TCP 193 / QUIC 188 ms",
		"`MemoryMax=10G`", "some no reinício do host", "`db space <n>% free`", "`db full`",
	} {
		if !strings.Contains(readme, w) {
			t.Errorf("README.md sem %q", w)
		}
	}
	if !strings.Contains(api, "o **B** (só `finger-01.badblock.net.br`, ADR 0044)") {
		t.Error("api.md sem o certificado B só com finger-01.badblock.net.br")
	}
}

// verifyFsWebhook confere X-Fs-Signature e X-Fs-Timestamp de um webhook do bot. secretHex é o
// "webhook secret" impresso por `key create`; maxSkew recusa envios antigos (reenvio).
func verifyFsWebhook(secretHex, timestamp, signature string, body []byte, now time.Time, maxSkew time.Duration) bool {
	secret, err := hex.DecodeString(secretHex)
	if err != nil {
		return false
	}
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return false
	}
	if d := now.Sub(time.Unix(ts, 0)); d > maxSkew || d < -maxSkew {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(timestamp + "."))
	mac.Write(body)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(want), []byte(signature))
}

// fencedBlock devolve o conteúdo do primeiro bloco ```lang de doc que contém marker.
func fencedBlock(t *testing.T, doc, lang, marker string) string {
	t.Helper()
	re := regexp.MustCompile("(?s)```" + lang + "\n(.*?)```")
	for _, m := range re.FindAllStringSubmatch(doc, -1) {
		if strings.Contains(m[1], marker) {
			return m[1]
		}
	}
	t.Fatalf("bot.md sem bloco %s com %q", lang, marker)
	return ""
}

// TestBotWebhookExamples: os exemplos de verificação do webhook em bot.md (Go, Python e shell com openssl) aceitam
// uma assinatura gerada pelo pacote do bot e recusam corpo, segredo ou timestamp errados (spec 020, critério de
// aceite do webhook). O exemplo Go é a função verifyFsWebhook acima, idêntica ao bloco do documento.
func TestBotWebhookExamples(t *testing.T) {
	data, err := os.ReadFile("bot.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(data)
	src, err := os.ReadFile("docs_test.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	i := strings.Index(s, "// verifyFsWebhook confere")
	if i < 0 {
		t.Fatal("verifyFsWebhook não achada em docs_test.go")
	}
	goSrc := s[i : i+strings.Index(s[i:], "\n}\n")+3]
	if got := fencedBlock(t, doc, "go", "func verifyFsWebhook"); got != goSrc {
		t.Errorf("bloco Go de bot.md difere de verifyFsWebhook em docs_test.go:\n%s", got)
	}

	// segredo como a CLI gera (32 bytes) e imprime (hex); corpo VerdictEvent qualquer
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i*7 + 3)
	}
	secretHex := hex.EncodeToString(secret)
	body := []byte(`{"kind":"verdict","ts":"2026-11-16T12:00:00.060000000Z","verdict":{"class":"bot","score":70}}`)
	now := time.Now()
	ts := now.Unix()
	tsStr := strconv.FormatInt(ts, 10)
	sig := webhook.Sign(secret, ts, body)
	if !webhook.Verify(secret, tsStr, sig, body, now, 5*time.Minute) {
		t.Fatal("webhook.Verify recusa a própria assinatura")
	}

	// Go
	if !verifyFsWebhook(secretHex, tsStr, sig, body, now, 5*time.Minute) {
		t.Error("Go: assinatura válida recusada")
	}
	for name, ok := range map[string]bool{
		"corpo alterado":     verifyFsWebhook(secretHex, tsStr, sig, append(append([]byte{}, body...), ' '), now, 5*time.Minute),
		"segredo errado":     verifyFsWebhook(strings.Repeat("00", 32), tsStr, sig, body, now, 5*time.Minute),
		"timestamp velho":    verifyFsWebhook(secretHex, tsStr, sig, body, now.Add(10*time.Minute), 5*time.Minute),
		"segredo como texto": verifyFsWebhook(hex.EncodeToString([]byte(secretHex)), tsStr, sig, body, now, 5*time.Minute),
	} {
		if ok {
			t.Errorf("Go: aceitou %s", name)
		}
	}

	dir := t.TempDir()

	// Python: a função do documento, chamada por um harness que lê o corpo de um arquivo
	if py, err := exec.LookPath("python3"); err != nil {
		t.Log("python3 ausente: exemplo Python não executado")
	} else {
		code := fencedBlock(t, doc, "python", "def verify_fs_webhook") + `
import sys
print("ok" if verify_fs_webhook(sys.argv[1], sys.argv[2], sys.argv[3], open(sys.argv[4], "rb").read()) else "invalid")
`
		script := filepath.Join(dir, "verify.py")
		bodyFile := filepath.Join(dir, "body.bin")
		if err := os.WriteFile(script, []byte(code), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(bodyFile, body, 0o600); err != nil {
			t.Fatal(err)
		}
		for _, c := range []struct{ sig, want string }{{sig, "ok"}, {webhook.Sign([]byte("x"), ts, body), "invalid"}} {
			out, err := exec.Command(py, "-I", script, secretHex, tsStr, c.sig, bodyFile).CombinedOutput()
			if err != nil || strings.TrimSpace(string(out)) != c.want {
				t.Errorf("Python: quer %s, saiu %q (%v)", c.want, out, err)
			}
		}
	}

	// shell: o comando do documento, com openssl dgst
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Log("openssl ausente: exemplo de shell não executado")
	} else {
		cmd := fencedBlock(t, doc, "sh", "openssl dgst")
		if err := os.WriteFile(filepath.Join(dir, "body.json"), body, 0o600); err != nil {
			t.Fatal(err)
		}
		for _, c := range []struct{ sig, want string }{{sig, "ok"}, {webhook.Sign(secret, ts+1, body), "invalid"}} {
			sh := exec.Command("/bin/sh", "-c", cmd)
			sh.Dir = dir
			sh.Env = append(os.Environ(), "SECRET="+secretHex, "TS="+tsStr, "SIG="+c.sig)
			out, err := sh.CombinedOutput()
			if err != nil || strings.TrimSpace(string(out)) != c.want {
				t.Errorf("shell: quer %s, saiu %q (%v)", c.want, out, err)
			}
		}
	}
}

// botPathRe acha as rotas do openapi do bot (chaves de paths com dois espaços de recuo).
var botPathRe = regexp.MustCompile(`(?m)^  (/bot/v1/[^:]+):\n    (get|post):`)

// TestBotDoc: bot.md cita cada rota do openapi do bot com um exemplo curl, todos os sinais da spec 018, os códigos
// de erro da spec 020, o webhook, os três casos de integração, as limitações conhecidas, o uso não comercial e a
// retenção (task 286).
func TestBotDoc(t *testing.T) {
	data, err := os.ReadFile("bot.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(data)
	api, err := os.ReadFile("../cmd/finger-sniffer-bot/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	routes := botPathRe.FindAllStringSubmatch(string(api), -1)
	if len(routes) < 10 {
		t.Fatalf("só %d rotas achadas no openapi do bot: o padrão do teste ficou velho", len(routes))
	}
	for _, m := range routes {
		method, path := strings.ToUpper(m[2]), m[1]
		// o título leva o caminho até o "?" da query (ex. "GET /bot/v1/verdict?src_ip=...")
		if !strings.Contains(doc, "`"+method+" "+path) {
			t.Errorf("bot.md não tem a rota %s %s", method, path)
		}
		// exemplo curl: o prefixo fixo do caminho (antes do primeiro parâmetro) aparece num comando curl
		prefix, _, _ := strings.Cut(path, "{")
		found := false
		for _, line := range strings.Split(doc, "\n") {
			if strings.Contains(line, "curl ") && strings.Contains(line, prefix) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("bot.md sem exemplo curl de %s", path)
		}
	}
	spec, err := os.ReadFile("../specs/018-bot.md")
	if err != nil {
		t.Fatal(err)
	}
	signals := regexp.MustCompile("(?m)^\\| `([a-z0-9_]+)` \\| (?:incoerência|lista|comportamento) \\|").FindAllStringSubmatch(string(spec), -1)
	if len(signals) < 15 {
		t.Fatalf("só %d sinais achados na spec 018", len(signals))
	}
	for _, m := range signals {
		if !strings.Contains(doc, "| `"+m[1]+"` |") {
			t.Errorf("bot.md sem o sinal %s na tabela", m[1])
		}
	}
	for _, w := range []string{
		"`invalid_key`", "`rate_limited`", "`not_found`", "`bad_request`", "`missing_fork_headers`",
		"`payload_too_large`", "`forbidden_origin`", "`internal`", "Retry-After",
		"X-Fs-Signature", "X-Fs-Timestamp", "X-Fs-Key-Prefix", "1 s, 5 s e 30 s", "4xx não repete",
		"10.249.255.254:9003", "failOpen", "authResponseHeaders", "X-Traefix-Verdict: unavailable", "tmsoftbrasil/traefix",
		"spec 019", "url: https://finger-01.badblock.net.br:9002/bot/v1/ingest/traefik", ".finger-west-01.badblock.net.br:8443/p/",
		"mas não a ordem deles", "Automação não declarada de um Chrome real sai `human`", "Uso não comercial",
		"7 dias e 1 hora", "`observe`", "`block`", "key create", "forget",
		// forwardAuth do bot (ADRs 0058, 0062 e 0063): contrato 0.4.0, regras v1.3 (ADR 0060), perfil da spec 019
		// com X-Traefix-*, fail-open de 4xx, visão TCP, latest e o processo de andar juntos, licença FoxIO
		"versão\n0.4.0", "`v1.3`", "sem `Origin` e `Referer`", "O veredito por probe não vai ao feed nem ao webhook",
		"X-Traefix-Ja4h", "X-Traefix-Ja4t", "X-Traefix-Alpn", "X-Traefix-Conn-Id",
		"**Os backends leem só `X-Traefix-*`, nunca `X-Fs-*`.**", "fingerprint:\n      tcp: true", "rawBytes: true",
		"timeout: 200ms", "authRequestHeaders: [User-Agent, Accept, Accept-Language, Accept-Encoding]", "**nunca vazio**",
		"requestHeaders:\n          Authorization: \"Bearer fsk_...\"", "denyRequiresResponseHeader: X-Traefix-Verdict",
		"header: { name: X-Traefix-Verdict, value: unavailable }",
		"address: https://finger-01.badblock.net.br:9002/bot/v1/auth", "traefik_forwardauth_failopen_total{reason=\"http_4xx\"}",
		"4xx **sem** `X-Traefix-Verdict`", "403 **com** `X-Traefix-Verdict`", "o `Cookie` e o `Authorization` do visitante\nnunca vão ao bot",
		"`fs_bot_auth_ja4h_total{source}`", "`fs_bot_auth_fingerprint_total{kind,source}`",
		"`fs_bot_ingest_fingerprint_mismatch_total{kind}`", "`traefik_fingerprint_export_dropped_total{entrypoint,reason}`",
		"JA4T sem o MSS", "`traefix.fingerprint/v1`", "`TraefikIngestBatch`", "`traefix.fingerprint/v2`",
		"`tmsoftbrasil/traefix:latest`", "**andam juntos**", "`PT-nn`", "LicenseRef-FoxIO-1.1", "### Visão TCP do traefix",
	} {
		if !strings.Contains(doc, w) {
			t.Errorf("bot.md sem %q", w)
		}
	}
	// configuração antiga do traefix (antes das ADRs 0062 e 0063): não pode voltar a nenhum doc de docs/
	files, _ := filepath.Glob("*.md")
	sub, _ := filepath.Glob("*/*.md")
	for _, f := range append(files, sub...) {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, w := range []string{
			"experimental.fingerSniffer", "fingerSniffer:", "fingerSniffer=", "forwardAuth.fingerSniffer",
			"forwardauth.fingerSniffer", "apiKey", "headerPrefix: X-Fs-", "ingestURL", "fingersniffer_",
			"X-Fs-Verdict: unavailable",
		} {
			if strings.Contains(string(data), w) {
				t.Errorf("%s ainda cita a configuração antiga do traefix: %q", f, w)
			}
		}
	}
}
