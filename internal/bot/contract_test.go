package bot

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const openapiFile = "../../cmd/finger-sniffer-bot/openapi.yaml"

// redoclyPath: binário instalado por npm ci em scripts/contracts-tools (relativo a internal/bot).
const redoclyPath = "../../scripts/contracts-tools/node_modules/.bin/redocly"

// Refs dos schemas usados nos testes de contrato.
const (
	refError       = "#/components/schemas/Error"
	refHealth      = "#/components/schemas/BotHealth"
	refVerdict     = "#/components/schemas/Verdict"
	refIPRep       = "#/components/schemas/IPReputation"
	refFPStats     = "#/components/schemas/FingerprintStats"
	refEvent       = "#/components/schemas/VerdictEvent"
	refBatch       = "#/components/schemas/TraefikIngestBatch"
	refIngestReply = "#/paths/~1bot~1v1~1ingest~1traefik/post/responses/202/content/application~1json/schema"
	// refTraefixIngestBody é o corpo da rota de ingest (os dois esquemas, ADR 0062 item 2).
	refTraefixIngestBody = "#/paths/~1bot~1v1~1ingest~1traefik/post/requestBody/content/application~1json/schema"
)

// traefixSchemaCopy é a cópia do esquema publicado pelo traefix (ADR 0063 item 3).
const traefixSchemaCopy = "../../cmd/finger-sniffer-bot/traefix-fingerprint-v1.schema.json"

// contractValues junta os valores a validar por schema; o teste de contrato valida tudo num só lint por ref.
type contractValues map[string][][]byte

func (c contractValues) add(ref string, v []byte) { c[ref] = append(c[ref], append([]byte(nil), v...)) }

// validateContract valida cada valor contra o schema ref do openapi do bot com o mesmo Redocly do verify (como o
// teste de contrato do store): acrescenta uma rota sintética cuja resposta é o schema e cujos exemplos são os
// valores, e roda o lint (no-invalid-media-type-examples = erro). Com -short, ou sem o Redocly instalado fora do
// CI, o teste é pulado.
func validateContract(t *testing.T, ref string, values ...[]byte) {
	t.Helper()
	if out, err := lintContract(t, ref, values...); err != nil {
		t.Fatalf("%d valores não validam contra %s: %v\n%s", len(values), ref, err, out)
	}
}

func redoclyBin(t *testing.T) string {
	t.Helper()
	bin, err := filepath.Abs(redoclyPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(bin); err != nil {
		msg := "Redocly ausente (" + redoclyPath + "): rode npm ci --ignore-scripts --prefix scripts/contracts-tools"
		if os.Getenv("CI") == "true" {
			t.Fatal(msg)
		}
		t.Skip(msg)
	}
	return bin
}

func lintContract(t *testing.T, ref string, values ...[]byte) ([]byte, error) {
	t.Helper()
	return lintContractWith(t, ref, false, nil, values...)
}

// lintTraefixCopy valida os valores contra a cópia do esquema do traefix: o arquivo vai para o diretório
// temporário ao lado do openapi, e um componente sintético faz $ref a ele (task 302).
func lintTraefixCopy(t *testing.T, values ...[]byte) ([]byte, error) {
	t.Helper()
	const name = "traefix-fingerprint-v1.schema.json"
	return lintContractWith(t, "#/components/schemas/TraefixSchemaCopy", true, func(dir, spec string) string {
		b, err := os.ReadFile(traefixSchemaCopy)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
		const anchor = "\n  schemas:\n"
		if !strings.Contains(spec, anchor) {
			t.Fatal("openapi sem components.schemas")
		}
		return strings.Replace(spec, anchor, anchor+"    TraefixSchemaCopy: { $ref: \"./"+name+"\" }\n", 1)
	}, values...)
}

// lintContractWith é lintContract com prep (opcional), que recebe o diretório temporário e o openapi e devolve o
// openapi a validar (para acrescentar arquivos e componentes). additional valida os exemplos com a semântica do
// JSON Schema (propriedade a mais vale onde o schema não a proíbe), em vez do padrão do Redocly, que recusa
// qualquer propriedade não declarada: os lotes do traefix podem trazer campos e tipos novos (ADR 0063 item 2).
func lintContractWith(t *testing.T, ref string, additional bool, prep func(dir, spec string) string, values ...[]byte) ([]byte, error) {
	t.Helper()
	if testing.Short() {
		t.Skip("contrato via Redocly pulado com -short")
	}
	bin := redoclyBin(t)
	spec := string(openapiBytes(t))
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "testdata"), 0o750); err != nil {
		t.Fatal(err)
	}
	if prep != nil {
		spec = prep(dir, spec)
	}
	name := strings.ToLower(strings.NewReplacer("#", "", "/", "", "~1", "", "~0", "").Replace(ref))
	if len(name) > 40 {
		name = name[len(name)-40:]
	}
	var route strings.Builder
	fmt.Fprintf(&route, "  /contract-check/%s:\n    get:\n      tags: [health]\n      operationId: contractCheck\n      summary: x\n      security: []\n      responses:\n", name)
	fmt.Fprintf(&route, "        \"200\":\n          description: x\n          content:\n            application/json:\n              schema: { $ref: \"%s\" }\n              examples:\n", ref)
	for i, v := range values {
		file := fmt.Sprintf("contract-%03d.json", i)
		ex, _ := json.Marshal(map[string]any{"summary": "x", "value": json.RawMessage(v)})
		if err := os.WriteFile(filepath.Join(dir, "testdata", file), ex, 0o600); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&route, "                e%03d: { $ref: \"./testdata/%s\" }\n", i, file)
	}
	route.WriteString("        \"400\": { $ref: \"#/components/responses/BadRequest\" }\n")
	text := strings.Replace(spec, "\npaths:\n", "\npaths:\n"+route.String(), 1)
	if err := os.WriteFile(filepath.Join(dir, "openapi.yaml"), []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	redocly, err := os.ReadFile("../../redocly.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if additional {
		redocly = append(redocly, []byte("\n  # lotes do traefix: campos e tipos novos são aceitos (ADR 0063 item 2)\n"+
			"  no-invalid-media-type-examples: { severity: error, allowAdditionalProperties: true }\n")...)
		redocly = []byte(strings.Replace(string(redocly), "  no-invalid-media-type-examples: error\n", "", 1))
	}
	if err := os.WriteFile(filepath.Join(dir, "redocly.yaml"), redocly, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "lint", "--format=summary", "openapi.yaml") //nolint:gosec // binário do repositório
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "REDOCLY_TELEMETRY=off", "REDOCLY_SUPPRESS_UPDATE_NOTICE=true")
	return cmd.CombinedOutput()
}

// TestContractRejectsInvalidExample: o lint reprova um valor fora do schema (o teste não passa vazio).
func TestContractRejectsInvalidExample(t *testing.T) {
	if out, err := lintContract(t, refError, []byte(`{"error":"nope"}`)); err == nil {
		t.Fatalf("valor inválido aceito:\n%s", out)
	}
}

// TestContractResponses exercita cada rota implementada e valida as respostas contra o openapi do bot (critério
// da task 267: "cada resposta implementada valida contra o openapi do bot").
func TestContractResponses(t *testing.T) {
	if testing.Short() {
		t.Skip("contrato via Redocly pulado com -short")
	}
	f := newFixture(t)
	_, key := f.createKey(KeyOptions{Name: "c", Domains: []string{"example.com"}, Burst: 1, RatePerS: 1})
	_, key2 := f.createKey(KeyOptions{Name: "c2", Domains: []string{"*.example.org"}})
	vals := contractValues{}
	expect := func(want, got int, ref string, body []byte) {
		t.Helper()
		if got != want {
			t.Fatalf("status %d, esperado %d: %s", got, want, body)
		}
		vals.add(ref, body)
	}
	// Health e openapi sem chave.
	c, _, b := f.do(f.public, "GET", "/bot/v1/health", "", nil, "")
	expect(200, c, refHealth, b)
	// 401, 404, 400 e 429.
	c, _, b = f.do(f.public, "GET", "/bot/v1/verdict?src_ip=192.0.2.1&src_port=1&site=example.com", "", nil, "")
	expect(401, c, refError, b)
	c, _, b = f.do(f.public, "GET", "/bot/v1/verdict?src_ip=192.0.2.1&src_port=1&site=other.com", key2, nil, "")
	expect(404, c, refError, b)
	c, _, b = f.do(f.public, "GET", "/bot/v1/verdict/conn/bad", key2, nil, "")
	expect(400, c, refError, b)
	c, _, b = f.do(f.public, "GET", "/bot/v1/probes/abcdefgh12/verdict", key2, nil, "")
	expect(404, c, refError, b)
	c, _, b = f.do(f.public, "GET", "/bot/v1/auth", key2, nil, "")
	expect(400, c, refError, b)
	c, _, b = f.do(f.public, "GET", "/bot/v1/ip/192.0.2.1", key, nil, "")
	expect(200, c, refIPRep, b)
	c, h, b := f.do(f.public, "GET", "/bot/v1/ip/192.0.2.1", key, nil, "")
	expect(429, c, refError, b)
	if h.Get("Retry-After") == "" {
		t.Error("429 sem Retry-After")
	}
	// Agregados com linhas (gravadas à mão: o flush dos agregados é da segunda onda).
	hour := f.clock.Now().Unix() / 3600
	if _, err := f.db.Exec(`INSERT INTO ip_hourly (ip, site, hour, requests, conns, class_bot) VALUES (?, 'a.example.org', ?, 5, 2, 1)`,
		ipKey(mustAddr("192.0.2.1")), hour); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(`INSERT INTO fp_daily (kind, value, day, ua_family, requests, ips) VALUES ('ja4', 't13d1516h2_8daaf6152771_02713d6af862', ?, 'curl', 3, 1)`,
		f.clock.Now().Unix()/86400); err != nil {
		t.Fatal(err)
	}
	c, _, b = f.do(f.public, "GET", "/bot/v1/ip/192.0.2.1", key2, nil, "")
	expect(200, c, refIPRep, b)
	c, _, b = f.do(f.public, "GET", "/bot/v1/fingerprints/ja4/t13d1516h2_8daaf6152771_02713d6af862", key2, nil, "")
	expect(200, c, refFPStats, b)
	c, _, b = f.do(f.public, "GET", "/bot/v1/fingerprints/ja3/x", key2, nil, "")
	expect(400, c, refError, b)
	// Ingest: lote válido, com registro inválido, 413 e 403 de origem.
	batch := validBatch()
	vals.add(refBatch, []byte(batch))
	c, _, b = f.do(f.internal, "POST", "/bot/v1/ingest/traefik", "", nil, batch)
	expect(202, c, refIngestReply, b)
	c, _, b = f.do(f.internal, "POST", "/bot/v1/ingest/traefik", "", nil, `{"records":[{"type":"x","fs_conn_id":"bad","ts":"x"}]}`)
	expect(202, c, refIngestReply, b)
	c, _, b = f.do(f.internal, "POST", "/bot/v1/ingest/traefik", "", nil, strings.Repeat(" ", MaxIngestBytes+1))
	expect(413, c, refError, b)
	// 503 busy sem vaga entre os lotes simultâneos (ADR 0073 item 2, task 370)
	busy := newFixture(t)
	busy.srv.api.gate = newIngestGate(0, 0, 0)
	c, h, b = busy.do(busy.internal, "POST", "/bot/v1/ingest/traefik", "", nil, batch)
	expect(503, c, refError, b)
	if errorCode(t, b) != errBusy || h.Get("Retry-After") != "1" {
		t.Errorf("503 do ingest: %v %s", h, b)
	}
	// forwardAuth com as duas visões.
	f.putStore()
	c, h, b = f.do(f.internal, "GET", "/bot/v1/auth", "", forkHeadersFor(), "")
	expect(200, c, refVerdict, b)
	if h.Get("X-Fs-Verdict") == "" || h.Get("X-Fs-Score") == "" {
		t.Errorf("cabeçalhos do forwardAuth: %v", h)
	}
	// X-Fs-Ja4h (openapi 0.2.0, ADR 0058 item 1): primeira requisição de um curl, 200 sem chave e 403 em block.
	ja4hHdr := curlAuthHeaders()
	ja4hHdr["X-Fs-Conn-Id"], ja4hHdr["X-Fs-Src-Port"] = "01JC0X3K8V2T7Q9F4M6P1R5S99", "51299"
	ja4hHdr["X-Fs-Ja4h"] = ja4hCurl
	c, h, b = f.do(f.internal, "GET", "/bot/v1/auth", "", ja4hHdr, "")
	expect(200, c, refVerdict, b)
	if h.Get("X-Fs-Verdict") != ClassBot {
		t.Errorf("X-Fs-Ja4h: %v", h)
	}
	_, blk := f.createKey(KeyOptions{Name: "blk0", Domains: []string{"www.example.com"}, Mode: ModeBlock})
	c, h, b = f.do(f.internal, "GET", "/bot/v1/auth", blk, ja4hHdr, "")
	expect(403, c, refVerdict, b)
	if h.Get("X-Fs-Verdict") != ClassBot || h.Get("X-Fs-Signals") != "ja4h_library,library_client" {
		t.Errorf("X-Fs-Ja4h em block: %v", h)
	}
	// Vereditos reais das rotas de consulta (task 282): pelo id do fork, pela origem, por probe e o 403 do block.
	c, _, b = f.do(f.internal, "GET", "/bot/v1/verdict/conn/"+testForkConnID, "", nil, "")
	expect(200, c, refVerdict, b)
	c, _, b = f.do(f.internal, "GET", "/bot/v1/verdict?src_ip=198.51.100.7&src_port=51234&site=www.example.com", "", nil, "")
	expect(200, c, refVerdict, b)
	probe := storeMessageWith(t, "01JC0X3K8V2T7Q9N4M6P1R5S71", "probe5678", 4445, map[string]any{
		"http2": map[string]any{"streams": []any{h2Stream(1)}},
	})
	if err := f.srv.feed.Handle(probe); err != nil {
		t.Fatal(err)
	}
	c, _, b = f.do(f.internal, "GET", "/bot/v1/probes/probe5678/verdict", "", nil, "")
	expect(200, c, refVerdict, b)
	c, _, b = f.do(f.internal, "GET", "/bot/v1/fingerprints/ja4/t13d1517h2_8daaf6152771_cb7bf5808d99", "", nil, "")
	expect(200, c, refFPStats, b)
	// Goldens ponta a ponta: lote e veredito de cada cliente.
	for i, vc := range verdictCases {
		batch, _ := vc.build(t, i)
		vals.add(refBatch, batch)
		g := newFixture(t)
		g.goldenSetup(vc.name)
		fsID, _, _ := goldenIDs(i)
		c, _, b = g.do(g.internal, "GET", "/bot/v1/verdict/conn/"+fsID, "", nil, "")
		expect(200, c, refVerdict, b)
		// forwardAuth com chave em modo block: 403 com o Verdict para bot, 200 para os demais
		_, block := g.createKey(KeyOptions{Name: "blk", Domains: []string{"www.example.com"}, Mode: ModeBlock})
		want := 200
		if vc.wantClass == ClassBot {
			want = 403
		}
		c, _, b = g.do(g.internal, "GET", "/bot/v1/auth", block, authHeaders(i, vc.ua), "")
		expect(want, c, refVerdict, b)
	}
	// Evento do feed (o serializador é o mesmo do SSE).
	var v Verdict
	_ = json.Unmarshal(b, &v)
	ev, _ := json.Marshal(VerdictEvent{Kind: "verdict", Ts: v.Ts, Verdict: &v})
	vals.add(refEvent, ev)
	ev, _ = json.Marshal(VerdictEvent{Kind: "stream.dropped", Ts: v.Ts, Dropped: 3})
	vals.add(refEvent, ev)

	for ref, vs := range vals {
		validateContract(t, ref, vs...)
	}
}
