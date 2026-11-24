package store

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const openapiFile = "../../cmd/finger-sniffer-store/openapi.yaml"

// validateContract valida cada valor JSON contra um schema do openapi.yaml com o mesmo Redocly do verify: copia o
// contrato e os exemplos para um diretório temporário, acrescenta uma rota sintética cuja resposta é o schema e
// cujos exemplos são os valores, e roda o lint (regra no-invalid-media-type-examples = erro). Com -short, ou sem
// o Redocly instalado em scripts/contracts-tools fora do CI, o teste é pulado.
func validateContract(t *testing.T, schema string, values ...[]byte) {
	t.Helper()
	if out, err := lintContract(t, schema, values...); err != nil {
		t.Fatalf("%d valores não validam contra %s: %v\n%s", len(values), schema, err, out)
	}
}

// redoclyBin devolve o Redocly travado no package-lock.json de scripts/contracts-tools (o mesmo do verify). Sem o
// binário, pula o teste; no CI (CI=true) falha, porque lá o verify-full instala as ferramentas antes dos testes.
func redoclyBin(t *testing.T) string {
	t.Helper()
	bin, err := filepath.Abs(redoclyPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(bin); err != nil {
		msg := "Redocly ausente (" + redoclyPath + "): rode npm ci --ignore-scripts --prefix scripts/contracts-tools " +
			"(ou make verify-full, que instala)"
		if os.Getenv("CI") == "true" {
			t.Fatal(msg)
		}
		t.Skip(msg)
	}
	return bin
}

// redoclyPath: binário instalado por npm ci em scripts/contracts-tools (relativo a internal/store).
const redoclyPath = "../../scripts/contracts-tools/node_modules/.bin/redocly"

// lintContract monta o openapi com a rota sintética e roda o Redocly; devolve a saída e o erro do lint.
func lintContract(t *testing.T, schema string, values ...[]byte) ([]byte, error) {
	t.Helper()
	if testing.Short() {
		t.Skip("contrato via Redocly pulado com -short")
	}
	bin := redoclyBin(t)
	spec, err := os.ReadFile(openapiFile)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "testdata"), 0o750); err != nil {
		t.Fatal(err)
	}
	golden, _ := filepath.Glob(filepath.Join(filepath.Dir(openapiFile), "testdata", "*.json"))
	for _, g := range golden {
		b, _ := os.ReadFile(g)
		if err := os.WriteFile(filepath.Join(dir, "testdata", filepath.Base(g)), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var route strings.Builder
	fmt.Fprintf(&route, "  /contract-check/%s:\n    get:\n      tags: [health]\n      operationId: contractCheck%s\n      summary: x\n      responses:\n", strings.ToLower(schema), schema)
	fmt.Fprintf(&route, "        \"200\":\n          description: x\n          content:\n            application/json:\n              schema: { $ref: \"#/components/schemas/%s\" }\n              examples:\n", schema)
	for i, v := range values {
		name := fmt.Sprintf("contract-%s-%03d.json", strings.ToLower(schema), i)
		ex, _ := json.Marshal(map[string]any{"summary": "x", "value": json.RawMessage(v)})
		if err := os.WriteFile(filepath.Join(dir, "testdata", name), ex, 0o600); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&route, "                e%03d: { $ref: \"./testdata/%s\" }\n", i, name)
	}
	route.WriteString("        \"400\": { $ref: \"#/components/responses/BadRequest\" }\n")
	text := strings.Replace(string(spec), "\npaths:\n", "\npaths:\n"+route.String(), 1)
	if err := os.WriteFile(filepath.Join(dir, "openapi.yaml"), []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	redocly, err := os.ReadFile("../../redocly.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "redocly.yaml"), redocly, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "lint", "--format=summary", "openapi.yaml")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "REDOCLY_TELEMETRY=off", "REDOCLY_SUPPRESS_UPDATE_NOTICE=true")
	return cmd.CombinedOutput()
}

// TestContractRejectsInvalidExample: o lint do contrato reprova um valor fora do schema (o teste de contrato não
// passa vazio quando o Redocly não valida nada).
func TestContractRejectsInvalidExample(t *testing.T) {
	if out, err := lintContract(t, "Error", []byte(`{"error":42}`)); err == nil {
		t.Fatalf("valor inválido aceito pelo lint do contrato:\n%s", out)
	}
	if out, err := lintContract(t, "Error", []byte(`{"error":"not found"}`)); err != nil {
		t.Fatalf("valor válido reprovado: %v\n%s", err, out)
	}
}

// TestAPIQUICExample grava/confere o exemplo de uma conexão quic/h3 (connection-quic-example.json) e o valida
// contra o schema Connection do openapi.
func TestAPIQUICExample(t *testing.T) {
	in, _ := newTestIngestor(t, nil)
	in.flows.newID = fixedIDs()
	msgs := h3Session(t, 1000)
	run(t, in, 900, msgs[:6]...)
	run(t, in, 1100, msgs[6])
	run(t, in, 3100)
	api := &API{
		OpenAPI: []byte("x"), Health: func(context.Context, time.Time) Health { return Health{} }, Now: time.Now,
		Q: NewQueries(in.db, in.flows.live, 65535), W: in.db,
	}
	srv := httptest.NewServer(api.Handler())
	defer srv.Close()
	var id string
	if err := in.db.QueryRow("SELECT conn_id FROM connections").Scan(&id); err != nil {
		t.Fatal(err)
	}
	f := &apiFixture{srv: srv}
	code, body := f.get(t, "/api/v1/connections/"+id)
	if code != 200 {
		t.Fatalf("%d %s", code, body)
	}
	var v any
	_ = json.Unmarshal([]byte(body), &v)
	got, _ := json.MarshalIndent(map[string]any{"summary": "Conexão quic/h3 com duas requisições, encerrada pelo cliente", "value": v}, "", "  ")
	got = append(got, '\n')
	file := filepath.Join(filepath.Dir(openapiFile), "testdata", "connection-quic-example.json")
	if *update {
		if err := os.WriteFile(file, got, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("%v (rode com -update)", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("exemplo quic diverge de %s; rode go test ./internal/store -run TestAPIQUICExample -update", file)
	}
	validateContract(t, "Connection", []byte(body))
}
