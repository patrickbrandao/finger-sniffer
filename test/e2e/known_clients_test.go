package e2e

// Base própria de fingerprints medidos (spec 018 "Base própria", ADR 0050 item 1, task 270). Este arquivo não
// tem a tag e2e: o formato de internal/bot/lists/known_clients.json e a regra de regravação (só com
// FS_E2E_UPDATE=1) são conferidos no verify-quick. A medida em si é o TestF8KnownClients (f8_known_clients_test.go,
// tag e2e), que roda os mesmos clientes do TestF5Fingerprints contra o espelho.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

// knownClients é o arquivo inteiro (formato da spec 018; contrato entre o tester e o implementer-bot).
type knownClients struct {
	Version  int           `json:"version"`
	Measured []knownClient `json:"measured"`
}

// knownClient é uma medida: um cliente (família, versão, SO) num protocolo, com as impressões vistas no espelho.
// Campos nulos: akamai fora do h2; ja4t e p0f_os no h3 (sem SYN); p0f_os quando o p0f não reconhece o SYN.
type knownClient struct {
	Client        string   `json:"client"`
	ClientVersion string   `json:"client_version"`
	OS            string   `json:"os"`
	Proto         string   `json:"proto"`
	JA4           string   `json:"ja4"`
	JA4R          string   `json:"ja4_r"`
	Akamai        *string  `json:"akamai"`
	JA4HAB        string   `json:"ja4h_ab"`
	JA4T          *string  `json:"ja4t"`
	P0FOS         *string  `json:"p0f_os"`
	TTLInitial    int      `json:"ttl_initial"`
	ALPN          []string `json:"alpn"`
	MeasuredAt    string   `json:"measured_at"`
	Commit        string   `json:"commit"`
}

// key identifica a medida: o mesmo cliente pode ter mais de um JA4 (ex.: curl com OpenSSL e com LibreSSL).
func (k knownClient) key() string {
	return strings.Join([]string{k.Client, k.ClientVersion, k.OS, k.Proto, k.JA4}, "|")
}

// sameFingerprint diz se duas medidas viram as mesmas impressões (ignora quando e em que commit).
func (k knownClient) sameFingerprint(o knownClient) bool {
	k.MeasuredAt, k.Commit, o.MeasuredAt, o.Commit = "", "", "", ""
	a, _ := json.Marshal(k)
	b, _ := json.Marshal(o)
	return bytes.Equal(a, b)
}

// knownClientsPath é o caminho do arquivo no repositório.
func knownClientsPath() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "internal", "bot", "lists", "known_clients.json")
}

// mergeKnownClients junta as medidas novas às do arquivo: medida com a mesma chave e as mesmas impressões
// mantém a data e o commit antigos (regravar sem mudança não mexe no arquivo); impressão diferente substitui;
// as medidas antigas que esta execução não refez (cliente não instalado, versão anterior) ficam. Remover
// versão velha é decisão do PR que regrava a base.
func mergeKnownClients(old, got []knownClient) []knownClient {
	by := map[string]knownClient{}
	for _, k := range old {
		by[k.key()] = k
	}
	for _, k := range got {
		if prev, ok := by[k.key()]; ok && prev.sameFingerprint(k) {
			continue
		}
		by[k.key()] = k
	}
	out := make([]knownClient, 0, len(by))
	for _, k := range by {
		out = append(out, k)
	}
	sortKnownClients(out)
	return out
}

func sortKnownClients(ks []knownClient) {
	slices.SortFunc(ks, func(a, b knownClient) int { return strings.Compare(a.key(), b.key()) })
}

// encodeKnownClients é a forma canônica do arquivo (ordenado, indentado, com quebra de linha no fim).
func encodeKnownClients(ks []knownClient) ([]byte, error) {
	b, err := json.MarshalIndent(knownClients{Version: 1, Measured: ks}, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// readKnownClients lê o arquivo; ausente devolve vazio.
func readKnownClients(path string) (*knownClients, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return &knownClients{Version: 1}, nil
	}
	if err != nil {
		return nil, err
	}
	var kc knownClients
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&kc); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &kc, nil
}

// recordKnownClients junta as medidas ao arquivo em path e devolve o conteúdo resultante. Só grava com
// FS_E2E_UPDATE=1; sem isso o arquivo não muda (o conteúdo vai só para o log de quem chamou).
func recordKnownClients(path string, got []knownClient) ([]byte, bool, error) {
	old, err := readKnownClients(path)
	if err != nil {
		return nil, false, err
	}
	b, err := encodeKnownClients(mergeKnownClients(old.Measured, got))
	if err != nil {
		return nil, false, err
	}
	if os.Getenv("FS_E2E_UPDATE") != "1" {
		return b, false, nil
	}
	if cur, err := os.ReadFile(path); err == nil && bytes.Equal(cur, b) {
		return b, false, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, false, err
	}
	return b, true, os.WriteFile(path, b, 0o644)
}

// numVersion extrai a versão da primeira sequência numérica de s ("curl 8.23.0 (...)" → "8.23.0") cortada em
// parts componentes (1 = principal, como no User-Agent dos navegadores; 2 = principal.secundária).
func numVersion(s string, parts int) string {
	v := versionRe.FindString(s)
	if v == "" {
		return ""
	}
	p := strings.Split(v, ".")
	return strings.Join(p[:min(parts, len(p))], ".")
}

var versionRe = regexp.MustCompile(`\d+(\.\d+)*`)

// ---------------------------------------------------------------- formato

// Famílias e SO da spec 018 RF-06.
var (
	kcFamilies = []string{"chrome", "firefox", "safari", "edge", "curl", "go", "python", "java", "node", "headless", "other"}
	kcOS       = []string{"windows", "macos", "linux", "android", "ios", "other"}
	kcTTL      = []int{32, 64, 128, 255}

	kcVersionRe = regexp.MustCompile(`^\d+(\.\d+)*$`)
	kcJA4Re     = regexp.MustCompile(`^[tq](10|11|12|13|s3|d1|d2|d3|00)[di]\d{2}\d{2}[a-z0-9]{2}_[0-9a-f]{12}_[0-9a-f]{12}$`)
	kcJA4RRe    = regexp.MustCompile(`^[tq][a-z0-9]{9}_[0-9a-f,]*_[0-9a-f,]*_[0-9a-f,]*$`)
	kcAkamaiRe  = regexp.MustCompile(`^[0-9:;]*\|\d+\|[0-9:,]*\|[mpsa,]*$`)
	kcJA4HABRe  = regexp.MustCompile(`^[a-z]{2}(10|11|20|30)[cn][nr]\d{2}[a-z0-9]{4}_[0-9a-f]{12}$`)
	kcJA4TRe    = regexp.MustCompile(`^\d+_[0-9-]*_\d+_\d+$`)
)

// validateKnownClients confere o formato da base: cada campo, a coerência com o protocolo, chaves únicas e a
// forma canônica (o arquivo é o que encodeKnownClients gravaria).
func validateKnownClients(raw []byte) []error {
	var errs []error
	bad := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	var kc knownClients
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&kc); err != nil {
		return []error{err}
	}
	if kc.Version != 1 {
		bad("version = %d, quer 1", kc.Version)
	}
	if len(kc.Measured) == 0 {
		bad("measured vazio")
	}
	// campos obrigatórios presentes (também os nuláveis: a chave existe, com null)
	var probe struct {
		Measured []map[string]json.RawMessage `json:"measured"`
	}
	_ = json.Unmarshal(raw, &probe)
	fields := []string{"client", "client_version", "os", "proto", "ja4", "ja4_r", "akamai", "ja4h_ab", "ja4t", "p0f_os", "ttl_initial", "alpn", "measured_at", "commit"}
	for i, m := range probe.Measured {
		for _, f := range fields {
			if _, ok := m[f]; !ok {
				bad("measured[%d]: falta %q", i, f)
			}
		}
	}
	seen := map[string]bool{}
	for i, k := range kc.Measured {
		at := fmt.Sprintf("measured[%d] (%s %s %s)", i, k.Client, k.ClientVersion, k.Proto)
		if seen[k.key()] {
			bad("%s: chave repetida", at)
		}
		seen[k.key()] = true
		if !slices.Contains(kcFamilies, k.Client) && !strings.HasPrefix(k.Client, "crawler:") {
			bad("%s: client %q fora da spec 018 RF-06", at, k.Client)
		}
		if !kcVersionRe.MatchString(k.ClientVersion) {
			bad("%s: client_version %q", at, k.ClientVersion)
		}
		if !slices.Contains(kcOS, k.OS) {
			bad("%s: os %q", at, k.OS)
		}
		want := "t"
		switch k.Proto {
		case "h1", "h2":
		case "h3":
			want = "q"
		default:
			bad("%s: proto %q (h1, h2 ou h3)", at, k.Proto)
		}
		if !kcJA4Re.MatchString(k.JA4) || !strings.HasPrefix(k.JA4, want) {
			bad("%s: ja4 %q", at, k.JA4)
		}
		if !kcJA4RRe.MatchString(k.JA4R) || len(k.JA4) < 10 || !strings.HasPrefix(k.JA4R, k.JA4[:10]) {
			bad("%s: ja4_r %q não casa com o ja4 %q", at, k.JA4R, k.JA4)
		}
		switch {
		case k.Proto == "h2" && (k.Akamai == nil || !kcAkamaiRe.MatchString(*k.Akamai)):
			bad("%s: akamai %v", at, nullStr(k.Akamai))
		case k.Proto != "h2" && k.Akamai != nil:
			bad("%s: akamai fora do h2", at)
		}
		if !kcJA4HABRe.MatchString(k.JA4HAB) {
			bad("%s: ja4h_ab %q", at, k.JA4HAB)
		} else if v := map[string][]string{"h1": {"10", "11"}, "h2": {"20"}, "h3": {"30"}}[k.Proto]; v != nil &&
			!slices.Contains(v, k.JA4HAB[2:4]) {
			bad("%s: ja4h_ab %q com versão HTTP diferente do proto", at, k.JA4HAB)
		}
		if k.Proto == "h3" {
			if k.JA4T != nil || k.P0FOS != nil {
				bad("%s: ja4t/p0f_os no h3 (sem SYN)", at)
			}
		} else {
			if k.JA4T == nil || !kcJA4TRe.MatchString(*k.JA4T) {
				bad("%s: ja4t %v", at, nullStr(k.JA4T))
			}
			if k.P0FOS != nil && *k.P0FOS == "" {
				bad("%s: p0f_os vazio (use null)", at)
			}
		}
		if !slices.Contains(kcTTL, k.TTLInitial) {
			bad("%s: ttl_initial %d", at, k.TTLInitial)
		}
		if k.ALPN == nil {
			bad("%s: alpn ausente (lista vazia quando o cliente não oferece)", at)
		}
		if p := map[string]string{"h2": "h2", "h3": "h3"}[k.Proto]; p != "" && !slices.Contains(k.ALPN, p) {
			bad("%s: alpn %v sem %s", at, k.ALPN, p)
		}
		if ts, err := time.Parse(time.RFC3339, k.MeasuredAt); err != nil || ts.Location() != time.UTC {
			bad("%s: measured_at %q (RFC 3339 em UTC)", at, k.MeasuredAt)
		}
		if strings.TrimSpace(k.Commit) == "" {
			bad("%s: commit vazio", at)
		}
	}
	sorted := slices.Clone(kc.Measured)
	sortKnownClients(sorted)
	if canon, err := encodeKnownClients(sorted); err != nil || !bytes.Equal(canon, raw) {
		bad("arquivo fora da forma canônica (ordem por client|client_version|os|proto|ja4, indentação de 2): regrave com FS_E2E_UPDATE=1")
	}
	return errs
}

func nullStr(s *string) string {
	if s == nil {
		return "null"
	}
	return *s
}

// kcRequired são as medidas que a base tem de ter (task 270): família e protocolo.
var kcRequired = []struct{ client, proto string }{
	{"curl", "h1"},
	{"curl", "h2"},
	{"go", "h1"},
	{"go", "h2"},
	{"chrome", "h1"},
	{"chrome", "h2"},
	{"chrome", "h3"},
	{"firefox", "h1"},
	{"firefox", "h2"},
	{"firefox", "h3"},
	{"python", "h1"},
	{"headless", "h2"},
}

// TestKnownClientsFormat confere o arquivo versionado da base própria.
func TestKnownClientsFormat(t *testing.T) {
	raw, err := os.ReadFile(knownClientsPath())
	if err != nil {
		t.Fatal(err)
	}
	for _, err := range validateKnownClients(raw) {
		t.Error(err)
	}
	kc, err := readKnownClients(knownClientsPath())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range kcRequired {
		if !slices.ContainsFunc(kc.Measured, func(k knownClient) bool { return k.Client == r.client && k.Proto == r.proto }) {
			t.Errorf("base sem %s %s", r.client, r.proto)
		}
	}
	// curl com OpenSSL e com LibreSSL: dois JA4 diferentes no h2
	var curl []string
	for _, k := range kc.Measured {
		if k.Client == "curl" && k.Proto == "h2" && !slices.Contains(curl, k.JA4) {
			curl = append(curl, k.JA4)
		}
	}
	if len(curl) < 2 {
		t.Errorf("curl h2 com %d JA4 (quer OpenSSL e LibreSSL)", len(curl))
	}
}

// TestKnownClientsValidateRejects: o validador pega os erros de formato mais prováveis.
func TestKnownClientsValidateRejects(t *testing.T) {
	good := sampleKnownClient()
	enc := func(k knownClient) []byte {
		b, err := encodeKnownClients([]knownClient{k})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	if errs := validateKnownClients(enc(good)); len(errs) > 0 {
		t.Fatalf("amostra válida rejeitada: %v", errs)
	}
	s := func(v string) *string { return &v }
	cases := map[string]func(*knownClient){
		"família":         func(k *knownClient) { k.Client = "chromium" },
		"proto":           func(k *knownClient) { k.Proto = "http/2" },
		"ja4 q no h2":     func(k *knownClient) { k.JA4 = "q" + k.JA4[1:] },
		"ja4_r":           func(k *knownClient) { k.JA4R = "t13d0000h1_x" },
		"akamai ausente":  func(k *knownClient) { k.Akamai = nil },
		"akamai no h1":    func(k *knownClient) { k.Proto, k.JA4HAB = "h1", "ge11nn05enus_9ed1ff1f7b03" },
		"ja4h_ab inteiro": func(k *knownClient) { k.JA4HAB += "_cd8dafe26982" },
		"ja4t":            func(k *knownClient) { k.JA4T = s("65535") },
		"ttl":             func(k *knownClient) { k.TTLInitial = 63 },
		"alpn sem h2":     func(k *knownClient) { k.ALPN = []string{"http/1.1"} },
		"data":            func(k *knownClient) { k.MeasuredAt = "16/11/2026" },
		"commit":          func(k *knownClient) { k.Commit = "" },
	}
	for name, mut := range cases {
		k := good
		k.ALPN = slices.Clone(good.ALPN)
		mut(&k)
		if errs := validateKnownClients(enc(k)); len(errs) == 0 {
			t.Errorf("%s: aceito", name)
		}
	}
	// fora da ordem canônica
	a, b := good, good
	b.Client = "curl"
	raw, _ := json.MarshalIndent(knownClients{Version: 1, Measured: []knownClient{b, a}}, "", "  ")
	if errs := validateKnownClients(append(raw, '\n')); len(errs) == 0 {
		t.Error("fora de ordem: aceito")
	}
	// campo desconhecido
	if errs := validateKnownClients([]byte(`{"version":1,"measured":[],"x":1}`)); len(errs) == 0 {
		t.Error("campo desconhecido: aceito")
	}
}

// TestKnownClientsRecordOnlyWithUpdate: o arquivo só muda com FS_E2E_UPDATE=1; regravar as mesmas impressões
// não muda nada (data e commit antigos ficam); impressão nova entra e as medidas antigas não refeitas ficam.
func TestKnownClientsRecordOnlyWithUpdate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lists", "known_clients.json")
	old := sampleKnownClient()
	base, err := encodeKnownClients([]knownClient{old})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, base, 0o600); err != nil {
		t.Fatal(err)
	}
	read := func() []byte {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	// medida nova (outro cliente) e a mesma do arquivo remedida em outra data
	again := old
	again.MeasuredAt, again.Commit = "2026-12-01T10:00:00Z", "abcdef1"
	fresh := sampleKnownClient()
	fresh.Client, fresh.ClientVersion = "firefox", "159"
	got := []knownClient{again, fresh}

	for _, v := range []string{"", "0", "true"} {
		t.Setenv("FS_E2E_UPDATE", v)
		b, wrote, err := recordKnownClients(path, got)
		if err != nil {
			t.Fatal(err)
		}
		if wrote || !bytes.Equal(read(), base) {
			t.Fatalf("FS_E2E_UPDATE=%q mudou o arquivo", v)
		}
		if !bytes.Contains(b, []byte(`"firefox"`)) {
			t.Fatalf("FS_E2E_UPDATE=%q: conteúdo devolvido sem a medida nova", v)
		}
	}

	t.Setenv("FS_E2E_UPDATE", "1")
	if _, wrote, err := recordKnownClients(path, got); err != nil || !wrote {
		t.Fatalf("FS_E2E_UPDATE=1 não gravou: %v", err)
	}
	after := read()
	if errs := validateKnownClients(after); len(errs) > 0 {
		t.Fatalf("arquivo gravado inválido: %v", errs)
	}
	kc, _ := readKnownClients(path)
	if len(kc.Measured) != 2 {
		t.Fatalf("medidas: %d, quer 2", len(kc.Measured))
	}
	for _, k := range kc.Measured {
		if k.Client == old.Client && (k.MeasuredAt != old.MeasuredAt || k.Commit != old.Commit) {
			t.Errorf("impressão igual trocou data/commit: %s %s", k.MeasuredAt, k.Commit)
		}
	}

	// segunda regravação igual: nada muda
	if _, wrote, err := recordKnownClients(path, got); err != nil || wrote || !bytes.Equal(read(), after) {
		t.Fatalf("regravação sem mudança alterou o arquivo (wrote=%v, err=%v)", wrote, err)
	}

	// impressão diferente para a mesma chave substitui (data e commit novos)
	changed := again
	changed.TTLInitial = 128
	if _, wrote, err := recordKnownClients(path, []knownClient{changed}); err != nil || !wrote {
		t.Fatalf("impressão diferente não gravou: %v", err)
	}
	kc, _ = readKnownClients(path)
	for _, k := range kc.Measured {
		if k.Client == old.Client && (k.TTLInitial != 128 || k.Commit != "abcdef1") {
			t.Errorf("medida não substituída: %+v", k)
		}
	}
}

func TestNumVersion(t *testing.T) {
	for _, c := range []struct {
		in    string
		parts int
		want  string
	}{
		{"curl 8.23.0 (aarch64-apple-darwin27.0.0) libcurl/8.23.0", 2, "8.23"},
		{"Google Chrome 156.0.8078.80", 1, "156"},
		{"Mozilla Firefox 159.0", 1, "159"},
		{"go1.27.3", 2, "1.27"},
		{"2.32.5", 2, "2.32"},
		{"7", 2, "7"},
		{"sem versão", 1, ""},
	} {
		if got := numVersion(c.in, c.parts); got != c.want {
			t.Errorf("numVersion(%q, %d) = %q, quer %q", c.in, c.parts, got, c.want)
		}
	}
}

func sampleKnownClient() knownClient {
	akamai, ja4t, p0f := "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p", "65535_2-1-3-1-1-8-4-0-0_1460_6", "Mac OS X"
	return knownClient{
		Client: "chrome", ClientVersion: "156", OS: "macos", Proto: "h2",
		JA4:    "t13d1516h2_8daaf6152771_d8a2da3f94cd",
		JA4R:   "t13d1516h2_002f,0035_0005,000a_0403,0804",
		Akamai: &akamai, JA4HAB: "ge20nn14enus_7cf2b917f4b0", JA4T: &ja4t, P0FOS: &p0f, TTLInitial: 64,
		ALPN: []string{"h2", "http/1.1"}, MeasuredAt: "2026-11-16T16:09:00Z", Commit: "7e14cd1",
	}
}
