package bot

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/patrickbrandao/finger-sniffer/internal/bot/webhook"
)

// siteConn é um registro de conexão do ingest com o SNI dado ("" sem SNI).
func siteConn(i int, sni string) string {
	fsID, _, port := goldenIDs(i)
	s := ""
	if sni != "" {
		s = `"sni":"` + sni + `",`
	}
	return fmt.Sprintf(`{"type":"connection","fs_conn_id":"%s","ts":"2026-11-16T12:00:00.000000000Z",`+
		`"src":{"ip":"%s","port":%d},"dst":{"ip":"10.249.0.2","port":443},"entry_point":"websecure",%s`+
		`"alpn_offered":["h2"],"alpn":"h2","tls_version":"1.3"}`, fsID, goldenSrcIP, port, s)
}

// siteRequest é um resumo de requisição do ingest com o SNI ("" sem) e o authority dados.
func siteRequest(i int, sni, authority string) string {
	fsID, _, port := goldenIDs(i)
	s := ""
	if sni != "" {
		s = `"sni":"` + sni + `",`
	}
	return fmt.Sprintf(`{"type":"request","fs_conn_id":"%s","ts":"2026-11-16T12:00:00.050000000Z",`+
		`"src":{"ip":"%s","port":%d},"dst":{"ip":"10.249.0.2","port":443},%s"proto":"h2","method":"GET",`+
		`"authority":"%s","path":"/","http_version":"2.0","field_names":["user-agent"],"fields":{"user-agent":"curl/8.10.1"},`+
		`"cookie_names":[],"ja4h":"ge20nn010000_x_y_z"}`, fsID, goldenSrcIP, port, s, authority)
}

func batchOf(recs ...string) string {
	out := `{"sender":"v3.6.2-fs.1","records":[`
	for i, r := range recs {
		if i > 0 {
			out += ","
		}
		out += r
	}
	return out + "]}"
}

// TestIngestKeyForeignSite: B1 da auditoria da F8 — uma chave de a.com não escreve nada de victim.org pelo ingest,
// nem com o SNI dela e o authority do outro (o veredito usa o authority), nem com o SNI do outro, nem pendurando
// requisição sem domínio na conexão de outro site (spec 020 RF-03, ADRs 0051 item 3 e 0052 item 3).
func TestIngestKeyForeignSite(t *testing.T) {
	var hooks atomic.Int32
	rcv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		hooks.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer rcv.Close()
	f := newFixture(t)
	hc, hookURL := hookReceiver(t, rcv, "/hook")
	f.srv.hooks = webhook.New(webhook.Options{Client: hc, Now: f.clock.Now, Count: f.metrics.Add})
	f.srv.hub.SetSink(f.srv.publishWebhook)
	f.createWebhookKey(KeyOptions{
		Name: "victim", Domains: []string{"victim.org"}, WebhookURL: hookURL,
		WebhookClasses: []string{ClassBot, ClassSuspect, ClassHuman, ClassUnknown, ClassGoodBot},
	})
	ctx, cancel := context.WithCancel(context.Background())
	var once sync.Once
	stop := func() { once.Do(func() { cancel(); f.srv.hooks.Wait() }) }
	defer stop()
	f.srv.syncWebhooks(ctx)
	feed := &streamClient{queue: make(chan *Verdict, 64)}
	if err := f.srv.hub.add(feed); err != nil {
		t.Fatal(err)
	}
	_, key := f.createKey(KeyOptions{Name: "a", Domains: []string{"a.com"}})

	// conexão de victim.org vinda do traefix do próprio operador (9003, sem chave)
	if c, _, b := f.do(f.internal, "POST", "/bot/v1/ingest/traefik", "", nil, batchOf(siteConn(3, "victim.org"))); c != 202 ||
		string(b) != `{"accepted":1,"rejected":0}`+"\n" {
		t.Fatalf("conexão interna: %d %s", c, b)
	}
	for _, tc := range []struct {
		name, batch, want string
	}{
		{"sni da chave, authority de outro", batchOf(siteConn(0, "a.com"), siteRequest(0, "", "victim.org")), `{"accepted":1,"rejected":1}`},
		{"request com sni da chave e authority de outro", batchOf(siteRequest(1, "a.com", "victim.org")), `{"accepted":0,"rejected":1}`},
		{"sni de outro", batchOf(siteConn(2, "victim.org"), siteRequest(2, "victim.org", "a.com")), `{"accepted":0,"rejected":2}`},
		{"authority com porta e caixa", batchOf(siteRequest(4, "", "VICTIM.org:443")), `{"accepted":0,"rejected":1}`},
		{"sem domínio na conexão de outro", batchOf(siteRequest(3, "", "")), `{"accepted":0,"rejected":1}`},
	} {
		if c, _, b := f.do(f.public, "POST", "/bot/v1/ingest/traefik", key, nil, tc.batch); c != 202 || string(b) != tc.want+"\n" {
			t.Errorf("%s: %d %s, quer %s", tc.name, c, b, tc.want)
		}
	}
	// nenhum veredito saiu (feed e webhook) e o cache de comportamento de victim.org está vazio
	if n := len(feed.queue); n != 0 {
		t.Errorf("feed com %d vereditos", n)
	}
	if st := f.srv.agg.Query(mustAddr(goldenSrcIP), "victim.org", f.clock.Now()); st.HourRequests != 0 || st.DayRequests != 0 {
		t.Errorf("cache de comportamento de victim.org: %+v", st)
	}
	if err := f.srv.flushAgg(context.Background()); err != nil {
		t.Fatal(err)
	}
	var rows int
	if err := f.db.QueryRow("SELECT count(*) FROM ip_hourly").Scan(&rows); err != nil || rows != 0 {
		t.Errorf("ip_hourly com %d linhas (%v)", rows, err)
	}
	// controle: a requisição do domínio da chave entra e vira veredito publicado
	if c, _, b := f.do(f.public, "POST", "/bot/v1/ingest/traefik", key, nil, batchOf(siteRequest(0, "", "a.com"))); c != 202 ||
		string(b) != `{"accepted":1,"rejected":0}`+"\n" {
		t.Fatalf("domínio da chave: %d %s", c, b)
	}
	if n := len(feed.queue); n != 1 {
		t.Errorf("feed com %d vereditos depois da requisição de a.com, quer 1", n)
	}
	stop()
	if n := hooks.Load(); n != 0 {
		t.Errorf("webhook de victim.org recebeu %d", n)
	}
}

// TestJudgeIngestSiteCheck: defesa em profundidade — o Judge.Ingest não registra nem publica a requisição cujo
// site final (authority, ou o SNI da conexão sem ele) não é da chave.
func TestJudgeIngestSiteCheck(t *testing.T) {
	f := newFixture(t)
	feed := &streamClient{queue: make(chan *Verdict, 8)}
	if err := f.srv.hub.add(feed); err != nil {
		t.Fatal(err)
	}
	allowA := func(s string) bool { return MatchDomain([]string{"a.com"}, s) }
	for i, recs := range [][]string{
		{siteConn(0, "a.com"), siteRequest(0, "", "victim.org")},
		{siteConn(1, "victim.org"), siteRequest(1, "", "")},
	} {
		fsID, _, _ := goldenIDs(i)
		for _, raw := range recs {
			rec, err := parseRecord([]byte(raw))
			if err != nil {
				t.Fatal(err)
			}
			f.srv.Index().UpdateFork(fsID, f.clock.Now(), rec.apply)
		}
		if f.srv.judge.Ingest(fsID, allowA) {
			t.Errorf("caso %d: site de outro domínio registrado", i)
		}
	}
	if n := len(feed.queue); n != 0 {
		t.Errorf("feed com %d vereditos", n)
	}
	if st := f.srv.agg.Query(mustAddr(goldenSrcIP), "victim.org", f.clock.Now()); st.HourRequests != 0 {
		t.Errorf("agregados de victim.org: %+v", st)
	}
	// sem chave (nil), o mesmo registro passa
	fsID, _, _ := goldenIDs(0)
	if !f.srv.judge.Ingest(fsID, nil) {
		t.Error("sem chave recusado")
	}
}

// TestIngestFieldAllowlist: N2 da auditoria da F8 — só os valores da lista permitida da spec 019 RF-04 ficam no
// índice; os nomes de todos os campos continuam em field_names (ordem e JA4H, ADR 0048 item 3, ADR 0052 item 2).
func TestIngestFieldAllowlist(t *testing.T) {
	f := newFixture(t)
	fsID, _, _ := goldenIDs(0)
	rec := `{"type":"request","fs_conn_id":"` + fsID + `","ts":"2026-11-16T12:00:00.050000000Z","proto":"h2","method":"GET",` +
		`"authority":"www.example.com","path":"/","http_version":"2.0",` +
		`"field_names":["user-agent","accept","accept-language","accept-encoding","sec-ch-ua","Sec-CH-UA-Platform","sec-fetch-site","referer","x-api-token","cookie","Authorization"],` +
		`"fields":{"user-agent":"ua","accept":"*/*","accept-language":"pt-BR","accept-encoding":"gzip","sec-ch-ua":"\"x\"",` +
		`"Sec-CH-UA-Platform":"\"Linux\"","sec-fetch-site":"none","referer":"https://x.example/secret","x-api-token":"tok",` +
		`"cookie":"sid=1","Authorization":"Bearer z"},"cookie_names":["sid"],"ja4h":"ge20nn110000_x_y_z"}`
	if c, _, b := f.do(f.internal, "POST", "/bot/v1/ingest/traefik", "", nil, batchOf(rec)); c != 202 ||
		string(b) != `{"accepted":1,"rejected":0}`+"\n" {
		t.Fatalf("ingest: %d %s", c, b)
	}
	fc, ok := f.srv.Index().Fork(fsID, f.clock.Now())
	if !ok || len(fc.Requests) != 1 {
		t.Fatal("requisição fora do índice")
	}
	r := fc.Requests[0]
	want := map[string]string{
		"user-agent": "ua", "accept": "*/*", "accept-language": "pt-BR", "accept-encoding": "gzip", "sec-ch-ua": `"x"`,
		"Sec-CH-UA-Platform": `"Linux"`, "sec-fetch-site": "none",
	}
	if len(r.Fields) != len(want) {
		t.Errorf("campos guardados: %v", r.Fields)
	}
	for k, v := range want {
		if r.Fields[k] != v {
			t.Errorf("%s = %q, quer %q", k, r.Fields[k], v)
		}
	}
	for _, k := range []string{"referer", "x-api-token", "cookie", "Authorization"} {
		if _, ok := r.Fields[k]; ok {
			t.Errorf("valor de %s guardado", k)
		}
	}
	if len(r.FieldNames) != 11 || r.JA4H != "ge20nn110000_x_y_z" {
		t.Errorf("nomes ou JA4H perdidos: %v %q", r.FieldNames, r.JA4H)
	}
}

// foreignBatch é o lote de validBatch (conexão com ClientHello e h2 do cliente Go e uma requisição) do site dado.
func foreignBatch(site string) string {
	return strings.ReplaceAll(validBatch(), "www.example.com", site)
}

// foreignRequest é só o registro de requisição de validBatch, do site dado (a requisição seguinte da conexão).
func foreignRequest(site string) string {
	b := foreignBatch(site)
	i := strings.Index(b, `{"type":"request"`)
	return `{"sender":"v3.6.2-fs.1","records":[` + b[i:]
}

// TestForwardAuthKeyForeignConn: task 369 — uma chave de a.com que faz forwardAuth na 9002 com o fs_conn_id de uma
// conexão de victim.org recebe 200 avaliado só pelos cabeçalhos: sem as fingerprints de victim.org no corpo, sem
// trocar o LastVerdict da conexão e sem roubar a vez de publicação da requisição seguinte de victim.org (spec 020
// RF-03, ADR 0051 item 3).
func TestForwardAuthKeyForeignConn(t *testing.T) {
	f := newFixture(t)
	feed := &streamClient{queue: make(chan *Verdict, 64)}
	if err := f.srv.hub.add(feed); err != nil {
		t.Fatal(err)
	}
	if c, _, b := f.do(f.internal, "POST", "/bot/v1/ingest/traefik", "", nil, foreignBatch("victim.org")); c != 202 ||
		string(b) != `{"accepted":2,"rejected":0}`+"\n" {
		t.Fatalf("conexão interna: %d %s", c, b)
	}
	before, ok := f.srv.Index().Fork(testForkConnID, f.clock.Now())
	if !ok || before.TLS == nil || before.TLS.JA4 == "" || before.LastVerdict == nil {
		t.Fatalf("conexão de victim.org sem JA4 ou veredito: %+v", before)
	}
	ja4 := before.TLS.JA4
	for len(feed.queue) > 0 {
		<-feed.queue
	}

	_, key := f.createKey(KeyOptions{Name: "a", Domains: []string{"a.com"}})
	hdr := forkHeadersFor()
	hdr["X-Forwarded-Host"] = "a.com"
	// duas chamadas: com a vez roubada, a segunda passaria do published e a próxima de victim.org não sairia
	for i := range 2 {
		c, _, v, b := f.authVerdict("public", key, hdr)
		if c != 200 || v.Class == "" {
			t.Fatalf("forwardAuth %d: %d %s", i, c, b)
		}
		if strings.Contains(string(b), ja4) || v.View.TLS || v.Fingerprints.Akamai != nil {
			t.Errorf("forwardAuth %d com as fingerprints de victim.org: %s", i, b)
		}
		if v.Subject.Site == nil || *v.Subject.Site != "a.com" {
			t.Errorf("forwardAuth %d: subject %+v", i, v.Subject)
		}
	}
	after, _ := f.srv.Index().Fork(testForkConnID, f.clock.Now())
	if !bytes.Equal(after.LastVerdict, before.LastVerdict) {
		t.Errorf("LastVerdict trocado: %s", after.LastVerdict)
	}
	if after.authSeen != before.authSeen || after.published != before.published {
		t.Errorf("contadores de publicação: auth %d→%d, published %d→%d", before.authSeen, after.authSeen,
			before.published, after.published)
	}
	if n := len(feed.queue); n != 0 {
		t.Errorf("forwardAuth da outra chave publicou %d vereditos", n)
	}
	// a requisição seguinte de victim.org pelo ingest sai no feed
	if c, _, b := f.do(f.internal, "POST", "/bot/v1/ingest/traefik", "", nil, foreignRequest("victim.org")); c != 202 ||
		string(b) != `{"accepted":1,"rejected":0}`+"\n" {
		t.Fatalf("requisição seguinte: %d %s", c, b)
	}
	if n := len(feed.queue); n != 1 {
		t.Fatalf("feed com %d vereditos depois da requisição de victim.org, quer 1", n)
	}
	if v := <-feed.queue; v.Subject.Site == nil || *v.Subject.Site != "victim.org" {
		t.Errorf("veredito publicado: %+v", v.Subject)
	}
}

// TestForwardAuthCoalescedConn: task 369 — coalescência h2 com uma chave por site: a requisição de b.example.com numa
// conexão de SNI a.example.com dá 200 com veredito (não 400, que jogaria o site em fail-open).
func TestForwardAuthCoalescedConn(t *testing.T) {
	f := newFixture(t)
	if c, _, b := f.do(f.internal, "POST", "/bot/v1/ingest/traefik", "", nil, foreignBatch("a.example.com")); c != 202 {
		t.Fatalf("conexão interna: %d %s", c, b)
	}
	_, key := f.createKey(KeyOptions{Name: "b", Domains: []string{"b.example.com"}})
	hdr := forkHeadersFor()
	hdr["X-Forwarded-Host"] = "b.example.com"
	c, h, v, b := f.authVerdict("public", key, hdr)
	if c != 200 || v.Class == "" || h.Get("X-Fs-Verdict") != v.Class {
		t.Fatalf("coalescência: %d %v %s", c, h, b)
	}
	if v.Subject.Site == nil || *v.Subject.Site != "b.example.com" || v.View.TLS {
		t.Errorf("veredito: %s", b)
	}
}
