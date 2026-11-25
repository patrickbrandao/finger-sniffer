package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

// captured é o que o bot falso recebeu.
type captured struct {
	method, uri string
	header      http.Header
	body        []byte
}

// fakeBot sobe um ingest falso que grava a requisição e responde 202 com cabeçalhos e corpo próprios.
func fakeBot(t *testing.T) (*httptest.Server, chan captured) {
	t.Helper()
	ch := make(chan captured, 1)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		ch <- captured{method: r.Method, uri: r.URL.RequestURI(), header: r.Header.Clone(), body: b}
		w.Header().Set("Content-Type", "application/json")
		w.Header()["X-Bot-Test"] = []string{"a", "b"}
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"accepted":3,"rejected":0}`))
	}))
	t.Cleanup(s.Close)
	return s, ch
}

// rawPost manda a requisição byte a byte (sem cliente Go no meio, que acrescentaria cabeçalhos) e lê a resposta.
func rawPost(t *testing.T, addr, head string, body []byte) (*http.Response, []byte) {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, head); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(body); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	rb, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, rb
}

// TestRecorderForwardsUnchanged: o lote chega ao bot com os mesmos bytes e cabeçalhos (inclusive repetidos, sem
// User-Agent nem Accept-Encoding acrescentados), a resposta do bot volta como veio e o lote fica gravado sem a chave.
func TestRecorderForwardsUnchanged(t *testing.T) {
	bot, got := fakeBot(t)
	dir := t.TempDir()
	rc, err := newRecorder(bot.URL, dir)
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(rc)
	defer front.Close()

	// corpo com bytes fora do UTF-8 e um \r\n no meio: tem de passar idêntico
	body := append([]byte(`{"schema":"traefix.fingerprint/v1","records":[`), 0x00, 0xff, '\r', '\n', 0x1f, 0x8b)
	body = append(body, []byte(`]}`)...)
	head := "POST /bot/v1/ingest/traefik?x=1 HTTP/1.1\r\n" +
		"Host: 127.0.0.1:18090\r\n" +
		"Content-Type: application/json\r\n" +
		"Content-Encoding: identity\r\n" +
		"X-Traefix-Sender: traefix/fork-point-999-gabc\r\n" +
		"X-Multi: um\r\n" +
		"X-Multi: dois\r\n" +
		"Authorization: Bearer fsk_segredo_de_teste\r\n" +
		"Content-Length: " + strconv.Itoa(len(body)) + "\r\n" +
		"Connection: close, X-Hop\r\n" +
		"X-Hop: só até o gravador\r\n\r\n"
	resp, rb := rawPost(t, strings.TrimPrefix(front.URL, "http://"), head, body)

	c := <-got
	if c.method != http.MethodPost || c.uri != "/bot/v1/ingest/traefik?x=1" {
		t.Errorf("bot recebeu %s %s", c.method, c.uri)
	}
	if !bytes.Equal(c.body, body) {
		t.Errorf("corpo mudou no repasse:\n got %q\nwant %q", c.body, body)
	}
	want := http.Header{
		"Content-Type":     {"application/json"},
		"Content-Encoding": {"identity"},
		"X-Traefix-Sender": {"traefix/fork-point-999-gabc"},
		"X-Multi":          {"um", "dois"},
		"Authorization":    {"Bearer fsk_segredo_de_teste"},
		"Content-Length":   {strconv.Itoa(len(body))},
	}
	// Connection é salto a salto: o servidor de cá consome e o cliente de lá não manda
	if !reflect.DeepEqual(c.header, want) {
		t.Errorf("cabeçalhos mudaram no repasse:\n got %v\nwant %v", c.header, want)
	}

	if resp.StatusCode != http.StatusAccepted || string(rb) != `{"accepted":3,"rejected":0}` ||
		!reflect.DeepEqual(resp.Header.Values("X-Bot-Test"), []string{"a", "b"}) ||
		resp.Header.Get("Content-Type") != "application/json" {
		t.Errorf("resposta ao traefix: %d %v %q", resp.StatusCode, resp.Header, rb)
	}

	saved, err := os.ReadFile(filepath.Join(dir, "000001.body"))
	if err != nil || !bytes.Equal(saved, body) {
		t.Errorf("corpo gravado %q (%v), esperado igual ao recebido", saved, err)
	}
	mj, err := os.ReadFile(filepath.Join(dir, "000001.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(mj, []byte("fsk_")) {
		t.Errorf("a chave foi ao disco: %s", mj)
	}
	var m meta
	if err := json.Unmarshal(mj, &m); err != nil {
		t.Fatal(err)
	}
	if m.Status != http.StatusAccepted || m.BodyBytes != len(body) || m.Response != `{"accepted":3,"rejected":0}` ||
		m.Header["Authorization"][0] != "[redacted]" || m.Path != "/bot/v1/ingest/traefik?x=1" {
		t.Errorf("metadados gravados: %+v", m)
	}
}

// TestRecorderUpstreamDown: bot fora do ar dá 502 ao traefix (o export conta como perda) e o lote fica gravado.
func TestRecorderUpstreamDown(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	dir := t.TempDir()
	rc, err := newRecorder("http://"+addr, dir)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	rc.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/bot/v1/ingest/traefik", strings.NewReader("{}")))
	if rec.Code != http.StatusBadGateway {
		t.Errorf("bot parado: %d, esperado 502", rec.Code)
	}
	var m meta
	mj, _ := os.ReadFile(filepath.Join(dir, "000001.json"))
	if json.Unmarshal(mj, &m) != nil || m.Error == "" || m.Status != http.StatusBadGateway {
		t.Errorf("metadados do lote sem resposta: %s", mj)
	}
}

func TestNewRecorderBadUpstream(t *testing.T) {
	if _, err := newRecorder("10.249.255.254:9003", t.TempDir()); err == nil {
		t.Error("upstream sem esquema aceito")
	}
}
