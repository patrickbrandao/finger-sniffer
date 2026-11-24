package store

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"strings"
	"testing"
	"time"
)

// bigPcap troca o pcap da conexão encerrada da fixture por um BLOB de n bytes.
func bigPcap(t *testing.T, f *apiFixture, n int) {
	t.Helper()
	if _, err := f.in.db.Exec("INSERT OR REPLACE INTO pcaps (conn_id, data) VALUES (?, zeroblob(?))", f.closed, n); err != nil {
		t.Fatal(err)
	}
}

// TestBlobBusy: com as 4 vagas de download ocupadas, /pcap e /raw recebem 503 na hora com Retry-After; com uma
// vaga livre o download sai (ADR 0032, task 129).
func TestBlobBusy(t *testing.T) {
	f := newAPIFixture(t)
	for range blobMax {
		f.q.blobs <- struct{}{}
	}
	for _, path := range []string{"/api/v1/connections/" + f.closed + "/pcap", "/api/v1/connections/" + f.closed + "/raw?dir=in"} {
		resp, err := http.Get(f.srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Retry-After") != "1" || !strings.Contains(string(b), `"error"`) {
			t.Fatalf("%s: %d Retry-After=%q %s", path, resp.StatusCode, resp.Header.Get("Retry-After"), b)
		}
	}
	<-f.q.blobs
	if code, _ := f.get(t, "/api/v1/connections/"+f.closed+"/pcap"); code != 200 {
		t.Fatalf("com vaga livre: %d", code)
	}
	if n := len(f.q.blobs); n != blobMax-1 {
		t.Fatalf("vagas ocupadas depois do download: %d", n)
	}
}

// stalledGet abre uma conexão TCP, pede o caminho e não lê nada.
func stalledGet(t *testing.T, f *apiFixture, path string) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", strings.TrimPrefix(f.srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if _, err := io.WriteString(c, "GET "+path+" HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	return c
}

// TestBlobStalledClients: 4 clientes que não leem um pcap de 16 MiB ocupam as 4 vagas e o quinto recebe 503; no
// prazo de escrita eles são cortados (conexão encerrada antes do fim do corpo) e as vagas voltam.
func TestBlobStalledClients(t *testing.T) {
	f := newAPIFixture(t)
	const size = 16 << 20
	bigPcap(t, f, size)
	f.q.blobWrite = 500 * time.Millisecond
	path := "/api/v1/connections/" + f.closed + "/pcap"
	var conns []net.Conn
	for range blobMax {
		conns = append(conns, stalledGet(t, f, path))
	}
	eventually(t, 2*time.Second, func() bool { return len(f.q.blobs) == blobMax }, "downloads parados não ocuparam as vagas")
	if code, _ := f.get(t, path); code != http.StatusServiceUnavailable {
		t.Fatalf("quinto download: %d", code)
	}
	start := time.Now()
	eventually(t, 5*time.Second, func() bool { return len(f.q.blobs) == 0 }, "vagas não voltaram no prazo de escrita")
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("vagas voltaram em %v (prazo 500 ms)", d)
	}
	// o cliente que volta a ler recebe menos que o corpo inteiro: a conexão foi encerrada
	for _, c := range conns {
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, _ := io.Copy(io.Discard, c)
		if n >= size {
			t.Fatalf("cliente parado recebeu o corpo inteiro (%d bytes)", n)
		}
	}
	if code, _ := f.get(t, path); code != 200 {
		t.Fatalf("download depois do corte: %d", code)
	}
}

// TestBlobDeadlineNotInherited: na mesma conexão keep-alive, um long-poll depois do download não herda o prazo de
// escrita do download.
func TestBlobDeadlineNotInherited(t *testing.T) {
	f := newAPIFixture(t)
	f.q.blobWrite = 200 * time.Millisecond
	client := &http.Client{Transport: &http.Transport{MaxConnsPerHost: 1}}
	defer client.CloseIdleConnections()
	get := func(path string) (int, bool) {
		var reused bool
		trace := &httptrace.ClientTrace{GotConn: func(i httptrace.GotConnInfo) { reused = i.Reused }}
		req, _ := http.NewRequestWithContext(httptrace.WithClientTrace(t.Context(), trace), http.MethodGet, f.srv.URL+path, nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode, reused
	}
	if code, _ := get("/api/v1/connections/" + f.closed + "/pcap"); code != 200 {
		t.Fatal(code)
	}
	// o 404 do wait sai 600 ms depois, bem além do prazo de 200 ms do download anterior
	code, reused := get("/api/v1/probes/zzzzzzzz?wait=600ms")
	if code != 404 || !reused {
		t.Fatalf("%d reused=%v", code, reused)
	}
}

// TestBlobRawStreamsWhole: o /raw com pedaços devolve os bytes na ordem, com Content-Length.
func TestBlobRawStreamsWhole(t *testing.T) {
	f := newAPIFixture(t)
	if _, err := f.in.db.Exec("INSERT INTO raw_streams (conn_id, dir, offset, data) VALUES (?, 0, 3, x'646566'), (?, 0, 0, x'616263')", f.opened, f.opened); err != nil {
		t.Fatal(err)
	}
	resp, err := http.Get(f.srv.URL + "/api/v1/connections/" + f.opened + "/raw?dir=in")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(bufio.NewReader(resp.Body))
	if resp.StatusCode != 200 || string(b) != "abcdef" || resp.ContentLength != 6 {
		t.Fatalf("%d %q len=%d", resp.StatusCode, b, resp.ContentLength)
	}
}
