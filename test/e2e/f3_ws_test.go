//go:build e2e

package e2e

// Caso 9 da matriz da spec 017 no caminho direto: WebSocket ws:// e wss:// (HTTP/1.1 Upgrade, coder/websocket,
// com e sem permessage-deflate) e WebSocket sobre h2 (RFC 8441, CONNECT estendido montado à mão). O espelho ecoa
// e o registro lista cada frame com opcode, FIN, RSV, máscara e tamanho, e o fechamento.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// TestCase9WebSocket: ws:// e wss:// com eco de texto e binário, fechamento 1000 pelo cliente e frames no
// registro; wss:// com permessage-deflate negociado.
func TestCase9WebSocket(t *testing.T) {
	cases := []struct {
		name, scheme, path string
		deflate            bool
		port               int
	}{
		{"ws", "ws", "ws", false, 80},
		{"wss", "wss", "ws", false, 443},
		{"wss-deflate", "wss", "r?upgrade=ws", true, 443},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			id := newID(t)
			url := fmt.Sprintf("%s://%s/p/%s/%s", tc.scheme, probeHost(id), id, tc.path)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			opts := &websocket.DialOptions{CompressionMode: websocket.CompressionDisabled}
			if tc.deflate {
				opts.CompressionMode = websocket.CompressionNoContextTakeover
				opts.CompressionThreshold = 1
			}
			c, resp, err := websocket.Dial(ctx, url, opts)
			if err != nil {
				t.Fatalf("dial %s: %v", url, err)
			}
			if resp.StatusCode != 101 {
				t.Fatalf("status %d", resp.StatusCode)
			}
			ext := resp.Header.Get("Sec-WebSocket-Extensions")
			if tc.deflate != strings.Contains(ext, "permessage-deflate") {
				t.Errorf("Sec-WebSocket-Extensions = %q (deflate pedido: %v)", ext, tc.deflate)
			}
			msgs := []struct {
				typ  websocket.MessageType
				data []byte
			}{
				{websocket.MessageText, []byte("hello finger-sniffer " + tc.name)},
				{websocket.MessageBinary, []byte{0, 1, 2, 3, 0xff}},
			}
			for _, m := range msgs {
				if err := c.Write(ctx, m.typ, m.data); err != nil {
					t.Fatal(err)
				}
				typ, data, err := c.Read(ctx)
				if err != nil || typ != m.typ || !bytes.Equal(data, m.data) {
					t.Fatalf("eco: %v %q / %v, esperado %v %q", typ, data, err, m.typ, m.data)
				}
			}
			if err := c.Close(websocket.StatusNormalClosure, "bye"); err != nil {
				t.Errorf("close: %v", err)
			}

			p := waitProbe(t, id, func(p *probeResp) bool {
				for _, c := range p.conns(tc.port) {
					if c.WebSocket != nil && c.WebSocket.Close != nil {
						return true
					}
				}
				return false
			})
			var w *wsInfo
			var rc record
			for _, c := range p.conns(tc.port) {
				if c.WebSocket != nil {
					w, rc = c.WebSocket, c
				}
			}
			wantProto := "http1.1/ws"
			if tc.scheme == "wss" {
				wantProto = "tls/http1.1/ws"
			}
			// path é só o caminho, sem a query
			if rc.Proto != wantProto || w.Over != "http1.1" || w.Path != fmt.Sprintf("/p/%s/%s", id, strings.Split(tc.path, "?")[0]) {
				t.Errorf("proto=%s over=%s path=%s", rc.Proto, w.Over, w.Path)
			}
			if len(rc.HTTP) == 0 || ptr(rc.HTTP[0].Upgrade) != "websocket" || rc.HTTP[0].Status != 101 {
				t.Errorf("requisição de Upgrade não registrada como websocket/101")
			}
			if tc.deflate && !strings.Contains(ptr2(w.Extensions), "permessage-deflate") {
				t.Errorf("extensions = %v, esperado permessage-deflate com os parâmetros", ptr(w.Extensions))
			}
			checkWSFrames(t, w, tc.deflate)
		})
	}
}

// checkWSFrames confere os frames: do cliente mascarados (com a chave), do servidor sem máscara; texto,
// binário e close nos dois sentidos; RSV1 nos frames de dados comprimidos.
func checkWSFrames(t *testing.T, w *wsInfo, deflate bool) {
	t.Helper()
	count := map[string]int{}
	for _, f := range w.Frames {
		count[fmt.Sprintf("%s/%d", f.Dir, f.Opcode)]++
		switch f.Dir {
		case "in":
			if !f.Masked || len(ptr2(f.MaskKeyHex)) != 8 {
				t.Errorf("frame do cliente sem máscara: %+v", f)
			}
		case "out":
			if f.Masked {
				t.Errorf("frame do servidor mascarado: %+v", f)
			}
		}
		if !f.Fin {
			t.Errorf("frame fragmentado inesperado: %+v", f)
		}
		// o cliente comprime tudo (CompressionThreshold 1); o servidor pode mandar mensagens curtas sem
		// comprimir (RSV1 é por mensagem)
		if deflate && f.Dir == "in" && f.Opcode == 1 && f.Rsv&4 == 0 {
			t.Errorf("frame de texto do cliente sem RSV1 com permessage-deflate: %+v", f)
		}
	}
	for _, k := range []string{"in/1", "in/2", "in/8", "out/1", "out/2", "out/8"} {
		if count[k] != 1 {
			t.Errorf("frames %s = %d, esperado 1 (todos: %v)", k, count[k], count)
		}
	}
	if w.Close == nil || w.Close.By != "client" || ptr(w.Close.Code) != 1000 || ptr2(w.Close.Reason) != "bye" {
		t.Errorf("close = %+v", w.Close)
	}
}

// TestCase9WebSocketH2: WebSocket sobre h2 (RFC 8441): o servidor anuncia SETTINGS_ENABLE_CONNECT_PROTOCOL e
// aceita CONNECT com :protocol websocket; o eco segue nos DATA do stream.
func TestCase9WebSocketH2(t *testing.T) {
	t.Parallel()
	id := newID(t)
	host := probeHost(id)
	path := "/p/" + id + "/ws"
	tc, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp4", vps4+":443",
		&tls.Config{ServerName: host, NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatal(err)
	}
	defer tc.Close() //nolint:errcheck // teste
	_ = tc.SetDeadline(time.Now().Add(20 * time.Second))
	if tc.ConnectionState().NegotiatedProtocol != "h2" {
		t.Fatalf("ALPN = %q", tc.ConnectionState().NegotiatedProtocol)
	}
	if _, err := io.WriteString(tc, http2.ClientPreface); err != nil {
		t.Fatal(err)
	}
	fr := http2.NewFramer(tc, tc)
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	if err := fr.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	// SETTINGS do servidor com ENABLE_CONNECT_PROTOCOL=1
	enabled := false
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			t.Fatalf("lendo SETTINGS: %v", err)
		}
		if sf, ok := f.(*http2.SettingsFrame); ok && !sf.IsAck() {
			v, ok := sf.Value(http2.SettingEnableConnectProtocol)
			enabled = ok && v == 1
			if err := fr.WriteSettingsAck(); err != nil {
				t.Fatal(err)
			}
			break
		}
	}
	if !enabled {
		t.Fatal("servidor não anunciou SETTINGS_ENABLE_CONNECT_PROTOCOL=1")
	}
	var hb bytes.Buffer
	enc := hpack.NewEncoder(&hb)
	for _, f := range [][2]string{
		{":method", "CONNECT"},
		{":protocol", "websocket"},
		{":scheme", "https"},
		{":path", path},
		{":authority", host},
		{"sec-websocket-version", "13"},
		{"user-agent", "fs-e2e-rfc8441"},
	} {
		_ = enc.WriteField(hpack.HeaderField{Name: f[0], Value: f[1]})
	}
	if err := fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: hb.Bytes(), EndHeaders: true}); err != nil {
		t.Fatal(err)
	}
	// resposta 200 e depois os ecos
	readData := func() []byte {
		t.Helper()
		for {
			f, err := fr.ReadFrame()
			if err != nil {
				t.Fatalf("lendo stream 1: %v", err)
			}
			switch f := f.(type) {
			case *http2.MetaHeadersFrame:
				if st := f.PseudoValue("status"); st != "200" {
					t.Fatalf("CONNECT estendido: :status %s", st)
				}
			case *http2.DataFrame:
				if f.StreamID == 1 && len(f.Data()) > 0 {
					_ = fr.WriteWindowUpdate(0, uint32(len(f.Data())))
					_ = fr.WriteWindowUpdate(1, uint32(len(f.Data())))
					return append([]byte(nil), f.Data()...)
				}
			case *http2.RSTStreamFrame:
				t.Fatalf("RST_STREAM %v", f.ErrCode)
			case *http2.GoAwayFrame:
				t.Fatalf("GOAWAY %v", f.ErrCode)
			}
		}
	}
	msg := "hello over h2"
	if err := fr.WriteData(1, false, wsFrame(1, []byte(msg))); err != nil {
		t.Fatal(err)
	}
	if got := readData(); !bytes.Equal(got, append([]byte{0x81, byte(len(msg))}, msg...)) {
		t.Errorf("eco em h2: %x", got)
	}
	closeBody := binary.BigEndian.AppendUint16(nil, 1000)
	closeBody = append(closeBody, "bye"...)
	if err := fr.WriteData(1, false, wsFrame(8, closeBody)); err != nil {
		t.Fatal(err)
	}
	if got := readData(); len(got) < 4 || got[0] != 0x88 || binary.BigEndian.Uint16(got[2:4]) != 1000 {
		t.Errorf("close de volta em h2: %x", got)
	}
	_ = fr.WriteData(1, true, nil)
	_ = fr.WriteGoAway(1, http2.ErrCodeNo, nil)
	time.Sleep(200 * time.Millisecond)
	_ = tc.Close()

	p := waitProbe(t, id, func(p *probeResp) bool {
		for _, c := range p.conns(443) {
			if c.WebSocket != nil && c.WebSocket.Close != nil {
				return true
			}
		}
		return false
	})
	for _, c := range p.conns(443) {
		w := c.WebSocket
		if w == nil {
			continue
		}
		if w.Over != "h2" || w.Path != path || !strings.HasSuffix(c.Proto, "/ws") || !strings.HasPrefix(c.Proto, "tls/h2") {
			t.Errorf("RFC 8441: proto=%s over=%s path=%s", c.Proto, w.Over, w.Path)
		}
		n := map[string]int{}
		for _, f := range w.Frames {
			n[fmt.Sprintf("%s/%d", f.Dir, f.Opcode)]++
		}
		if n["in/1"] != 1 || n["out/1"] != 1 || n["in/8"] != 1 || n["out/8"] != 1 {
			t.Errorf("RFC 8441: frames %v", n)
		}
		if w.Close == nil || w.Close.By != "client" || ptr(w.Close.Code) != 1000 {
			t.Errorf("RFC 8441: close = %+v", w.Close)
		}
		return
	}
	t.Fatal("RFC 8441: nenhuma conexão com websocket no registro")
}

// wsFrame monta um frame WebSocket do cliente (FIN, mascarado, tamanho < 126).
func wsFrame(opcode byte, payload []byte) []byte {
	var key [4]byte
	_, _ = rand.Read(key[:])
	out := []byte{0x80 | opcode, 0x80 | byte(len(payload))}
	out = append(out, key[:]...)
	for i, b := range payload {
		out = append(out, b^key[i%4])
	}
	return out
}
