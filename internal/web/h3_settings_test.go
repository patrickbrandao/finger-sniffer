package web

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/quicparse"
)

// maxVarint é o maior valor de um varint QUIC (2^62-1).
const maxVarint = 1<<62 - 1

// lateSettings são os SETTINGS do cliente de teste: um valor 2^62-1, um GREASE e um zero.
var lateSettings = [][2]uint64{
	{quicparse.SettingMaxFieldSectionSize, maxVarint},
	{0x21, 7},
	{quicparse.SettingQPACKMaxTableCapacity, 0},
}

// rawH3 é um cliente h3 mínimo sobre quic-go que controla quando o stream de controle é aberto.
type rawH3 struct {
	t  *testing.T
	qc *quic.Conn
}

func dialRawH3(t *testing.T, pc *net.UDPConn) *rawH3 {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	qc, err := quic.DialAddr(ctx, pc.LocalAddr().String(),
		&tls.Config{ServerName: testSNI, InsecureSkipVerify: true, NextProtos: []string{"h3"}}, //nolint:gosec // autoassinado de teste
		&quic.Config{MaxIdleTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return &rawH3{t: t, qc: qc}
}

func (c *rawH3) port() int { return c.qc.LocalAddr().(*net.UDPAddr).Port }

// request manda um GET (HEADERS e FIN) e devolve o stream para ler a resposta depois.
func (c *rawH3) request(path string) *quic.Stream {
	c.t.Helper()
	str, err := c.qc.OpenStreamSync(context.Background())
	if err != nil {
		c.t.Fatal(err)
	}
	fs := quicparse.AppendFieldSection(nil, [][2]string{
		{":method", "GET"}, {":scheme", "https"}, {":authority", testSNI}, {":path", path},
	})
	if _, err := str.Write(quicparse.AppendH3Frame(nil, quicparse.H3FrameHeaders, fs)); err != nil {
		c.t.Fatal(err)
	}
	if err := str.Close(); err != nil {
		c.t.Fatal(err)
	}
	return str
}

// sendSettings abre o stream de controle do cliente com lateSettings.
func (c *rawH3) sendSettings() {
	c.t.Helper()
	u, err := c.qc.OpenUniStream()
	if err != nil {
		c.t.Fatal(err)
	}
	var p []byte
	for _, kv := range lateSettings {
		p = quicparse.AppendVarint(p, kv[0])
		p = quicparse.AppendVarint(p, kv[1])
	}
	if _, err := u.Write(quicparse.AppendH3Frame([]byte{quicparse.StreamTypeControl}, quicparse.H3FrameSettings, p)); err != nil {
		c.t.Fatal(err)
	}
}

// readResponse lê a resposta inteira e confere que ela começa por um HEADERS.
func (c *rawH3) readResponse(str *quic.Stream) {
	c.t.Helper()
	_ = str.SetReadDeadline(time.Now().Add(5 * time.Second))
	b, err := io.ReadAll(str)
	if err != nil || len(b) == 0 || b[0] != quicparse.H3FrameHeaders {
		c.t.Fatalf("resposta %v %x", err, b[:min(len(b), 16)])
	}
}

// finalSettings espera o http3.connection com close da porta e devolve os h3_settings com os inteiros
// exatos (json.Number).
func finalSettings(t *testing.T, h *harness, port int) [][2]uint64 {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		conns := h.events.find(t, event.SubjectWebHTTP3Connection, port)
		if n := len(conns); n > 0 && conns[n-1].Payload["close"] != nil {
			var p struct {
				H3Settings [][2]json.Number `json:"h3_settings"`
			}
			d := json.NewDecoder(bytes.NewReader(conns[n-1].Env.Payload))
			d.UseNumber()
			if err := d.Decode(&p); err != nil {
				t.Fatal(err)
			}
			out := make([][2]uint64, 0, len(p.H3Settings))
			for _, kv := range p.H3Settings {
				var pair [2]uint64
				for i, s := range kv {
					var v uint64
					if err := json.Unmarshal([]byte(s.String()), &v); err != nil {
						t.Fatalf("setting %v: %v", kv, err)
					}
					pair[i] = v
				}
				out = append(out, pair)
			}
			return out
		}
		if time.Now().After(deadline) {
			t.Fatalf("sem http3.connection com close na porta %d", port)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func checkLateSettings(t *testing.T, got [][2]uint64) {
	t.Helper()
	if len(got) != len(lateSettings) {
		t.Fatalf("h3_settings %v, quer %v", got, lateSettings)
	}
	for i := range got {
		if got[i] != lateSettings[i] {
			t.Fatalf("h3_settings[%d] = %v, quer %v", i, got[i], lateSettings[i])
		}
	}
}

// TestH3SettingsAfterHeaders: o cliente manda o SETTINGS só depois do HEADERS (10 ms depois) e fecha a
// conexão assim que lê a resposta, como o curl: sem a espera do servidor o SETTINGS e o CONNECTION_CLOSE
// chegam colados e o quic-go descarta o stream de controle ainda não lido. O SETTINGS entra no
// http3.connection final, com 2^62-1 exato (task 063).
func TestH3SettingsAfterHeaders(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	pc := startH3(t, h)
	for range 5 {
		c := dialRawH3(t, pc)
		str := c.request("/p/" + testProbe + "/")
		time.Sleep(10 * time.Millisecond)
		c.sendSettings()
		c.readResponse(str)
		_ = c.qc.CloseWithError(h3NoError, "")
		checkLateSettings(t, finalSettings(t, h, c.port()))
	}
}

// TestH3SettingsAfterResponse: o SETTINGS chega depois da resposta (passada a espera); o http3.connection
// final da conexão traz os SETTINGS.
func TestH3SettingsAfterResponse(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	pc := startH3(t, h)
	c := dialRawH3(t, pc)
	start := time.Now()
	c.readResponse(c.request("/p/" + testProbe + "/"))
	if el := time.Since(start); el < h3SettingsWait {
		t.Fatalf("resposta em %v sem esperar o SETTINGS", el)
	}
	// a segunda requisição não espera de novo
	start = time.Now()
	c.readResponse(c.request("/p/" + testProbe + "/"))
	if el := time.Since(start); el >= h3SettingsWait {
		t.Fatalf("segunda resposta esperou %v", el)
	}
	c.sendSettings()
	time.Sleep(100 * time.Millisecond)
	_ = c.qc.CloseWithError(h3NoError, "")
	checkLateSettings(t, finalSettings(t, h, c.port()))
}

// finalControlSeen espera o http3.connection com close da porta e devolve h3_control_stream_seen (que
// precisa estar presente) e h3_settings.
func finalControlSeen(t *testing.T, h *harness, port int) (bool, [][2]uint64) {
	t.Helper()
	settings := finalSettings(t, h, port)
	conns := h.events.find(t, event.SubjectWebHTTP3Connection, port)
	for _, c := range conns {
		if _, ok := c.Payload["h3_control_stream_seen"].(bool); !ok {
			t.Fatalf("h3_control_stream_seen ausente: %v", c.Payload["h3_control_stream_seen"])
		}
	}
	return conns[len(conns)-1].Payload["h3_control_stream_seen"].(bool), settings
}

// TestH3ControlStreamSeen: sem stream de controle do cliente → false e []; SETTINGS vazio → true e [];
// SETTINGS normal → true (task 073).
func TestH3ControlStreamSeen(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	pc := startH3(t, h)

	t.Run("sem stream de controle", func(t *testing.T) {
		c := dialRawH3(t, pc)
		c.readResponse(c.request("/p/" + testProbe + "/"))
		_ = c.qc.CloseWithError(h3NoError, "")
		seen, settings := finalControlSeen(t, h, c.port())
		if seen || len(settings) != 0 {
			t.Fatalf("seen=%v settings=%v", seen, settings)
		}
	})
	t.Run("SETTINGS vazio", func(t *testing.T) {
		c := dialRawH3(t, pc)
		u, err := c.qc.OpenUniStream()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := u.Write(quicparse.AppendH3Frame([]byte{quicparse.StreamTypeControl}, quicparse.H3FrameSettings, nil)); err != nil {
			t.Fatal(err)
		}
		c.readResponse(c.request("/p/" + testProbe + "/"))
		time.Sleep(50 * time.Millisecond)
		_ = c.qc.CloseWithError(h3NoError, "")
		seen, settings := finalControlSeen(t, h, c.port())
		if !seen || len(settings) != 0 {
			t.Fatalf("seen=%v settings=%v", seen, settings)
		}
	})
	t.Run("SETTINGS normal", func(t *testing.T) {
		c := dialRawH3(t, pc)
		c.sendSettings()
		c.readResponse(c.request("/p/" + testProbe + "/"))
		time.Sleep(50 * time.Millisecond)
		_ = c.qc.CloseWithError(h3NoError, "")
		seen, settings := finalControlSeen(t, h, c.port())
		if !seen {
			t.Fatal("seen=false")
		}
		checkLateSettings(t, settings)
	})
}
