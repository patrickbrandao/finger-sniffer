package bot

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// Parâmetros do health `store feed silent` (spec 018 RF-11).
const (
	// storeFeedSilence é quanto tempo sem fs.v1.store.connection, com o store ok, deixa o bot degraded.
	storeFeedSilence = 60 * time.Second
	// storeHeartbeatDown é quando o heartbeat do store deixa de valer (o store marca down após 15 s, asyncapi).
	storeHeartbeatDown = 15 * time.Second
)

// storeWatch acompanha o estado do store pelos heartbeats dele (fs.v1.svc.heartbeat; o bot só lê, não publica nada
// além do próprio heartbeat).
type storeWatch struct {
	mu      sync.Mutex
	status  string    // último status do store
	at      time.Time // chegada do último heartbeat do store
	okSince time.Time // desde quando o store está ok sem interrupção
}

// heartbeat trata uma mensagem de fs.v1.svc.heartbeat; as de outros serviços e as inválidas são ignoradas.
func (w *storeWatch) heartbeat(data []byte, now time.Time) {
	env, err := event.Decode(data)
	if err != nil || env.Service != event.ServiceStore {
		return
	}
	var hb event.Heartbeat
	if err := json.Unmarshal(env.Payload, &hb); err != nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if hb.Status == event.StatusOK && !w.okLocked(now) {
		w.okSince = now
	}
	w.status, w.at = hb.Status, now
}

// okLocked diz se o store está ok agora (heartbeat ok e recente).
func (w *storeWatch) okLocked(now time.Time) bool {
	return w.status == event.StatusOK && !w.at.IsZero() && now.Sub(w.at) <= storeHeartbeatDown
}

// silent diz se o feed do store está calado: store ok e nenhuma mensagem há mais de 60 s, contando a partir da
// última mensagem ou de quando o store ficou ok (o que for mais recente). Store down, degraded ou desconhecido
// nunca dá silêncio: sem store não há o que receber.
func (w *storeWatch) silent(lastMessage, now time.Time) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.okLocked(now) {
		return false
	}
	ref := w.okSince
	if lastMessage.After(ref) {
		ref = lastMessage
	}
	return now.Sub(ref) > storeFeedSilence
}
