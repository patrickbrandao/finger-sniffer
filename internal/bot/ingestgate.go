package bot

import (
	"errors"
	"net"
	"os"
	"sync"
	"time"
)

// Limites de lotes do ingest (ADR 0073 item 2; spec 020 RF-04). Constantes do código.
const (
	// MaxIngestBatches é o teto de lotes em leitura, decodificação e aplicação ao mesmo tempo no processo.
	MaxIngestBatches = 8
	// MaxIngestBatchesPublic é quantos desses a 9002 pode usar (2 ficam para a 9003).
	MaxIngestBatchesPublic = 6
	// MaxIngestBatchesPerKey é o teto por chave da 9002 (na 9003 não há parte por chave, ADR 0073 item 4).
	MaxIngestBatchesPerKey = 2
	// ingestBodyTimeout é o prazo para o corpo do lote chegar, desde o início do handler.
	ingestBodyTimeout = 10 * time.Second
	// metricIngestRefused conta os lotes recusados pelos limites de entrada do ingest, por reason.
	metricIngestRefused = "bot_ingest_refused_total"
)

// Motivos de bot_ingest_refused_total.
const (
	refusedBusy          = "busy"
	refusedKeyConcurrent = "key_concurrency"
	refusedBodyTimeout   = "body_timeout"
)

func ingestRefusedMetric(reason string) string {
	return metricIngestRefused + `{reason="` + reason + `"}`
}

// ingestGate é o semáforo sem espera dos lotes do ingest: total no processo, parte da 9002 e parte por chave da
// 9002.
type ingestGate struct {
	maxTotal, maxPublic, maxKey int

	mu            sync.Mutex
	total, public int
	perKey        map[string]int
}

func newIngestGate(total, public, perKey int) *ingestGate {
	return &ingestGate{maxTotal: total, maxPublic: public, maxKey: perKey, perKey: map[string]int{}}
}

// acquire pega uma vaga para um lote; keyID vazio = sem parte por chave (9003, com ou sem chave). Sem vaga, devolve
// o motivo (refusedBusy ou refusedKeyConcurrent) e release nil.
func (g *ingestGate) acquire(public bool, keyID string) (release func(), reason string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.total >= g.maxTotal || (public && g.public >= g.maxPublic) {
		return nil, refusedBusy
	}
	if keyID != "" && g.perKey[keyID] >= g.maxKey {
		return nil, refusedKeyConcurrent
	}
	g.total++
	if public {
		g.public++
	}
	if keyID != "" {
		g.perKey[keyID]++
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			g.mu.Lock()
			defer g.mu.Unlock()
			g.total--
			if public {
				g.public--
			}
			if keyID != "" {
				if g.perKey[keyID]--; g.perKey[keyID] <= 0 {
					delete(g.perKey, keyID)
				}
			}
		})
	}, ""
}

// inUse devolve quantos lotes estão em andamento (testes).
func (g *ingestGate) inUse() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.total
}

// readTimedOut diz se o erro de leitura é o prazo estourado (SetReadDeadline).
func readTimedOut(err error) bool {
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
