package store

import (
	"context"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// Configuração do stream FS_EVENTS (ADR 0016: em memória, 32 MiB, 60 s).
const (
	StreamName   = "FS_EVENTS"
	ConsumerName = "store"
	streamMaxAge = 60 * time.Second
	streamMaxMem = 32 << 20
)

// StreamConfig devolve a configuração do stream.
func StreamConfig() jetstream.StreamConfig {
	return jetstream.StreamConfig{
		Name:     StreamName,
		Subjects: []string{event.SubjectAll},
		Storage:  jetstream.MemoryStorage,
		MaxAge:   streamMaxAge,
		MaxBytes: streamMaxMem,
		Discard:  jetstream.DiscardOld,
	}
}

// EnsureStream cria ou ajusta o stream e o consumidor durável do store. Se existir um stream com outro tipo
// de armazenamento (que não muda por update), ele é recriado.
func EnsureStream(ctx context.Context, js jetstream.JetStream) (jetstream.Consumer, error) {
	cfg := StreamConfig()
	if s, err := js.Stream(ctx, StreamName); err == nil {
		if info, err := s.Info(ctx); err == nil && info.Config.Storage != cfg.Storage {
			if err := js.DeleteStream(ctx, StreamName); err != nil {
				return nil, err
			}
		}
	}
	if _, err := js.CreateOrUpdateStream(ctx, cfg); err != nil {
		return nil, err
	}
	return js.CreateOrUpdateConsumer(ctx, StreamName, jetstream.ConsumerConfig{
		Durable:       ConsumerName,
		AckPolicy:     jetstream.AckExplicitPolicy,
		MaxAckPending: 4096,
	})
}
