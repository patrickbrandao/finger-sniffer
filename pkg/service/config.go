// Package service é a base comum dos cinco serviços (spec 001): configuração FS_*, log slog em JSON,
// conexão NATS com reconexão, produtor com buffer curto (ADR 0003) e heartbeat (spec 004 RF-09).
package service

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// Config reúne a configuração comum a todos os serviços.
type Config struct {
	NATSURL string
	// NATSUser é o usuário NATS do serviço (FS_NATS_USER, ADR 0075 item 1.3); vazio = sem autenticação.
	NATSUser string
	// NATSPassword é a senha do NATSUser (FS_NATS_PASSWORD_FILE ou FS_NATS_PASSWORD). O tipo Secret esconde o valor
	// em qualquer formatação (%v, %+v, slog, JSON): a senha nunca vai para log, health nem mensagem de erro.
	NATSPassword      Secret
	LogLevel          slog.Level
	BufferMaxAge      time.Duration
	BufferMaxBytes    int
	HeartbeatInterval time.Duration
	// EventInlineMax é o teto de bytes crus por campo inline dos eventos (FS_EVENT_INLINE_MAX, ADR 0018).
	EventInlineMax int
	// RawStreamMaxBytes é o teto do fluxo de aplicação por sentido e conexão (FS_RAW_STREAM_MAX_BYTES).
	RawStreamMaxBytes int
}

// LoadConfig lê a configuração comum das variáveis FS_* (modelo em .env.example).
func LoadConfig() (Config, error) {
	var c Config
	var err error
	c.NATSURL = Env("FS_NATS_URL", "nats://127.0.0.1:4222")
	if c.NATSUser, c.NATSPassword, err = loadNATSAuth(); err != nil {
		return c, err
	}
	if c.LogLevel, err = parseLevel(Env("FS_LOG_LEVEL", "info")); err != nil {
		return c, err
	}
	if c.BufferMaxAge, err = EnvDuration("FS_PRODUCER_BUFFER_MAX_AGE", 30*time.Second); err != nil {
		return c, err
	}
	if c.BufferMaxBytes, err = EnvInt("FS_PRODUCER_BUFFER_MAX_BYTES", 16<<20); err != nil {
		return c, err
	}
	if c.BufferMaxAge < 0 || c.BufferMaxBytes < 0 {
		return c, errors.New("service: FS_PRODUCER_BUFFER_MAX_AGE e FS_PRODUCER_BUFFER_MAX_BYTES não podem ser negativos")
	}
	if c.HeartbeatInterval, err = EnvDuration("FS_HEARTBEAT_INTERVAL", 5*time.Second); err != nil {
		return c, err
	}
	// time.NewTicker entra em pânico com intervalo <= 0, na goroutine do heartbeat.
	if c.HeartbeatInterval <= 0 {
		return c, errors.New("service: FS_HEARTBEAT_INTERVAL precisa ser maior que zero")
	}
	if c.EventInlineMax, err = EnvInt(event.EnvEventInlineMax, event.DefaultEventInlineMax); err != nil {
		return c, err
	}
	// Em base64 o campo cresce 4/3; com o envelope ele precisa caber no teto de 900 KiB do evento.
	if c.EventInlineMax <= 0 || c.EventInlineMax > event.MaxEventBytes/2 {
		return c, fmt.Errorf("service: %s precisa estar entre 1 e %d", event.EnvEventInlineMax, event.MaxEventBytes/2)
	}
	if c.RawStreamMaxBytes, err = EnvInt(event.EnvRawStreamMaxBytes, event.DefaultRawStreamMaxBytes); err != nil {
		return c, err
	}
	if c.RawStreamMaxBytes < 0 {
		return c, fmt.Errorf("service: %s não pode ser negativo", event.EnvRawStreamMaxBytes)
	}
	return c, nil
}

// Secret guarda um valor sensível; toda forma de impressão devolve "[redacted]". O valor só sai por Reveal.
type Secret string

const redacted = "[redacted]"

// Reveal devolve o valor real, para entregar à biblioteca que precisa dele.
func (s Secret) Reveal() string { return string(s) }

// String esconde o valor (%v, %s, %+v).
func (Secret) String() string { return redacted }

// GoString esconde o valor (%#v).
func (Secret) GoString() string { return redacted }

// LogValue esconde o valor no slog.
func (Secret) LogValue() slog.Value { return slog.StringValue(redacted) }

// MarshalText esconde o valor em JSON e afins.
func (Secret) MarshalText() ([]byte, error) { return []byte(redacted), nil }

// loadNATSAuth lê o usuário e a senha do NATS (ADR 0075 item 1.3). Sem usuário, nada de senha. Com usuário, a
// senha vem de exatamente uma das duas chaves e não pode ser vazia. Os erros citam chaves e caminho, nunca a senha.
func loadNATSAuth() (string, Secret, error) {
	user := Env("FS_NATS_USER", "")
	direct := Env("FS_NATS_PASSWORD", "")
	file := Env("FS_NATS_PASSWORD_FILE", "")
	if direct != "" && file != "" {
		return "", "", errors.New("service: FS_NATS_PASSWORD e FS_NATS_PASSWORD_FILE juntos; use só uma")
	}
	if user == "" {
		if direct != "" || file != "" {
			return "", "", errors.New("service: senha do NATS sem FS_NATS_USER")
		}
		return "", "", nil
	}
	pw := direct
	if file != "" {
		b, err := os.ReadFile(file) //nolint:gosec // caminho vem da unit, não do cliente
		if err != nil {
			// Só o erro do sistema (caminho e motivo): o conteúdo do arquivo nunca entra na mensagem.
			return "", "", fmt.Errorf("service: FS_NATS_PASSWORD_FILE: %w", err)
		}
		pw = strings.TrimRight(string(b), " \t\r\n")
	}
	if pw == "" {
		return "", "", fmt.Errorf("service: FS_NATS_USER=%s sem senha (FS_NATS_PASSWORD_FILE ou FS_NATS_PASSWORD)", user)
	}
	return user, Secret(pw), nil
}

// Env devolve a variável ou o padrão quando ausente ou vazia.
func Env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

// EnvInt lê um inteiro.
func EnvInt(key string, def int) (int, error) {
	v := Env(key, "")
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("service: %s: %w", key, err)
	}
	return n, nil
}

// EnvDuration lê uma duração no formato do Go (ex.: 30s, 10m).
func EnvDuration(key string, def time.Duration) (time.Duration, error) {
	v := Env(key, "")
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("service: %s: %w", key, err)
	}
	return d, nil
}

func parseLevel(s string) (slog.Level, error) {
	var l slog.Level
	if err := l.UnmarshalText([]byte(strings.ToUpper(s))); err != nil {
		return 0, fmt.Errorf("service: FS_LOG_LEVEL: %w", err)
	}
	return l, nil
}
