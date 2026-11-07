// Package service é a base comum dos cinco serviços (spec 001): configuração FS_*, log slog em JSON,
// conexão NATS com reconexão, produtor com buffer curto (ADR 0003) e heartbeat (spec 004 RF-09).
package service

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config reúne a configuração comum a todos os serviços.
type Config struct {
	NATSURL           string
	LogLevel          slog.Level
	BufferMaxAge      time.Duration
	BufferMaxBytes    int
	HeartbeatInterval time.Duration
}

// LoadConfig lê a configuração comum das variáveis FS_* (modelo em .env.example).
func LoadConfig() (Config, error) {
	var c Config
	var err error
	c.NATSURL = Env("FS_NATS_URL", "nats://127.0.0.1:4222")
	if c.LogLevel, err = parseLevel(Env("FS_LOG_LEVEL", "info")); err != nil {
		return c, err
	}
	if c.BufferMaxAge, err = EnvDuration("FS_PRODUCER_BUFFER_MAX_AGE", 30*time.Second); err != nil {
		return c, err
	}
	if c.BufferMaxBytes, err = EnvInt("FS_PRODUCER_BUFFER_MAX_BYTES", 16<<20); err != nil {
		return c, err
	}
	if c.HeartbeatInterval, err = EnvDuration("FS_HEARTBEAT_INTERVAL", 5*time.Second); err != nil {
		return c, err
	}
	return c, nil
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
