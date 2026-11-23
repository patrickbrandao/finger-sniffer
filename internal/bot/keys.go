package bot

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/patrickbrandao/finger-sniffer/internal/bot/webhook"
)

// Formato da chave (ADR 0051 item 2): "fsk_" + 32 bytes aleatórios em base32 minúsculo sem preenchimento.
const (
	keyPrefix     = "fsk_"
	keyBodyLen    = 52
	keyPrefixShow = 8 // caracteres do corpo guardados para exibição
)

// Padrões dos limites por chave (ADR 0051 item 4).
const (
	DefaultRatePerS   = 20
	DefaultBurst      = 40
	DefaultDailyQuota = 100000
)

// Modos da chave.
const (
	ModeObserve = "observe"
	ModeBlock   = "block"
)

var keyEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// Erros das operações de chave.
var (
	ErrKeyNotFound = errors.New("bot: key not found")
	ErrKeyRevoked  = errors.New("bot: key already revoked")
)

// Key é uma chave de API como fica no banco, sem o segredo.
type Key struct {
	ID             string
	Name           string
	Prefix         string
	Domains        []string
	RatePerS       int // 0 = padrão
	Burst          int // 0 = padrão
	DailyQuota     int // 0 = padrão
	Mode           string
	WebhookURL     string
	WebhookClasses []string
	CreatedAt      time.Time
	RevokedAt      *time.Time
	hash           [32]byte
	webhookSecret  []byte
}

// WebhookSecret devolve o segredo do HMAC do webhook (nil sem webhook).
func (k *Key) WebhookSecret() []byte { return k.webhookSecret }

// Rate devolve as requisições por segundo efetivas (com o padrão).
func (k *Key) Rate() int { return orDefault(k.RatePerS, DefaultRatePerS) }

// BurstSize devolve o tamanho efetivo do balde.
func (k *Key) BurstSize() int { return orDefault(k.Burst, DefaultBurst) }

// Quota devolve a cota diária efetiva.
func (k *Key) Quota() int { return orDefault(k.DailyQuota, DefaultDailyQuota) }

func orDefault(v, def int) int {
	if v > 0 {
		return v
	}
	return def
}

// KeyOptions são os parâmetros de `key create`.
type KeyOptions struct {
	Name           string
	Domains        []string
	RatePerS       int
	Burst          int
	DailyQuota     int
	Mode           string
	WebhookURL     string
	WebhookClasses []string
}

// NewKeySecret gera uma chave nova e devolve o texto (mostrado uma vez) e o SHA-256 guardado no banco.
func NewKeySecret() (string, [32]byte, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", [32]byte{}, err
	}
	s := keyPrefix + strings.ToLower(keyEncoding.EncodeToString(raw[:]))
	return s, sha256.Sum256([]byte(s)), nil
}

// ParseKey confere o formato de uma chave apresentada e devolve o SHA-256 dela.
func ParseKey(s string) ([32]byte, bool) {
	body, ok := strings.CutPrefix(s, keyPrefix)
	if !ok || len(body) != keyBodyLen {
		return [32]byte{}, false
	}
	for i := 0; i < len(body); i++ {
		c := body[i]
		if (c < 'a' || c > 'z') && (c < '2' || c > '7') {
			return [32]byte{}, false
		}
	}
	return sha256.Sum256([]byte(s)), true
}

// validateOptions normaliza e confere as opções de uma chave nova.
func validateOptions(o *KeyOptions) error {
	o.Name = strings.TrimSpace(o.Name)
	if o.Name == "" {
		return errors.New("bot: --name is required")
	}
	doms, err := NormalizeDomains(o.Domains)
	if err != nil {
		return err
	}
	o.Domains = doms
	if o.Mode == "" {
		o.Mode = ModeObserve
	}
	if o.Mode != ModeObserve && o.Mode != ModeBlock {
		return fmt.Errorf("bot: --mode must be %s or %s", ModeObserve, ModeBlock)
	}
	if o.RatePerS < 0 || o.Burst < 0 || o.DailyQuota < 0 {
		return errors.New("bot: limits must not be negative")
	}
	if o.WebhookURL != "" {
		u, err := url.Parse(o.WebhookURL)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return errors.New("bot: --webhook-url must be an https URL")
		}
		// IP literal interno é recusado já aqui (o dial do webhook também recusa, depois da resolução; task 372)
		if ip, err := netip.ParseAddr(u.Hostname()); err == nil && webhook.BlockedAddr(ip) {
			return errors.New("bot: --webhook-url must not point to an internal address")
		}
		if len(o.WebhookClasses) == 0 {
			o.WebhookClasses = []string{"bot", "suspect"}
		}
		for _, c := range o.WebhookClasses {
			if !validClass(c) {
				return fmt.Errorf("bot: unknown verdict class %q", c)
			}
		}
	}
	return nil
}

func validClass(c string) bool {
	switch c {
	case "human", "good_bot", "bot", "suspect", "unknown":
		return true
	}
	return false
}

func nullInt(v int) any {
	if v <= 0 {
		return nil
	}
	return v
}

func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// CreateKey emite uma chave (ADR 0051 item 2). Devolve o texto da chave e o segredo do webhook (se houver),
// mostrados uma vez; o banco só guarda o SHA-256 da chave.
func CreateKey(ctx context.Context, db *sql.DB, o KeyOptions, now time.Time) (Key, string, []byte, error) {
	if err := validateOptions(&o); err != nil {
		return Key{}, "", nil, err
	}
	secret, hash, err := NewKeySecret()
	if err != nil {
		return Key{}, "", nil, err
	}
	var whSecret []byte
	if o.WebhookURL != "" {
		whSecret = make([]byte, 32)
		if _, err := rand.Read(whSecret); err != nil {
			return Key{}, "", nil, err
		}
	}
	k := Key{
		ID: ulid.Make().String(), Name: o.Name, Prefix: secret[len(keyPrefix) : len(keyPrefix)+keyPrefixShow],
		Domains: o.Domains, RatePerS: o.RatePerS, Burst: o.Burst, DailyQuota: o.DailyQuota, Mode: o.Mode,
		WebhookURL: o.WebhookURL, WebhookClasses: o.WebhookClasses, CreatedAt: now.UTC().Truncate(time.Second),
		hash: hash,
	}
	doms, _ := json.Marshal(k.Domains)
	var classes any
	if len(k.WebhookClasses) > 0 {
		classes = strings.Join(k.WebhookClasses, ",")
	}
	_, err = db.ExecContext(ctx, `INSERT INTO api_keys (id, name, key_sha256, prefix, domains, rate_per_s, burst,
		daily_quota, mode, webhook_url, webhook_secret, webhook_classes, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		k.ID, k.Name, hash[:], k.Prefix, string(doms), nullInt(k.RatePerS), nullInt(k.Burst), nullInt(k.DailyQuota),
		k.Mode, nullString(k.WebhookURL), whSecret, classes, k.CreatedAt.Unix())
	if err != nil {
		return Key{}, "", nil, fmt.Errorf("bot: create key: %w", err)
	}
	return k, secret, whSecret, nil
}

const keyColumns = `id, name, key_sha256, prefix, domains, rate_per_s, burst, daily_quota, mode, webhook_url,
	webhook_classes, created_at, revoked_at, webhook_secret`

func scanKey(sc interface{ Scan(...any) error }) (Key, error) {
	var (
		k                  Key
		hash               []byte
		doms               string
		rate, burst, daily sql.NullInt64
		whURL, whClasses   sql.NullString
		createdAt          int64
		revokedAt          sql.NullInt64
	)
	if err := sc.Scan(&k.ID, &k.Name, &hash, &k.Prefix, &doms, &rate, &burst, &daily, &k.Mode, &whURL, &whClasses,
		&createdAt, &revokedAt, &k.webhookSecret); err != nil {
		return Key{}, err
	}
	copy(k.hash[:], hash)
	if err := json.Unmarshal([]byte(doms), &k.Domains); err != nil {
		return Key{}, fmt.Errorf("bot: key %s: domains: %w", k.ID, err)
	}
	k.RatePerS, k.Burst, k.DailyQuota = int(rate.Int64), int(burst.Int64), int(daily.Int64)
	k.WebhookURL = whURL.String
	if whClasses.String != "" {
		k.WebhookClasses = strings.Split(whClasses.String, ",")
	}
	k.CreatedAt = time.Unix(createdAt, 0).UTC()
	if revokedAt.Valid {
		t := time.Unix(revokedAt.Int64, 0).UTC()
		k.RevokedAt = &t
	}
	return k, nil
}

// ListKeys devolve todas as chaves, das mais antigas para as mais novas.
func ListKeys(ctx context.Context, db *sql.DB) ([]Key, error) {
	rows, err := db.QueryContext(ctx, "SELECT "+keyColumns+" FROM api_keys ORDER BY created_at, id")
	if err != nil {
		return nil, fmt.Errorf("bot: list keys: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Key
	for rows.Next() {
		k, err := scanKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// findKey acha a chave pelo id ou pelo prefixo de exibição (com ou sem "fsk_").
func findKey(ctx context.Context, db *sql.DB, ref string) (Key, error) {
	ref = strings.TrimSpace(ref)
	pfx := strings.TrimPrefix(strings.ToLower(ref), keyPrefix)
	rows, err := db.QueryContext(ctx, "SELECT "+keyColumns+" FROM api_keys WHERE id = ? OR prefix = ?", strings.ToUpper(ref), pfx)
	if err != nil {
		return Key{}, err
	}
	defer func() { _ = rows.Close() }()
	var found []Key
	for rows.Next() {
		k, err := scanKey(rows)
		if err != nil {
			return Key{}, err
		}
		found = append(found, k)
	}
	if err := rows.Err(); err != nil {
		return Key{}, err
	}
	switch len(found) {
	case 0:
		return Key{}, fmt.Errorf("%w: %s", ErrKeyNotFound, ref)
	case 1:
		return found[0], nil
	}
	return Key{}, fmt.Errorf("bot: %q matches %d keys, use the id", ref, len(found))
}

// RevokeKey revoga a chave (id ou prefixo); ela deixa de valer na próxima recarga do serviço.
func RevokeKey(ctx context.Context, db *sql.DB, ref string, now time.Time) (Key, error) {
	k, err := findKey(ctx, db, ref)
	if err != nil {
		return Key{}, err
	}
	if k.RevokedAt != nil {
		return k, ErrKeyRevoked
	}
	if _, err := db.ExecContext(ctx, "UPDATE api_keys SET revoked_at = ? WHERE id = ?", now.Unix(), k.ID); err != nil {
		return Key{}, fmt.Errorf("bot: revoke key: %w", err)
	}
	t := now.UTC().Truncate(time.Second)
	k.RevokedAt = &t
	return k, nil
}

// RotateKey troca o segredo da chave mantendo id, domínios, limites e webhook; a chave antiga deixa de valer.
func RotateKey(ctx context.Context, db *sql.DB, ref string) (Key, string, error) {
	k, err := findKey(ctx, db, ref)
	if err != nil {
		return Key{}, "", err
	}
	if k.RevokedAt != nil {
		return k, "", ErrKeyRevoked
	}
	secret, hash, err := NewKeySecret()
	if err != nil {
		return Key{}, "", err
	}
	k.Prefix, k.hash = secret[len(keyPrefix):len(keyPrefix)+keyPrefixShow], hash
	if _, err := db.ExecContext(ctx, "UPDATE api_keys SET key_sha256 = ?, prefix = ? WHERE id = ?", hash[:], k.Prefix, k.ID); err != nil {
		return Key{}, "", fmt.Errorf("bot: rotate key: %w", err)
	}
	return k, secret, nil
}

// KeyStore é a cópia em memória das chaves ativas, recarregada do banco (a CLI escreve no mesmo banco com o
// serviço rodando; criação, revogação e rotação valem na recarga seguinte).
type KeyStore struct {
	db     *sql.DB
	mu     sync.RWMutex
	byHash map[[32]byte]*Key
}

// NewKeyStore cria o cache; chame Reload antes do primeiro uso.
func NewKeyStore(db *sql.DB) *KeyStore {
	return &KeyStore{db: db, byHash: map[[32]byte]*Key{}}
}

// Reload relê as chaves não revogadas.
func (s *KeyStore) Reload(ctx context.Context) error {
	keys, err := ListKeys(ctx, s.db)
	if err != nil {
		return err
	}
	m := make(map[[32]byte]*Key, len(keys))
	for i := range keys {
		if keys[i].RevokedAt == nil {
			m[keys[i].hash] = &keys[i]
		}
	}
	s.mu.Lock()
	s.byHash = m
	s.mu.Unlock()
	return nil
}

// Lookup acha a chave ativa pelo texto apresentado.
func (s *KeyStore) Lookup(secret string) (*Key, bool) {
	h, ok := ParseKey(secret)
	if !ok {
		return nil, false
	}
	s.mu.RLock()
	k, ok := s.byHash[h]
	s.mu.RUnlock()
	return k, ok
}

// HasHash diz se a chave com o hash dado está ativa (o feed aberto confere depois de cada recarga, task 368).
func (s *KeyStore) HasHash(h [32]byte) bool {
	s.mu.RLock()
	_, ok := s.byHash[h]
	s.mu.RUnlock()
	return ok
}

// WebhookKeys devolve as chaves ativas com webhook_url.
func (s *KeyStore) WebhookKeys() []*Key {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*Key
	for _, k := range s.byHash {
		if k.WebhookURL != "" {
			out = append(out, k)
		}
	}
	return out
}

// Active conta as chaves ativas (bot_keys_active).
func (s *KeyStore) Active() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byHash)
}
