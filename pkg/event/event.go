// Package event define o envelope v1 dos eventos no NATS (ADR 0003, eventbus/nats/asyncapi.yaml) e o formato
// binário FSPB v1 do lote de pacotes (ADR 0015).
package event

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// SchemaVersion é a versão do envelope.
const SchemaVersion = 1

// Subjects do barramento (fs.v1.<origem>.<tipo>).
const (
	SubjectCapturePacket = "fs.v1.capture.packet"
	SubjectHeartbeat     = "fs.v1.svc.heartbeat"
	SubjectAll           = "fs.v1.>"
)

// Nomes dos serviços.
const (
	ServiceCapture = "capture"
	ServiceWeb     = "web"
	ServiceRaw     = "raw"
	ServiceDNS     = "dns"
	ServiceStore   = "store"
)

// Services lista todos os serviços esperados pelo health.
var Services = []string{ServiceCapture, ServiceWeb, ServiceRaw, ServiceDNS, ServiceStore}

// TimeFormat é RFC 3339 em UTC com nanossegundos.
const TimeFormat = "2006-01-02T15:04:05.000000000Z07:00"

// Flow é a 5-tupla do ponto de vista do cliente (src = cliente, dst = espelho).
type Flow struct {
	L4          string `json:"l4"`
	SrcIP       string `json:"src_ip"`
	SrcPort     int    `json:"src_port"`
	DstIP       string `json:"dst_ip"`
	DstPort     int    `json:"dst_port"`
	QUICDCIDHex string `json:"quic_dcid_hex,omitempty"`
}

// Envelope é o envelope JSON comum dos eventos de aplicação.
type Envelope struct {
	SchemaVersion  int             `json:"schema_version"`
	Service        string          `json:"service"`
	ServiceVersion string          `json:"service_version"`
	Ts             string          `json:"ts"`
	Flow           *Flow           `json:"flow,omitempty"`
	ProbeID        *string         `json:"probe_id,omitempty"`
	Payload        json.RawMessage `json:"payload,omitempty"`
}

// FormatTime formata um instante no padrão dos eventos.
func FormatTime(t time.Time) string { return t.UTC().Format(TimeFormat) }

// New monta um envelope com o payload serializado.
func New(service, version string, ts time.Time, flow *Flow, payload any) (Envelope, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return Envelope{}, fmt.Errorf("event: payload: %w", err)
	}
	return Envelope{
		SchemaVersion: SchemaVersion, Service: service, ServiceVersion: version,
		Ts: FormatTime(ts), Flow: flow, Payload: raw,
	}, nil
}

// Erros de Decode.
var (
	ErrSchemaVersion = errors.New("event: unsupported schema_version")
	ErrMissingField  = errors.New("event: missing required field")
)

// Decode lê um envelope e confere os campos obrigatórios do contrato. Campos desconhecidos são ignorados
// (compatibilidade aditiva, ADR 0001).
func Decode(data []byte) (Envelope, error) {
	var e Envelope
	if err := json.Unmarshal(data, &e); err != nil {
		return Envelope{}, fmt.Errorf("event: %w", err)
	}
	if e.SchemaVersion != SchemaVersion {
		return Envelope{}, fmt.Errorf("%w: %d", ErrSchemaVersion, e.SchemaVersion)
	}
	switch {
	case e.Service == "":
		return Envelope{}, fmt.Errorf("%w: service", ErrMissingField)
	case e.ServiceVersion == "":
		return Envelope{}, fmt.Errorf("%w: service_version", ErrMissingField)
	case e.Ts == "":
		return Envelope{}, fmt.Errorf("%w: ts", ErrMissingField)
	}
	return e, nil
}

// Time devolve o instante do envelope.
func (e Envelope) Time() (time.Time, error) { return time.Parse(time.RFC3339Nano, e.Ts) }

// Heartbeat é o payload de fs.v1.svc.heartbeat.
type Heartbeat struct {
	Status    string             `json:"status"` // ok | degraded
	Reasons   []string           `json:"reasons,omitempty"`
	Commit    string             `json:"commit"`
	StartedAt string             `json:"started_at"`
	Metrics   map[string]float64 `json:"metrics,omitempty"`
}

// Status dos serviços.
const (
	StatusOK       = "ok"
	StatusDegraded = "degraded"
	StatusDown     = "down"
)
