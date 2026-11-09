package h2passive

import (
	"fmt"
	"os"
	"strconv"
)

// Padrões dos limites do parser.
const (
	// DefaultMaxPriorityFrames é o padrão de FS_MAX_H2_PRIORITY_FRAMES (spec 010 RF-03).
	DefaultMaxPriorityFrames = 10000
	// DefaultMaxFrames limita a lista de frames registrada (ADR 0018: cada frame custa ~90 bytes de JSON).
	DefaultMaxFrames = 4096
	// DefaultMaxStreams limita os streams registrados por conexão.
	DefaultMaxStreams = 1000
	// DefaultMaxSettings limita os pares do SETTINGS registrados.
	DefaultMaxSettings = 256
	// DefaultMaxFieldsPerBlock limita os campos decodificados por bloco de cabeçalho.
	DefaultMaxFieldsPerBlock = 1024
	// DefaultMaxHeaderBlock limita o bloco de cabeçalho (HEADERS + CONTINUATION) guardado para decodificar.
	DefaultMaxHeaderBlock = 1 << 20
	// DefaultHeaderTableSize é o SETTINGS_HEADER_TABLE_SIZE inicial (RFC 9113 seção 6.5.2).
	DefaultHeaderTableSize = 4096
)

// Limits são os tetos do parser contra entradas hostis.
type Limits struct {
	MaxPriorityFrames int // frames PRIORITY registrados; acima disso `priority_frames_capped`
	MaxFrames         int // frames na lista; acima disso `frames_truncated`
	MaxStreams        int // streams registrados
	MaxSettings       int // pares do SETTINGS registrados
	MaxFieldsPerBlock int // campos por bloco HPACK
	MaxHeaderBlock    int // bytes por bloco de cabeçalho; acima disso a decodificação HPACK para
}

// DefaultLimits devolve os limites padrão.
func DefaultLimits() Limits {
	return Limits{
		MaxPriorityFrames: DefaultMaxPriorityFrames,
		MaxFrames:         DefaultMaxFrames,
		MaxStreams:        DefaultMaxStreams,
		MaxSettings:       DefaultMaxSettings,
		MaxFieldsPerBlock: DefaultMaxFieldsPerBlock,
		MaxHeaderBlock:    DefaultMaxHeaderBlock,
	}
}

// LimitsFromEnv devolve os limites padrão com FS_MAX_H2_PRIORITY_FRAMES lido do ambiente.
func LimitsFromEnv() (Limits, error) {
	l := DefaultLimits()
	if v, ok := os.LookupEnv("FS_MAX_H2_PRIORITY_FRAMES"); ok && v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return l, fmt.Errorf("h2passive: FS_MAX_H2_PRIORITY_FRAMES inválido: %q", v)
		}
		l.MaxPriorityFrames = n
	}
	return l, nil
}

// normalize troca zeros e negativos pelos padrões (MaxPriorityFrames aceita 0: nenhum PRIORITY registrado).
func (l Limits) normalize() Limits {
	d := DefaultLimits()
	if l.MaxPriorityFrames < 0 {
		l.MaxPriorityFrames = d.MaxPriorityFrames
	}
	if l.MaxFrames <= 0 {
		l.MaxFrames = d.MaxFrames
	}
	if l.MaxStreams <= 0 {
		l.MaxStreams = d.MaxStreams
	}
	if l.MaxSettings <= 0 {
		l.MaxSettings = d.MaxSettings
	}
	if l.MaxFieldsPerBlock <= 0 {
		l.MaxFieldsPerBlock = d.MaxFieldsPerBlock
	}
	if l.MaxHeaderBlock <= 0 {
		l.MaxHeaderBlock = d.MaxHeaderBlock
	}
	return l
}
