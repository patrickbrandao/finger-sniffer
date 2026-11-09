package quicparse

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

// Codepoints da extensão TLS com os parâmetros de transporte: 0x39 (RFC 9001 seção 8.2) e 0xffa5 (rascunhos
// anteriores ao v1, ainda vistos em clientes antigos).
const (
	ExtQUICTransportParams      uint16 = 0x0039
	ExtQUICTransportParamsDraft uint16 = 0xffa5
)

// MaxTransportParams limita os parâmetros registrados (a extensão cabe em 64 KiB; cada um custa ~2 bytes).
const MaxTransportParams = 1024

// ErrTransportParams indica a extensão de parâmetros de transporte cortada.
var ErrTransportParams = errors.New("quicparse: parâmetros de transporte truncados")

// TransportParam é um parâmetro de transporte como chegou; vai para o JSON como `[id, nome, valor_hex]`.
type TransportParam struct {
	ID    uint64
	Name  string
	Value []byte
}

// MarshalJSON escreve `[id, nome, valor_hex]` (schema HTTP3Info.transport_params).
func (p TransportParam) MarshalJSON() ([]byte, error) {
	return json.Marshal([3]any{p.ID, p.Name, hex.EncodeToString(p.Value)})
}

// UnmarshalJSON lê `[id, nome, valor_hex]`.
func (p *TransportParam) UnmarshalJSON(b []byte) error {
	var raw [3]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	var h string
	if err := json.Unmarshal(raw[0], &p.ID); err != nil {
		return err
	}
	if err := json.Unmarshal(raw[1], &p.Name); err != nil {
		return err
	}
	if err := json.Unmarshal(raw[2], &h); err != nil {
		return err
	}
	v, err := hex.DecodeString(h)
	if err != nil {
		return err
	}
	p.Value = v
	return nil
}

// transportParamNames: RFC 9000 seção 18.2, RFC 9221 (datagram), RFC 9287 (grease_quic_bit), RFC 9368
// (version_information) e rascunhos/extensões comuns, com os nomes que o tshark usa.
var transportParamNames = map[uint64]string{
	0x00:               "original_destination_connection_id",
	0x01:               "max_idle_timeout",
	0x02:               "stateless_reset_token",
	0x03:               "max_udp_payload_size",
	0x04:               "initial_max_data",
	0x05:               "initial_max_stream_data_bidi_local",
	0x06:               "initial_max_stream_data_bidi_remote",
	0x07:               "initial_max_stream_data_uni",
	0x08:               "initial_max_streams_bidi",
	0x09:               "initial_max_streams_uni",
	0x0a:               "ack_delay_exponent",
	0x0b:               "max_ack_delay",
	0x0c:               "disable_active_migration",
	0x0d:               "preferred_address",
	0x0e:               "active_connection_id_limit",
	0x0f:               "initial_source_connection_id",
	0x10:               "retry_source_connection_id",
	0x11:               "version_information",
	0x20:               "max_datagram_frame_size",
	0x1057:             "loss_bits",
	0x173e:             "discard",
	0x2ab2:             "grease_quic_bit",
	0x3127:             "google_initial_rtt",
	0x3128:             "google_connection_options",
	0x3129:             "google_user_agent",
	0x4752:             "google_quic_version",
	0x7157:             "enable_time_stamp",
	0x7158:             "enable_time_stamp_v2",
	0xde1a:             "min_ack_delay",
	0xff02de1a:         "min_ack_delay",
	0xff04de1b:         "min_ack_delay",
	0xff73db:           "version_information_draft",
	0x0f739bbc1b666d04: "enable_multipath",
	0x0f739bbc1b666d05: "enable_multipath",
	0x0f739bbc1b666d06: "enable_multipath",
	0x0f739bbc1b666d09: "initial_max_path_id",
	0x0f739bbc1b666d0c: "initial_max_path_id",
}

// IsGREASEParam informa se o id é reservado para GREASE (31 * N + 27, RFC 9000 seção 18.1).
func IsGREASEParam(id uint64) bool { return id%31 == 27 }

// TransportParamName devolve o nome do parâmetro: `GREASE`, o nome conhecido ou `unknown`.
func TransportParamName(id uint64) string {
	if n, ok := transportParamNames[id]; ok {
		return n
	}
	if IsGREASEParam(id) {
		return "GREASE"
	}
	return "unknown"
}

// ParseTransportParams lê os dados da extensão quic_transport_parameters na ordem. Em caso de corte,
// devolve os parâmetros inteiros lidos até ali com ErrTransportParams; truncated indica a lista cortada
// em MaxTransportParams.
func ParseTransportParams(b []byte) (params []TransportParam, truncated bool, err error) {
	params = []TransportParam{}
	r := reader{buf: b}
	for !r.empty() {
		id := r.varint()
		v := r.bytes(r.varint())
		if r.bad {
			return params, truncated, fmt.Errorf("%w no byte %d", ErrTransportParams, len(b)-len(r.rest()))
		}
		if len(params) >= MaxTransportParams {
			truncated = true
			continue
		}
		params = append(params, TransportParam{ID: id, Name: TransportParamName(id), Value: append([]byte{}, v...)})
	}
	return params, truncated, nil
}
