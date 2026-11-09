package store

import "strings"

// proto deriva a pilha da conexão dos eventos (regra da spec 004): `tls/` como prefixo quando houve ClientHello;
// depois http1.0/http1.1 (versão da primeira requisição), h2 (ALPN) ou h2c (prior knowledge/Upgrade), `/ws` quando
// houve Upgrade para WebSocket; raw (serviço raw), raw/unknown (web sem protocolo reconhecido), dns (dns.query).
// Sem evento de aplicação: tcp ou udp.
func (l *layers) proto(l4 string) string {
	var parts []string
	if l.clientHello != nil {
		parts = append(parts, "tls")
	}
	switch {
	case l.http2 != nil || len(l.h2Streams) > 0:
		if mode, _ := l.http2["mode"].(string); mode == "alpn" || (mode == "" && l.clientHello != nil) {
			parts = append(parts, "h2")
		} else {
			parts = append(parts, "h2c")
		}
	case len(l.http1) > 0:
		switch strings.ToUpper(l.http1Version) {
		case "HTTP/1.0":
			parts = append(parts, "http1.0")
		default:
			parts = append(parts, "http1.1")
		}
	case l.raw != nil && l.rawFromWeb:
		parts = append(parts, "raw", "unknown")
	case l.raw != nil:
		parts = append(parts, "raw")
	case l.dns:
		parts = append(parts, "dns")
	}
	if l.ws != nil && (l.ws.Over != "" || len(l.ws.Frames) > 0) && len(parts) > 0 {
		parts = append(parts, "ws")
	}
	if len(parts) == 0 {
		return l4
	}
	return strings.Join(parts, "/")
}
