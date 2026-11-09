// Package xconnect liga o CONNECT estendido (RFC 8441) do servidor h2 do net/http, que o x/net/http2 do Go
// 1.27 embrulha: o pacote interno lê GODEBUG=http2xconnect=1 no init e, sem isso, recusa `:protocol` e não
// anuncia SETTINGS_ENABLE_CONNECT_PROTOCOL.
//
// O init deste pacote acrescenta a chave ao GODEBUG do processo antes do init de net/http/internal/http2: a
// especificação do Go (seção "Package initialization") inicializa, a cada passo, o primeiro pacote pronto na
// ordem do caminho de importação, e este só depende de os e strings, que ficam prontos muito antes do
// net/http (que depende de crypto/tls e de dezenas de outros). O pacote web o importa; o teste TestWSOverH2
// confere que o servidor anuncia o SETTINGS. Sem fork do x/net (ADR 0009) e sem mexer nas units (infra).
package xconnect

import (
	"os"
	"strings"
)

// Key é a chave do GODEBUG lida pelo h2 do net/http.
const Key = "http2xconnect=1"

func init() {
	cur := os.Getenv("GODEBUG")
	if strings.Contains(cur, "http2xconnect=") {
		// Quem configurou o ambiente decide (inclusive http2xconnect=0).
		return
	}
	if cur != "" {
		cur += ","
	}
	_ = os.Setenv("GODEBUG", cur+Key)
}
