//go:build load

// Comando botload: carga da F8 no bot (tasks 285 e 304; spec 018 RNF-01 e RNF-02, spec 017 RF-17, ADRs 0055 item 2,
// 0057 item 2 e 0058). Os modos auth e hostile rodam num container temporário na bridge br-net-public do
// finger-01 (origem 10.249.0.0/16, como o traefik), contra a 9003 do bot; report roda em qualquer lugar.
//
//	botload auth    -out DIR [flags]  traefix simulado: lê do feed do store (connection.opened nas portas web) as
//	                                  conexões reais da carga oficial, manda o lote traefix.fingerprint/v1 da conexão
//	                                  (task 304, ADRs 0062 e 0063) e, a -rate requisições/s, o GET /bot/v1/auth com os
//	                                  X-Traefix-* (origem, JA4, JA3, Akamai, ALPN e JA4H) e a chave, o registro
//	                                  type=request no ingest e consultas GET /bot/v1/verdict; lê o feed SSE do bot e
//	                                  mede o atraso de cada veredito;
//	botload hostile -out DIR [flags]  ingest traefix.fingerprint/v1 de conexões com valores únicos (16 requisições por
//	                                  conexão, UA de 512 bytes, campos longos, visão TCP) para passar do
//	                                  FS_BOT_INDEX_MAX_BYTES (ADR 0057 item 2);
//	botload feed    -out DIR [flags]  feed global do store lido de dentro do finger-01: atraso ts → chegada de cada
//	                                  evento e stream.dropped, sem o enlace do gerador no Mac (ADR 0046);
//	botload report  -dir DIR [flags]  percentis por janela das amostras (samples.csv) e, com dois health do store,
//	                                  as contas das métricas bot_* do heartbeat.
//
// A chave de teste chega pela entrada padrão (primeira linha), nunca por argumento, variável ou arquivo; ela não é
// escrita em log nem nas amostras.
package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "uso: botload auth|hostile|feed|report [flags]")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "auth":
		err = authCmd(os.Args[2:])
	case "hostile":
		err = hostileCmd(os.Args[2:])
	case "feed":
		err = feedCmd(os.Args[2:])
	case "report":
		err = reportCmd(os.Args[2:], os.Stdout)
	default:
		err = fmt.Errorf("modo desconhecido: %s", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "botload:", err)
		os.Exit(1)
	}
}

// readKey lê a chave fsk_... da primeira linha de r.
func readKey(r io.Reader) (string, error) {
	line, err := bufio.NewReader(r).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("ler a chave da entrada: %w", err)
	}
	k := strings.TrimSpace(line)
	if !strings.HasPrefix(k, "fsk_") {
		// sem eco do que foi lido: pode ser um segredo mal colado
		return "", errors.New("a entrada padrão não começa com uma chave fsk_")
	}
	return k, nil
}
