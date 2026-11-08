//go:build golden

// Cliente Go (net/http) usado por test/golden/collect.sh para gerar o golden pcap "go".
// Uso: go run -tags golden ./test/golden/goclient <url>
package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

func main() {
	c := &http.Client{Timeout: 20 * time.Second}
	resp, err := c.Get(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	n, _ := io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	fmt.Println(resp.Status, n)
}
