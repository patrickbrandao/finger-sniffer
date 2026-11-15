//go:build e2e

package e2e

// Ociosidade do TCP estabelecido no store (task 217, item da task 151; ADR 0034 item 2, spec 004 RF-11a): com
// idle=300 o web mantém a conexão h1 parada por mais que FS_IDLE_DEFAULT + 30 s (150 s); o store fica com o fluxo
// por max(FS_IDLE_DEFAULT, FS_IDLE_MAX) + 30 s e, quando a conexão volta a trocar dados depois de 200 s parada,
// registra uma conexão só (as duas requisições no mesmo registro), não duas. Duração: ~3,5 min.

import (
	"fmt"
	"io"
	"testing"
	"time"
)

// storeIdleGap é quanto a conexão fica parada: além dos 150 s de FS_IDLE_DEFAULT + 30 s, abaixo do idle=300.
const storeIdleGap = 200 * time.Second

func TestStoreIdleKeepsOneConnection(t *testing.T) {
	t.Parallel()
	id := newID(t)
	c, err := openIdleH1(id, "r?idle=300")
	if err != nil {
		t.Fatal(err)
	}
	defer c.close()
	ic := c.(*idleTCP) //nolint:forcetypeassert // openIdleH1 devolve *idleTCP
	t0 := time.Now()
	closed, err := c.wait(storeIdleGap)
	switch {
	case err != nil:
		t.Fatalf("esperando %s: %v", storeIdleGap, err)
	case closed:
		t.Fatalf("o web fechou a conexão aos %s com idle=300", time.Since(t0).Round(time.Second))
	}
	// segunda requisição na mesma conexão, depois da pausa
	req := fmt.Sprintf("GET /p/%s/r HTTP/1.1\r\nHost: %s\r\nUser-Agent: fs-e2e-store-idle\r\n\r\n", id, probeHost(id))
	if _, err := io.WriteString(ic.c, req); err != nil {
		t.Fatalf("segunda requisição: %v", err)
	}
	_ = ic.c.SetReadDeadline(time.Now().Add(15 * time.Second))
	var buf []byte
	tmp := make([]byte, 64<<10)
	for {
		n, err := ic.c.Read(tmp)
		buf = append(buf, tmp[:n]...)
		done, bad := h1Complete(buf)
		if bad != nil {
			t.Fatal(bad)
		}
		if done {
			break
		}
		if err != nil {
			t.Fatalf("resposta da segunda requisição: %v (lido %q)", err, buf)
		}
	}
	if err := c.closeClient(); err != nil {
		t.Fatalf("fechando: %v", err)
	}

	p := waitProbe(t, id, atLeast(1, portHTTP))
	cs := p.conns(portHTTP)
	if len(cs) != 1 {
		for _, r := range cs {
			t.Logf("%s started=%s requests=%d close=%+v", r.ConnID, r.Started, r.Requests, r.Close)
		}
		t.Fatalf("%d conexões na porta 8080 depois de %s parada, esperado 1 (ADR 0034 item 2)", len(cs), storeIdleGap)
	}
	rc := connRecord(t, cs[0].ConnID)
	if rc.Requests != 2 || len(rc.HTTP) != 2 {
		t.Errorf("requests = %d, http = %d, esperado 2 no mesmo registro", rc.Requests, len(rc.HTTP))
	}
	if rc.Close.By != "client" || rc.Close.How != "fin" {
		t.Errorf("close = %+v, esperado client/fin", rc.Close)
	}
	t.Logf("probe %s: %s com %d requisições, %s parada no meio", id, rc.ConnID, rc.Requests, storeIdleGap)
}
