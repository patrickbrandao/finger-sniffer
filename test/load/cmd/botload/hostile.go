//go:build load

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"math/rand/v2"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/oklog/ulid/v2"
)

// Limites do contrato do ingest (openapi TraefixFingerprintBatch, os mesmos do TraefikIngestBatch; ADR 0062 item 2;
// internal/bot/ingest.go).
const (
	maxBatchRecords = 1024
	maxBatchBytes   = 4 << 20
	maxPathBytes    = 256
	maxFieldValue   = 512
	hostileReqs     = 16 // requisições por conexão (o índice guarda até 16; ADR 0057 item 2)
	hostileUALen    = 512
	hostileFields   = 6 // campos longos além do User-Agent
)

const (
	alnum  = "abcdefghijklmnopqrstuvwxyz0123456789"
	digits = "0123456789"
)

func randFrom(rng *rand.Rand, set string, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = set[rng.IntN(len(set))]
	}
	return string(b)
}

func randStr(rng *rand.Rand, n int) string { return randFrom(rng, alnum, n) }

func randHex(rng *rand.Rand, n int) string { return randFrom(rng, "0123456789abcdef", n) }

// hostileFieldName é um nome de campo único da lista padrão de fields do traefix (Sec-CH-UA* e Sec-Fetch-*): só
// esses chegam com valor ao bot (spec 019 RF-06), e o valor longo e único é o que pesa no índice.
func hostileFieldName(rng *rand.Rand, i int) string {
	if i%2 == 0 {
		return "sec-ch-ua-" + randStr(rng, 24)
	}
	return "sec-fetch-" + randStr(rng, 24)
}

// hostileJA4H é um JA4H único no formato do esquema do traefix (`^.{2}[0-9]{2}[cn][rn][0-9]{2}.+_…`) e do
// X-Traefix-Ja4h do bot (12 caracteres [a-z0-9] na parte a).
func hostileJA4H(rng *rand.Rand) string {
	return "ge20nn" + randFrom(rng, digits, 2) + randStr(rng, 4) + "_" + randHex(rng, 12) + "_" + randHex(rng, 12) + "_" + randHex(rng, 12)
}

// hostileTCP é uma visão TCP do traefix com JA4T e raw_sig do p0f únicos (sem o SYN cru: sem palpite de SO, como
// um traefix com rawBytes e SYN cookies); o TTL e o RTT variam.
func hostileTCP(rng *rand.Rand) map[string]any {
	win := 1024 + rng.IntN(64000)
	return map[string]any{
		"ja4t":      fmt.Sprintf("%d_2-4-8-1-3_%d_%d", win, 1200+rng.IntN(260), 10+rng.IntN(5)), // escala com dois dígitos (esquema do traefix)
		"p0f":       fmt.Sprintf("4:%d+0:0:1460:%d,7:mss,sok,ts,nop,ws:df,id+:0", 40+rng.IntN(24), win),
		"ttl":       40 + rng.IntN(24),
		"rttMicros": rng.IntN(500000),
	}
}

// hostileConn monta os 1 + 16 registros traefix.fingerprint/v1 de uma conexão com valores únicos: SNI, entry
// point, ALPN, cifra, visão TCP, caminho de 256 bytes, UA de 512 bytes, seis campos de 512 bytes, nomes de campo e
// de cookie, JA4H, router e service, tudo novo (o interner do bot não compartilha nada; ADR 0057 item 2). A origem
// é da faixa de testes de desempenho 198.18.0.0/15 (RFC 2544), sem conexão do store para casar (e fora das faixas
// privadas, então a visão TCP do traefix fica no índice).
func hostileConn(rng *rand.Rand, tpl *template, suffix string, now time.Time) []map[string]any {
	id := ulid.Make().String()
	sni := randStr(rng, 24) + "." + suffix
	src := map[string]any{"ip": fmt.Sprintf("198.%d.%d.%d", 18+rng.IntN(2), rng.IntN(256), 1+rng.IntN(254)), "port": 1024 + rng.IntN(64000)}
	dst := map[string]any{"ip": "10.249.0.2", "port": 443}
	conn, tls := withTLS(tpl.conn)
	conn["connId"], conn["time"], conn["src"], conn["dst"] = id, ts(now), src, dst
	conn["entryPoint"] = "ep-" + randStr(rng, 60)
	conn["tcp"] = hostileTCP(rng)
	tls["sni"] = sni
	tls["alpnOffered"] = []string{randStr(rng, 32), randStr(rng, 32), randStr(rng, 32), randStr(rng, 32)}
	tls["alpn"], tls["cipher"] = randStr(rng, 32), "TLS_"+randStr(rng, 60)
	out := []map[string]any{conn}
	for i := range hostileReqs {
		names := make([]string, 0, 12)
		fields := []map[string]any{{"name": "user-agent", "value": "Mozilla/5.0 " + randStr(rng, hostileUALen-12)}}
		names = append(names, "user-agent")
		for j := range hostileFields {
			n := hostileFieldName(rng, j)
			names = append(names, n)
			fields = append(fields, map[string]any{"name": n, "value": randStr(rng, maxFieldValue)})
		}
		for range 5 {
			names = append(names, "x-"+randStr(rng, 30))
		}
		t := now.Add(time.Duration(i) * time.Millisecond)
		rq := clone(tpl.req)
		rq["connId"], rq["start"], rq["end"] = id, ts(t), ts(t.Add(time.Millisecond))
		rq["entryPoint"] = conn["entryPoint"]
		rq["authority"], rq["path"] = sni, "/"+randStr(rng, maxPathBytes-1)
		rq["fieldNames"], rq["fields"] = names, fields
		rq["cookieNames"] = []string{randStr(rng, 24), randStr(rng, 24), randStr(rng, 24), randStr(rng, 24)}
		rq["ja4h"] = hostileJA4H(rng)
		rq["router"], rq["service"] = "r-"+randStr(rng, 60), "s-"+randStr(rng, 60)
		rq["method"] = "GET"
		out = append(out, rq)
	}
	return out
}

func hostileCmd(args []string) error {
	fs := flag.NewFlagSet("hostile", flag.ContinueOnError)
	bot := fs.String("bot", "http://10.249.255.254:9003/bot/v1", "base da API interna do bot")
	suffix := fs.String("suffix", "hostile.fs-load.example", "sufixo dos SNI únicos (a chave autoriza *.<sufixo>)")
	rate := fs.Int("rate", 50, "conexões únicas por segundo (cada uma com 16 requisições)")
	perBatch := fs.Int("per-batch", 40, "conexões por lote (17 registros cada; até 1024 registros e 4 MiB)")
	workers := fs.Int("workers", 2, "lotes em voo")
	duration := fs.Duration("duration", 2*time.Minute, "duração")
	out := fs.String("out", "/out", "pasta dos resultados")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *perBatch*(hostileReqs+1) > maxBatchRecords {
		return fmt.Errorf("-per-batch %d passa de %d registros", *perBatch, maxBatchRecords)
	}
	key, err := readKey(os.Stdin)
	if err != nil {
		return err
	}
	tpls, err := loadTemplates()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*out, 0o750); err != nil {
		return err
	}
	rec, err := newRecorder(filepath.Join(*out, "hostile_samples.csv"))
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *duration)
	defer cancel()
	log.Printf("hostile: %d conexões únicas/s, %d por lote, %v, sufixo %s (início %s)", *rate, *perBatch, *duration, *suffix, ts(time.Now()))

	jobs := make(chan []byte, *workers)
	c := newClient(*workers)
	var sentConns, accepted, rejected, errs atomic.Int64
	var wg sync.WaitGroup
	for range *workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for body := range jobs {
				t0 := time.Now()
				pctx, pcancel := context.WithTimeout(context.Background(), 30*time.Second)
				status, acc, rej, err := postIngest(pctx, c, *bot, key, body)
				pcancel()
				rec.add(sample{t: t0.UnixNano(), kind: "hostile_ingest", latUS: time.Since(t0).Microseconds(), status: status, flag: acc})
				accepted.Add(int64(acc))
				rejected.Add(int64(rej))
				if err != nil || status != http.StatusAccepted {
					errs.Add(1)
					log.Printf("hostile ingest: status %d erro %v", status, err)
				}
			}
		}()
	}
	rng := rand.New(rand.NewPCG(uint64(time.Now().UnixNano()), 285)) //nolint:gosec // valores de teste
	interval := time.Duration(float64(*perBatch) / float64(*rate) * float64(time.Second))
	tick := time.NewTicker(interval)
	logTick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	defer logTick.Stop()
	skipped := 0
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case <-logTick.C:
			log.Printf("hostile 10s: conexões %d, registros aceitos %d recusados %d, erros %d, lotes pulados %d",
				sentConns.Load(), accepted.Load(), rejected.Load(), errs.Load(), skipped)
		case <-tick.C:
			recs := make([]map[string]any, 0, *perBatch*(hostileReqs+1))
			now := time.Now()
			for range *perBatch {
				recs = append(recs, hostileConn(rng, tpls[0], *suffix, now)...)
			}
			body, err := batchBody(recs)
			if err != nil || len(body) > maxBatchBytes {
				return fmt.Errorf("lote de %d bytes (máx %d): %v", len(body), maxBatchBytes, err)
			}
			select {
			case jobs <- body:
				sentConns.Add(int64(*perBatch))
			default:
				// o bot não acompanha: o lote é pulado e contado (o ritmo real fica no log)
				skipped++
			}
		}
	}
	close(jobs)
	wg.Wait()
	lost := rec.close()
	log.Printf("hostile fim: conexões %d, registros aceitos %d recusados %d, erros %d, lotes pulados %d, amostras perdidas %d",
		sentConns.Load(), accepted.Load(), rejected.Load(), errs.Load(), skipped, lost)
	return nil
}
