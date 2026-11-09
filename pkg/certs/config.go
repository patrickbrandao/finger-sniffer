// Package certs é o TLS comum de web, raw e store (spec 015 RF-04, spec 008 RF-06).
//
// Conteúdo:
//   - ServerConfig: configuração TLS fixa e documentada do espelho (TLS 1.0–1.3, cifras padrão do Go mais as
//     legadas CBC, troca de chaves RSA e 3DES, listadas explicitamente) e Describe para host.tls_server do health;
//   - Store: certificados lidos de FS_CERT_DIR (dns01.{crt,key} = A, http01.{crt,key} = B), recarregados a quente
//     por fsnotify, escolhidos por SNI (nomes de FS_CERT_NAMES_DNS01 → A; qualquer outro ou sem SNI → B) e
//     substituídos por um autoassinado em memória quando falta arquivo;
//   - State/Reasons: estado dos certificados para host.certificates e motivos do heartbeat;
//   - WritePair: escrita atômica de um par PEM (usada pelo ACME e pelos testes).
//
// GODEBUG no Go 1.27: tls10server, tlsrsakex e tls3des foram removidos (as versões e cifras legadas valem só por
// estarem listadas na configuração, sem GODEBUG). Continua existindo tlssha1, que desde o Go 1.25 recusa
// assinaturas SHA-1 no TLS 1.2 e clientes TLS 1.2 sem a extensão signature_algorithms. Para observar esses
// clientes antigos, o go.mod do módulo fixa "godebug tlssha1=1", que vale para todos os main (e testes) do
// módulo; o TLS 1.0/1.1 não depende dele (usa MD5+SHA1 legado).
package certs

import (
	"crypto/tls"
	"os"
	"strings"
)

// Nomes fixos dos arquivos em FS_CERT_DIR (spec 015 RF-04).
const (
	SlotDNS01  = "dns01"  // certificado A (DNS-01)
	SlotHTTP01 = "http01" // certificado B (HTTP-01), padrão para SNI desconhecido ou ausente
)

// Padrões de .env.example.
const (
	DefaultDir         = "/finger-sniffer/var/certs"
	DefaultNamesDNS01  = "dns-monitor.tmsoft.com.br,*.dns-monitor.tmsoft.com.br"
	DefaultNamesHTTP01 = "vps602.tmsoft.com.br,fingerprint.tmsoft.com.br,tcp.tmsoft.com.br,udp.tmsoft.com.br"
)

// Config diz onde estão os certificados e quais nomes cada um cobre.
type Config struct {
	Dir         string   // FS_CERT_DIR
	NamesDNS01  []string // FS_CERT_NAMES_DNS01 (aceita curinga *.zona)
	NamesHTTP01 []string // FS_CERT_NAMES_HTTP01
}

// LoadConfig lê FS_CERT_DIR, FS_CERT_NAMES_DNS01 e FS_CERT_NAMES_HTTP01 (vazio ou ausente = padrão).
func LoadConfig() Config {
	return Config{
		Dir:         env("FS_CERT_DIR", DefaultDir),
		NamesDNS01:  SplitNames(env("FS_CERT_NAMES_DNS01", DefaultNamesDNS01)),
		NamesHTTP01: SplitNames(env("FS_CERT_NAMES_HTTP01", DefaultNamesHTTP01)),
	}
}

// SplitNames separa uma lista por vírgulas, normalizando cada nome (minúsculas, sem ponto final).
func SplitNames(s string) []string {
	var out []string
	for _, n := range strings.Split(s, ",") {
		if n = normalizeName(n); n != "" {
			out = append(out, n)
		}
	}
	return out
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func normalizeName(n string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(n)), ".")
}

// cipherSuites é a lista fixa de cifras TLS 1.0–1.2: as padrão do Go seguidas das legadas (CBC com SHA-256,
// troca de chaves RSA e 3DES). RC4 fica de fora. O Go ignora a ordem; as de TLS 1.3 não são configuráveis.
var cipherSuites = []uint16{
	// padrão do Go
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	// legadas: CBC com SHA-256
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	// legadas: troca de chaves RSA
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
	tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	// legadas: 3DES
	tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
}

// tls13Suites são as cifras do TLS 1.3 que o Go sempre oferece (só para Describe).
var tls13Suites = []uint16{
	tls.TLS_AES_128_GCM_SHA256,
	tls.TLS_AES_256_GCM_SHA384,
	tls.TLS_CHACHA20_POLY1305_SHA256,
}

// ServerConfig devolve a configuração TLS fixa do espelho, sem certificado (spec 008 RF-06). Quem serve
// preenche GetCertificate (ver Store.TLSConfig), NextProtos e, se quiser, GetConfigForClient.
func ServerConfig() *tls.Config {
	return &tls.Config{ //nolint:gosec // TLS 1.0 é proposital: o espelho observa clientes antigos (spec 008 RF-06)
		MinVersion:   tls.VersionTLS10,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: append([]uint16(nil), cipherSuites...),
	}
}

// TLSServerInfo é o objeto host.tls_server do health (openapi).
type TLSServerInfo struct {
	MinVersion   string   `json:"min_version"`
	MaxVersion   string   `json:"max_version"`
	CipherSuites []string `json:"cipher_suites"`
}

// Describe descreve ServerConfig para o health: versões e cifras (TLS 1.3 primeiro, depois a lista fixa).
func Describe() TLSServerInfo {
	c := ServerConfig()
	info := TLSServerInfo{
		MinVersion: tls.VersionName(c.MinVersion),
		MaxVersion: tls.VersionName(c.MaxVersion),
	}
	for _, id := range tls13Suites {
		info.CipherSuites = append(info.CipherSuites, tls.CipherSuiteName(id))
	}
	for _, id := range c.CipherSuites {
		info.CipherSuites = append(info.CipherSuites, tls.CipherSuiteName(id))
	}
	return info
}
