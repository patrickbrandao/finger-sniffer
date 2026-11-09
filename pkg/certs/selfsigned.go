package certs

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"
)

// SelfSignedIssuer é o CN (emissor e sujeito) do autoassinado em memória.
const SelfSignedIssuer = "finger-sniffer self-signed"

// selfSignedValidity é a validade do autoassinado; ele vive só na memória do processo.
const selfSignedValidity = 90 * 24 * time.Hour

// newSelfSigned gera um certificado autoassinado com todos os nomes. A chave é RSA 2048 para que as cifras
// legadas com troca de chaves RSA (e clientes que só falam RSA) continuem negociáveis.
func newSelfSigned(names []string, now time.Time) (*tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("certs: chave do autoassinado: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, fmt.Errorf("certs: serial do autoassinado: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: SelfSignedIssuer},
		DNSNames:              names,
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(selfSignedValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("certs: autoassinado: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("certs: autoassinado: %w", err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}
