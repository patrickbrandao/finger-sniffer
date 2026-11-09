package certs

import (
	"fmt"
	"os"
	"path/filepath"
)

// WritePair grava <dir>/<name>.key e <dir>/<name>.crt de forma atômica (spec 015 RF-04): cada arquivo vai
// para um temporário no mesmo diretório e é renomeado por cima do definitivo, a chave antes do certificado
// (assim quem observa por fsnotify nunca vê um certificado novo com a chave velha por muito tempo, e o Store
// tolera o intervalo). A chave fica com modo 0600 e o certificado com 0644.
func WritePair(dir, name string, certPEM, keyPEM []byte) error {
	if name == "" || filepath.Base(name) != name {
		return fmt.Errorf("certs: nome inválido %q", name)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("certs: %w", err)
	}
	if err := writeAtomic(dir, name+".key", keyPEM, 0o600); err != nil {
		return err
	}
	return writeAtomic(dir, name+".crt", certPEM, 0o644)
}

func writeAtomic(dir, file string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(dir, "."+file+".tmp-*")
	if err != nil {
		return fmt.Errorf("certs: %w", err)
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("certs: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("certs: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("certs: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("certs: %w", err)
	}
	if err := os.Rename(tmpName, filepath.Join(dir, file)); err != nil {
		return fmt.Errorf("certs: %w", err)
	}
	ok = true
	// fsync do diretório para o rename sobreviver a uma queda; falha aqui não invalida a escrita.
	if d, err := os.Open(dir); err == nil { //nolint:gosec // diretório de certificados escolhido por quem chama
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
