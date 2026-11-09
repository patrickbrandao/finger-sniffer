package certs

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// slots na ordem de State: A (dns01) e B (http01).
var slots = []string{SlotDNS01, SlotHTTP01}

// Tempos da recarga. debounce junta a rajada de eventos de um WritePair (dois renames); retryDelay refaz a
// leitura quando o par está inconsistente (chave e certificado trocados em momentos diferentes); pollInterval
// é a rede de segurança: confere tamanho e data dos arquivos e tenta de novo vigiar o diretório se ele não
// existia ou o watcher falhou.
const (
	debounce     = 100 * time.Millisecond
	retryDelay   = 500 * time.Millisecond
	pollInterval = 5 * time.Second
)

type entry struct {
	cert       *tls.Certificate
	selfSigned bool
	sig        string // assinatura (tamanho e data) dos arquivos lidos; vazia para o autoassinado
}

// Store guarda os certificados A e B lidos de FS_CERT_DIR e os recarrega a quente. Seguro para uso
// concorrente; GetCertificate pode ser usado direto em tls.Config.
type Store struct {
	cfg Config
	log *slog.Logger
	now func() time.Time

	mu         sync.RWMutex
	entries    map[string]*entry
	selfSigned *tls.Certificate // gerado uma vez, com todos os nomes, quando falta algum arquivo

	stop    chan struct{}
	stopped sync.WaitGroup
	once    sync.Once
}

// Open lê os certificados de cfg.Dir (usando o autoassinado onde faltar arquivo) e começa a vigiar o
// diretório. Feche com Close.
func Open(cfg Config, log *slog.Logger) (*Store, error) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	s := &Store{
		cfg:     cfg,
		log:     log,
		now:     time.Now,
		entries: map[string]*entry{},
		stop:    make(chan struct{}),
	}
	if _, err := s.Reload(); err != nil && s.missingAll() {
		return nil, err
	}
	s.stopped.Add(1)
	go s.watch()
	return s, nil
}

// Close para a vigilância do diretório. Os certificados em memória continuam válidos.
func (s *Store) Close() error {
	s.once.Do(func() { close(s.stop) })
	s.stopped.Wait()
	return nil
}

// TLSConfig devolve ServerConfig com GetCertificate deste Store.
func (s *Store) TLSConfig() *tls.Config {
	c := ServerConfig()
	c.GetCertificate = s.GetCertificate
	return c
}

// GetCertificate escolhe o certificado por SNI (spec 015 RF-02, RF-03, RF-07): nome coberto por
// FS_CERT_NAMES_DNS01 → A; qualquer outro, ou sem SNI → B.
func (s *Store) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	slot := s.SlotFor(hello.ServerName)
	s.mu.RLock()
	e := s.entries[slot]
	s.mu.RUnlock()
	if e == nil || e.cert == nil {
		return nil, fmt.Errorf("certs: sem certificado para %s", slot)
	}
	return e.cert, nil
}

// SlotFor diz qual certificado serve um SNI: SlotDNS01 se o nome casa com FS_CERT_NAMES_DNS01, senão
// SlotHTTP01. O curinga "*.zona" cobre qualquer nome abaixo da zona (um ou mais rótulos): um probe com
// rótulos de controle (<id>.noh3.zona) não é validado por nenhum dos dois, e o A é o mais próximo.
func (s *Store) SlotFor(serverName string) string {
	name := normalizeName(serverName)
	if name == "" {
		return SlotHTTP01
	}
	for _, n := range s.cfg.NamesDNS01 {
		if matchName(n, name) {
			return SlotDNS01
		}
	}
	return SlotHTTP01
}

func matchName(pattern, name string) bool {
	if zone, ok := strings.CutPrefix(pattern, "*."); ok {
		return strings.HasSuffix(name, "."+zone)
	}
	return pattern == name
}

// Reload relê os dois pares. Devolve se algo mudou e o erro do par inconsistente, se houver: nesse caso o
// certificado anterior (ou o autoassinado, se não havia nenhum) continua em uso.
func (s *Store) Reload() (bool, error) {
	changed := false
	var errs []error
	for _, slot := range slots {
		c, err := s.reloadSlot(slot)
		changed = changed || c
		if err != nil {
			errs = append(errs, err)
		}
	}
	return changed, errors.Join(errs...)
}

func (s *Store) reloadSlot(slot string) (bool, error) {
	crtPath := filepath.Join(s.cfg.Dir, slot+".crt")
	keyPath := filepath.Join(s.cfg.Dir, slot+".key")
	sig, missing := fileSig(crtPath, keyPath)

	s.mu.RLock()
	cur := s.entries[slot]
	s.mu.RUnlock()

	if missing {
		if cur != nil && cur.selfSigned {
			return false, nil
		}
		ss, err := s.selfSignedCert()
		if err != nil {
			return false, err
		}
		s.set(slot, &entry{cert: ss, selfSigned: true})
		s.log.Warn("certs: arquivo ausente, usando autoassinado", "slot", slot, "dir", s.cfg.Dir)
		return true, nil
	}
	if cur != nil && !cur.selfSigned && cur.sig == sig {
		return false, nil
	}
	cert, err := tls.LoadX509KeyPair(crtPath, keyPath)
	if err != nil {
		err = fmt.Errorf("certs: %s: %w", slot, err)
		if cur == nil {
			// Primeira leitura com par inválido: serve o autoassinado até o par ficar bom.
			ss, sErr := s.selfSignedCert()
			if sErr != nil {
				return false, errors.Join(err, sErr)
			}
			s.set(slot, &entry{cert: ss, selfSigned: true})
			return true, err
		}
		return false, err
	}
	s.set(slot, &entry{cert: &cert, sig: sig})
	s.log.Info("certs: certificado carregado", "slot", slot, "names", cert.Leaf.DNSNames,
		"not_after", cert.Leaf.NotAfter)
	return true, nil
}

func (s *Store) set(slot string, e *entry) {
	s.mu.Lock()
	s.entries[slot] = e
	s.mu.Unlock()
}

func (s *Store) missingAll() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, slot := range slots {
		if s.entries[slot] != nil {
			return false
		}
	}
	return true
}

// selfSignedCert gera (uma vez) o autoassinado com todos os nomes de A e B.
func (s *Store) selfSignedCert() (*tls.Certificate, error) {
	s.mu.RLock()
	ss := s.selfSigned
	s.mu.RUnlock()
	if ss != nil {
		return ss, nil
	}
	names := append(append([]string(nil), s.cfg.NamesDNS01...), s.cfg.NamesHTTP01...)
	ss, err := newSelfSigned(names, s.now())
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	if s.selfSigned == nil {
		s.selfSigned = ss
	}
	ss = s.selfSigned
	s.mu.Unlock()
	return ss, nil
}

// fileSig resume tamanho e data de modificação dos dois arquivos; missing quando algum não existe ou não é
// um arquivo regular.
func fileSig(paths ...string) (sig string, missing bool) {
	var b strings.Builder
	for _, p := range paths {
		fi, err := os.Stat(p)
		if err != nil || !fi.Mode().IsRegular() {
			return "", true
		}
		fmt.Fprintf(&b, "%d:%d;", fi.Size(), fi.ModTime().UnixNano())
	}
	return b.String(), false
}

// isOurFile diz se o evento é de um dos quatro arquivos vigiados (os temporários do WritePair são ignorados;
// o rename deles gera evento com o nome definitivo).
func isOurFile(name string) bool {
	switch filepath.Base(name) {
	case SlotDNS01 + ".crt", SlotDNS01 + ".key", SlotHTTP01 + ".crt", SlotHTTP01 + ".key":
		return true
	}
	return false
}

// watch é a técnica do certwatcher do fingerproxy: vigia o diretório (não os arquivos, que o rename atômico
// troca de inode), junta rajadas de eventos e relê; par inconsistente é relido de novo pouco depois.
func (s *Store) watch() {
	defer s.stopped.Done()
	var w *fsnotify.Watcher
	defer func() {
		if w != nil {
			_ = w.Close()
		}
	}()
	addWatch := func() {
		if w != nil {
			return
		}
		nw, err := fsnotify.NewWatcher()
		if err != nil {
			s.log.Warn("certs: fsnotify indisponível", "err", err)
			return
		}
		if err := nw.Add(s.cfg.Dir); err != nil {
			_ = nw.Close()
			if !errors.Is(err, fs.ErrNotExist) {
				s.log.Warn("certs: não consegui vigiar o diretório", "dir", s.cfg.Dir, "err", err)
			}
			return
		}
		w = nw
	}
	addWatch()

	timer := time.NewTimer(time.Hour)
	timer.Stop()
	poll := time.NewTicker(pollInterval)
	defer poll.Stop()

	doReload := func() {
		if _, err := s.Reload(); err != nil {
			s.log.Warn("certs: recarga falhou, mantendo o anterior", "err", err)
			timer.Reset(retryDelay)
		}
	}

	for {
		var events chan fsnotify.Event
		var errs chan error
		if w != nil {
			events, errs = w.Events, w.Errors
		}
		select {
		case <-s.stop:
			return
		case ev, ok := <-events:
			if !ok {
				w = nil
				continue
			}
			if isOurFile(ev.Name) {
				timer.Reset(debounce)
			} else if filepath.Clean(ev.Name) == filepath.Clean(s.cfg.Dir) && ev.Has(fsnotify.Remove|fsnotify.Rename) {
				// O próprio diretório sumiu: recria o watcher no próximo poll.
				_ = w.Close()
				w = nil
				timer.Reset(debounce)
			}
		case err, ok := <-errs:
			if ok {
				s.log.Warn("certs: erro do fsnotify", "err", err)
			}
		case <-timer.C:
			doReload()
		case <-poll.C:
			addWatch()
			doReload()
		}
	}
}
