package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"modernc.org/sqlite"
)

// Espaço do sistema de arquivos do banco (ADR 0045 itens 4 e 5). O banco fica num tmpfs dedicado de tamanho fixo:
// encher o tmpfs dá ENOSPC, que o SQLite devolve como SQLITE_FULL. O store previne (expurgo pelo livre do tmpfs,
// Retention.Space) e, se mesmo assim encher, degrada sem travar nem morrer (Ingestor.processBatch).
const (
	// spaceLowPct: com o livre abaixo disso (em % do tamanho do sistema de arquivos) o expurgo por espaço começa e
	// o health mostra "db space <n>% free".
	spaceLowPct = 10
	// spaceOKPct: o expurgo por espaço e o modo banco cheio só terminam com o livre de volta a isso.
	spaceOKPct = 15
	// fullHealthHold é quanto o health continua com "db full" depois do último SQLITE_FULL.
	fullHealthHold = 5 * time.Minute
	// emergencyPurgeMax é o prazo do expurgo de emergência depois de um SQLITE_FULL no ingest.
	emergencyPurgeMax = 2 * time.Second
	// sqliteFull é o código primário SQLITE_FULL (13) do SQLite.
	sqliteFull = 13
)

// SpaceReader lê o tamanho e o livre (em bytes) do sistema de arquivos do banco. Fica atrás de uma interface para
// os testes simularem um tmpfs cheio sem montar um.
type SpaceReader interface {
	Space() (size, free int64, err error)
}

// statfsSpace lê o statfs do diretório do banco.
type statfsSpace struct{ dir string }

// NewStatfsSpace devolve o leitor de espaço do diretório que contém o banco em path.
func NewStatfsSpace(path string) SpaceReader { return statfsSpace{dir: filepath.Dir(path)} }

func (s statfsSpace) Space() (size, free int64, err error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(s.dir, &st); err != nil {
		return 0, 0, fmt.Errorf("statfs %s: %w", s.dir, err)
	}
	bs := int64(st.Bsize)                                    //nolint:unconvert,gosec // uint32 no darwin, int64 no linux; blocos sempre pequenos
	return int64(st.Blocks) * bs, int64(st.Bavail) * bs, nil //nolint:gosec // contagens de blocos cabem em int64
}

// freePct é o livre em % do tamanho (100 quando o tamanho é desconhecido).
func freePct(size, free int64) float64 {
	if size <= 0 {
		return 100
	}
	return float64(free) * 100 / float64(size)
}

// spaceDeficit é quanto falta liberar para o livre voltar a spaceOKPct do tamanho (0 se já está).
func spaceDeficit(size, free int64) int64 {
	want := size * spaceOKPct / 100
	if free >= want {
		return 0
	}
	return want - free
}

// isDBFull diz se o erro é SQLITE_FULL (banco ou disco cheio), mesmo embrulhado por fmt.Errorf.
func isDBFull(err error) bool {
	if err == nil {
		return false
	}
	var se *sqlite.Error
	if errors.As(err, &se) {
		return se.Code()&0xff == sqliteFull
	}
	// Algum caminho pode ter perdido o tipo (%v): o texto do SQLite é estável.
	msg := err.Error()
	return strings.Contains(msg, "SQLITE_FULL") || strings.Contains(msg, "database or disk is full")
}

// ReserveBytes é o tamanho da reserva de espaço ao lado do banco (arquivo path-reserve). Com o tmpfs cheio de
// verdade, nem o expurgo nem o checkpoint conseguem rodar: o DELETE precisa de quadros novos no WAL e o
// checkpoint, de páginas novas no arquivo do banco, e os dois dão SQLITE_FULL (medido num tmpfs de 32 MiB). O
// expurgo de emergência apaga a reserva antes de começar, e o laço do store a recria quando o livre volta a
// spaceOKPct. 32 MiB são 0,8% do tmpfs de 4G e cobrem com folga o WAL de um expurgo de 2 s. Variável para os
// testes.
var ReserveBytes int64 = 32 << 20

// dbSpace é o estado do espaço do banco que o ingest, o expurgo, o health e as métricas compartilham.
type dbSpace struct {
	reader SpaceReader // nil: sem statfs (o modo banco cheio sai só pelo tempo, ver checkExit)
	// reserve é o arquivo da reserva de espaço (ReserveBytes); vazio = sem reserva.
	reserve string
	// full é o modo banco cheio (ADR 0045 item 5): conexões novas degradadas e lotes sem BLOBs.
	full atomic.Bool
	// lastFull é o instante (UnixNano) do último SQLITE_FULL; fullSince, o da entrada no modo banco cheio.
	lastFull  atomic.Int64
	fullSince atomic.Int64
}

func newDBSpace(r SpaceReader) *dbSpace { return &dbSpace{reader: r} }

// withReserve liga a reserva de espaço ao lado do banco em dbPath.
func (s *dbSpace) withReserve(dbPath string) *dbSpace {
	s.reserve = dbPath + "-reserve"
	return s
}

// ensureReserve cria a reserva se ela não existe (ou ficou menor), só com o livre em spaceOKPct ou mais (nunca
// gasta o último espaço do tmpfs) e fora do modo banco cheio. Na falta de espaço, a reserva parcial é apagada.
func (s *dbSpace) ensureReserve() error {
	if s == nil || s.reserve == "" || s.isFull() || ReserveBytes <= 0 {
		return nil
	}
	if st, err := os.Stat(s.reserve); err == nil && st.Size() >= ReserveBytes { //nolint:gosec // ao lado de FS_STORE_DB
		return nil
	}
	if size, free, ok := s.read(); ok && freePct(size, free-ReserveBytes) < spaceOKPct {
		return nil
	}
	f, err := os.OpenFile(s.reserve, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600) //nolint:gosec // ao lado de FS_STORE_DB
	if err != nil {
		return err
	}
	// Escreve de verdade: um arquivo esparso (Truncate) não ocupa páginas do tmpfs.
	buf := make([]byte, 1<<20)
	for left := ReserveBytes; left > 0 && err == nil; left -= int64(len(buf)) {
		_, err = f.Write(buf[:min(left, int64(len(buf)))])
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(s.reserve) //nolint:gosec // ao lado de FS_STORE_DB
	}
	return err
}

// releaseReserve apaga a reserva (o espaço volta ao tmpfs na hora); true se havia reserva.
func (s *dbSpace) releaseReserve() bool {
	return s != nil && s.reserve != "" && os.Remove(s.reserve) == nil //nolint:gosec // ao lado de FS_STORE_DB
}

// read devolve tamanho e livre; ok=false sem leitor ou com erro.
func (s *dbSpace) read() (size, free int64, ok bool) {
	if s == nil || s.reader == nil {
		return 0, 0, false
	}
	size, free, err := s.reader.Space()
	if err != nil || size <= 0 {
		return 0, 0, false
	}
	return size, free, true
}

// noteFull registra um SQLITE_FULL em now.
func (s *dbSpace) noteFull(now time.Time) {
	if s != nil {
		s.lastFull.Store(now.UnixNano())
	}
}

// isFull diz se o modo banco cheio está ligado.
func (s *dbSpace) isFull() bool { return s != nil && s.full.Load() }

// enterFull liga o modo banco cheio; devolve true se estava desligado.
func (s *dbSpace) enterFull(now time.Time) bool {
	if s == nil || s.full.Swap(true) {
		return false
	}
	s.fullSince.Store(now.UnixNano())
	return true
}

// fullNoReaderHold: sem leitor de espaço, o modo banco cheio dura isso e o ingest volta a tentar com BLOBs.
const fullNoReaderHold = 30 * time.Second

// checkExit desliga o modo banco cheio quando o livre voltou a spaceOKPct (ou, sem leitor, depois de
// fullNoReaderHold). Devolve true se saiu agora.
func (s *dbSpace) checkExit(now time.Time) bool {
	if !s.isFull() {
		return false
	}
	if size, free, ok := s.read(); ok {
		if freePct(size, free) < spaceOKPct {
			return false
		}
	} else if now.UnixNano()-s.fullSince.Load() < fullNoReaderHold.Nanoseconds() {
		return false
	}
	return s.full.CompareAndSwap(true, false)
}

// reasons são os motivos do health do store ligados ao espaço do banco (ADR 0045 item 5).
func (s *dbSpace) reasons(now time.Time) []string {
	if s == nil {
		return nil
	}
	var out []string
	if last := s.lastFull.Load(); s.isFull() || (last != 0 && now.UnixNano()-last < fullHealthHold.Nanoseconds()) {
		out = append(out, "db full")
	}
	if size, free, ok := s.read(); ok {
		if pct := freePct(size, free); pct < spaceLowPct {
			out = append(out, fmt.Sprintf("db space %d%% free", int(pct)))
		}
	}
	return out
}
