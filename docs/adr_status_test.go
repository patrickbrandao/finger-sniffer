package docs

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// adrDir é a pasta das ADRs, relativa a este pacote.
const adrDir = "../specs/decisions"

var (
	// adrFileRe acha o número de uma ADR pelo nome do arquivo (nnnn-titulo.md).
	adrFileRe = regexp.MustCompile(`^(\d{4})-.+\.md$`)
	// adrStatusRe pega o campo Status inteiro, que pode quebrar linha antes do Data.
	adrStatusRe = regexp.MustCompile(`(?ms)^Status:(.*?)^Data:`)
	// adrChangeRe acha "substitui/altera/complementa …" até o fim da oração; as ADRs citadas no trecho são as
	// alteradas. O texto já vem com os espaços normalizados (aceita quebra de linha no meio).
	adrChangeRe = regexp.MustCompile(`(?i)\b(?:substitui|altera|complementa)\b([^.;()]{0,160})`)
	// adrRefRe acha "ADR nnnn" ou "ADRs nnnn" dentro do trecho.
	adrRefRe = regexp.MustCompile(`\bADRs?\s+(\d{4})`)
	// historyRowRe acha uma linha do HISTORY: | [nnnn](arquivo) | título | status | conteúdo |.
	historyRowRe = regexp.MustCompile(`(?m)^\| \[(\d{4})\]\([^)]+\) \| [^|]* \| ([^|]*) \|`)
)

// TestADRStatusCitesLaterChanges segura a regra das ADRs (specs/002, AGENTS.md): quando uma ADR posterior diz que
// substitui, altera ou complementa a ADR N, o Status de N (no arquivo e no HISTORY) cita a posterior (task 405).
func TestADRStatusCitesLaterChanges(t *testing.T) {
	entries, err := os.ReadDir(adrDir)
	if err != nil {
		t.Fatal(err)
	}
	texts := map[string]string{}
	status := map[string]string{}
	for _, e := range entries {
		m := adrFileRe.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		data, err := os.ReadFile(filepath.Join(adrDir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		texts[m[1]] = strings.Join(strings.Fields(string(data)), " ")
		sm := adrStatusRe.FindStringSubmatch(string(data))
		if sm == nil {
			t.Errorf("%s: sem campo Status antes do Data", e.Name())
			continue
		}
		status[m[1]] = sm[1]
	}
	if len(texts) < 70 {
		t.Fatalf("só %d ADRs lidas em %s", len(texts), adrDir)
	}

	hist, err := os.ReadFile(filepath.Join(adrDir, "HISTORY.md"))
	if err != nil {
		t.Fatal(err)
	}
	histStatus := map[string]string{}
	for _, m := range historyRowRe.FindAllStringSubmatch(string(hist), -1) {
		histStatus[m[1]] = m[2]
	}

	nums := make([]string, 0, len(texts))
	for n := range texts {
		nums = append(nums, n)
	}
	sort.Strings(nums)
	for _, later := range nums {
		seen := map[string]bool{}
		for _, cm := range adrChangeRe.FindAllStringSubmatch(texts[later], -1) {
			for _, rm := range adrRefRe.FindAllStringSubmatch(cm[1], -1) {
				target := rm[1]
				// só as anteriores: uma ADR que cita uma posterior não a altera
				if target >= later || seen[target] {
					continue
				}
				seen[target] = true
				st, ok := status[target]
				if !ok {
					continue
				}
				if !strings.Contains(st, later) {
					t.Errorf("ADR %s altera a %s (%q), mas o Status do arquivo %s não cita a %s", later, target,
						strings.TrimSpace(cm[0]), target, later)
				}
				if hs, ok := histStatus[target]; !ok {
					t.Errorf("HISTORY.md sem a linha da ADR %s", target)
				} else if !strings.Contains(hs, later) {
					t.Errorf("ADR %s altera a %s, mas o Status da %s no HISTORY.md não cita a %s", later, target,
						target, later)
				}
			}
		}
	}
}
