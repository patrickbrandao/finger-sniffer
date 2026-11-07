package version

import "testing"

func TestString(t *testing.T) {
	// Garante o formato usado por -version e pelos logs de início.
	oldVersion, oldCommit := Version, Commit
	t.Cleanup(func() { Version, Commit = oldVersion, oldCommit })

	Version, Commit = "1.2.3", "abc1234"
	got := String("finger-sniffer-web")
	want := "finger-sniffer-web 1.2.3 (abc1234)"
	if got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}

func TestDefaults(t *testing.T) {
	// Sem -ldflags os valores padrão precisam ser não vazios.
	if Version == "" || Commit == "" {
		t.Fatalf("defaults must not be empty: Version=%q Commit=%q", Version, Commit)
	}
}
