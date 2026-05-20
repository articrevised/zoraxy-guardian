package guardian

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAtomicWriteLeavesNoTmpOnSuccess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := atomicWriteFile(path, []byte(`{"x":1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") || strings.Contains(e.Name(), ".tmp") {
			t.Errorf("found stray tmp file: %s", e.Name())
		}
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != `{"x":1}` {
		t.Fatalf("got %q, err=%v", data, err)
	}
}

func TestAtomicWriteOverwrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	_ = os.WriteFile(path, []byte("old"), 0o644)
	if err := atomicWriteFile(path, []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if string(data) != "new" {
		t.Errorf("got %q want new", data)
	}
}
