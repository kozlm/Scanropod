package scanner

import (
	"os"
	"testing"
)

func TestEnsureDirSuccess(t *testing.T) {
	called := false

	defaultMkdirAll := mkdirAll
	t.Cleanup(func() { mkdirAll = defaultMkdirAll })

	mkdirAll = func(path string, perm os.FileMode) error {
		called = true
		if path != "test-dir" {
			t.Fatalf("unexpected path: %s", path)
		}
		if perm != 0o755 {
			t.Fatalf("unexpected perm: %v", perm)
		}
		return nil
	}

	ensureDir("test-dir")

	if !called {
		t.Fatal("expected mkdirAll to be called")
	}
}

func TestSanitizeFilenameEmpty(t *testing.T) {
	if got := sanitizeFilename(""); got != "unknown" {
		t.Fatalf("expected unknown, got %q", got)
	}
}

func TestSanitizeFilenameReplacesUnsafeChars(t *testing.T) {
	in := "https://example.com/a?b=1&c=2"
	exp := "https_example.com_a_b_1_c_2"

	if got := sanitizeFilename(in); got != exp {
		t.Fatalf("expected %q, got %q", exp, got)
	}
}

func TestSanitizeFilenameTrimSpace(t *testing.T) {
	in := "  http://example.com  "
	exp := "http_example.com"

	if got := sanitizeFilename(in); got != exp {
		t.Fatalf("expected %q, got %q", exp, got)
	}
}
