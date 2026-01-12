package helper

import (
	"os"
	"testing"

	"github.com/kozlm/scanropods/internal/model"
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

	EnsureDir("test-dir")

	if !called {
		t.Fatal("expected mkdirAll to be called")
	}
}

func TestSanitizeFilenameEmpty(t *testing.T) {
	if got := SanitizeFilename(""); got != "unknown" {
		t.Fatalf("expected unknown, got %q", got)
	}
}

func TestSanitizeFilenameReplacesUnsafeChars(t *testing.T) {
	in := "https://example.com/a?b=1&c=2"
	exp := "https_example.com_a_b_1_c_2"

	if got := SanitizeFilename(in); got != exp {
		t.Fatalf("expected %q, got %q", exp, got)
	}
}

func TestSanitizeFilenameTrimSpace(t *testing.T) {
	in := "  http://example.com  "
	exp := "http_example.com"

	if got := SanitizeFilename(in); got != exp {
		t.Fatalf("expected %q, got %q", exp, got)
	}
}

func TestSchemeFromReportFileNameHTTPS(t *testing.T) {
	if got := SchemeFromReportFileName("nikto-https_example.com.json"); got != "https" {
		t.Fatalf("expected https, got %q", got)
	}
}

func TestSchemeFromReportFileNameHTTP(t *testing.T) {
	if got := SchemeFromReportFileName("nikto-http_example.com.json"); got != "http" {
		t.Fatalf("expected http, got %q", got)
	}
}

func TestSchemeFromReportFileNameUnknownScheme(t *testing.T) {
	if got := SchemeFromReportFileName("nikto-ftp_example.com.json"); got != "http" {
		t.Fatalf("expected http, got %q", got)
	}
}

func TestSchemeFromReportFileNameNoUnderscore(t *testing.T) {
	if got := SchemeFromReportFileName("nikto-httpsexample.com.json"); got != "http" {
		t.Fatalf("expected http, got %q", got)
	}
}

func TestCleanUrl(t *testing.T) {
	raw := "http://example.com//a/b/../c?x=1#frag"
	exp := "http://example.com/a/c"

	got, err := CleanUrl(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got != exp {
		t.Fatalf("expected %q, got %q", exp, got)
	}
}

func TestCleanUrlEncoded(t *testing.T) {
	raw := "http://example.com/%2Ftest%2F"
	exp := "http://example.com/test"

	got, err := CleanUrl(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got != exp {
		t.Fatalf("expected %q, got %q", exp, got)
	}
}

func TestCleanUrlInvalid(t *testing.T) {
	_, err := CleanUrl("://bad-url")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestBuildUrlHTTPDefaultPort(t *testing.T) {
	got := BuildUrl("example.com", "/a", "80", "http")
	exp := "http://example.com/a"

	if got != exp {
		t.Fatalf("expected %q, got %q", exp, got)
	}
}

func TestBuildUrlNonDefaultPort(t *testing.T) {
	got := BuildUrl("example.com", "/a", "8080", "http")
	exp := "http://example.com:8080/a"

	if got != exp {
		t.Fatalf("expected %q, got %q", exp, got)
	}
}

func TestBuildUrlHTTPSDefaultPort(t *testing.T) {
	got := BuildUrl("example.com", "/", "443", "https")
	exp := "https://example.com/"

	if got != exp {
		t.Fatalf("expected %q, got %q", exp, got)
	}
}

func TestValidateScanRequestNil(t *testing.T) {
	if err := ValidateScanRequest(nil); err == nil {
		t.Fatal("expected error")
	}
}

func TestValidateScanRequestEmptyTargets(t *testing.T) {
	req := &model.ScanRequest{}
	if err := ValidateScanRequest(req); err == nil {
		t.Fatal("expected error")
	}
}

func TestValidateScanRequestInvalidTarget(t *testing.T) {
	req := &model.ScanRequest{
		Targets: []string{"ftp://example.com"},
	}

	if err := ValidateScanRequest(req); err == nil {
		t.Fatal("expected error")
	}
}

func TestValidateScanRequestValid(t *testing.T) {
	req := &model.ScanRequest{
		Targets:  []string{"http://example.com"},
		Scanners: []string{"Zap", "nikto", "zap"},
	}

	err := ValidateScanRequest(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(req.Scanners) != 2 {
		t.Fatalf("expected 2 scanners, got %d", len(req.Scanners))
	}
}

func TestValidateScanRequestUnsupportedScanner(t *testing.T) {
	req := &model.ScanRequest{
		Targets:  []string{"http://example.com"},
		Scanners: []string{"nikto", "unknown"},
	}

	if err := ValidateScanRequest(req); err == nil {
		t.Fatal("expected error")
	}
}

func TestValidateScanRequestNoScanners(t *testing.T) {
	req := &model.ScanRequest{
		Targets: []string{"http://example.com"},
	}

	if err := ValidateScanRequest(req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(req.Scanners) != 0 {
		t.Fatalf("expected empty scanners, got %v", req.Scanners)
	}
}
