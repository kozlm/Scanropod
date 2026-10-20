package report

import "testing"

func TestCleanUrl(t *testing.T) {
	raw := "http://example.com//a/b/../c?x=1#frag"
	exp := "http://example.com/a/c"

	got, err := cleanURL(raw)
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

	got, err := cleanURL(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got != exp {
		t.Fatalf("expected %q, got %q", exp, got)
	}
}

func TestCleanUrlInvalid(t *testing.T) {
	_, err := cleanURL("://bad-url")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestBuildUrlHTTPDefaultPort(t *testing.T) {
	got := buildURL("example.com", "/a", "80", "http")
	exp := "http://example.com/a"

	if got != exp {
		t.Fatalf("expected %q, got %q", exp, got)
	}
}

func TestBuildUrlNonDefaultPort(t *testing.T) {
	got := buildURL("example.com", "/a", "8080", "http")
	exp := "http://example.com:8080/a"

	if got != exp {
		t.Fatalf("expected %q, got %q", exp, got)
	}
}

func TestBuildUrlHTTPSDefaultPort(t *testing.T) {
	got := buildURL("example.com", "/", "443", "https")
	exp := "https://example.com/"

	if got != exp {
		t.Fatalf("expected %q, got %q", exp, got)
	}
}

func TestSchemeFromReportFileNameHTTPS(t *testing.T) {
	if got := schemeFromReportFileName("nikto-https_example.com.json"); got != "https" {
		t.Fatalf("expected https, got %q", got)
	}
}

func TestSchemeFromReportFileNameHTTP(t *testing.T) {
	if got := schemeFromReportFileName("nikto-http_example.com.json"); got != "http" {
		t.Fatalf("expected http, got %q", got)
	}
}

func TestSchemeFromReportFileNameUnknownScheme(t *testing.T) {
	if got := schemeFromReportFileName("nikto-ftp_example.com.json"); got != "http" {
		t.Fatalf("expected http, got %q", got)
	}
}

func TestSchemeFromReportFileNameNoUnderscore(t *testing.T) {
	if got := schemeFromReportFileName("nikto-httpsexample.com.json"); got != "http" {
		t.Fatalf("expected http, got %q", got)
	}
}
