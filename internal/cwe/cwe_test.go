package cwe

import (
	"os"
	"testing"
)

func writeTempCSV(t *testing.T, content string) string {
	t.Helper()

	f, err := os.CreateTemp("", "wapiti-*.csv")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}

	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("failed to write csv: %v", err)
	}

	if err := f.Close(); err != nil {
		t.Fatalf("failed to close file: %v", err)
	}

	t.Cleanup(func() {
		_ = os.Remove(f.Name())
	})

	return f.Name()
}

func TestLoadWapitiMapValidCSV(t *testing.T) {
	path := writeTempCSV(t,
		"name,cwe,keyphrase\n"+
			"SQL Injection,89,\n"+
			"TLS/SSL misconfigurations,326,expired certificate\n",
	)

	m, err := LoadWapitiMap(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if m == nil {
		t.Fatal("expected non-nil map")
	}
}

func TestWapitiMapLookupNil(t *testing.T) {
	var m *WapitiMap

	if got := m.Lookup("SQL Injection", ""); got != "0" {
		t.Fatalf("expected 0, got %q", got)
	}
}

func TestWapitiMapLookupByName(t *testing.T) {
	path := writeTempCSV(t,
		"name,cwe,keyphrase\n"+
			"SQL Injection,89,\n",
	)

	m, err := LoadWapitiMap(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := m.Lookup("SQL Injection", "anything")
	if got != "89" {
		t.Fatalf("expected 89, got %q", got)
	}
}

func TestWapitiMapLookupTLSByPhrase(t *testing.T) {
	path := writeTempCSV(t,
		"name,cwe,keyphrase\n"+
			"TLS/SSL misconfigurations,326,expired certificate\n",
	)

	m, err := LoadWapitiMap(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	info := "The server uses an expired certificate"
	got := m.Lookup("TLS/SSL misconfigurations", info)

	if got != "326" {
		t.Fatalf("expected 326, got %q", got)
	}
}

func TestWapitiMapLookupTLSNoPhraseMatch(t *testing.T) {
	path := writeTempCSV(t,
		"name,cwe,keyphrase\n"+
			"TLS/SSL misconfigurations,326,expired certificate\n",
	)

	m, err := LoadWapitiMap(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := m.Lookup("TLS/SSL misconfigurations", "some other issue")
	if got != "0" {
		t.Fatalf("expected 0, got %q", got)
	}
}

func TestWapitiMapLookupUnknown(t *testing.T) {
	path := writeTempCSV(t,
		"name,cwe,keyphrase\n"+
			"SQL Injection,89,\n",
	)

	m, err := LoadWapitiMap(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := m.Lookup("XSS", "")
	if got != "0" {
		t.Fatalf("expected 0, got %q", got)
	}
}
