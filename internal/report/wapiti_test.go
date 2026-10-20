package report

import (
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/kozlm/scanropod/internal/model"
)

func TestIsWapitiReportFile(t *testing.T) {
	tests := []struct {
		name     string
		expected bool
	}{
		{"wapiti-test.json", true},
		{"wapiti-test.txt", false},
		{"other.json", false},
	}

	for _, test := range tests {
		if got := isReportFile(test.name, "wapiti-"); got != test.expected {
			t.Errorf("for %q expected %v, got %v", test.name, test.expected, got)
		}
	}
}

func TestParseWapitiSingleReportSuccess(t *testing.T) {
	cleanup(t)

	readFile = func(string) ([]byte, error) {
		return json.Marshal(wapitiReport{
			Infos: wapitiInfo{
				Target: "http://example.com",
			},
			Vulnerabilities: map[string][]wapitiFinding{
				"SQL Injection": {
					{
						Method:      "GET",
						Path:        "/test",
						Info:        "SQL injection detected",
						Level:       2,
						Module:      "sql",
						HTTPRequest: "GET /test",
					},
				},
			},
		})
	}

	cleanURL = func(string) (string, error) {
		return "http://example.com", nil
	}

	tmpFile, err := os.CreateTemp("", "wapiti-map-*.csv")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	t.Cleanup(func() { os.Remove(tmpFile.Name()) })

	_, err = tmpFile.WriteString(
		"name,cwe,keyphrase\n" +
			"SQL Injection,89,\n",
	)
	if err != nil {
		t.Fatalf("failed to write csv: %v", err)
	}
	tmpFile.Close()

	cweLookup, err := loadWapitiMap(tmpFile.Name())
	if err != nil {
		t.Fatalf("failed to load wapiti map: %v", err)
	}

	findings, err := parseWapitiFile("ignored.json", cweLookup)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]

	if f.CWEID != "89" {
		t.Fatalf("expected CWE 89, got %s", f.CWEID)
	}

	if f.TargetURL != "http://example.com" {
		t.Fatalf("unexpected URL: %s", f.TargetURL)
	}

	if f.Scanner != model.ScannerWapiti {
		t.Fatalf("unexpected scanner: %v", f.Scanner)
	}
}

func TestParseWapitiSingleReportCleanUrlFail(t *testing.T) {
	cleanup(t)

	readFile = func(string) ([]byte, error) {
		return json.Marshal(wapitiReport{
			Infos: wapitiInfo{
				Target: "bad-url",
			},
			Vulnerabilities: map[string][]wapitiFinding{
				"XSS": {
					{Info: "xss"},
				},
			},
		})
	}

	cleanURL = func(string) (string, error) {
		return "", errors.New("error")
	}

	_, err := parseWapitiFile("ignored.json", &wapitiCWEMap{})
	if err == nil {
		t.Fatal("expected error from cleanURL")
	}
}

func TestParseWapitiReports(t *testing.T) {
	cleanup(t)

	tmpFile, err := os.CreateTemp("", "wapiti-map-*.csv")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	t.Cleanup(func() { os.Remove(tmpFile.Name()) })

	_, err = tmpFile.WriteString(
		"name,cwe,keyphrase\n" +
			"XSS,79,\n",
	)
	if err != nil {
		t.Fatalf("failed to write csv: %v", err)
	}
	tmpFile.Close()

	readDir = func(string) ([]os.DirEntry, error) {
		return []os.DirEntry{
			fakeDirEntry{name: "wapiti-scan.json"},
			fakeDirEntry{name: "ignored.txt"},
		}, nil
	}

	readFile = func(string) ([]byte, error) {
		return json.Marshal(wapitiReport{
			Infos: wapitiInfo{
				Target: "http://example.com",
			},
			Vulnerabilities: map[string][]wapitiFinding{
				"XSS": {
					{
						Method: "GET",
						Info:   "xss",
					},
				},
			},
		})
	}

	cleanURL = func(string) (string, error) {
		return "http://example.com", nil
	}

	findings, err := parseWapitiReports("scan1", tmpFile.Name())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
}
