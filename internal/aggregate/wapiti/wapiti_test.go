package wapiti

import (
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/kozlm/scanropod/internal/cwe"
	"github.com/kozlm/scanropod/internal/model"
)

var (
	defaultReadFile      = readFile
	defaultReadDir       = readDir
	defaultCleanUrl      = cleanUrl
	defaultLoadWapitiMap = loadWapitiMap
)

func cleanup(t *testing.T) {
	t.Cleanup(func() {
		readFile = defaultReadFile
		readDir = defaultReadDir
		cleanUrl = defaultCleanUrl
		loadWapitiMap = defaultLoadWapitiMap
	})
}

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
		if got := isWapitiReportFile(test.name); got != test.expected {
			t.Errorf("for %q expected %v, got %v", test.name, test.expected, got)
		}
	}
}

func TestParseSingleReportSuccess(t *testing.T) {
	cleanup(t)

	readFile = func(string) ([]byte, error) {
		return json.Marshal(result{
			Infos: info{
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

	cleanUrl = func(string) (string, error) {
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

	cweMap, err := cwe.LoadWapitiMap(tmpFile.Name())
	if err != nil {
		t.Fatalf("failed to load wapiti map: %v", err)
	}

	findings, err := parseSingleReport("ignored.json", cweMap)
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

func TestParseSingleReportCleanUrlFail(t *testing.T) {
	cleanup(t)

	readFile = func(string) ([]byte, error) {
		return json.Marshal(result{
			Infos: info{
				Target: "bad-url",
			},
			Vulnerabilities: map[string][]wapitiFinding{
				"XSS": {
					{Info: "xss"},
				},
			},
		})
	}

	cleanUrl = func(string) (string, error) {
		return "", errors.New("error")
	}

	_, err := parseSingleReport("ignored.json", &cwe.WapitiMap{})
	if err == nil {
		t.Fatal("expected error from cleanUrl")
	}
}

func TestParseReports(t *testing.T) {
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
		return json.Marshal(result{
			Infos: info{
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

	cleanUrl = func(string) (string, error) {
		return "http://example.com", nil
	}

	findings, err := ParseReports("scan1", tmpFile.Name())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
}

type fakeDirEntry struct {
	name string
}

func (f fakeDirEntry) Name() string               { return f.name }
func (f fakeDirEntry) IsDir() bool                { return false }
func (f fakeDirEntry) Type() os.FileMode          { return 0 }
func (f fakeDirEntry) Info() (os.FileInfo, error) { return nil, nil }
