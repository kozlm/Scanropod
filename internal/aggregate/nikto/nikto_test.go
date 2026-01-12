package nikto

import (
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/kozlm/scanropods/internal/cwe"
	"github.com/kozlm/scanropods/internal/model"
)

var (
	defaultReadFile     = readFile
	defaultReadDir      = readDir
	defaultLoadNiktoMap = loadNiktoMap
	defaultBuildUrl     = buildUrl
	defaultCleanUrl     = cleanUrl
)

func cleanup(t *testing.T) {
	t.Cleanup(func() {
		readFile = defaultReadFile
		readDir = defaultReadDir
		loadNiktoMap = defaultLoadNiktoMap
		buildUrl = defaultBuildUrl
		cleanUrl = defaultCleanUrl
	})
}

func TestIsNiktoReportFile(t *testing.T) {
	tests := []struct {
		name     string
		expected bool
	}{
		{"nikto-test.json", true},
		{"nikto-test.txt", false},
		{"other.json", false},
	}

	for _, test := range tests {
		if got := isNiktoReportFile(test.name); got != test.expected {
			t.Errorf("for %q expected %v, got %v", test.name, test.expected, got)
		}
	}
}

func TestParseSingleReportSuccess(t *testing.T) {
	cleanup(t)

	readFile = func(string) ([]byte, error) {
		return json.Marshal([]hostResult{
			{
				Host: "example.com",
				Port: "80",
				Vulnerabilities: []vulnEntry{
					{
						ID:     "123",
						Method: "GET",
						URL:    "/test",
						Msg:    "XSS",
					},
				},
			},
		})
	}

	buildUrl = func(host, path, port, scheme string) string {
		return "RAW_URL"
	}

	cleanUrl = func(string) (string, error) {
		return "http://example.com/test", nil
	}

	findings, err := parseSingleReport("ignored.json", "http", cwe.NiktoMap{
		"123": "79",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]

	if f.CWEID != "79" {
		t.Fatalf("expected CWE 79, got %s", f.CWEID)
	}

	if f.TargetURL != "http://example.com/test" {
		t.Fatalf("unexpected URL: %s", f.TargetURL)
	}

	if f.Scanner != model.ScannerNikto {
		t.Fatalf("unexpected scanner: %v", f.Scanner)
	}
}

func TestParseSingleReportCleanUrlFail(t *testing.T) {
	cleanup(t)

	readFile = func(string) ([]byte, error) {
		return json.Marshal([]hostResult{
			{
				Host: "example.com",
				Port: "80",
				Vulnerabilities: []vulnEntry{
					{
						ID:     "123",
						Method: "GET",
						URL:    "/test",
						Msg:    "XSS",
					},
				},
			},
		})
	}

	buildUrl = func(string, string, string, string) string {
		return "bad-url"
	}

	cleanUrl = func(string) (string, error) {
		return "", errors.New("error")
	}
	_, err := parseSingleReport("ignored", "http", cwe.NiktoMap{})
	if err == nil {
		t.Fatal("expected error from cleanUrl")
	}
}

func TestParseReports(t *testing.T) {
	cleanup(t)

	loadNiktoMap = func(string) (cwe.NiktoMap, error) {
		return cwe.NiktoMap{"1": "22"}, nil
	}

	readDir = func(string) ([]os.DirEntry, error) {
		return []os.DirEntry{
			fakeDirEntry{name: "nikto-http.json"},
			fakeDirEntry{name: "ignored.txt"},
		}, nil
	}

	readFile = func(string) ([]byte, error) {
		return json.Marshal([]hostResult{
			{
				Host: "example.com",
				Vulnerabilities: []vulnEntry{
					{ID: "1", URL: "/"},
				},
			},
		})
	}

	buildUrl = func(string, string, string, string) string {
		return "RAW"
	}

	cleanUrl = func(string) (string, error) {
		return "http://example.com/", nil
	}

	findings, err := ParseReports("scan1", "map.csv")
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
