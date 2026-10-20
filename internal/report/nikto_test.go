package report

import (
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/kozlm/scanropod/internal/model"
)

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
		if got := isReportFile(test.name, "nikto-"); got != test.expected {
			t.Errorf("for %q expected %v, got %v", test.name, test.expected, got)
		}
	}
}

func TestParseNiktoSingleReportSuccess(t *testing.T) {
	cleanup(t)

	readFile = func(string) ([]byte, error) {
		return json.Marshal([]niktoHostResult{
			{
				Host: "example.com",
				Port: "80",
				Vulnerabilities: []niktoVulnEntry{
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

	buildURL = func(host, path, port, scheme string) string {
		return "RAW_URL"
	}

	cleanURL = func(string) (string, error) {
		return "http://example.com/test", nil
	}

	findings, err := parseNiktoFile("ignored.json", "http", cweMap{
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

func TestParseNiktoSingleReportCleanUrlFail(t *testing.T) {
	cleanup(t)

	readFile = func(string) ([]byte, error) {
		return json.Marshal([]niktoHostResult{
			{
				Host: "example.com",
				Port: "80",
				Vulnerabilities: []niktoVulnEntry{
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

	buildURL = func(string, string, string, string) string {
		return "bad-url"
	}

	cleanURL = func(string) (string, error) {
		return "", errors.New("error")
	}
	_, err := parseNiktoFile("ignored", "http", cweMap{})
	if err == nil {
		t.Fatal("expected error from cleanURL")
	}
}

func TestParseNiktoReports(t *testing.T) {
	cleanup(t)

	loadNiktoMap = func(string) (cweMap, error) {
		return cweMap{"1": "22"}, nil
	}

	readDir = func(string) ([]os.DirEntry, error) {
		return []os.DirEntry{
			fakeDirEntry{name: "nikto-http.json"},
			fakeDirEntry{name: "ignored.txt"},
		}, nil
	}

	readFile = func(string) ([]byte, error) {
		return json.Marshal([]niktoHostResult{
			{
				Host: "example.com",
				Vulnerabilities: []niktoVulnEntry{
					{ID: "1", URL: "/"},
				},
			},
		})
	}

	buildURL = func(string, string, string, string) string {
		return "RAW"
	}

	cleanURL = func(string) (string, error) {
		return "http://example.com/", nil
	}

	findings, err := parseNiktoReports("scan1", "map.csv")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
}
