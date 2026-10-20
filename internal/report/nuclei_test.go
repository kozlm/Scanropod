package report

import (
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/kozlm/scanropod/internal/model"
)

func TestIsNucleiReportFile(t *testing.T) {
	tests := []struct {
		name     string
		expected bool
	}{
		{"nuclei-test.json", true},
		{"nuclei-test.txt", false},
		{"other.json", false},
	}

	for _, test := range tests {
		if got := isReportFile(test.name, "nuclei-"); got != test.expected {
			t.Errorf("for %q expected %v, got %v", test.name, test.expected, got)
		}
	}
}

func TestParseNucleiSingleReportSuccess(t *testing.T) {
	cleanup(t)

	readFile = func(string) ([]byte, error) {
		return json.Marshal([]nucleiTemplateResult{
			{
				TemplateID: "tpl-1",
				URL:        "http://example.com/test",
				Type:       "http",
				Request:    "GET /test",
			},
		})
	}

	cleanURL = func(string) (string, error) {
		return "http://example.com/test", nil
	}

	findings, err := parseNucleiFile("ignored.json", cweMap{
		"tpl-1": "79",
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

	if f.Scanner != model.ScannerNuclei {
		t.Fatalf("unexpected scanner: %v", f.Scanner)
	}
}

func TestParseNucleiSingleReportCleanUrlFail(t *testing.T) {
	cleanup(t)

	readFile = func(string) ([]byte, error) {
		return json.Marshal([]nucleiTemplateResult{
			{TemplateID: "tpl", URL: "bad-url"},
		})
	}

	cleanURL = func(string) (string, error) {
		return "", errors.New("error")
	}

	_, err := parseNucleiFile("ignored.json", cweMap{})
	if err == nil {
		t.Fatal("expected error from cleanURL")
	}
}

func TestParseNucleiReports(t *testing.T) {
	cleanup(t)

	loadNucleiMap = func(string) (cweMap, error) {
		return cweMap{"tpl": "22"}, nil
	}

	readDir = func(string) ([]os.DirEntry, error) {
		return []os.DirEntry{
			fakeDirEntry{name: "nuclei-http.json"},
			fakeDirEntry{name: "ignored.txt"},
		}, nil
	}

	readFile = func(string) ([]byte, error) {
		return json.Marshal([]nucleiTemplateResult{
			{TemplateID: "tpl", URL: "http://example.com"},
		})
	}

	cleanURL = func(string) (string, error) {
		return "http://example.com", nil
	}

	findings, err := parseNucleiReports("scan1", "map.csv")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
}
