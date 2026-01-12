package zap

import (
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/kozlm/scanropods/internal/cwe"
	"github.com/kozlm/scanropods/internal/model"
)

var (
	defaultReadFile   = readFile
	defaultReadDir    = readDir
	defaultCleanUrl   = cleanUrl
	defaultLoadZapMap = loadZapMap
)

func cleanup(t *testing.T) {
	t.Cleanup(func() {
		readFile = defaultReadFile
		readDir = defaultReadDir
		cleanUrl = defaultCleanUrl
		loadZapMap = defaultLoadZapMap
	})
}

func TestIsZapReportFile(t *testing.T) {
	tests := []struct {
		name     string
		expected bool
	}{
		{"zap-test.json", true},
		{"zap-test.txt", false},
		{"other.json", false},
	}

	for _, test := range tests {
		if got := isZapReportFile(test.name); got != test.expected {
			t.Errorf("for %q expected %v, got %v", test.name, test.expected, got)
		}
	}
}

func TestParseSingleReportSuccess(t *testing.T) {
	cleanup(t)

	readFile = func(string) ([]byte, error) {
		return json.Marshal(result{
			Sites: []zapSite{
				{
					Alerts: []zapAlert{
						{
							AlertRef: "10001",
							Alert:    "XSS",
							Name:     "Cross Site Scripting",
							RiskCode: "3",
							Instances: []zapInstance{
								{
									URI:      "http://example.com/test",
									Method:   "GET",
									Param:    "q",
									Evidence: "<script>",
								},
							},
						},
					},
				},
			},
		})
	}

	cleanUrl = func(string) (string, error) {
		return "http://example.com/test", nil
	}

	findings, err := parseSingleReport("ignored.json", cwe.ZapMap{
		"10001": "79",
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

	if f.Scanner != model.ScannerZap {
		t.Fatalf("unexpected scanner: %v", f.Scanner)
	}
}

func TestParseSingleReportCleanUrlFail(t *testing.T) {
	cleanup(t)

	readFile = func(string) ([]byte, error) {
		return json.Marshal(result{
			Sites: []zapSite{
				{
					Alerts: []zapAlert{
						{
							AlertRef: "1",
							Instances: []zapInstance{
								{URI: "bad-url"},
							},
						},
					},
				},
			},
		})
	}

	cleanUrl = func(string) (string, error) {
		return "", errors.New("error")
	}

	_, err := parseSingleReport("ignored.json", cwe.ZapMap{})
	if err == nil {
		t.Fatal("expected error from cleanUrl")
	}
}

func TestParseReports(t *testing.T) {
	cleanup(t)

	loadZapMap = func(string) (cwe.ZapMap, error) {
		return cwe.ZapMap{"1": "22"}, nil
	}

	readDir = func(string) ([]os.DirEntry, error) {
		return []os.DirEntry{
			fakeDirEntry{name: "zap-scan.json"},
			fakeDirEntry{name: "ignored.txt"},
		}, nil
	}

	readFile = func(string) ([]byte, error) {
		return json.Marshal(result{
			Sites: []zapSite{
				{
					Alerts: []zapAlert{
						{
							AlertRef: "1",
							Instances: []zapInstance{
								{URI: "http://example.com"},
							},
						},
					},
				},
			},
		})
	}

	cleanUrl = func(string) (string, error) {
		return "http://example.com", nil
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
