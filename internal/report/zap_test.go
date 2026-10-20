package report

import (
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/kozlm/scanropod/internal/model"
)

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
		if got := isReportFile(test.name, "zap-"); got != test.expected {
			t.Errorf("for %q expected %v, got %v", test.name, test.expected, got)
		}
	}
}

func TestParseZapSingleReportSuccess(t *testing.T) {
	cleanup(t)

	readFile = func(string) ([]byte, error) {
		return json.Marshal(zapReport{
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

	cleanURL = func(string) (string, error) {
		return "http://example.com/test", nil
	}

	findings, err := parseZapFile("ignored.json", cweMap{
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

func TestParseZapSingleReportCleanUrlFail(t *testing.T) {
	cleanup(t)

	readFile = func(string) ([]byte, error) {
		return json.Marshal(zapReport{
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

	cleanURL = func(string) (string, error) {
		return "", errors.New("error")
	}

	_, err := parseZapFile("ignored.json", cweMap{})
	if err == nil {
		t.Fatal("expected error from cleanURL")
	}
}

func TestParseZapReports(t *testing.T) {
	cleanup(t)

	loadZapMap = func(string) (cweMap, error) {
		return cweMap{"1": "22"}, nil
	}

	readDir = func(string) ([]os.DirEntry, error) {
		return []os.DirEntry{
			fakeDirEntry{name: "zap-scan.json"},
			fakeDirEntry{name: "ignored.txt"},
		}, nil
	}

	readFile = func(string) ([]byte, error) {
		return json.Marshal(zapReport{
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

	cleanURL = func(string) (string, error) {
		return "http://example.com", nil
	}

	findings, err := parseZapReports("scan1", "map.csv")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
}
