package report

import (
	"os"
	"testing"

	"github.com/kozlm/scanropod/internal/model"
)

// Test seam defaults; tests override the package-level seams and
// cleanup restores them.
var (
	defaultReadFile      = readFile
	defaultReadDir       = readDir
	defaultCleanURL      = cleanURL
	defaultBuildURL      = buildURL
	defaultLoadZapMap    = loadZapMap
	defaultLoadNiktoMap  = loadNiktoMap
	defaultLoadNucleiMap = loadNucleiMap
	defaultLoadWapitiMap = loadWapitiMap
)

func cleanup(t *testing.T) {
	t.Helper()

	t.Cleanup(func() {
		readFile = defaultReadFile
		readDir = defaultReadDir
		cleanURL = defaultCleanURL
		buildURL = defaultBuildURL
		loadZapMap = defaultLoadZapMap
		loadNiktoMap = defaultLoadNiktoMap
		loadNucleiMap = defaultLoadNucleiMap
		loadWapitiMap = defaultLoadWapitiMap
	})
}

type fakeDirEntry struct {
	name string
}

func (f fakeDirEntry) Name() string               { return f.name }
func (f fakeDirEntry) IsDir() bool                { return false }
func (f fakeDirEntry) Type() os.FileMode          { return 0 }
func (f fakeDirEntry) Info() (os.FileInfo, error) { return nil, nil }

func TestGroupFindings(t *testing.T) {
	findings := []normalizedFinding{
		{
			TargetURL: "http://example.com",
			CWEID:     "79",
			Scanner:   model.ScannerZap,
			Payload:   "zap-payload",
		},
		{
			TargetURL: "http://example.com",
			CWEID:     "79",
			Scanner:   model.ScannerNikto,
			Payload:   "nikto-payload",
		},
	}

	report := groupFindings(findings)

	targets := report.Findings
	if len(targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(targets))
	}

	cwes := targets["http://example.com"]
	if len(cwes) != 1 {
		t.Fatalf("expected 1 CWE, got %d", len(cwes))
	}

	scanners := cwes["79"]
	if len(scanners) != 2 {
		t.Fatalf("expected 2 scanners, got %d", len(scanners))
	}
}

func TestGroupFindingsMissingTargetURL(t *testing.T) {
	findings := []normalizedFinding{
		{
			TargetURL: "",
			CWEID:     "89",
			Scanner:   model.ScannerNuclei,
			Payload:   "payload",
		},
	}

	report := groupFindings(findings)

	if _, ok := report.Findings["unknown"]; !ok {
		t.Fatal(`expected target "unknown"`)
	}
}

func TestGroupFindingsMultiplePayloadsSameScanner(t *testing.T) {
	findings := []normalizedFinding{
		{
			TargetURL: "http://a",
			CWEID:     "79",
			Scanner:   model.ScannerZap,
			Payload:   "p1",
		},
		{
			TargetURL: "http://a",
			CWEID:     "79",
			Scanner:   model.ScannerZap,
			Payload:   "p2",
		},
	}

	report := groupFindings(findings)

	payloads := report.
		Findings["http://a"]["79"][model.ScannerZap]

	if len(payloads) != 2 {
		t.Fatalf("expected 2 payloads, got %d", len(payloads))
	}
}

func TestBuildNoPathsProvided(t *testing.T) {
	report, err := Build("scan1", Config{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(report.Findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(report.Findings))
	}
}

func TestBuildInvalidPath(t *testing.T) {
	_, err := Build("scan1", Config{
		ZapCSVPath: "does-not-exist.csv",
	})

	if err == nil {
		t.Fatal("expected error for invalid CSV path")
	}
}
