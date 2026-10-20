// Package report builds the aggregated vulnerability report for a scan:
// it loads CWE mapping files, parses the JSON reports produced by the
// four external scanners, normalizes their findings, and groups them by
// target URL, CWE identifier, and scanner.
package report

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kozlm/scanropod/internal/model"
)

// Config holds the paths of the CWE mapping CSV files read from config/.
type Config struct {
	ZapCSVPath    string
	WapitiCSVPath string
	NiktoCSVPath  string
	NucleiCSVPath string
}

var (
	readDir  = os.ReadDir
	readFile = os.ReadFile
)

// normalizedFinding is a single scanner finding in the common shape
// shared by all parsers.
type normalizedFinding struct {
	TargetURL string            // e.g. "http://192.168.0.156"
	CWEID     string            // "CWE-79", "0" for informational
	Scanner   model.ScannerName // zap/wapiti/...
	Payload   interface{}       // concrete struct per scanner
}

// Build builds the final AggregatedReport for given scanID.
func Build(scanID string, cfg Config) (model.AggregatedReport, error) {
	var all []normalizedFinding

	// ZAP
	if cfg.ZapCSVPath != "" {
		zapFindings, err := parseZapReports(scanID, cfg.ZapCSVPath)
		if err != nil {
			return model.AggregatedReport{}, err
		}
		all = append(all, zapFindings...)
	}

	// Wapiti
	if cfg.WapitiCSVPath != "" {
		wapitiFindings, err := parseWapitiReports(scanID, cfg.WapitiCSVPath)
		if err != nil {
			return model.AggregatedReport{}, err
		}
		all = append(all, wapitiFindings...)
	}

	// Nikto
	if cfg.NiktoCSVPath != "" {
		niktoFindings, err := parseNiktoReports(scanID, cfg.NiktoCSVPath)
		if err != nil {
			return model.AggregatedReport{}, err
		}
		all = append(all, niktoFindings...)
	}

	// Nuclei
	if cfg.NucleiCSVPath != "" {
		nucleiFindings, err := parseNucleiReports(scanID, cfg.NucleiCSVPath)
		if err != nil {
			return model.AggregatedReport{}, err
		}
		all = append(all, nucleiFindings...)
	}

	return groupFindings(all), nil
}

func groupFindings(rawFindings []normalizedFinding) model.AggregatedReport {
	// map[target][cwe][scanner] -> []payload

	byTarget := make(map[string]map[string]map[model.ScannerName][]interface{})

	for _, finding := range rawFindings {
		if finding.TargetURL == "" {
			finding.TargetURL = "unknown"
		}
		if byTarget[finding.TargetURL] == nil {
			byTarget[finding.TargetURL] = make(map[string]map[model.ScannerName][]interface{})
		}
		if byTarget[finding.TargetURL][finding.CWEID] == nil {
			byTarget[finding.TargetURL][finding.CWEID] = make(map[model.ScannerName][]interface{})
		}
		byTarget[finding.TargetURL][finding.CWEID][finding.Scanner] =
			append(byTarget[finding.TargetURL][finding.CWEID][finding.Scanner], finding.Payload)
	}

	return model.AggregatedReport{
		ScanDate: time.Now().UTC(),
		Findings: byTarget,
	}
}

// isReportFile reports whether name is a JSON report file produced by
// the scanner identified by prefix (e.g. "zap-", "nikto-").
func isReportFile(name, prefix string) bool {
	return filepath.Ext(name) == ".json" && strings.HasPrefix(name, prefix)
}

// collectReportFiles returns the paths of all JSON report files for
// scanID and the given scanner prefix, looked up relative to the
// working directory: reports/<scanID>/.
func collectReportFiles(scanID, prefix string) ([]string, error) {
	reportsDir := filepath.Join("reports", scanID)

	entries, err := readDir(reportsDir)
	if err != nil {
		return nil, fmt.Errorf("read reports dir: %w", err)
	}

	var paths []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !isReportFile(name, prefix) {
			continue
		}
		paths = append(paths, filepath.Join(reportsDir, name))
	}

	return paths, nil
}
