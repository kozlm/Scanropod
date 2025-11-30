package nikto

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kozlm/scanropods/internal/cwe"
	"github.com/kozlm/scanropods/internal/models"
)

type hostReport struct {
	Host            string      `json:"host"`
	IP              string      `json:"ip"`
	Port            string      `json:"port"`
	Banner          string      `json:"banner"`
	Vulnerabilities []vulnEntry `json:"vulnerabilities"`
}

type vulnEntry struct {
	ID         string `json:"id"`
	References string `json:"references"`
	Method     string `json:"method"`
	URL        string `json:"url"`
	Msg        string `json:"msg"`
}

type NiktoFindingPayload struct {
	ID         string `json:"id"`
	Method     string `json:"method"`
	Msg        string `json:"msg"`
	References string `json:"references"`
	URL        string `json:"url"`
}

// ParseReports reads all Nikto JSON files for given scanID
func ParseReports(scanID, niktoCSVPath string) ([]models.NormalizedFinding, error) {
	nm, err := cwe.LoadNiktoMap(niktoCSVPath)
	if err != nil {
		return nil, fmt.Errorf("load nikto cwe map: %w", err)
	}

	reportsDir := filepath.Join("reports", scanID)
	entries, err := os.ReadDir(reportsDir)
	if err != nil {
		return nil, fmt.Errorf("read reports dir: %w", err)
	}

	var out []models.NormalizedFinding

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !isNiktoReportFile(name) {
			continue
		}

		scheme := schemeFromName(name) // http / https
		path := filepath.Join(reportsDir, name)

		fileFindings, err := parseSingleReport(path, scheme, nm)
		if err != nil {
			return nil, fmt.Errorf("parse nikto report %s: %w", name, err)
		}
		out = append(out, fileFindings...)
	}

	return out, nil
}

func isNiktoReportFile(name string) bool {
	return filepath.Ext(name) == ".json" && strings.HasPrefix(name, "nikto-")
}

func schemeFromName(name string) string {
	// after "nikto-" up to first "_"
	s := strings.TrimPrefix(name, "nikto-")
	idx := strings.IndexRune(s, '_')
	if idx == -1 {
		return "http"
	}
	proto := s[:idx]
	if proto == "https" {
		return "https"
	}
	return "http"
}

func parseSingleReport(path, scheme string, nm cwe.NiktoMap) ([]models.NormalizedFinding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var hosts []hostReport
	if err := json.Unmarshal(data, &hosts); err != nil {
		return nil, fmt.Errorf("unmarshal nikto json: %w", err)
	}

	var findings []models.NormalizedFinding

	for _, h := range hosts {
		targetURL := fmt.Sprintf("%s://%s:%s", scheme, h.Host, h.Port)

		for _, v := range h.Vulnerabilities {
			cweID := nm[v.ID]

			payload := NiktoFindingPayload{
				ID:         v.ID,
				Method:     v.Method,
				Msg:        v.Msg,
				References: v.References,
				URL:        v.URL,
			}

			findings = append(findings, models.NormalizedFinding{
				TargetURL: targetURL,
				CWEID:     cweID,
				Scanner:   models.ScannerNikto,
				Payload:   payload,
			})
		}
	}

	return findings, nil
}
