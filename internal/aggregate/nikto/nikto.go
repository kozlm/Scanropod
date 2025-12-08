package nikto

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kozlm/scanropods/internal/cwe"
	"github.com/kozlm/scanropods/internal/helper"
	"github.com/kozlm/scanropods/internal/model"
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
func ParseReports(scanID, niktoCSVPath string) ([]model.NormalizedFinding, error) {
	nm, err := cwe.LoadNiktoMap(niktoCSVPath)
	if err != nil {
		return nil, fmt.Errorf("load nikto cwe map: %w", err)
	}

	reportsDir := filepath.Join("reports", scanID)
	entries, err := os.ReadDir(reportsDir)
	if err != nil {
		return nil, fmt.Errorf("read reports dir: %w", err)
	}

	var out []model.NormalizedFinding

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !isNiktoReportFile(name) {
			continue
		}

		scheme := helper.SchemeFromReportFileName(name) // http / https
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

func parseSingleReport(path, scheme string, nm cwe.NiktoMap) ([]model.NormalizedFinding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var hosts []hostReport
	if err := json.Unmarshal(data, &hosts); err != nil {
		return nil, fmt.Errorf("unmarshal nikto json: %w", err)
	}

	var findings []model.NormalizedFinding

	for _, h := range hosts {

		for _, v := range h.Vulnerabilities {
			targetUrl, err := helper.CleanUrl(helper.BuildUrl(h.Host, v.URL, h.Port, scheme))
			if err != nil {
				return nil, fmt.Errorf("clean nikto targetUrl: %w", err)
			}

			cweID := nm[v.ID]

			payload := NiktoFindingPayload{
				ID:         v.ID,
				Method:     v.Method,
				Msg:        v.Msg,
				References: v.References,
				URL:        v.URL,
			}

			findings = append(findings, model.NormalizedFinding{
				TargetURL: targetUrl,
				CWEID:     cweID,
				Scanner:   model.ScannerNikto,
				Payload:   payload,
			})
		}
	}

	return findings, nil
}
