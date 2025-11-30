package wapiti

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/kozlm/scanropods/internal/cwe"
	"github.com/kozlm/scanropods/internal/models"
)

type Report struct {
	Vulnerabilities map[string][]wapitiFinding `json:"vulnerabilities"`
	Anomalies       map[string][]wapitiFinding `json:"anomalies"`
	Additionals     map[string][]wapitiFinding `json:"additionals"`
	Infos           info                       `json:"infos"`
}

type info struct {
	Target string `json:"target"`
}

type wapitiFinding struct {
	Method      string   `json:"method"`
	Path        string   `json:"path"`
	Info        string   `json:"info"`
	Level       int      `json:"level"`
	Parameter   *string  `json:"parameter"`
	Referer     string   `json:"referer"`
	Module      string   `json:"module"`
	HTTPRequest string   `json:"http_request"`
	CurlCommand string   `json:"curl_command"`
	WSTG        []string `json:"wstg"`
}

type WapitiFindingPayload struct {
	Name    string `json:"name"`
	Method  string `json:"method"`
	Info    string `json:"info"`
	Level   int    `json:"level"`
	Module  string `json:"module"`
	Request string `json:"request"`
	Path    string `json:"path"`
}

// ParseReports reads all Wapiti JSON files for given scanID
func ParseReports(scanID, wapitiCSVPath string) ([]models.NormalizedFinding, error) {
	wm, err := cwe.LoadWapitiMap(wapitiCSVPath)
	if err != nil {
		return nil, fmt.Errorf("load wapiti cwe map: %w", err)
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
		if !isWapitiReportFile(name) {
			continue
		}

		path := filepath.Join(reportsDir, name)
		fileFindings, err := parseSingleReport(path, wm)
		if err != nil {
			return nil, fmt.Errorf("parse wapiti report %s: %w", name, err)
		}
		out = append(out, fileFindings...)
	}

	return out, nil
}

func isWapitiReportFile(name string) bool {
	return filepath.Ext(name) == ".json" && (name == "wapiti.json" || len(name) >= 7 && name[:7] == "wapiti-")
}

func parseSingleReport(path string, wm *cwe.WapitiMap) ([]models.NormalizedFinding, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var r Report
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("unmarshal wapiti json: %w", err)
	}

	target := r.Infos.Target
	findings := make([]models.NormalizedFinding, 0)

	// vulnerabilities, anomalies, additionals have same structure
	addCategory := func(name string, list []wapitiFinding) {
		for _, v := range list {
			cweID := wm.Lookup(name, v.Info)

			payload := WapitiFindingPayload{
				Name:    name,
				Method:  v.Method,
				Info:    v.Info,
				Level:   v.Level,
				Module:  v.Module,
				Request: v.HTTPRequest,
				Path:    v.Path,
			}

			findings = append(findings, models.NormalizedFinding{
				TargetURL: target,
				CWEID:     cweID,
				Scanner:   models.ScannerWapiti,
				Payload:   payload,
			})
		}
	}

	for name, list := range r.Vulnerabilities {
		addCategory(name, list)
	}
	for name, list := range r.Anomalies {
		addCategory(name, list)
	}
	for name, list := range r.Additionals {
		addCategory(name, list)
	}

	return findings, nil
}
