package wapiti

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/kozlm/scanropods/internal/cwe"
	"github.com/kozlm/scanropods/internal/helper"
	"github.com/kozlm/scanropods/internal/model"
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
func ParseReports(scanID, wapitiCSVPath string) ([]model.NormalizedFinding, error) {
	wm, err := cwe.LoadWapitiMap(wapitiCSVPath)
	if err != nil {
		return nil, fmt.Errorf("load wapiti cwe map: %w", err)
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

func parseSingleReport(path string, wm *cwe.WapitiMap) ([]model.NormalizedFinding, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var r Report
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("unmarshal wapiti json: %w", err)
	}

	findings := make([]model.NormalizedFinding, 0)

	// vulnerabilities, anomalies, additionals have same structure
	addCategory := func(name string, list []wapitiFinding) error {
		for _, v := range list {
			targetUrl, err := helper.CleanUrl(r.Infos.Target)
			if err != nil {
				return fmt.Errorf("clean wapiti targetUrl: %w", err)
			}

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

			findings = append(findings, model.NormalizedFinding{
				TargetURL: targetUrl,
				CWEID:     cweID,
				Scanner:   model.ScannerWapiti,
				Payload:   payload,
			})
		}
		return nil
	}

	for name, list := range r.Vulnerabilities {
		if err := addCategory(name, list); err != nil {
			return nil, err
		}
	}
	for name, list := range r.Anomalies {
		if err := addCategory(name, list); err != nil {
			return nil, err
		}
	}
	for name, list := range r.Additionals {
		if err := addCategory(name, list); err != nil {
			return nil, err
		}
	}

	return findings, nil
}
