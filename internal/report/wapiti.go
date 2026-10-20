package report

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/kozlm/scanropod/internal/model"
)

// parseWapitiReports reads all Wapiti JSON files for given scanID
func parseWapitiReports(scanID, wapitiCSVPath string) ([]normalizedFinding, error) {
	cweLookup, err := loadWapitiMap(wapitiCSVPath)
	if err != nil {
		return nil, fmt.Errorf("load wapiti cwe map: %w", err)
	}

	paths, err := collectReportFiles(scanID, "wapiti-")
	if err != nil {
		return nil, err
	}

	var out []normalizedFinding
	for _, path := range paths {
		name := filepath.Base(path)
		fileFindings, err := parseWapitiFile(path, cweLookup)
		if err != nil {
			return nil, fmt.Errorf("parse wapiti report %s: %w", name, err)
		}
		out = append(out, fileFindings...)
	}

	return out, nil
}

type wapitiReport struct {
	Vulnerabilities map[string][]wapitiFinding `json:"vulnerabilities"`
	Anomalies       map[string][]wapitiFinding `json:"anomalies"`
	Additionals     map[string][]wapitiFinding `json:"additionals"`
	Infos           wapitiInfo                 `json:"infos"`
}

type wapitiInfo struct {
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

type wapitiFindingPayload struct {
	Name    string `json:"name"`
	Method  string `json:"method"`
	Info    string `json:"info"`
	Level   int    `json:"level"`
	Module  string `json:"module"`
	Request string `json:"request"`
	Path    string `json:"path"`
}

func parseWapitiFile(path string, cweLookup *wapitiCWEMap) ([]normalizedFinding, error) {
	data, err := readFile(path)
	if err != nil {
		return nil, err
	}

	var res wapitiReport
	if err := json.Unmarshal(data, &res); err != nil {
		return nil, fmt.Errorf("unmarshal wapiti json: %w", err)
	}

	findings := make([]normalizedFinding, 0)

	// vulnerabilities, anomalies, additionals have same structure
	addCategory := func(name string, categoryEntries []wapitiFinding) error {
		for _, categoryEntry := range categoryEntries {
			targetUrl, err := cleanURL(res.Infos.Target)
			if err != nil {
				return fmt.Errorf("clean wapiti targetUrl: %w", err)
			}

			cweID := cweLookup.Lookup(name, categoryEntry.Info)

			payload := wapitiFindingPayload{
				Name:    name,
				Method:  categoryEntry.Method,
				Info:    categoryEntry.Info,
				Level:   categoryEntry.Level,
				Module:  categoryEntry.Module,
				Request: categoryEntry.HTTPRequest,
				Path:    categoryEntry.Path,
			}

			findings = append(findings, normalizedFinding{
				TargetURL: targetUrl,
				CWEID:     cweID,
				Scanner:   model.ScannerWapiti,
				Payload:   payload,
			})
		}
		return nil
	}

	// append findings from vulnerabilities, anomalies and additionals categories
	for name, list := range res.Vulnerabilities {
		if err := addCategory(name, list); err != nil {
			return nil, err
		}
	}
	for name, list := range res.Anomalies {
		if err := addCategory(name, list); err != nil {
			return nil, err
		}
	}
	for name, list := range res.Additionals {
		if err := addCategory(name, list); err != nil {
			return nil, err
		}
	}

	return findings, nil
}
