package wapiti

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kozlm/scanropod/internal/cwe"
	"github.com/kozlm/scanropod/internal/helper"
	"github.com/kozlm/scanropod/internal/model"
)

type result struct {
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

type wapitiFindingPayload struct {
	Name    string `json:"name"`
	Method  string `json:"method"`
	Info    string `json:"info"`
	Level   int    `json:"level"`
	Module  string `json:"module"`
	Request string `json:"request"`
	Path    string `json:"path"`
}

var (
	loadWapitiMap = cwe.LoadWapitiMap
	readDir       = os.ReadDir
	readFile      = os.ReadFile
	cleanUrl      = helper.CleanUrl
)

// ParseReports reads all Wapiti JSON files for given scanID
func ParseReports(scanID, wapitiCSVPath string) ([]model.NormalizedFinding, error) {
	cweMap, err := loadWapitiMap(wapitiCSVPath)
	if err != nil {
		return nil, fmt.Errorf("load wapiti cwe map: %w", err)
	}

	reportsDir := filepath.Join("reports", scanID)
	entries, err := readDir(reportsDir)
	if err != nil {
		return nil, fmt.Errorf("read reports dir: %w", err)
	}

	var out []model.NormalizedFinding

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !isWapitiReportFile(name) {
			continue
		}

		path := filepath.Join(reportsDir, name)
		fileFindings, err := parseSingleReport(path, cweMap)
		if err != nil {
			return nil, fmt.Errorf("parse wapiti report %s: %w", name, err)
		}
		out = append(out, fileFindings...)
	}

	return out, nil
}

func isWapitiReportFile(name string) bool {
	return filepath.Ext(name) == ".json" && strings.HasPrefix(name, "wapiti-")
}

func parseSingleReport(path string, cweMap *cwe.WapitiMap) ([]model.NormalizedFinding, error) {
	data, err := readFile(path)
	if err != nil {
		return nil, err
	}

	var res result
	if err := json.Unmarshal(data, &res); err != nil {
		return nil, fmt.Errorf("unmarshal wapiti json: %w", err)
	}

	findings := make([]model.NormalizedFinding, 0)

	// vulnerabilities, anomalies, additionals have same structure
	addCategory := func(name string, categoryEntries []wapitiFinding) error {
		for _, categoryEntry := range categoryEntries {
			targetUrl, err := cleanUrl(res.Infos.Target)
			if err != nil {
				return fmt.Errorf("clean wapiti targetUrl: %w", err)
			}

			cweID := cweMap.Lookup(name, categoryEntry.Info)

			payload := wapitiFindingPayload{
				Name:    name,
				Method:  categoryEntry.Method,
				Info:    categoryEntry.Info,
				Level:   categoryEntry.Level,
				Module:  categoryEntry.Module,
				Request: categoryEntry.HTTPRequest,
				Path:    categoryEntry.Path,
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
