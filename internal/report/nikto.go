package report

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/kozlm/scanropod/internal/model"
)

// parseNiktoReports reads all Nikto JSON files for given scanID
func parseNiktoReports(scanID, niktoCSVPath string) ([]normalizedFinding, error) {
	cweIDMap, err := loadNiktoMap(niktoCSVPath)
	if err != nil {
		return nil, fmt.Errorf("load nikto cwe map: %w", err)
	}

	paths, err := collectReportFiles(scanID, "nikto-")
	if err != nil {
		return nil, err
	}

	var out []normalizedFinding
	for _, path := range paths {
		// http / https, from the report file name (e.g. nikto-https_...)
		name := filepath.Base(path)
		scheme := schemeFromReportFileName(name)
		fileFindings, err := parseNiktoFile(path, scheme, cweIDMap)
		if err != nil {
			return nil, fmt.Errorf("parse nikto report %s: %w", name, err)
		}
		out = append(out, fileFindings...)
	}

	return out, nil
}

type niktoHostResult struct {
	Host            string           `json:"host"`
	IP              string           `json:"ip"`
	Port            string           `json:"port"`
	Banner          string           `json:"banner"`
	Vulnerabilities []niktoVulnEntry `json:"vulnerabilities"`
}

type niktoVulnEntry struct {
	ID         string `json:"id"`
	References string `json:"references"`
	Method     string `json:"method"`
	URL        string `json:"url"`
	Msg        string `json:"msg"`
}

type niktoFindingPayload struct {
	ID         string `json:"id"`
	Method     string `json:"method"`
	Msg        string `json:"msg"`
	References string `json:"references"`
	URL        string `json:"url"`
}

var loadNiktoMap = func(path string) (cweMap, error) {
	return loadMap(path, "nikto")
}

func parseNiktoFile(path, scheme string, cweIDMap cweMap) ([]normalizedFinding, error) {
	data, err := readFile(path)
	if err != nil {
		return nil, err
	}

	var hosts []niktoHostResult
	if err := json.Unmarshal(data, &hosts); err != nil {
		return nil, fmt.Errorf("unmarshal nikto json: %w", err)
	}

	var findings []normalizedFinding

	for _, host := range hosts {

		for _, vuln := range host.Vulnerabilities {
			targetUrl, err := cleanURL(buildURL(host.Host, vuln.URL, host.Port, scheme))
			if err != nil {
				return nil, fmt.Errorf("clean nikto targetUrl: %w", err)
			}

			cweID := cweIDMap[vuln.ID]
			if cweID == "" {
				cweID = "0"
			}

			payload := niktoFindingPayload{
				ID:         vuln.ID,
				Method:     vuln.Method,
				Msg:        vuln.Msg,
				References: vuln.References,
				URL:        vuln.URL,
			}

			findings = append(findings, normalizedFinding{
				TargetURL: targetUrl,
				CWEID:     cweID,
				Scanner:   model.ScannerNikto,
				Payload:   payload,
			})
		}
	}

	return findings, nil
}
