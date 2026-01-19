package nikto

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

type hostResult struct {
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

type niktoFindingPayload struct {
	ID         string `json:"id"`
	Method     string `json:"method"`
	Msg        string `json:"msg"`
	References string `json:"references"`
	URL        string `json:"url"`
}

var (
	loadNiktoMap   = cwe.LoadNiktoMap
	readDir        = os.ReadDir
	readFile       = os.ReadFile
	buildUrl       = helper.BuildUrl
	cleanUrl       = helper.CleanUrl
	schemeFromName = helper.SchemeFromReportFileName
)

// ParseReports reads all Nikto JSON files for given scanID
func ParseReports(scanID, niktoCSVPath string) ([]model.NormalizedFinding, error) {
	cweMap, err := loadNiktoMap(niktoCSVPath)
	if err != nil {
		return nil, fmt.Errorf("load nikto cwe map: %w", err)
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
		if !isNiktoReportFile(name) {
			continue
		}

		scheme := schemeFromName(name) // http / https
		path := filepath.Join(reportsDir, name)

		fileFindings, err := parseSingleReport(path, scheme, cweMap)
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

func parseSingleReport(path, scheme string, cweMap cwe.NiktoMap) ([]model.NormalizedFinding, error) {
	data, err := readFile(path)
	if err != nil {
		return nil, err
	}

	var hosts []hostResult
	if err := json.Unmarshal(data, &hosts); err != nil {
		return nil, fmt.Errorf("unmarshal nikto json: %w", err)
	}

	var findings []model.NormalizedFinding

	for _, host := range hosts {

		for _, vuln := range host.Vulnerabilities {
			targetUrl, err := cleanUrl(buildUrl(host.Host, vuln.URL, host.Port, scheme))
			if err != nil {
				return nil, fmt.Errorf("clean nikto targetUrl: %w", err)
			}

			cweID := cweMap[vuln.ID]
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
