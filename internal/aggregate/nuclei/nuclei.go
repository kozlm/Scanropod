package nuclei

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/kozlm/scanropod/internal/cwe"
	"github.com/kozlm/scanropod/internal/helper"
	"github.com/kozlm/scanropod/internal/model"
)

type templateResult struct {
	TemplateID      string `json:"template-id"`
	TemplatePath    string `json:"template-path"`
	TemplateEncoded string `json:"template-encoded"`

	Info json.RawMessage `json:"info"` // raw blob
	Type string          `json:"type"`

	Host string `json:"host"`
	Port string `json:"port"`
	URL  string `json:"url"`

	Request string `json:"request"`
}

type nucleiFindingPayload struct {
	TemplateID string          `json:"template_id"`
	Info       json.RawMessage `json:"info"`
	Type       string          `json:"type"`
	Request    string          `json:"request"`
	URL        string          `json:"url"`
}

var (
	loadNucleiMap = cwe.LoadNucleiMap
	readDir       = os.ReadDir
	readFile      = os.ReadFile
	cleanUrl      = helper.CleanUrl
)

// ParseReports reads all Nuclei JSON files for given scanID
func ParseReports(scanID, nucleiCSVPath string) ([]model.NormalizedFinding, error) {
	cweMap, err := loadNucleiMap(nucleiCSVPath)
	if err != nil {
		return nil, fmt.Errorf("load nuclei cwe map: %w", err)
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
		if !isNucleiReportFile(name) {
			continue
		}

		path := filepath.Join(reportsDir, name)
		fileFindings, err := parseSingleReport(path, cweMap)
		if err != nil {
			return nil, fmt.Errorf("parse nuclei report %s: %w", name, err)
		}
		out = append(out, fileFindings...)
	}

	return out, nil
}

func isNucleiReportFile(name string) bool {
	return filepath.Ext(name) == ".json" && strings.HasPrefix(name, "nuclei-")
}

func parseSingleReport(path string, cweMap cwe.NucleiMap) ([]model.NormalizedFinding, error) {
	data, err := readFile(path)
	if err != nil {
		return nil, err
	}

	// Nuclei writes JSON array or JSON lines
	var templates []templateResult
	if err := json.Unmarshal(data, &templates); err != nil {
		// try JSON lines
		templates = []templateResult{}
		decoder := json.NewDecoder(strings.NewReader(string(data)))
		for {
			var template templateResult
			if err := decoder.Decode(&template); err != nil {
				if err.Error() == "EOF" || err == io.EOF {
					break
				}
				return nil, fmt.Errorf("unmarshal nuclei json (lines fallback): %w", err)
			}
			templates = append(templates, template)
		}
	}

	var findings []model.NormalizedFinding

	for _, template := range templates {
		targetUrl, err := cleanUrl(template.URL)
		if err != nil {
			return nil, fmt.Errorf("clean nuclei targetUrl: %w", err)
		}

		cweID := cweMap[template.TemplateID]
		if cweID == "" {
			cweID = "0"
		}

		payload := nucleiFindingPayload{
			TemplateID: template.TemplateID,
			Info:       template.Info, // raw json copied unchanged
			Type:       template.Type,
			Request:    template.Request,
			URL:        template.URL,
		}

		findings = append(findings, model.NormalizedFinding{
			TargetURL: targetUrl,
			CWEID:     cweID,
			Scanner:   model.ScannerNuclei,
			Payload:   payload,
		})
	}

	return findings, nil
}
