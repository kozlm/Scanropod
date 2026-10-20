package report

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/kozlm/scanropod/internal/model"
)

// parseNucleiReports reads all Nuclei JSON files for given scanID
func parseNucleiReports(scanID, nucleiCSVPath string) ([]normalizedFinding, error) {
	cweIDMap, err := loadNucleiMap(nucleiCSVPath)
	if err != nil {
		return nil, fmt.Errorf("load nuclei cwe map: %w", err)
	}

	paths, err := collectReportFiles(scanID, "nuclei-")
	if err != nil {
		return nil, err
	}

	var out []normalizedFinding
	for _, path := range paths {
		name := filepath.Base(path)
		fileFindings, err := parseNucleiFile(path, cweIDMap)
		if err != nil {
			return nil, fmt.Errorf("parse nuclei report %s: %w", name, err)
		}
		out = append(out, fileFindings...)
	}

	return out, nil
}

type nucleiTemplateResult struct {
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

var loadNucleiMap = func(path string) (cweMap, error) {
	return loadMap(path, "nuclei")
}

func parseNucleiFile(path string, cweIDMap cweMap) ([]normalizedFinding, error) {
	data, err := readFile(path)
	if err != nil {
		return nil, err
	}

	// Nuclei writes JSON array or JSON lines
	var templates []nucleiTemplateResult
	if err := json.Unmarshal(data, &templates); err != nil {
		// try JSON lines
		templates = []nucleiTemplateResult{}
		decoder := json.NewDecoder(strings.NewReader(string(data)))
		for {
			var template nucleiTemplateResult
			if err := decoder.Decode(&template); err != nil {
				if err.Error() == "EOF" || err == io.EOF {
					break
				}
				return nil, fmt.Errorf("unmarshal nuclei json (lines fallback): %w", err)
			}
			templates = append(templates, template)
		}
	}

	var findings []normalizedFinding

	for _, template := range templates {
		targetUrl, err := cleanURL(template.URL)
		if err != nil {
			return nil, fmt.Errorf("clean nuclei targetUrl: %w", err)
		}

		cweID := cweIDMap[template.TemplateID]
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

		findings = append(findings, normalizedFinding{
			TargetURL: targetUrl,
			CWEID:     cweID,
			Scanner:   model.ScannerNuclei,
			Payload:   payload,
		})
	}

	return findings, nil
}
