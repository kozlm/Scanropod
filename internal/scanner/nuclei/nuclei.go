package nuclei

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/kozlm/scanropods/internal/cwe"
	"github.com/kozlm/scanropods/internal/models"
)

type Result struct {
	TemplateID      string `json:"template-id"`
	TemplatePath    string `json:"template-path"`
	TemplateEncoded string `json:"template-encoded"`

	Info json.RawMessage `json:"info"` // raw blob, untouched
	Type string          `json:"type"`

	Host string `json:"host"`
	Port string `json:"port"`
	URL  string `json:"url"`

	Request string `json:"request"`
}

type NucleiFindingPayload struct {
	TemplateID string          `json:"template_id"`
	Info       json.RawMessage `json:"info"`
	Type       string          `json:"type"`
	Request    string          `json:"request"`
	URL        string          `json:"url"`
}

// ParseReports reads all Nuclei JSON files for given scanID
func ParseReports(scanID, nucleiCSVPath string) ([]models.NormalizedFinding, error) {
	nm, err := cwe.LoadNucleiMap(nucleiCSVPath)
	if err != nil {
		return nil, fmt.Errorf("load nuclei cwe map: %w", err)
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
		if !isNucleiReportFile(name) {
			continue
		}

		path := filepath.Join(reportsDir, name)
		fileFindings, err := parseSingleReport(path, nm)
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

func parseSingleReport(path string, nm cwe.NucleiMap) ([]models.NormalizedFinding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Nuclei writes JSON array or JSON lines
	var arr []Result
	if err := json.Unmarshal(data, &arr); err != nil {
		// try JSON lines
		arr = []Result{}
		dec := json.NewDecoder(strings.NewReader(string(data)))
		for {
			var r Result
			if err := dec.Decode(&r); err != nil {
				if err.Error() == "EOF" || err == io.EOF {
					break
				}
				return nil, fmt.Errorf("unmarshal nuclei json (lines fallback): %w", err)
			}
			arr = append(arr, r)
		}
	}

	var findings []models.NormalizedFinding

	for _, r := range arr {
		targetURL := r.URL
		if strings.TrimSpace(targetURL) == "" {
			if r.Host != "" {
				if r.Port != "" {
					targetURL = "http://" + r.Host + ":" + r.Port
				} else {
					targetURL = "http://" + r.Host
				}
			} else {
				targetURL = "unknown"
			}
		}

		cweID := nm[r.TemplateID]
		if cweID == "" {
			cweID = "0"
		}

		payload := NucleiFindingPayload{
			TemplateID: r.TemplateID,
			Info:       r.Info, // raw json copied unchanged
			Type:       r.Type,
			Request:    r.Request,
			URL:        r.URL,
		}

		findings = append(findings, models.NormalizedFinding{
			TargetURL: targetURL,
			CWEID:     cweID,
			Scanner:   models.ScannerNuclei,
			Payload:   payload,
		})
	}

	return findings, nil
}
